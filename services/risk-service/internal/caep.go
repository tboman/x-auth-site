package internal

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/jwtx"
)

// caep.go is risk-service's CAEP / Shared Signals RECEIVER. It ingests signed
// Security Event Tokens (RFC 8417) emitted by authentication-service when
// device-fingerprint analysis or a step-up warrants a change, verifies them
// against authn's JWKS, audits them, and updates the subject's assurance posture
// that the risk evaluation reads.

// CAEP event type URIs (OpenID CAEP 1.0) — must match the transmitter's.
const (
	CAEPAssuranceLevelChange   = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
	CAEPDeviceComplianceChange = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
	CAEPSessionRevoked         = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
)

// AAL1 is the default assurance level when none has been recorded.
const AAL1 = "nist-aal1"

// CAEPEvent is one received SET event, kept as an append-only audit row.
type CAEPEvent struct {
	ID               string         `json:"id"`
	TenantID         string         `json:"tenant_id"`
	SubjectUserID    string         `json:"subject_user_id,omitempty"`
	SubjectSessionID string         `json:"subject_session_id,omitempty"`
	EventType        string         `json:"event_type"`
	Payload          map[string]any `json:"payload"`
	ReceivedAt       time.Time      `json:"received_at"`
}

// AssuranceState is the current derived posture per (tenant, user).
type AssuranceState struct {
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	Level     string    `json:"level"`
	Compliant bool      `json:"compliant"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ReceiveSET handles POST /internal/v1/ssf/events — a CAEP Security Event Token
// (a signed JWT, sent as the request body) from authentication-service. It
// verifies the signature/claims against authn's JWKS, records every carried
// event, and applies it to the subject's assurance posture. The tenant + subject
// come from the verified SET claims (not an X-Tenant-Id header).
func (h *Handlers) ReceiveSET(w http.ResponseWriter, r *http.Request) {
	if h.CAEPVerifier == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "caep_unconfigured", "SET receiver is not configured")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "read_error", "could not read SET")
		return
	}
	claims, extra, err := h.CAEPVerifier.Verify(strings.TrimSpace(string(body)), h.Clock.Now())
	if err != nil {
		h.Logger.Warn("caep_set_verify_failed", "err", err)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_set", "SET signature or claims invalid")
		return
	}
	events, ok := extra["events"].(map[string]any)
	if !ok || len(events) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "no_events", "SET carries no events")
		return
	}

	for uri, raw := range events {
		payload, _ := raw.(map[string]any)
		ev := CAEPEvent{
			ID:               "cev_" + uuid.NewString(),
			TenantID:         claims.TenantID,
			SubjectUserID:    claims.Sub,
			SubjectSessionID: claims.SessionID,
			EventType:        uri,
			Payload:          payload,
			ReceivedAt:       h.Clock.Now(),
		}
		if err := h.Store.RecordCAEPEvent(ev); err != nil {
			h.Logger.Error("caep_event_store_failed", "err", err, "event", uri)
		}
		h.applyEvent(claims, uri, payload)
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"received": len(events)})
}

// applyEvent updates the subject's assurance posture from one event.
func (h *Handlers) applyEvent(claims jwtx.Claims, uri string, payload map[string]any) {
	if claims.TenantID == "" || claims.Sub == "" {
		return
	}
	str := func(k string) string { v, _ := payload[k].(string); return v }
	cur, _ := h.Store.GetAssurance(claims.TenantID, claims.Sub)

	switch uri {
	case CAEPAssuranceLevelChange:
		level := str("current_level")
		if level == "" {
			return
		}
		compliant := true
		if cur.Level != "" {
			compliant = cur.Compliant
		}
		if err := h.Store.UpsertAssurance(AssuranceState{
			TenantID: claims.TenantID, UserID: claims.Sub, Level: level, Compliant: compliant, UpdatedAt: h.Clock.Now(),
		}); err != nil {
			h.Logger.Error("caep_assurance_upsert_failed", "err", err)
			return
		}
		h.Logger.Info("caep_assurance_updated", "tenant_id", claims.TenantID, "user_id", claims.Sub,
			"level", level, "direction", str("change_direction"))
	case CAEPDeviceComplianceChange:
		level := cur.Level
		if level == "" {
			level = AAL1
		}
		_ = h.Store.UpsertAssurance(AssuranceState{
			TenantID: claims.TenantID, UserID: claims.Sub, Level: level,
			Compliant: str("current_status") == "compliant", UpdatedAt: h.Clock.Now(),
		})
		h.Logger.Warn("caep_compliance_changed", "tenant_id", claims.TenantID, "user_id", claims.Sub, "status", str("current_status"))
	case CAEPSessionRevoked:
		// risk-service does not own sessions — authn already invalidated it.
		// Recorded for the audit trail / threat matrix.
		h.Logger.Warn("caep_session_revoked", "tenant_id", claims.TenantID, "user_id", claims.Sub, "session_id", claims.SessionID)
	}
}

// VerifierFromJWKS fetches a JWKS document over HTTP and builds a SET verifier
// bound to expectedIssuer. Used at startup to trust authn's signing key.
func VerifierFromJWKS(jwksURL, expectedIssuer string) (*jwtx.Verifier, error) {
	resp, err := http.Get(jwksURL) //nolint:gosec // operator-configured internal URL
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var set jwtx.JWKS
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, err
	}
	return jwtx.NewVerifierFromJWKS(expectedIssuer, set)
}
