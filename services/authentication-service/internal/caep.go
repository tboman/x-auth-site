package internal

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/jwtx"
)

// caep.go is the CAEP / Shared Signals transmitter side. When the device
// analyzer (device_analyzer.go) decides a fingerprint comparison or a step-up
// warrants a security event, it builds a signed Security Event Token (SET,
// RFC 8417) carrying a CAEP event and POSTs it to risk-service's receiver.
//
// The SET is signed with this service's RS256 key (the same key behind the
// public JWKS), so the receiver verifies it against authentication-service's
// published key set — no shared secret for authenticity, only the existing
// internal-auth header for transport authorization.
//
// If no receiver is configured (RISK_EVENTS_URL unset), the transmitter logs
// the event and drops it — so the analyzer works (and is testable) without
// risk-service deployed.

// CAEP event type URIs (OpenID CAEP 1.0).
const (
	CAEPAssuranceLevelChange   = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
	CAEPDeviceComplianceChange = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
	CAEPSessionRevoked         = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
)

// NIST Authenticator Assurance Levels used in assurance-level-change events.
const (
	AAL1 = "nist-aal1"
	AAL2 = "nist-aal2"
)

// CAEPTransmitter builds, signs, and delivers SETs to the risk-service receiver.
type CAEPTransmitter struct {
	Signer         *jwtx.Signer
	Issuer         string // SET `iss` (this service's issuer)
	EventsURL      string // receiver endpoint; "" → log-only (no risk-service)
	InternalSecret string // X-Internal-Auth header value for transport auth
	Logger         *slog.Logger
	HTTP           *http.Client
}

// NewCAEPTransmitter builds a transmitter. A blank eventsURL yields a log-only
// transmitter (everything works, nothing is sent).
func NewCAEPTransmitter(signer *jwtx.Signer, issuer, eventsURL, internalSecret string, logger *slog.Logger) *CAEPTransmitter {
	return &CAEPTransmitter{
		Signer:         signer,
		Issuer:         issuer,
		EventsURL:      eventsURL,
		InternalSecret: internalSecret,
		Logger:         logger,
		HTTP:           &http.Client{Timeout: 5 * time.Second},
	}
}

// caepSubject identifies who/what an event is about.
func caepSubject(tenantID, userID, sessionID string) map[string]any {
	s := map[string]any{"format": "opaque", "id": userID, "tenant_id": tenantID}
	if sessionID != "" {
		s["session_id"] = sessionID
	}
	return s
}

// AssuranceLevelChange builds an assurance-level-change event payload. direction
// is "increase" or "decrease".
func AssuranceLevelChange(tenantID, userID, sessionID, current, previous, direction, reason, fingerprint string) (string, map[string]any) {
	return CAEPAssuranceLevelChange, map[string]any{
		"subject":           caepSubject(tenantID, userID, sessionID),
		"current_level":     current,
		"previous_level":    previous,
		"change_direction":  direction,
		"initiating_entity": "policy",
		"reason_admin":      reason,
		"fingerprint":       fingerprint,
		"event_timestamp":   time.Now().UTC().Unix(),
	}
}

// SessionRevoked builds a session-revoked event payload.
func SessionRevoked(tenantID, userID, sessionID, reason, fingerprint string) (string, map[string]any) {
	return CAEPSessionRevoked, map[string]any{
		"subject":         caepSubject(tenantID, userID, sessionID),
		"reason_admin":    reason,
		"fingerprint":     fingerprint,
		"event_timestamp": time.Now().UTC().Unix(),
	}
}

// DeviceComplianceChange builds a device-compliance-change event payload.
// (Deferred trigger — kept so the receiver/contract is complete.)
func DeviceComplianceChange(tenantID, userID, sessionID, current, previous, reason, fingerprint string) (string, map[string]any) {
	return CAEPDeviceComplianceChange, map[string]any{
		"subject":         caepSubject(tenantID, userID, sessionID),
		"current_status":  current,
		"previous_status": previous,
		"reason_admin":    reason,
		"fingerprint":     fingerprint,
		"event_timestamp": time.Now().UTC().Unix(),
	}
}

// buildSET signs a Security Event Token carrying one CAEP event.
func (t *CAEPTransmitter) buildSET(tenantID, userID, sessionID, eventURI string, event map[string]any) (string, error) {
	now := time.Now().UTC()
	claims := jwtx.Claims{
		Iss:       t.Issuer,
		Aud:       "x-auth-risk-service",
		Sub:       userID,
		TenantID:  tenantID,
		SessionID: sessionID,
		Iat:       now.Unix(),
		Exp:       now.Add(5 * time.Minute).Unix(),
		JTI:       "set_" + uuid.NewString(),
	}
	return t.Signer.Sign(claims, map[string]any{
		"events": map[string]any{eventURI: event},
	})
}

// Emit builds, signs, and delivers a SET. Best-effort: a delivery failure is
// logged, never surfaced to the login path. With no EventsURL it logs only.
func (t *CAEPTransmitter) Emit(ctx context.Context, tenantID, userID, sessionID, eventURI string, event map[string]any) {
	if t == nil || t.Signer == nil {
		return
	}
	set, err := t.buildSET(tenantID, userID, sessionID, eventURI, event)
	if err != nil {
		t.Logger.Error("caep_set_build_failed", "err", err, "event", eventURI)
		return
	}
	if t.EventsURL == "" {
		t.Logger.Info("caep_event_logonly", "event", eventURI, "tenant_id", tenantID, "user_id", userID, "session_id", sessionID)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.EventsURL, bytes.NewReader([]byte(set)))
	if err != nil {
		t.Logger.Error("caep_request_build_failed", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	if t.InternalSecret != "" {
		req.Header.Set(httpx.InternalAuthHeader, t.InternalSecret)
	}
	resp, err := t.HTTP.Do(req)
	if err != nil {
		t.Logger.Error("caep_event_delivery_failed", "err", err, "event", eventURI)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Logger.Error("caep_event_rejected", "status", resp.StatusCode, "event", eventURI)
		return
	}
	t.Logger.Info("caep_event_delivered", "event", eventURI, "tenant_id", tenantID, "user_id", userID, "status", resp.StatusCode)
}
