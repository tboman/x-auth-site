package internal

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// Authorize handles POST /v1/authorize — a post-authentication policy check for a
// specific action on a specific resource.
//
// Orchestration rule (phase 1):
//   - Fetch the session from authentication-service.
//   - Re-evaluate via risk-service if:
//   - the session can't be read (no cached tier to trust), OR
//   - the session is stale (updated_at older than SessionStaleAfter), OR
//   - the requested resource_sensitivity (derived from the attributes, falling back
//     to the session's last observed tier) is "high" or "critical".
//   - Otherwise use the session's cached risk_level to decide.
//
// Decision from the tier:
//   - low    -> allow
//   - medium -> allow, but annotate the transaction so it can be audited
//   - high   -> deny at this layer (the caller should have sent the request through
//     /v1/advice to get a step-up flow, not /v1/authorize directly).
//
// This split is deliberate: /v1/authorize is the "trusted session, fast path" — it is
// never the vehicle for issuing a step-up. If policy needs more friction the caller
// re-enters /v1/advice. That keeps /v1/authorize a pure yes/no decision point.
func (h *Handlers) Authorize(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	var req AuthorizeRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		if errors.Is(err, io.EOF) {
			httpx.WriteError(w, http.StatusBadRequest, "empty_body", "request body required")
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	if strings.TrimSpace(req.UserID) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "user_id is required")
		return
	}
	if strings.TrimSpace(req.SessionID) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "session_id is required")
		return
	}
	if strings.TrimSpace(req.Action) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "action is required")
		return
	}

	now := time.Now().UTC()
	txn := Transaction{
		ID:        newTransactionID(),
		TenantID:  tenantID,
		UserID:    req.UserID,
		SessionID: req.SessionID,
		Action:    req.Action,
		Resource:  req.Resource,
		CreatedAt: now,
		Decision:  "pending",
		History:   []HistoryEntry{{At: now, Event: "authorize_received", Detail: req.Action}},
	}
	if _, err := h.Store.Create(txn); err != nil {
		h.Logger.Error("txn_create_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to create transaction")
		return
	}

	// Derive sensitivity from the attributes (if the caller hinted) or default low.
	sensitivity := "low"
	if s, ok := req.Attributes["resource_sensitivity"].(string); ok && s != "" {
		sensitivity = s
	}
	txn.ResourceSensitivity = sensitivity

	// --- Fetch session ---
	sess, err := h.Authentication.GetSession(r.Context(), tenantID, req.SessionID)
	sessionMissing := false
	if err != nil {
		// On a hard downstream failure we can't safely fall back to a risk re-eval
		// either (we'd be working from zero context). Treat as upstream unavailable.
		// But if authentication-service returned a 4xx we surface it as a client
		// error, since it means the session doesn't exist or doesn't belong to us.
		var de *DownstreamError
		if errors.As(err, &de) && de.Status >= 400 && de.Status < 500 {
			sessionMissing = true
		} else {
			h.logDownstream("session_get_failed", err, "txn_id", txn.ID, "tenant_id", tenantID)
			h.markError(&txn, "session_get_failed", err.Error())
			writeUpstreamError(w, "authentication-service", txn.ID)
			return
		}
	}

	needFresh := sessionMissing ||
		sensitivity == "high" || sensitivity == "critical" ||
		sessionStale(sess)

	tier := sess.RiskLevel
	var matchedPolicies []string

	if needFresh {
		result, err := h.Risk.Evaluate(r.Context(), tenantID, RiskEvaluateRequest{
			TenantID:            tenantID,
			UserID:              req.UserID,
			SessionID:           req.SessionID,
			Action:              req.Action,
			Resource:            req.Resource,
			ResourceSensitivity: sensitivity,
			// /authorize doesn't carry device/network context, so signals are left nil
			// and risk-service falls back to user/behavior history only.
		})
		if err != nil {
			h.logDownstream("risk_evaluate_failed", err, "txn_id", txn.ID, "tenant_id", tenantID)
			h.markError(&txn, "risk_evaluate_failed", err.Error())
			writeUpstreamError(w, "risk-service", txn.ID)
			return
		}
		tier = result.Tier
		matchedPolicies = result.MatchedPolicies
		txn.RiskEvaluationID = result.ID
		txn.RiskScore = result.Score
		txn.History = append(txn.History, HistoryEntry{
			At: time.Now().UTC(), Event: "risk_reevaluated", Detail: tier,
		})
	} else {
		txn.History = append(txn.History, HistoryEntry{
			At: time.Now().UTC(), Event: "cached_tier_used", Detail: tier,
		})
	}
	txn.RiskTier = tier

	// --- Decide ---
	decidedAt := time.Now().UTC()
	txn.DecidedAt = &decidedAt

	// risk-service reports every matched policy; the first (oldest by CreatedAt)
	// is recorded as the transaction's primary policy_id for backward compatibility
	// with the §4.1 response shape, and the full list rides alongside.
	var policyID string
	if len(matchedPolicies) > 0 {
		policyID = matchedPolicies[0]
	}
	txn.PolicyID = policyID

	switch tier {
	case TierLow, TierMedium:
		txn.Decision = DecisionAllow
		txn.History = append(txn.History, HistoryEntry{At: decidedAt, Event: "decision", Detail: DecisionAllow})
		if _, err := h.Store.Update(txn); err != nil {
			h.Logger.Error("txn_update_failed", "err", err, "txn_id", txn.ID)
		}
		httpx.WriteJSON(w, http.StatusOK, AuthorizeResponse{
			TransactionID:   txn.ID,
			Decision:        DecisionAllow,
			PolicyID:        policyID,
			MatchedPolicies: matchedPolicies,
			EvaluatedAt:     decidedAt,
		})
		return
	case TierHigh:
		txn.Decision = DecisionDeny
		txn.Reason = "step_up_required"
		txn.History = append(txn.History, HistoryEntry{At: decidedAt, Event: "decision", Detail: DecisionDeny})
		if _, err := h.Store.Update(txn); err != nil {
			h.Logger.Error("txn_update_failed", "err", err, "txn_id", txn.ID)
		}
		httpx.WriteJSON(w, http.StatusForbidden, AuthorizeResponse{
			TransactionID:   txn.ID,
			Decision:        DecisionDeny,
			PolicyID:        policyID,
			MatchedPolicies: matchedPolicies,
			Reason:          "step_up_required",
			EvaluatedAt:     decidedAt,
		})
		return
	default:
		h.Logger.Error("unknown_risk_tier", "tier", tier, "txn_id", txn.ID)
		h.markError(&txn, "unknown_risk_tier", tier)
		writeUpstreamError(w, "risk-service", txn.ID)
		return
	}
}

// sessionStale reports whether the session's updated_at (or created/expires proxy) is
// older than SessionStaleAfter. A zero updated_at defaults to stale, forcing a
// re-evaluation rather than silently trusting an unknown-age cached tier.
func sessionStale(s Session) bool {
	last := s.UpdatedAt
	if last.IsZero() {
		// Best-effort fallback: infer last update from expires_at minus a typical TTL.
		// If that's also zero (session missing entirely) we treat it as stale.
		if s.ExpiresAt.IsZero() {
			return true
		}
		// Assume 8h default session lifetime per §4.3 example — if expiry is further
		// than (lifetime - staleness) ahead we consider it fresh.
		const assumedLifetime = 8 * time.Hour
		return time.Until(s.ExpiresAt) < (assumedLifetime - SessionStaleAfter)
	}
	return time.Since(last) > SessionStaleAfter
}
