package internal

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// transactionIDPrefix is the canonical prefix for every transaction id we mint.
const transactionIDPrefix = "txn_"

// newTransactionID returns a fresh, prefixed uuid.
func newTransactionID() string {
	return transactionIDPrefix + uuid.NewString()
}

// methodsForTier is the phase 1 step-up policy per risk tier.
//
// medium: soft factors (email OTP, magic link) — friction is moderate, acceptable for
// ambiguous signals.
// high:   strong possession/biometric factors (FIDO2, push-to-trusted-device) — anything
// weaker (SMS OTP, email link) is trivially phishable and would defeat the whole point
// of the step-up at this tier.
//
// This policy intentionally lives in transaction-service: *which* factor to demand at a
// given tier is an orchestration decision, distinct from *what* the risk tier actually
// is. When per-tenant step-up policy lands (phase 2) this lookup gets replaced by a call
// into risk-service's policy engine (§7 of ARCHITECTURE.md).
func methodsForTier(tier string) []string {
	switch tier {
	case TierMedium:
		return []string{"otp", "magic_link"}
	case TierHigh:
		return []string{"fido2", "push"}
	default:
		return nil
	}
}

// Advice handles POST /v1/advice (and POST /v1/evaluate — same handler, two paths).
//
// Orchestration:
//  1. Validate input. user_id, action, context.ip_address are required.
//  2. Mint a transaction id and persist a pending record so we always have a paper
//     trail — even if downstream calls blow up.
//  3. Call risk-service. On error mark the transaction "error" and return 502.
//  4. tier == low                -> decision "allow".
//  5. tier == medium | high      -> call authenticator-service for a challenge;
//                                   decision "step_up_required".
//  6. unknown tier               -> 502 (risk-service contract violation).
func (h *Handlers) Advice(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	var req AdviceRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		if errors.Is(err, io.EOF) {
			httpx.WriteError(w, http.StatusBadRequest, "empty_body", "request body required")
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	if msg := validateAdvice(req); msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}

	now := time.Now().UTC()
	txn := Transaction{
		ID:                  newTransactionID(),
		TenantID:            tenantID,
		UserID:              req.UserID,
		SessionID:           req.SessionID,
		Action:              req.Action,
		Resource:            req.Resource,
		ResourceSensitivity: req.ResourceSensitivity,
		Decision:            "pending",
		CreatedAt:           now,
		History: []HistoryEntry{
			{At: now, Event: "advice_received", Detail: req.Action},
		},
	}
	if _, err := h.Store.Create(txn); err != nil {
		h.Logger.Error("txn_create_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to create transaction")
		return
	}

	// --- Risk evaluation ---
	rreq := RiskEvaluateRequest{
		TenantID:            tenantID,
		UserID:              req.UserID,
		SessionID:           req.SessionID,
		Action:              req.Action,
		Resource:            req.Resource,
		ResourceSensitivity: req.ResourceSensitivity,
		Signals:             signalsFromContext(req.Context),
	}
	result, err := h.Risk.Evaluate(tenantID, rreq)
	if err != nil {
		h.Logger.Error("risk_evaluate_failed", "err", err, "txn_id", txn.ID, "tenant_id", tenantID)
		h.markError(&txn, "risk_evaluate_failed", err.Error())
		writeUpstreamError(w, "risk-service", txn.ID)
		return
	}

	txn.RiskEvaluationID = result.ID
	txn.RiskTier = result.Tier
	txn.RiskScore = result.Score
	txn.History = append(txn.History, HistoryEntry{
		At:     time.Now().UTC(),
		Event:  "risk_evaluated",
		Detail: result.Tier,
	})

	evalView := buildRiskEvaluation(result)

	// --- Branch on tier ---
	switch result.Tier {
	case TierLow:
		decidedAt := time.Now().UTC()
		txn.Decision = DecisionAllow
		txn.DecidedAt = &decidedAt
		txn.History = append(txn.History, HistoryEntry{At: decidedAt, Event: "decision", Detail: DecisionAllow})
		if _, err := h.Store.Update(txn); err != nil {
			h.Logger.Error("txn_update_failed", "err", err, "txn_id", txn.ID)
		}
		httpx.WriteJSON(w, http.StatusOK, AdviceResponse{
			TransactionID:  txn.ID,
			RiskEvaluation: evalView,
			Decision:       DecisionAllow,
		})
		return

	case TierMedium, TierHigh:
		methods := methodsForTier(result.Tier)
		ch, err := h.Authenticator.CreateChallenge(tenantID, ChallengeCreateRequest{
			TenantID: tenantID,
			UserID:   req.UserID,
			Methods:  methods,
			Context: map[string]any{
				"transaction_id": txn.ID,
				"action":         req.Action,
				"resource":       req.Resource,
			},
		})
		if err != nil {
			h.Logger.Error("challenge_create_failed", "err", err, "txn_id", txn.ID, "tenant_id", tenantID)
			// Persist the risk evaluation even though we couldn't dispense a challenge,
			// then surface the upstream failure to the caller. The transaction is marked
			// "error" rather than "deny" — there's no policy verdict, just a broken
			// downstream. Clients retrying get a fresh evaluation.
			h.markError(&txn, "challenge_create_failed", err.Error())
			writeUpstreamError(w, "authenticator-service", txn.ID)
			return
		}

		decidedAt := time.Now().UTC()
		txn.Decision = DecisionStepUpRequired
		txn.ChallengeID = ch.ID
		txn.DecidedAt = &decidedAt
		txn.History = append(txn.History,
			HistoryEntry{At: decidedAt, Event: "challenge_issued", Detail: ch.ID},
			HistoryEntry{At: decidedAt, Event: "decision", Detail: DecisionStepUpRequired},
		)
		if _, err := h.Store.Update(txn); err != nil {
			h.Logger.Error("txn_update_failed", "err", err, "txn_id", txn.ID)
		}

		httpx.WriteJSON(w, http.StatusOK, AdviceResponse{
			TransactionID:  txn.ID,
			RiskEvaluation: evalView,
			Decision:       DecisionStepUpRequired,
			StepUp: &StepUpChallenge{
				ChallengeID: ch.ID,
				Methods:     methods,
				ExpiresAt:   ch.ExpiresAt,
			},
		})
		return

	default:
		h.Logger.Error("unknown_risk_tier", "tier", result.Tier, "txn_id", txn.ID)
		h.markError(&txn, "unknown_risk_tier", result.Tier)
		writeUpstreamError(w, "risk-service", txn.ID)
		return
	}
}

// validateAdvice runs shape-level validation on an AdviceRequest. Returns "" when
// the request is valid, otherwise a human-readable error string suitable for 400.
func validateAdvice(req AdviceRequest) string {
	if strings.TrimSpace(req.UserID) == "" {
		return "user_id is required"
	}
	if strings.TrimSpace(req.Action) == "" {
		return "action is required"
	}
	if strings.TrimSpace(req.Context.IPAddress) == "" {
		return "context.ip_address is required"
	}
	if req.ResourceSensitivity != "" {
		switch req.ResourceSensitivity {
		case "low", "medium", "high", "critical":
		default:
			return "resource_sensitivity must be one of low|medium|high|critical"
		}
	}
	return ""
}

// signalsFromContext packages the incoming /v1/advice context into the nested shape
// risk-service expects. Fields absent from the request are simply omitted so the
// downstream service can fall back to defaults / signal-absent scoring.
func signalsFromContext(c EvalContext) map[string]any {
	device := map[string]any{}
	if c.DeviceFingerprint != "" {
		device["fingerprint"] = c.DeviceFingerprint
	}
	if c.UserAgent != "" {
		device["user_agent"] = c.UserAgent
	}

	network := map[string]any{"ip_address": c.IPAddress}
	if c.Geo != nil {
		network["geo"] = map[string]any{"lat": c.Geo.Lat, "lon": c.Geo.Lon}
	}

	out := map[string]any{"network": network}
	if len(device) > 0 {
		out["device"] = device
	}
	return out
}

// buildRiskEvaluation converts a risk-service result into the slimmed client view.
// We preserve both the per-scorer scores and the flag set; flags are bucketed back
// onto the scorer they most plausibly came from for clients that want structured
// rendering, but we can't perfectly reverse the merge — any flag the risk-service
// didn't prefix is dropped into a generic "other" entry so nothing is silently lost.
func buildRiskEvaluation(result RiskEvaluationResult) *RiskEvaluation {
	signals := map[string]SignalSummary{}
	for name, score := range result.Scores {
		signals[name] = SignalSummary{Score: score}
	}
	// Flags: partition by name-prefix convention. Flags without a recognised prefix
	// go to the "user" bucket (most conservative catch-all) so they still surface.
	for _, flag := range result.Flags {
		target := "user"
		switch {
		case strings.HasPrefix(flag, "device_") || flag == "unknown_device":
			target = "device"
		case strings.HasPrefix(flag, "behavior_") || flag == "unusual_time" || flag == "anomalous":
			target = "behavior"
		case strings.HasPrefix(flag, "network_") || flag == "flagged_ip" || flag == "vpn_detected" || flag == "tor_exit":
			target = "network"
		}
		sum := signals[target]
		sum.Flags = append(sum.Flags, flag)
		signals[target] = sum
	}

	return &RiskEvaluation{
		ID:      result.ID,
		Tier:    result.Tier,
		Score:   result.Score,
		Signals: signals,
	}
}

// markError persists an error decision on the transaction. Never fails the response —
// best-effort audit.
func (h *Handlers) markError(txn *Transaction, event, detail string) {
	now := time.Now().UTC()
	txn.Decision = DecisionError
	txn.DecidedAt = &now
	txn.Reason = event
	txn.History = append(txn.History,
		HistoryEntry{At: now, Event: event, Detail: detail},
		HistoryEntry{At: now, Event: "decision", Detail: DecisionError},
	)
	if _, err := h.Store.Update(*txn); err != nil {
		h.Logger.Error("txn_error_persist_failed", "err", err, "txn_id", txn.ID)
	}
}

// writeUpstreamError is the single choke-point for 502s — keeps the body shape uniform
// so clients can pattern-match on "error":"upstream_unavailable".
func writeUpstreamError(w http.ResponseWriter, service, txnID string) {
	httpx.WriteJSON(w, http.StatusBadGateway, map[string]any{
		"error":          "upstream_unavailable",
		"service":        service,
		"transaction_id": txnID,
	})
}
