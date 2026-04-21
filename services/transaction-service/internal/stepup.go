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

// StepUpVerify handles POST /v1/step-up/verify.
//
// Orchestration:
//  1. Validate body; find the transaction; enforce tenant scope.
//  2. Sanity-check the challenge id matches the one we dispensed.
//  3. Forward to authenticator-service to verify the presented response.
//  4. If verified and the request carried a session id, promote the session via
//     authentication-service so downstream /authorize calls see step_up_completed=true
//     and a risk level that reflects the original tier that triggered the step-up.
//  5. Persist the updated transaction with the method used, decision, and history.
//
// Failure modes:
//  - Verification 401/false -> 401 to caller, transaction stays step_up_required (the
//    challenge may still have retries; we don't flip to deny on a single miss).
//  - Any upstream 5xx/network error -> 502, transaction marked error.
func (h *Handlers) StepUpVerify(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	var req StepUpVerifyRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		if errors.Is(err, io.EOF) {
			httpx.WriteError(w, http.StatusBadRequest, "empty_body", "request body required")
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	if strings.TrimSpace(req.TransactionID) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "transaction_id is required")
		return
	}
	if strings.TrimSpace(req.ChallengeID) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "challenge_id is required")
		return
	}
	if strings.TrimSpace(req.Method) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "method is required")
		return
	}

	txn, err := h.Store.Get(tenantID, req.TransactionID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "transaction not found")
			return
		}
		h.Logger.Error("txn_get_failed", "err", err, "txn_id", req.TransactionID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to read transaction")
		return
	}

	if txn.Decision != DecisionStepUpRequired {
		httpx.WriteError(w, http.StatusConflict, "invalid_state",
			"transaction is not awaiting step-up")
		return
	}
	if txn.ChallengeID != req.ChallengeID {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "challenge_id mismatch")
		return
	}

	// --- Verify via authenticator-service ---
	result, err := h.Authenticator.VerifyChallenge(tenantID, req.ChallengeID, req.Method, req.Response)
	if err != nil {
		h.Logger.Error("challenge_verify_failed", "err", err, "txn_id", txn.ID)
		h.markError(&txn, "challenge_verify_failed", err.Error())
		writeUpstreamError(w, "authenticator-service", txn.ID)
		return
	}

	if !result.Verified {
		// Soft failure: do not flip the transaction's decision (caller may retry with
		// another factor until authenticator-service burns through attempts_remaining).
		// We still record the attempt in history so the audit trail is complete.
		_ = h.Store.AppendHistory(tenantID, txn.ID, HistoryEntry{
			At: time.Now().UTC(), Event: "challenge_verification_rejected", Detail: result.Reason,
		})
		httpx.WriteJSON(w, http.StatusUnauthorized, StepUpVerifyResponse{
			TransactionID: txn.ID,
			Decision:      DecisionStepUpRequired,
			Reason:        result.Reason,
		})
		return
	}

	// --- Verified: promote the session if we have one ---
	var sessView *SessionView
	if txn.SessionID != "" {
		upgraded, err := h.Authentication.UpdateSession(tenantID, txn.SessionID, SessionUpdateRequest{
			RiskLevel:       txn.RiskTier,
			StepUpCompleted: true,
		})
		if err != nil {
			// Session upgrade is best-effort from the caller's POV — verification
			// succeeded, so the user should be allowed to proceed. But we must surface
			// that session promotion failed so the client knows to retry /authorize
			// carefully. Return 502 with the verified txn so clients don't blindly
			// assume allow.
			h.Logger.Error("session_update_failed", "err", err, "txn_id", txn.ID)
			h.markError(&txn, "session_update_failed", err.Error())
			writeUpstreamError(w, "authentication-service", txn.ID)
			return
		}
		sessView = &SessionView{
			ID:              upgraded.ID,
			RiskLevel:       upgraded.RiskLevel,
			StepUpCompleted: true,
			ExpiresAt:       upgraded.ExpiresAt,
		}
	}

	// --- Persist the satisfied state ---
	decidedAt := time.Now().UTC()
	txn.Decision = DecisionStepUpSatisfied
	txn.StepUpUsed = true
	txn.StepUpMethod = result.Method
	txn.DecidedAt = &decidedAt
	txn.History = append(txn.History,
		HistoryEntry{At: decidedAt, Event: "challenge_verified", Detail: result.Method},
		HistoryEntry{At: decidedAt, Event: "decision", Detail: DecisionStepUpSatisfied},
	)
	if _, err := h.Store.Update(txn); err != nil {
		h.Logger.Error("txn_update_failed", "err", err, "txn_id", txn.ID)
	}

	httpx.WriteJSON(w, http.StatusOK, StepUpVerifyResponse{
		TransactionID: txn.ID,
		Decision:      DecisionAllow,
		Session:       sessView,
	})
}
