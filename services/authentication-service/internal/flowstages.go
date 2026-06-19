package internal

// flowstages.go holds the Phase-1 wrapper stages for the authorization-stepup
// flow. Each stage delegates to the existing handlers so behavior is identical
// to the legacy /authorize branch — the executor just sequences them.
//
// P1 keeps the CHALLENGE path on the battle-tested step-up machinery untouched:
// authenticator-validate, when a challenge is needed, calls the existing
// startStepUpFlow (which parks a pendingAuthorize and renders), and the resume
// stays AuthorizeVerify. Only the pass-through / no-step-up path is genuinely
// executor-driven (validate → Continue → issue mints). Later phases move the
// resume onto the executor and add risk-evaluation/policy stages.

import (
	"net/http"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// toPending builds the legacy pendingAuthorize from an execution so the existing
// step-up handlers can be reused verbatim.
func (e *FlowExecution) toPending() pendingAuthorize {
	return pendingAuthorize{
		ClientID:      e.ClientID,
		TenantID:      e.TenantID,
		UserID:        e.UserID,
		RedirectURI:   e.RedirectURI,
		Scope:         e.Scope,
		State:         e.State,
		Nonce:         e.Nonce,
		CodeChallenge: e.CodeChallenge,
		TransactionID: e.TransactionID,
	}
}

// authValidateStage decides — exactly as handleProtection/the acr_values dispatch
// do — whether the request passes through or needs a step-up challenge.
type authValidateStage struct{ h *OIDCHandlers }

func (s authValidateStage) Type() string { return "authenticator-validate" }

func (s authValidateStage) Execute(w http.ResponseWriter, r *http.Request, exec *FlowExecution) (StageResult, error) {
	h := s.h
	pend := exec.toPending()

	if lvl, ok := matchProtection(exec.ACRValues); ok {
		if h.protectionSatisfied(lvl, exec.AuthzSessionID) {
			h.Logger.Info("protection_passthrough", "acr", lvl.ACR, "rank", lvl.Rank,
				"user_id", exec.UserID, "tenant_id", exec.TenantID)
			exec.AchievedACR = lvl.ACR // legacy pass-through stamps acr=level, no amr
			return StageContinue, nil
		}
		spec, ok2 := specForMethod(lvl.Method)
		if !ok2 {
			h.Logger.Error("protection_method_unknown", "method", lvl.Method, "acr", lvl.ACR)
			httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "protection level has no challenge method")
			return StageDeny, nil
		}
		pend.TargetACR = lvl.ACR
		pend.TargetRank = lvl.Rank
		pend.AuthzSessionID = exec.AuthzSessionID
		h.Logger.Info("protection_challenge", "acr", lvl.ACR, "rank", lvl.Rank, "method", lvl.Method,
			"user_id", exec.UserID, "tenant_id", exec.TenantID)
		h.startStepUpFlow(w, r, spec, pend) // renders + parks pendingAuthorize; resume via AuthorizeVerify
		return StageRespond, nil
	}

	if spec, ok := matchStepUp(exec.ACRValues); ok {
		h.startStepUpFlow(w, r, spec, pend)
		return StageRespond, nil
	}

	return StageContinue, nil // no step-up requested
}

// issueStage mints the authorization code and redirects back to the client —
// the terminal stage. acr/amr come from the execution (set by validate's
// pass-through, or empty for a plain request).
type issueStage struct{ h *OIDCHandlers }

func (s issueStage) Type() string { return "user-login" }

func (s issueStage) Execute(w http.ResponseWriter, r *http.Request, exec *FlowExecution) (StageResult, error) {
	s.h.mintCodeAndRedirect(w, r, AuthCode{
		ClientID:      exec.ClientID,
		TenantID:      exec.TenantID,
		UserID:        exec.UserID,
		RedirectURI:   exec.RedirectURI,
		Scope:         exec.Scope,
		State:         exec.State,
		Nonce:         exec.Nonce,
		CodeChallenge: exec.CodeChallenge,
		ACR:           exec.AchievedACR,
		AMR:           exec.AchievedAMR,
		TransactionID: exec.TransactionID,
	})
	return StageComplete, nil
}

// defaultAuthorizeStepUpFlow is the built-in flow /authorize runs when the engine
// is enabled and the tenant has no custom flow. It reproduces the legacy branch:
// validate (pass-through or challenge) then issue.
func (h *OIDCHandlers) defaultAuthorizeStepUpFlow() *Flow {
	return &Flow{
		Slug:        "default-authorization-stepup",
		Designation: FlowAuthorizeStepUp,
		Title:       "Authorization step-up",
		Stages:      []Stage{authValidateStage{h}, issueStage{h}},
	}
}
