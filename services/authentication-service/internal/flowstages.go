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
	"context"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/services/authentication-service/internal/policy"
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
		spec = h.effectiveStepUpSpec(exec.TenantID, spec)
		pend.TargetACR = lvl.ACR
		pend.TargetRank = lvl.Rank
		pend.AuthzSessionID = exec.AuthzSessionID
		h.Logger.Info("protection_challenge", "acr", lvl.ACR, "rank", lvl.Rank, "method", spec.Method,
			"user_id", exec.UserID, "tenant_id", exec.TenantID)
		h.startStepUpFlow(w, r, spec, pend) // renders + parks pendingAuthorize; resume via AuthorizeVerify
		return StageRespond, nil
	}

	if spec, ok := matchStepUp(exec.ACRValues); ok {
		h.startStepUpFlow(w, r, h.effectiveStepUpSpec(exec.TenantID, spec), pend)
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

// riskEvaluationStage fetches a live risk score/tier from risk-service and
// writes it into the execution context so downstream stage-bound policies can
// gate on it (risk.tier, risk.score, risk.flags, …). It always Continues — risk
// is an input, never a decision. Fail-open: a nil client or a risk-service error
// leaves falsy defaults so policies behave as if risk were absent (a risk outage
// must not break login).
type riskEvaluationStage struct{ h *OIDCHandlers }

func (s riskEvaluationStage) Type() string { return "risk-evaluation" }

func (s riskEvaluationStage) Execute(w http.ResponseWriter, r *http.Request, exec *FlowExecution) (StageResult, error) {
	h := s.h
	risk := map[string]any{
		"tier": "", "score": 0.0, "impossible_travel": false,
		"flags": []string{}, "device": 0.0, "behavior": 0.0, "network": 0.0, "user": 0.0,
	}
	if h.Risk != nil {
		req := mapOrEmpty(exec.Context["request"])
		a, err := h.Risk.Evaluate(r.Context(), RiskEvalInput{
			TenantID:    exec.TenantID,
			UserID:      exec.UserID,
			SessionID:   exec.AuthzSessionID,
			Action:      "authorize",
			Resource:    exec.ClientID,
			Sensitivity: RiskMedium,
			DeviceFP:    asString(req["device_fp"]),
			IP:          asString(req["ip"]),
			Country:     asString(req["country"]),
			UserAgent:   asString(req["user_agent"]),
		})
		if err != nil {
			h.Logger.Warn("risk_evaluation_failed", "err", err, "user_id", exec.UserID, "tenant_id", exec.TenantID)
		} else {
			risk = map[string]any{
				"tier": a.Tier, "score": a.Score, "impossible_travel": a.ImpossibleTravel,
				"flags": a.Flags, "device": a.Device, "behavior": a.Behavior,
				"network": a.Network, "user": a.User,
			}
			h.Logger.Info("risk_evaluation", "tier", a.Tier, "score", a.Score,
				"user_id", exec.UserID, "tenant_id", exec.TenantID)
		}
	}
	exec.Context["risk"] = risk
	return StageContinue, nil
}

// denyStage refuses the authorization. It is only reached when its bound policy
// passes (e.g. risk.impossible_travel) — the executor skips it otherwise.
type denyStage struct {
	h      *OIDCHandlers
	reason string
}

func (s denyStage) Type() string { return "deny" }

func (s denyStage) Execute(w http.ResponseWriter, r *http.Request, exec *FlowExecution) (StageResult, error) {
	s.h.Logger.Warn("flow_deny", "reason", s.reason, "user_id", exec.UserID, "tenant_id", exec.TenantID)
	redir, err := url.Parse(exec.RedirectURI)
	if err != nil || exec.RedirectURI == "" {
		httpx.WriteError(w, http.StatusForbidden, "access_denied", s.reason)
		return StageDeny, nil
	}
	s.h.redirectAuthorizeError(w, r, redir, exec.State, "access_denied", s.reason)
	return StageDeny, nil
}

// policyEnv assembles the evaluation context handed to stage/flow policies. Risk
// facts come from the risk-evaluation stage (exec.Context["risk"]); request and
// protection facts are seeded by Authorize before the flow runs. Top-level keys
// are always present so a policy referencing a missing nested field reads nil
// (→ false) rather than erroring.
func (e *FlowExecution) policyEnv() policy.Env {
	return policy.Env{
		"user":       map[string]any{"id": e.UserID},
		"request":    mapOrEmpty(e.Context["request"]),
		"protection": mapOrEmpty(e.Context["protection"]),
		"risk":       mapOrEmpty(e.Context["risk"]),
		"time":       map[string]any{},
	}
}

func mapOrEmpty(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// policyBinding is one compiled policy attached to a gated stage. The stage runs
// only when every binding "passes": pass = program(env) XOR-via-negate. On a
// policy evaluation error the result defaults to false (then negate applies) —
// which fails OPEN for an additive stage (e.g. deny: error → skip the deny) and
// fails CLOSED for a negate-gated relaxation (e.g. skip-step-up: error → run
// step-up). Either way an error never weakens security.
type policyBinding struct {
	name    string
	negate  bool
	program *policy.Program
}

// policyGatedStage wraps a stage with policy bindings. When the policies say the
// stage should not run, Execute returns StageContinue so the executor advances
// past it — keeping the executor itself policy-agnostic.
type policyGatedStage struct {
	inner    Stage
	policies []policyBinding
	logger   *slog.Logger
}

func (g policyGatedStage) Type() string { return g.inner.Type() }

func (g policyGatedStage) Execute(w http.ResponseWriter, r *http.Request, exec *FlowExecution) (StageResult, error) {
	if !g.shouldRun(r.Context(), exec) {
		return StageContinue, nil // skip → advance to the next stage
	}
	return g.inner.Execute(w, r, exec)
}

func (g policyGatedStage) shouldRun(ctx context.Context, exec *FlowExecution) bool {
	if len(g.policies) == 0 {
		return true
	}
	env := exec.policyEnv()
	for _, b := range g.policies {
		result := false
		if b.program != nil {
			v, err := b.program.Evaluate(ctx, env)
			if err != nil {
				if g.logger != nil {
					g.logger.Warn("policy_eval_failed", "policy", b.name, "stage", g.inner.Type(), "err", err)
				}
			} else {
				result = v
			}
		}
		pass := result
		if b.negate {
			pass = !pass
		}
		if !pass {
			return false
		}
	}
	return true
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
