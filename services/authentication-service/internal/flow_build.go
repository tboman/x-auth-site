package internal

// flow_build.go compiles a stored FlowDefinition into a runnable *Flow: each
// StageConfig becomes a Stage (via a type factory), optionally wrapped in a
// policyGatedStage whose expressions are compiled up front. A build error
// (unknown stage type or an uncompilable policy) is returned to the caller, which
// falls back to the code-defined default flow and logs — a misconfigured flow
// never breaks /authorize.

import (
	"fmt"

	"github.com/xentranet/x-auth/services/authentication-service/internal/policy"
)

// Stage taxonomy types accepted in a stored flow.
const (
	StageTypeRiskEvaluation = "risk-evaluation"
	StageTypeAuthValidate   = "authenticator-validate"
	StageTypeUserLogin      = "user-login"
	StageTypeDeny           = "deny"
)

// buildStage turns one StageConfig into a Stage, attaching any policies.
func (h *OIDCHandlers) buildStage(sc StageConfig) (Stage, error) {
	var base Stage
	switch sc.Type {
	case StageTypeRiskEvaluation:
		base = riskEvaluationStage{h}
	case StageTypeAuthValidate:
		base = authValidateStage{h}
	case StageTypeUserLogin, "issue":
		base = issueStage{h}
	case StageTypeDeny:
		reason := "access denied"
		if r, ok := sc.Config["reason"].(string); ok && r != "" {
			reason = r
		}
		base = denyStage{h: h, reason: reason}
	default:
		return nil, fmt.Errorf("unknown stage type %q", sc.Type)
	}

	if len(sc.Policies) == 0 {
		return base, nil
	}
	binds := make([]policyBinding, 0, len(sc.Policies))
	for _, pc := range sc.Policies {
		prog, err := policy.Compile(pc.Expression)
		if err != nil {
			return nil, fmt.Errorf("stage %q policy %q: %w", sc.Type, pc.Name, err)
		}
		binds = append(binds, policyBinding{name: pc.Name, negate: pc.Negate, program: prog})
	}
	return policyGatedStage{inner: base, policies: binds, logger: h.Logger}, nil
}

// buildFlow compiles a stored definition into a runnable flow.
func (h *OIDCHandlers) buildFlow(def FlowDefinition) (*Flow, error) {
	if len(def.Stages) == 0 {
		return nil, fmt.Errorf("flow %q has no stages", def.Slug)
	}
	stages := make([]Stage, 0, len(def.Stages))
	for i, sc := range def.Stages {
		st, err := h.buildStage(sc)
		if err != nil {
			return nil, fmt.Errorf("flow %q stage %d: %w", def.Slug, i, err)
		}
		stages = append(stages, st)
	}
	return &Flow{Slug: def.Slug, Designation: def.Designation, Title: def.Title, Stages: stages}, nil
}

// selectAuthorizeFlow returns the flow /authorize should run for a tenant: the
// tenant's enabled authorization-stepup flow if one is configured and compiles,
// otherwise the code-defined default (the legacy-equivalent behavior).
func (h *OIDCHandlers) selectAuthorizeFlow(tenantID string) *Flow {
	def, err := h.Store.GetEnabledFlow(tenantID, FlowAuthorizeStepUp)
	if err != nil {
		return h.defaultAuthorizeStepUpFlow() // none configured → default
	}
	built, berr := h.buildFlow(def)
	if berr != nil {
		h.Logger.Error("flow_build_failed", "flow_id", def.ID, "tenant_id", tenantID, "err", berr)
		return h.defaultAuthorizeStepUpFlow()
	}
	return built
}

// RiskAdaptiveFlowDefinition is the stored form of riskAdaptiveStepUpFlow — the
// template a tenant can apply (admin UI / tests). It mirrors the code-defined
// example so the two stay in lockstep.
func RiskAdaptiveFlowDefinition(id, tenantID string, enabled bool) FlowDefinition {
	return FlowDefinition{
		ID:          id,
		TenantID:    tenantID,
		Designation: FlowAuthorizeStepUp,
		Slug:        "risk-adaptive-stepup",
		Title:       "Risk-adaptive step-up",
		Enabled:     enabled,
		Stages: []StageConfig{
			{Type: StageTypeRiskEvaluation},
			{
				Type:   StageTypeDeny,
				Config: map[string]any{"reason": "high-risk location"},
				Policies: []PolicyConfig{
					{Name: "deny-high-risk-location", Expression: PolicyDenyHighRiskLocation},
				},
			},
			{
				Type: StageTypeAuthValidate,
				Policies: []PolicyConfig{
					{Name: "skip-stepup-when-low-risk", Expression: PolicySkipStepUpWhenLowRisk, Negate: true},
				},
			},
			{Type: StageTypeUserLogin},
		},
	}
}
