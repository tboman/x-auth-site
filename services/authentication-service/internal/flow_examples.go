package internal

// flow_examples.go ships code-defined example flows that exercise the policy
// engine — the risk-first differentiation. These are not yet selectable per
// tenant (that is P3: DB-backed flows + the owner-console Flows tab); they exist
// so the risk-evaluation stage + stage-bound policies are real, tested, and
// ready to surface. The expression strings below double as the seed templates
// the admin UI will offer.

import (
	"github.com/xentranet/x-auth/services/authentication-service/internal/policy"
)

// Example policy templates. Each is a boolean expr-lang expression over the
// {user, request, risk, protection, time} env (see policy.Keys). risk.* is
// filled by a preceding risk-evaluation stage.
const (
	// PolicySkipStepUpWhenLowRisk — bind to authenticator-validate with
	// negate=true: skip the challenge entirely when the journey scores low-risk.
	// This is the headline risk-adaptive behavior — a requested step-up is
	// downgraded purely on live risk, which a fixed pipeline cannot express.
	PolicySkipStepUpWhenLowRisk = `risk.tier == "low"`

	// PolicySkipStepUpWhenSafe — the conservative variant: skip only when
	// low-risk AND the session already meets the requested protection level
	// (a risk overlay on top of the existing freshness pass-through).
	PolicySkipStepUpWhenSafe = `risk.tier == "low" && protection.achieved_rank >= protection.requested_rank`

	// PolicyDenyHighRiskLocation — bind to a deny stage (negate=false): refuse
	// outright when the network signals an impossible travel or a Tor exit.
	PolicyDenyHighRiskLocation = `risk.impossible_travel || "tor_exit" in risk.flags`

	// PolicyForceStrongFactorOnCheckout — bind to a high-assurance validate stage
	// (negate=false): demand the strongest factor for a risky checkout.
	PolicyForceStrongFactorOnCheckout = `risk.score >= 0.7 && request.client_id == "checkout"`
)

// riskAdaptiveStepUpFlow is an authorization-stepup flow that uses live risk to
// adapt the challenge:
//
//	risk-evaluation → deny(high-risk location) → validate(skip when safe) → issue
//
// A low-risk session that already meets the level passes straight through; a
// high-risk one still challenges; an impossible-travel session is denied. The
// policies are compiled up front so a template typo surfaces at construction,
// not mid-login.
func (h *OIDCHandlers) riskAdaptiveStepUpFlow() (*Flow, error) {
	denyPol, err := policy.Compile(PolicyDenyHighRiskLocation)
	if err != nil {
		return nil, err
	}
	skipPol, err := policy.Compile(PolicySkipStepUpWhenLowRisk)
	if err != nil {
		return nil, err
	}
	return &Flow{
		Slug:        "risk-adaptive-stepup",
		Designation: FlowAuthorizeStepUp,
		Title:       "Risk-adaptive step-up",
		Stages: []Stage{
			riskEvaluationStage{h},
			policyGatedStage{
				inner:    denyStage{h: h, reason: "high-risk location"},
				policies: []policyBinding{{name: "deny-high-risk-location", program: denyPol}},
				logger:   h.Logger,
			},
			policyGatedStage{
				inner:    authValidateStage{h},
				policies: []policyBinding{{name: "skip-stepup-when-safe", negate: true, program: skipPol}},
				logger:   h.Logger,
			},
			issueStage{h},
		},
	}, nil
}
