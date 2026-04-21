// Package internal contains the risk-service domain model, storage, scorers,
// aggregation, policy engine, and HTTP handlers.
//
// See ARCHITECTURE.md §4.2 (risk-service contract) and §7 (Risk Signal Pipeline)
// for the source of truth on request/response shapes, scorers, weights, and
// tier thresholds. Phase 1 is deterministic, in-memory, and single-process —
// phase 2 introduces PostgreSQL persistence, richer scorers, and stream-based
// ingestion.
package internal

import "time"

// Risk tier strings. These map to the marketing site's three-tier model and
// to the step-up actions defined in ARCHITECTURE.md §7.3.
const (
	TierLow    = "low"
	TierMedium = "medium"
	TierHigh   = "high"
)

// Policy decisions returned by the policy engine. An `allow` decision simply
// accepts the derived tier; `deny` short-circuits evaluation regardless of
// tier.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

// Resource sensitivity levels. Only the three phase-1 values are supported:
// `low`, `medium`, `high`. The architecture doc mentions `critical` as well;
// phase 1 treats anything outside these three as invalid input.
const (
	SensitivityLow    = "low"
	SensitivityMedium = "medium"
	SensitivityHigh   = "high"
)

// Tier thresholds per the simplified phase-1 rules in the implementation spec:
//
//	score <  0.35            → low
//	0.35 ≤ score ≤ 0.70      → medium
//	score >  0.70            → high
const (
	TierLowMax    = 0.35
	TierMediumMax = 0.70
)

// Aggregation weights per the spec (device 0.25, behavior 0.20,
// network 0.30, user 0.25). These sum to 1.0. The slightly different mix in
// ARCHITECTURE.md §7 is the long-term default; phase 1 uses the simpler set
// the implementation spec pins so scoring is predictable and testable.
const (
	WeightDevice   = 0.25
	WeightBehavior = 0.20
	WeightNetwork  = 0.30
	WeightUser     = 0.25
)

// Sensitivity multipliers applied after aggregation. Only low/medium/high are
// supported in phase 1.
const (
	SensitivityMultLow    = 1.00
	SensitivityMultMedium = 1.15
	SensitivityMultHigh   = 1.30
)

// EvaluateRequest is the JSON body for POST /v1/evaluations.
// tenant_id comes from the X-Tenant-Id header and is never accepted in the body.
type EvaluateRequest struct {
	UserID              string         `json:"user_id"`
	SessionID           string         `json:"session_id"`
	Action              string         `json:"action"`
	Resource            string         `json:"resource"`
	ResourceSensitivity string         `json:"resource_sensitivity"`
	Context             EvaluateCtx    `json:"context"`
	// Signals is accepted for parity with ARCHITECTURE.md §4.2 but phase 1
	// scorers ignore it — the four scorers read from Context only. The field
	// is kept so callers can forward the richer payload without DisallowUnknownFields
	// refusing the body.
	Signals map[string]any `json:"signals,omitempty"`
}

// EvaluateCtx carries the primary request context the phase-1 scorers consume.
// All fields are optional — the scorers contribute specific flags when a field
// is missing or matches a mock blocklist/allowlist.
type EvaluateCtx struct {
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
	IPAddress         string `json:"ip_address,omitempty"`
	Country           string `json:"country,omitempty"`
	UserAgent         string `json:"user_agent,omitempty"`
}

// ScorerResult is what each of the four scorers returns. The score is clamped
// to [0, 1] by the scorer itself; aggregator does a final clamp as a belt-and-braces.
type ScorerResult struct {
	Score float64  `json:"score"`
	Flags []string `json:"flags"`
}

// SignalsBreakdown is the per-scorer detail included in every stored evaluation.
// It mirrors the `scores` + `flags` split that ARCHITECTURE.md §4.2 returns, but
// nests the flags under the scorer so callers can tell which signal raised which
// alarm.
type SignalsBreakdown struct {
	Device   ScorerResult `json:"device"`
	Behavior ScorerResult `json:"behavior"`
	Network  ScorerResult `json:"network"`
	User     ScorerResult `json:"user"`
}

// RiskEvaluation is the persisted, tenant-scoped record of a single evaluation.
type RiskEvaluation struct {
	ID                  string           `json:"id"`
	TenantID            string           `json:"tenant_id"`
	UserID              string           `json:"user_id"`
	SessionID           string           `json:"session_id,omitempty"`
	Action              string           `json:"action"`
	Resource            string           `json:"resource,omitempty"`
	ResourceSensitivity string           `json:"resource_sensitivity"`
	Tier                string           `json:"tier"`
	Score               float64          `json:"score"`
	Signals             SignalsBreakdown `json:"signals"`
	Flags               []string         `json:"flags"`
	PolicyDecision      string           `json:"policy_decision"`
	MatchedPolicies     []string         `json:"matched_policies,omitempty"`
	CreatedAt           time.Time        `json:"created_at"`
}

// Policy is a tenant-scoped collection of rules. All rules run on each
// evaluation; any match can floor the tier or deny outright.
type Policy struct {
	ID        string       `json:"id"`
	TenantID  string       `json:"tenant_id"`
	Name      string       `json:"name"`
	Rules     []PolicyRule `json:"rules"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// PolicyRule is one condition/action pair. In phase 1 a rule has exactly one
// condition; compound conditions ("AND", "OR") are deferred to phase 2.
type PolicyRule struct {
	Condition PolicyCondition `json:"condition"`
	Action    PolicyAction    `json:"action"`
}

// PolicyCondition is a single field/op/value triple. Supported fields and ops
// are documented in the package README and validated on policy write.
type PolicyCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value any    `json:"value"`
}

// PolicyAction is the effect of a matching rule. Either `deny` is true
// (terminal — overrides everything) or `tier_floor` raises the derived tier
// to at least that value. Both may be set; deny wins.
type PolicyAction struct {
	TierFloor string `json:"tier_floor,omitempty"`
	Deny      bool   `json:"deny,omitempty"`
}

// CreatePolicyRequest is the JSON body for POST /v1/policies.
type CreatePolicyRequest struct {
	Name  string       `json:"name"`
	Rules []PolicyRule `json:"rules"`
}

// UpdatePolicyRequest is the JSON body for PATCH /v1/policies/{id}. All fields
// are optional — a nil pointer means "leave as-is".
type UpdatePolicyRequest struct {
	Name  *string       `json:"name,omitempty"`
	Rules *[]PolicyRule `json:"rules,omitempty"`
}

// ListPoliciesResponse is the envelope for GET /v1/policies.
type ListPoliciesResponse struct {
	Items []Policy `json:"items"`
}

// Validation bounds.
const (
	MaxNameLen      = 100
	MaxRulesPerPolicy = 50
)

// ValidTier reports whether s is one of low/medium/high.
func ValidTier(s string) bool {
	switch s {
	case TierLow, TierMedium, TierHigh:
		return true
	}
	return false
}

// ValidSensitivity reports whether s is one of the three supported levels.
func ValidSensitivity(s string) bool {
	switch s {
	case SensitivityLow, SensitivityMedium, SensitivityHigh:
		return true
	}
	return false
}

// tierRank lets us compare tiers numerically for the tier_floor overlay.
// Higher number = more restrictive.
func tierRank(t string) int {
	switch t {
	case TierHigh:
		return 3
	case TierMedium:
		return 2
	case TierLow:
		return 1
	default:
		return 0
	}
}
