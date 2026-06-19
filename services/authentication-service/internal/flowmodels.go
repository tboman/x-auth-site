package internal

// flowmodels.go is the foundation of the configurable flow/stage engine (see
// ~/.claude/plans). A flow is an ordered list of stages driven by a small
// executor (flowexec.go); a stage performs one step (identify, validate a
// factor, evaluate risk, consent, issue, deny). FlowExecution generalizes the
// step-up interlude's pendingAuthorize (otp.go) into a resumable, multi-stage
// cursor.
//
// Phase 1 wires only the authorization-stepup designation behind the FLOW_ENGINE
// flag, using CODE-DEFINED default flows (flow_defaults.go) that reproduce
// today's behavior exactly. Per-tenant configuration, persistence, and the
// policy engine land in later phases.

import (
	"net/http"
	"time"
)

// Flow designations — which journey a flow drives.
const (
	FlowAuthentication  = "authentication"       // /login: identify the user
	FlowAuthorizeStepUp = "authorization-stepup" // /authorize: assurance/step-up → issue
	FlowEnrollment      = "enrollment"           // register a new factor
	FlowRecovery        = "recovery"             // account recovery
)

// StageResult is the verdict a stage returns to the executor.
type StageResult int

const (
	// StageContinue — the stage finished without rendering; advance to the next.
	StageContinue StageResult = iota
	// StageRespond — the stage rendered a page or redirected out; the execution
	// is parked and resumes (re-enters the executor) on the follow-up request.
	StageRespond
	// StageComplete — terminal success; the flow has issued its result.
	StageComplete
	// StageDeny — terminal failure; the flow denied the request.
	StageDeny
)

func (r StageResult) String() string {
	switch r {
	case StageContinue:
		return "continue"
	case StageRespond:
		return "respond"
	case StageComplete:
		return "complete"
	case StageDeny:
		return "deny"
	default:
		return "unknown"
	}
}

// Stage performs one step of a flow. Execute either finishes silently
// (StageContinue), renders/redirects and parks (StageRespond), or terminates the
// flow (StageComplete/StageDeny). A stage must not advance the cursor itself —
// the executor owns the cursor.
type Stage interface {
	// Type is the stage's taxonomy name (identification, authenticator-validate,
	// risk-evaluation, consent, prompt, user-login, deny, …).
	Type() string
	// Execute runs the stage against the current execution.
	Execute(w http.ResponseWriter, r *http.Request, exec *FlowExecution) (StageResult, error)
}

// Flow is a named, ordered list of stages for a designation. Phase 1 builds
// these in code (flow_defaults.go); later phases load them per-tenant.
type Flow struct {
	Slug        string
	Designation string
	Title       string
	Stages      []Stage
}

// FlowDefinition is the stored, declarative form of a tenant's flow — one row
// (the stages live in a JSONB column). It is compiled into a runnable *Flow by
// buildFlow (flow_build.go): each StageConfig becomes a Stage, optionally wrapped
// in a policyGatedStage. Keeping the whole flow in one document (policies inline,
// not separate rows) keeps P3 storage to a single table; normalization can come
// later without changing this contract.
type FlowDefinition struct {
	ID          string        `json:"id"`
	TenantID    string        `json:"tenant_id"`
	Designation string        `json:"designation"` // FlowAuthorizeStepUp, …
	Slug        string        `json:"slug"`
	Title       string        `json:"title"`
	Enabled     bool          `json:"enabled"` // the enabled flow per designation is the one Authorize runs
	Stages      []StageConfig `json:"stages"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// StageConfig is one stage in a stored flow: a taxonomy type, optional config
// (e.g. {"reason": …} for a deny stage), and zero or more attached policies that
// gate whether it runs.
type StageConfig struct {
	Type     string         `json:"type"`
	Config   map[string]any `json:"config,omitempty"`
	Policies []PolicyConfig `json:"policies,omitempty"`
}

// PolicyConfig is one boolean expr-lang policy bound to a stage. Negate flips the
// pass/skip sense (see policyGatedStage).
type PolicyConfig struct {
	Name       string `json:"name"`
	Expression string `json:"expression"`
	Negate     bool   `json:"negate"`
}

// FlowExecution is the parked, resumable state of a running flow. It carries the
// OIDC request facts (the former pendingAuthorize fields) plus a context bag the
// later risk/policy stages populate. It lives in an in-process TTL map keyed by
// ID, exactly like the step-up flows do today (single-replica caveat unchanged).
type FlowExecution struct {
	ID          string
	TenantID    string
	Designation string
	FlowSlug    string
	Cursor      int // index into the flow's stages

	// OIDC request facts (mirror pendingAuthorize).
	ClientID       string
	UserID         string
	RedirectURI    string
	Scope          string
	State          string
	Nonce          string
	CodeChallenge  string
	TransactionID  string
	AuthzSessionID string
	ACRValues      string // requested acr_values, verbatim

	// Filled as stages run.
	AchievedACR string   // the acr to stamp on the issued token
	AchievedAMR []string // the amr to stamp
	// Context is a free-form bag later stages (risk-evaluation) write into and
	// policies read from. Phase 1 leaves it empty.
	Context map[string]any

	CreatedAt time.Time
}
