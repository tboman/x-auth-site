// Package internal contains the transaction-service domain model, storage, inter-service
// clients, and HTTP handlers. transaction-service is the public-facing orchestrator for
// X-Auth for Apps — it owns /v1/advice (a.k.a. /v1/evaluate), drives risk evaluation via
// risk-service, triggers step-up via authenticator-service, and promotes sessions via
// authentication-service once a challenge has been satisfied.
package internal

import "time"

// Tier values returned by risk-service. Anything outside this set is treated as an error.
const (
	TierLow    = "low"
	TierMedium = "medium"
	TierHigh   = "high"
)

// Decision values that transaction-service can emit. Stored on the Transaction record
// and returned on the wire.
const (
	DecisionAllow           = "allow"
	DecisionDeny            = "deny"
	DecisionStepUpRequired  = "step_up_required"
	DecisionStepUpSatisfied = "step_up_satisfied"
	DecisionError           = "error"
)

// Pagination bounds for GET /v1/transactions.
const (
	DefaultListLimit = 100
	MaxListLimit     = 500
)

// SessionStaleAfter — /v1/authorize falls back to a fresh risk evaluation if the cached
// session risk was recorded longer ago than this.
const SessionStaleAfter = 5 * time.Minute

// -----------------------------------------------------------------------------
// Public request/response payloads (per ARCHITECTURE.md §4.1)
// -----------------------------------------------------------------------------

// Geo is an optional lat/lon pair attached to evaluation context.
type Geo struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// EvalContext is the device/network/geo bundle posted with /v1/advice.
type EvalContext struct {
	IPAddress         string `json:"ip_address"`
	UserAgent         string `json:"user_agent,omitempty"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
	Geo               *Geo   `json:"geo,omitempty"`
}

// AdviceRequest is the JSON body of POST /v1/advice (and its /v1/evaluate alias).
type AdviceRequest struct {
	UserID              string      `json:"user_id"`
	SessionID           string      `json:"session_id,omitempty"`
	Action              string      `json:"action"`
	Resource            string      `json:"resource,omitempty"`
	ResourceSensitivity string      `json:"resource_sensitivity,omitempty"`
	Context             EvalContext `json:"context"`
}

// SignalSummary is one signal row surfaced back to the caller.
type SignalSummary struct {
	Score float64  `json:"score"`
	Flags []string `json:"flags,omitempty"`
}

// RiskEvaluation is the slimmed view transaction-service returns to clients.
// It is assembled from the risk-service response — full scorer output, plus tier/score/id.
type RiskEvaluation struct {
	ID      string                   `json:"id"`
	Tier    string                   `json:"tier"`
	Score   float64                  `json:"score"`
	Signals map[string]SignalSummary `json:"signals"`
}

// StepUpChallenge is returned when decision == "step_up_required".
type StepUpChallenge struct {
	ChallengeID string    `json:"challenge_id"`
	Methods     []string  `json:"methods"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// AdviceResponse is the wire shape for /v1/advice.
type AdviceResponse struct {
	TransactionID  string           `json:"transaction_id"`
	RiskEvaluation *RiskEvaluation  `json:"risk_evaluation,omitempty"`
	Decision       string           `json:"decision"`
	StepUp         *StepUpChallenge `json:"step_up,omitempty"`
}

// StepUpVerifyRequest is the JSON body of POST /v1/step-up/verify.
type StepUpVerifyRequest struct {
	TransactionID string         `json:"transaction_id"`
	ChallengeID   string         `json:"challenge_id"`
	Method        string         `json:"method"`
	Response      map[string]any `json:"response"`
}

// SessionView is the minimal session shape the verify endpoint echoes back.
type SessionView struct {
	ID              string    `json:"id"`
	RiskLevel       string    `json:"risk_level"`
	StepUpCompleted bool      `json:"step_up_completed"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// StepUpVerifyResponse is the wire shape for /v1/step-up/verify.
type StepUpVerifyResponse struct {
	TransactionID string       `json:"transaction_id"`
	Decision      string       `json:"decision"`
	Session       *SessionView `json:"session,omitempty"`
	Reason        string       `json:"reason,omitempty"`
}

// AuthorizeRequest is the JSON body of POST /v1/authorize.
type AuthorizeRequest struct {
	UserID     string         `json:"user_id"`
	SessionID  string         `json:"session_id"`
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// AuthorizeResponse is the wire shape for /v1/authorize.
//
// policy_id keeps the ARCHITECTURE.md §4.1 contract: it carries the first policy
// risk-service matched. risk-service actually reports every matching policy
// (matched_policies), so the full list is surfaced alongside for callers that
// want more than the primary id.
type AuthorizeResponse struct {
	TransactionID   string    `json:"transaction_id"`
	Decision        string    `json:"decision"`
	PolicyID        string    `json:"policy_id,omitempty"`
	MatchedPolicies []string  `json:"matched_policies,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	EvaluatedAt     time.Time `json:"evaluated_at"`
}

// ListResponse is the envelope returned by GET /v1/transactions.
type ListResponse struct {
	Items      []Transaction `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

// HistoryEntry is one audit-trail row appended as a transaction transitions.
type HistoryEntry struct {
	At     time.Time `json:"at"`
	Event  string    `json:"event"`
	Detail string    `json:"detail,omitempty"`
}

// Transaction is the persisted orchestration record. Phase 1 is in-memory, tenant-scoped.
type Transaction struct {
	ID                  string         `json:"id"`
	TenantID            string         `json:"tenant_id"`
	UserID              string         `json:"user_id"`
	SessionID           string         `json:"session_id,omitempty"`
	Action              string         `json:"action"`
	Resource            string         `json:"resource,omitempty"`
	ResourceSensitivity string         `json:"resource_sensitivity,omitempty"`
	RiskEvaluationID    string         `json:"risk_evaluation_id,omitempty"`
	RiskTier            string         `json:"risk_tier,omitempty"`
	RiskScore           float64        `json:"risk_score,omitempty"`
	Decision            string         `json:"decision"`
	StepUpUsed          bool           `json:"step_up_used"`
	StepUpMethod        string         `json:"step_up_method,omitempty"`
	ChallengeID         string         `json:"challenge_id,omitempty"`
	PolicyID            string         `json:"policy_id,omitempty"`
	Reason              string         `json:"reason,omitempty"`
	History             []HistoryEntry `json:"history,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
	DecidedAt           *time.Time     `json:"decided_at,omitempty"`
}
