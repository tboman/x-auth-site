// Package internal contains the authenticator-service domain model, storage,
// vendor adapter stubs, and HTTP handlers. authenticator-service is an
// internal-only component of X-Auth for Apps — it owns authenticator CRUD
// (WebAuthn/FIDO2, TOTP, push, SMS, magic link), the challenge lifecycle
// (dispatch → verify), and the vendor adapter boundary.
//
// Phase 1 is entirely in-memory and tenant-scoped. No real FIDO2 crypto, no
// real SMS/push/email delivery — adapters return canned values so the higher
// services (transaction, risk, authentication) can be exercised end to end.
package internal

import "time"

// Supported authenticator methods. The string values are the wire form; they
// also index the adapter registry.
const (
	MethodFIDO2     = "fido2"
	MethodTOTP      = "totp"
	MethodPush      = "push"
	MethodSMS       = "sms"
	MethodMagicLink = "magic_link"
)

// Authenticator statuses. `disabled` is a soft-delete — the row stays on file
// so audit queries keep working, but it is filtered out of enrollment lookups
// and never selected for a new challenge.
const (
	AuthenticatorStatusActive   = "active"
	AuthenticatorStatusDisabled = "disabled"
)

// Challenge statuses.
const (
	ChallengeStatusPending   = "pending"
	ChallengeStatusCompleted = "completed"
	ChallengeStatusFailed    = "failed"
	ChallengeStatusExpired   = "expired"
)

// ChallengeTTL is how long a dispatched challenge remains verifiable.
// Phase 1 uses a single global constant; real deployments would vary per method.
const ChallengeTTL = 5 * time.Minute

// MaxChallengeAttempts is the number of failed verify attempts a challenge
// tolerates before it is marked `failed` (terminal).
const MaxChallengeAttempts = 3

// -----------------------------------------------------------------------------
// Wire payloads
// -----------------------------------------------------------------------------

// EnrollRequest is the body of POST /v1/authenticators.
type EnrollRequest struct {
	UserID   string         `json:"user_id"`
	Method   string         `json:"method"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// ChallengeRequest is the body of POST /v1/challenges. `methods` is the
// caller's preference order — the service picks the first one the user has
// an active authenticator for.
type ChallengeRequest struct {
	UserID  string   `json:"user_id"`
	Methods []string `json:"methods"`
}

// ChallengeDispatched is the response from POST /v1/challenges.
type ChallengeDispatched struct {
	ChallengeID string    `json:"challenge_id"`
	Method      string    `json:"method"`
	Prompt      string    `json:"prompt"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// VerifyRequest is the body of POST /v1/challenges/{id}/verify.
type VerifyRequest struct {
	Response map[string]any `json:"response"`
}

// VerifyResponse is the body of POST /v1/challenges/{id}/verify.
type VerifyResponse struct {
	Verified        bool   `json:"verified"`
	AuthenticatorID string `json:"authenticator_id,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

// ListResponse envelopes GET /v1/authenticators.
type ListResponse struct {
	Items []Authenticator `json:"items"`
}

// -----------------------------------------------------------------------------
// Persisted records
// -----------------------------------------------------------------------------

// Authenticator is one enrollment record. IDs are prefixed `authr_`.
type Authenticator struct {
	ID        string         `json:"id"`
	TenantID  string         `json:"tenant_id"`
	UserID    string         `json:"user_id"`
	Method    string         `json:"method"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	Status    string         `json:"status"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// Challenge is one step-up challenge. IDs are prefixed `ch_`.
type Challenge struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	UserID          string     `json:"user_id"`
	Method          string     `json:"method"`
	AuthenticatorID string     `json:"authenticator_id"`
	Prompt          string     `json:"prompt"`
	Status          string     `json:"status"`
	Attempts        int        `json:"attempts"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
}

// IsValidMethod reports whether m is one of the supported method strings.
func IsValidMethod(m string) bool {
	switch m {
	case MethodFIDO2, MethodTOTP, MethodPush, MethodSMS, MethodMagicLink:
		return true
	}
	return false
}
