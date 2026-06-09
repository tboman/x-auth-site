// Package internal contains the broker-service domain model, storage, HTTP handlers,
// OIDC/OAuth endpoints, MCP stubs, and thin clients for the other X-Auth services.
//
// See REQUIREMENTS.md §2 for the Install domain model and §4 for the service contracts.
package internal

import "time"

// Install runtime values. A runtime is the MCP host (Claude Desktop, ChatGPT,
// Cursor, etc.) in which the agent identity lives.
const (
	RuntimeClaude  = "claude"
	RuntimeChatGPT = "chatgpt"
	RuntimeCursor  = "cursor"
	RuntimeCustom  = "custom"
)

// Install lifecycle states. See REQUIREMENTS.md §2.
const (
	InstallStatusPending = "pending"
	InstallStatusActive  = "active"
	InstallStatusRevoked = "revoked"
)

// Install is one MCP connection installed in a runtime, bound to one persona + identity.
type Install struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Runtime    string    `json:"runtime"`
	PersonaID  string    `json:"persona_id"`
	IdentityID string    `json:"identity_id,omitempty"`
	ClientID   string    `json:"client_id"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// CreateInstallRequest is the JSON body for POST /v1/installs (manual install creation).
// tenant_id is sourced from the X-Tenant-Id header.
type CreateInstallRequest struct {
	Runtime   string `json:"runtime"`
	PersonaID string `json:"persona_id"`
	ClientID  string `json:"client_id"`
}

// DCRClient is an OAuth client registered via RFC 7591 Dynamic Client Registration.
// Phase 1 keeps these in memory; phase 2 moves them to persistent storage.
type DCRClient struct {
	ClientID       string         `json:"client_id"`
	ClientSecret   string         `json:"client_secret,omitempty"`
	ClientMetadata map[string]any `json:"client_metadata,omitempty"`
	CreatedAt      time.Time      `json:"client_id_issued_at,omitempty"`
}

// AuthCode is a transient record created by /authorize and consumed by /token.
// It remembers which persona/pool/client/tenant the user selected during
// authorization so /token can orchestrate the real install creation.
//
// CodeChallenge is the PKCE S256 challenge (RFC 7636) the client sent to
// /authorize — base64url-without-padding of SHA-256(code_verifier). PKCE is
// mandatory (ARCHITECTURE.md §10.4 and the MCP authorization spec), so the
// field is always populated for codes minted by /authorize, and /token rejects
// any code whose stored challenge does not match the presented code_verifier.
type AuthCode struct {
	Code          string
	TenantID      string
	Runtime       string
	PersonaID     string
	PoolID        string
	ClientID      string
	RedirectURI   string
	State         string
	Scope         string
	CodeChallenge string
	CreatedAt     time.Time
}

// TokenRecord is the broker's own view of an issued token. AccessToken holds the
// full compact JWT string (phase 2.1); RefreshToken stays an opaque UUID. The
// record doubles as the revocation deny-list for /userinfo's hybrid check —
// /revoke and install revocation delete it — and as the metadata source for
// /userinfo's response. A later phase defers this to grant-service introspection
// and drops the duplicated state.
type TokenRecord struct {
	AccessToken  string
	RefreshToken string
	InstallID    string
	PersonaID    string
	IdentityID   string
	Subject      string
	Scope        string
	TenantID     string
	ExpiresAt    time.Time
}

// Validation / default values.
const (
	DefaultTokenTTLSeconds = 900
	AuthCodeTTLSeconds     = 300
)

// Pagination bounds for GET /v1/installs — same contract as
// transaction-service's GET /v1/transactions.
const (
	DefaultListLimit = 100
	MaxListLimit     = 500
)

// InstallListResponse is the envelope returned by GET /v1/installs. NextCursor is
// only set when a full page was returned; pass it back as ?cursor= to fetch the
// next (strictly older) page.
type InstallListResponse struct {
	Installs   []Install `json:"installs"`
	NextCursor string    `json:"next_cursor,omitempty"`
}

// ValidRuntime reports whether s is one of the four supported runtime strings.
func ValidRuntime(s string) bool {
	switch s {
	case RuntimeClaude, RuntimeChatGPT, RuntimeCursor, RuntimeCustom:
		return true
	}
	return false
}
