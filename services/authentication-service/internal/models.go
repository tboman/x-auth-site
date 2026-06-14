// Package internal contains the authentication-service domain model, storage,
// HTTP handlers, OIDC/OAuth endpoints, and thin clients for sister services.
//
// authentication-service is the public OIDC provider for X-Auth for Apps. It owns:
//   - users (CRUD)
//   - sessions (create after first-factor auth, refresh, invalidate, upgrade on step-up)
//   - tokens (RS256 JWT access + ID tokens, opaque refresh tokens; all hashed at rest)
//   - OIDC endpoints (discovery, authorize, token, userinfo, revoke, jwks)
//   - social-login stubs (google, github, microsoft)
//
// Access and ID tokens are RS256 JWTs per ARCHITECTURE.md §10.1, verifiable by
// any service against GET /v1/auth/jwks. Refresh tokens remain opaque UUIDs.
// Remaining phase-2 shortcuts are flagged with `TODO(phase-2)` comments.
//
// See ARCHITECTURE.md §4.3 for the source-of-truth service contract.
package internal

import "time"

// Risk level values. Mirrors the shape the transaction-service and risk-service
// use so a session record can be compared / round-tripped without translation.
const (
	RiskLow    = "low"
	RiskMedium = "medium"
	RiskHigh   = "high"
)

// User identity record.
//
// Phase 1 identifies a user by (tenant_id, email). There is no password column:
// first-factor auth is performed by authenticator-service against its own
// credential store and authentication-service only learns about the user when
// transaction-service asks it to mint a session.
type User struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Email     string    `json:"email"`
	Name      string    `json:"name,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Pagination bounds for GET /v1/users — the same keyset-pagination contract as
// transaction-service's GET /v1/transactions.
const (
	DefaultListLimit = 100
	MaxListLimit     = 500
)

// ListUsersResponse is the envelope returned by GET /v1/users. next_cursor is
// only present when a full page was returned and carries the last item's
// created_at (RFC3339Nano); pass it back as ?cursor= to fetch strictly older
// users.
type ListUsersResponse struct {
	Users      []User `json:"users"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// CreateUserRequest is the JSON body for POST /v1/users. tenant_id is sourced
// from the X-Tenant-Id header, not the body.
type CreateUserRequest struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// UpdateUserRequest is the JSON body for PATCH /v1/users/{id}. Both fields are
// optional; only non-empty values are applied.
type UpdateUserRequest struct {
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}

// Session is a tenant-scoped, user-bound login session. risk_level and
// step_up_completed track the most recent authentication posture so the
// orchestrating transaction-service can decide whether to allow a high-risk
// action without re-evaluating from scratch.
type Session struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	UserID          string     `json:"user_id"`
	RiskLevel       string     `json:"risk_level"`
	StepUpCompleted bool       `json:"step_up_completed"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	InvalidatedAt   *time.Time `json:"invalidated_at,omitempty"`
}

// CreateSessionRequest is the JSON body for POST /v1/sessions. transaction-service
// supplies this after a successful first-factor check — authentication-service
// trusts the caller and mints the session without re-verifying credentials.
// TODO(phase-2): require a signed token from transaction-service so a rogue
// internal caller cannot fabricate sessions for arbitrary users.
type CreateSessionRequest struct {
	UserID          string `json:"user_id"`
	RiskLevel       string `json:"risk_level"`
	StepUpCompleted bool   `json:"step_up_completed"`
}

// UpgradeSessionRequest is the JSON body for POST /v1/sessions/{id}/upgrade.
// Used by transaction-service after authenticator-service verifies a step-up
// challenge to re-classify the session as step-up-completed and optionally
// lower the risk level.
type UpgradeSessionRequest struct {
	RiskLevel       string `json:"risk_level,omitempty"`
	StepUpCompleted bool   `json:"step_up_completed"`
}

// TenantSummary is one row of the admin console's tenant listing. The staff
// console still derives these by aggregating the records that reference each
// tenant_id (a tenant may exist only as users/sessions, with no registry row —
// e.g. ten_admin, ten_developer, ten_signup).
type TenantSummary struct {
	TenantID     string    `json:"tenant_id"`
	Users        int       `json:"users"`
	Sessions     int       `json:"sessions"`
	LastActivity time.Time `json:"last_activity"`
}

// Tenant is a self-service-provisioned workspace, created when a visitor signs
// up from the marketing site ("Get Started Free"). Unlike the derived
// TenantSummary, this is a first-class registry row: it carries the
// human-supplied CompanyName, the Slug used to derive the tenant id
// (ID == "ten_" + Slug), and the OwnerEmail of the Google account that created
// it. Slug and OwnerEmail are both unique — a company name can be claimed once,
// and a Google account owns at most one self-service tenant (so a returning
// owner is routed back to their workspace rather than making a second one).
type Tenant struct {
	ID          string    `json:"id"`
	CompanyName string    `json:"company_name"`
	Slug        string    `json:"slug"`
	OwnerEmail  string    `json:"owner_email"`
	CreatedAt   time.Time `json:"created_at"`
}

// Identity anchor types. An identity (a users row) can be identified by one or
// more anchors. Email is today's primary anchor, minted from Google social
// login and stored canonically on users.email; phone and passkey are additional
// anchor types whose ownership-proof (validation) flows are not built yet — see
// the IdentityAnchor doc and migration 000007.
const (
	AnchorEmail   = "email"
	AnchorPhone   = "phone"
	AnchorPasskey = "passkey"
)

// IdentityAnchor is one way an identity can be identified: an email address, an
// E.164 phone number, or a passkey (WebAuthn credential id). A user may hold
// several — notably one passkey per device. VerifiedAt is nil until the
// (not-yet-implemented) validation flow confirms ownership, so a freshly
// recorded phone/passkey anchor is unverified by construction.
//
// email remains the canonical primary anchor on users.email; this type backs
// the additional/alternative anchors persisted in the identity_anchors table.
type IdentityAnchor struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	TenantID   string     `json:"tenant_id"`
	Type       string     `json:"type"`
	Value      string     `json:"value"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// TokenType discriminates between access and refresh token records.
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

// Token is the authentication-service's internal record of an issued token —
// JWT access tokens and opaque refresh tokens alike. Plaintext tokens are never
// persisted — we store the SHA-256 hex digest and compare by re-hashing what
// the caller presents.
//
// Access tokens are stateless JWTs (§10.1), but their record is deliberately
// kept as a revocation deny list: /userinfo requires both a valid signature
// AND a live (non-revoked) record, so RFC 7009 /revoke keeps taking effect
// immediately. Drop the access-token record only when distributed revocation
// lands.
//
// FamilyID groups every token descending from one authorization-code login
// (ARCHITECTURE.md §10.1 family-based revocation): the code grant mints a
// fresh family id and every refresh rotation issues its replacement tokens
// into the same family. Presenting a refresh token that was already
// rotated-out is treated as a theft signal and revokes the whole family.
//
// ClientID is the OAuth client the tokens were issued to (from the auth code
// at login). The refresh grant sources the `aud` claim of rotated access
// tokens from here, so it no longer depends on what the client presents at
// refresh time.
type Token struct {
	TokenHash string     `json:"-"`
	SessionID string     `json:"session_id"`
	UserID    string     `json:"user_id"`
	TenantID  string     `json:"tenant_id"`
	ClientID  string     `json:"client_id,omitempty"`
	FamilyID  string     `json:"family_id,omitempty"`
	TokenType string     `json:"token_type"`
	Scope     string     `json:"scope,omitempty"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// AuthCode is the transient record created by /authorize and consumed by /token.
// Single-use by construction — the storage layer deletes it on read.
//
// CodeChallenge is the PKCE S256 challenge from the /authorize request
// (ARCHITECTURE.md §10.4). It is always present on codes minted by /authorize
// — PKCE is mandatory and S256-only, so no method field is stored: anything
// other than S256 is rejected at the /authorize boundary.
type AuthCode struct {
	Code          string
	ClientID      string
	TenantID      string
	UserID        string
	SessionID     string
	RedirectURI   string
	Scope         string
	State         string
	Nonce         string
	CodeChallenge string
	CreatedAt     time.Time

	// ACR/AMR record which authentication context the /authorize flow
	// satisfied (e.g. the SMS-OTP interlude) so the token mint can stamp the
	// claims into the ID token and mark the session stepped-up.
	ACR string
	AMR []string
}

// OIDCClient is a registered OAuth/OIDC client. Phase 1 seeds a single dev
// client (see storage.go seedDefaultClient); full dynamic registration lives in
// broker-service for now.
type OIDCClient struct {
	ClientID         string `json:"client_id"`
	ClientSecretHash string `json:"-"` // never marshal the hash back to the wire
	// TenantID binds the client to a single tenant. When set, /authorize uses
	// it as the authoritative tenant and rejects a contradicting tenant_id
	// parameter — a client cannot operate across tenant boundaries. Empty means
	// unbound (legacy clients seeded before this field; /authorize falls back to
	// the request's tenant_id).
	TenantID     string   `json:"tenant_id,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	// WebOrigins are the browser origins (scheme://host[:port]) allowed to make
	// cross-origin fetch calls to the public OIDC surface on this client's
	// behalf. The CORS handler unions these with the CORS_ALLOWED_ORIGINS env
	// baseline, so a client registered through the admin console can call
	// /token from its SPA without an env change + redeploy.
	WebOrigins []string  `json:"web_origins,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// SocialProfile is the canned profile returned by a social-login stub callback.
// Real providers return wildly different shapes; phase 1 normalises to this
// minimal set so the rest of the session-creation path does not care which
// provider the user came from.
type SocialProfile struct {
	Provider   string
	ExternalID string
	Email      string
	Name       string
}

// TTLs (in seconds) for the various artefacts authentication-service manages.
// Centralised here so tests can reason about expected lifetimes without repeating
// magic numbers throughout the handlers.
const (
	SessionTTLSeconds      = 3600    // 1 hour
	AccessTokenTTLSeconds  = 3600    // 1 hour per ARCHITECTURE.md §10.1; per-client overrides arrive with dynamic client registration
	RefreshTokenTTLSeconds = 2592000 // 30 days per ARCHITECTURE.md §6.2 (oidc_clients.refresh_ttl_sec default)
	AuthCodeTTLSeconds     = 300     // 5 minutes

	// DefaultClientID is the dev client seeded at startup. Using a stable, well-
	// known value keeps smoke tests and local cURL examples simple.
	DefaultClientID     = "cli_default"
	DefaultClientSecret = "dev-secret" // TODO(phase-2): replace with a random, hashed secret per environment.
)

// ValidRiskLevel returns true when s is one of {low, medium, high}.
func ValidRiskLevel(s string) bool {
	switch s {
	case RiskLow, RiskMedium, RiskHigh:
		return true
	}
	return false
}

// ValidSocialProvider returns true when s is a supported social-login stub.
// Phase 1 supports google, github, microsoft — any other string is rejected at
// the /v1/social/{provider}/authorize boundary.
func ValidSocialProvider(s string) bool {
	switch s {
	case "google", "github", "microsoft":
		return true
	}
	return false
}

// StaffUser represents a staff member with access to the internal administration console.
type StaffUser struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// StaffUserRole associates a StaffUser with an administrative role.
type StaffUserRole struct {
	StaffUserID string    `json:"staff_user_id"`
	Role        string    `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
}
