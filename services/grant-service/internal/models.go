// Package internal contains the grant-service domain model, storage, and HTTP handlers.
package internal

import "time"

// Grant status values. Status is derived at read time from revoked_at / expires_at;
// it is not stored as a column on the Grant itself.
const (
	StatusActive  = "active"
	StatusExpired = "expired"
	StatusRevoked = "revoked"
)

// Grant is an active OAuth grant issued to an install. See REQUIREMENTS.md §2.
//
// Token values are NEVER stored in plaintext. Callers either hand us the plaintext
// (which we hash before persistence) or pre-hashed values; only the SHA-256 hex digest
// is ever held in memory or returned to clients.
type Grant struct {
	ID               string     `json:"id"`
	TenantID         string     `json:"tenant_id"`
	InstallID        string     `json:"install_id"`
	IdentityID       string     `json:"identity_id"`
	PersonaID        string     `json:"persona_id"`
	AccessTokenHash  string     `json:"access_token_hash"`
	RefreshTokenHash string     `json:"refresh_token_hash"`
	IssuedAt         time.Time  `json:"issued_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	Status           string     `json:"status"`
}

// CreateGrantRequest is the JSON body for POST /v1/grants.
// tenant_id is sourced from the X-Tenant-Id header, never the body.
// Token hashes arrive pre-computed (SHA-256 hex) per REQUIREMENTS.md §4 —
// plaintext tokens never transit to or through grant-service on this path.
type CreateGrantRequest struct {
	InstallID        string `json:"install_id"`
	IdentityID       string `json:"identity_id"`
	PersonaID        string `json:"persona_id"`
	AccessTokenHash  string `json:"access_token_hash"`
	RefreshTokenHash string `json:"refresh_token_hash"`
	TTLSeconds       int    `json:"ttl_seconds"`
}

// IntrospectRequest is the body of POST /v1/introspect (RFC 7662).
type IntrospectRequest struct {
	Token string `json:"token"`
}

// RevokeTokenRequest is the body of POST /v1/revoke (RFC 7009 shape, as
// forwarded by broker-service's public /revoke endpoint).
type RevokeTokenRequest struct {
	Token string `json:"token"`
}

// IntrospectResponse is the RFC 7662 response shape. Only `active` is present when the
// token is unknown, expired, or revoked; the tenant-scoped fields are populated only on
// active tokens.
type IntrospectResponse struct {
	Active     bool   `json:"active"`
	InstallID  string `json:"install_id,omitempty"`
	IdentityID string `json:"identity_id,omitempty"`
	PersonaID  string `json:"persona_id,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	IssuedAt   int64  `json:"iat,omitempty"`
	ExpiresAt  int64  `json:"exp,omitempty"`
}

// AuditEvent is an append-only log entry. Once persisted, events cannot be modified or
// deleted; there is no update or delete endpoint.
type AuditEvent struct {
	ID        string         `json:"id"`
	TenantID  string         `json:"tenant_id"`
	Type      string         `json:"type"`
	Actor     string         `json:"actor"`
	InstallID string         `json:"install_id,omitempty"`
	GrantID   string         `json:"grant_id,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

// AppendAuditRequest is the body of POST /v1/audit.
type AppendAuditRequest struct {
	Type      string         `json:"type"`
	Actor     string         `json:"actor"`
	InstallID string         `json:"install_id,omitempty"`
	GrantID   string         `json:"grant_id,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
}

// AuditListResponse is the envelope returned by GET /v1/audit.
type AuditListResponse struct {
	Items []AuditEvent `json:"items"`
}

// Defaults and validation bounds.
const (
	DefaultTTLSeconds = 900
	MaxTTLSeconds     = 86400
	DefaultAuditLimit = 100
	MaxAuditLimit     = 1000
)
