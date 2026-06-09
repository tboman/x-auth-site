// Package internal contains the pool-service domain model, storage, and HTTP handlers.
package internal

import "time"

// IdentityStatus enumerates the lifecycle states of an Identity.
type IdentityStatus string

const (
	StatusAvailable IdentityStatus = "available"
	StatusClaimed   IdentityStatus = "claimed"
	StatusRevoked   IdentityStatus = "revoked"
)

// Pool is a container of concrete agent identities eligible to assume one or more
// personas. See REQUIREMENTS.md §2.
type Pool struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Name       string    `json:"name"`
	Size       int       `json:"size"`
	PersonaIDs []string  `json:"persona_ids"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Identity is a concrete identity belonging to a Pool. See REQUIREMENTS.md §2.
type Identity struct {
	ID                 string         `json:"id"`
	PoolID             string         `json:"pool_id"`
	SubjectID          string         `json:"subject_id"`
	Status             IdentityStatus `json:"status"`
	ClaimedByInstallID *string        `json:"claimed_by_install_id"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

// CreatePoolRequest is the JSON body for POST /v1/pools. tenant_id comes from the
// X-Tenant-Id header, not the body.
type CreatePoolRequest struct {
	Name       string   `json:"name"`
	Size       int      `json:"size"`
	PersonaIDs []string `json:"persona_ids"`
}

// AddIdentityRequest is the JSON body for POST /v1/pools/{id}/identities.
type AddIdentityRequest struct {
	SubjectID string `json:"subject_id"`
}

// ClaimRequest is the JSON body for POST /v1/pools/{id}/claim.
type ClaimRequest struct {
	PersonaID string `json:"persona_id"`
	InstallID string `json:"install_id"`
}

// PoolListResponse is the envelope returned by GET /v1/pools. NextCursor is set
// when a full page was returned; pass it back as ?cursor= to fetch the next page.
type PoolListResponse struct {
	Items      []Pool `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// IdentityListResponse is the envelope returned by GET /v1/pools/{id}/identities.
// NextCursor is set when a full page was returned; pass it back as ?cursor= to
// fetch the next page.
type IdentityListResponse struct {
	Items      []Identity `json:"items"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

// Validation bounds.
const (
	MaxNameLen = 100
	MinSize    = 1
	MaxSize    = 10000
)

// Pagination bounds for GET /v1/pools and GET /v1/pools/{id}/identities.
// Mirrors the transaction-service contract.
const (
	DefaultListLimit = 100
	MaxListLimit     = 500
)
