// Package internal contains the persona-service domain model, storage, and HTTP handlers.
package internal

import "time"

// Persona is a pre-authorized bundle of claims owned by a tenant. See REQUIREMENTS.md §2.
type Persona struct {
	ID              string         `json:"id"`
	TenantID        string         `json:"tenant_id"`
	Name            string         `json:"name"`
	Scopes          []string       `json:"scopes"`
	Claims          map[string]any `json:"claims,omitempty"`
	TokenTTLSeconds int            `json:"token_ttl_seconds"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// CreateRequest is the JSON body for POST /v1/personas.
// tenant_id is intentionally omitted — it is sourced from the X-Tenant-Id header.
type CreateRequest struct {
	Name            string         `json:"name"`
	Scopes          []string       `json:"scopes"`
	Claims          map[string]any `json:"claims,omitempty"`
	TokenTTLSeconds *int           `json:"token_ttl_seconds,omitempty"`
}

// UpdateRequest is the JSON body for PATCH /v1/personas/{id}. Fields are pointers so
// callers can patch individual fields without clearing the rest.
type UpdateRequest struct {
	Name            *string        `json:"name,omitempty"`
	Scopes          *[]string      `json:"scopes,omitempty"`
	Claims          map[string]any `json:"claims,omitempty"`
	TokenTTLSeconds *int           `json:"token_ttl_seconds,omitempty"`
}

// ListResponse is the envelope returned by GET /v1/personas.
type ListResponse struct {
	Items []Persona `json:"items"`
}

// Defaults and validation bounds.
const (
	DefaultTokenTTLSeconds = 900
	MaxTokenTTLSeconds     = 86400
	MaxNameLen             = 100
)
