package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/xentranet/x-auth/pkg/tenantx"
)

// defaultClientTimeout is the per-request timeout for all inter-service HTTP calls.
// Chosen conservatively for phase 1 — if a downstream service takes longer than 5s
// to respond the broker returns 502 and the caller retries.
const defaultClientTimeout = 5 * time.Second

// DownstreamError wraps failures from a sister service so handlers can log context
// and decide how to respond to the end user.
type DownstreamError struct {
	Service string
	Status  int
	Body    string
	Err     error
}

func (e *DownstreamError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Service, e.Err)
	}
	return fmt.Sprintf("%s: %d %s", e.Service, e.Status, e.Body)
}

func (e *DownstreamError) Unwrap() error { return e.Err }

// downstreamLogAttrs builds slog key/value pairs for logging a failed downstream
// call: always "err", plus "service" and "status" when err wraps a DownstreamError,
// followed by any handler-supplied request-scoped attrs. Keeping this in one place
// guarantees every 502 translation logs the same detail set.
func downstreamLogAttrs(err error, extra ...any) []any {
	attrs := []any{"err", err}
	var dse *DownstreamError
	if errors.As(err, &dse) {
		attrs = append(attrs, "service", dse.Service, "status", dse.Status)
	}
	return append(attrs, extra...)
}

// PersonaClient is the subset of persona-service that broker-service uses.
// All methods take a context so callers can propagate request cancellation and
// deadlines to the downstream HTTP call.
type PersonaClient interface {
	GetPersona(ctx context.Context, tenantID, personaID string) (Persona, error)
}

// PoolClient is the subset of pool-service that broker-service uses.
type PoolClient interface {
	ClaimIdentity(ctx context.Context, tenantID, poolID, personaID, installID string) (Identity, error)
	ReleaseIdentity(ctx context.Context, tenantID, identityID string) error
}

// GrantClient is the subset of grant-service that broker-service uses.
type GrantClient interface {
	CreateGrant(ctx context.Context, tenantID string, req GrantCreateRequest) (Grant, error)
	RevokeGrantsForInstall(ctx context.Context, tenantID, installID string) error
	RevokeToken(ctx context.Context, tenantID, token string) error
}

// Persona is the slimmed view of a persona returned by persona-service. Only the
// fields broker-service needs are decoded; other fields are ignored.
type Persona struct {
	ID       string   `json:"id"`
	TenantID string   `json:"tenant_id"`
	Name     string   `json:"name"`
	Scopes   []string `json:"scopes"`
	TokenTTL int      `json:"token_ttl_seconds"`
	PoolID   string   `json:"pool_id,omitempty"` // may be populated by persona-service once it tracks pool links; phase 1 callers can't rely on this.
}

// Identity is the slimmed view of a pool identity returned by pool-service.
type Identity struct {
	ID        string `json:"id"`
	PoolID    string `json:"pool_id"`
	SubjectID string `json:"subject_id"`
	Status    string `json:"status"`
}

// GrantCreateRequest is the body broker-service sends to grant-service to record a grant.
// Matches REQUIREMENTS.md §4 grant-service POST /v1/grants.
type GrantCreateRequest struct {
	InstallID        string `json:"install_id"`
	IdentityID       string `json:"identity_id"`
	PersonaID        string `json:"persona_id"`
	AccessTokenHash  string `json:"access_token_hash"`
	RefreshTokenHash string `json:"refresh_token_hash"`
	TTLSeconds       int    `json:"ttl_seconds"`
}

// Grant is the slimmed view returned by grant-service.
type Grant struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	InstallID string `json:"install_id"`
}

// HTTPClients wires concrete HTTP clients for each sister service.
type HTTPClients struct {
	HTTP       *http.Client
	PersonaURL string
	PoolURL    string
	GrantURL   string
}

// NewHTTPClients constructs the inter-service clients with a shared http.Client
// using defaultClientTimeout. A single http.Client is safe for concurrent use.
func NewHTTPClients(personaURL, poolURL, grantURL string) *HTTPClients {
	return &HTTPClients{
		HTTP:       &http.Client{Timeout: defaultClientTimeout},
		PersonaURL: personaURL,
		PoolURL:    poolURL,
		GrantURL:   grantURL,
	}
}

// do is the shared request helper: marshals body (if any), sets headers, forwards
// the tenant id, decodes the response JSON (if out != nil), and returns a typed
// DownstreamError on non-2xx responses so handlers can uniformly translate to 502.
// The supplied context bounds the request, so a cancelled caller aborts the
// downstream call (compensation paths deliberately pass a non-cancellable context).
func (c *HTTPClients) do(ctx context.Context, service, method, url, tenantID string, body, out any) error {
	var bodyReader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return &DownstreamError{Service: service, Err: err}
		}
		bodyReader = bytes.NewReader(raw)
	}

	var req *http.Request
	var err error
	if bodyReader != nil {
		req, err = http.NewRequestWithContext(ctx, method, url, bodyReader)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	if err != nil {
		return &DownstreamError{Service: service, Err: err}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if tenantID != "" {
		req.Header.Set(tenantx.Header, tenantID)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return &DownstreamError{Service: service, Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return &DownstreamError{Service: service, Status: resp.StatusCode, Body: string(raw)}
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && !errors.Is(err, io.EOF) {
			return &DownstreamError{Service: service, Err: err}
		}
	}
	return nil
}

// GetPersona calls GET {PERSONA_SERVICE_URL}/v1/personas/{id}.
// The REQUIREMENTS doc says "POST /v1/personas/{id}" for fetch in the broker orchestration
// section, but REQUIREMENTS.md §4 defines this endpoint as a GET. The GET is semantically
// correct and matches what persona-service actually implements.
func (c *HTTPClients) GetPersona(ctx context.Context, tenantID, personaID string) (Persona, error) {
	var p Persona
	url := fmt.Sprintf("%s/v1/personas/%s", c.PersonaURL, personaID)
	if err := c.do(ctx, "persona-service", http.MethodGet, url, tenantID, nil, &p); err != nil {
		return Persona{}, err
	}
	return p, nil
}

// claimRequest is the body for pool-service POST /v1/pools/{id}/claim.
type claimRequest struct {
	PersonaID string `json:"persona_id"`
	InstallID string `json:"install_id"`
}

// ClaimIdentity calls POST {POOL_SERVICE_URL}/v1/pools/{pool_id}/claim.
// pool-service returns the claimed Identity on success.
func (c *HTTPClients) ClaimIdentity(ctx context.Context, tenantID, poolID, personaID, installID string) (Identity, error) {
	var id Identity
	url := fmt.Sprintf("%s/v1/pools/%s/claim", c.PoolURL, poolID)
	body := claimRequest{PersonaID: personaID, InstallID: installID}
	if err := c.do(ctx, "pool-service", http.MethodPost, url, tenantID, body, &id); err != nil {
		return Identity{}, err
	}
	return id, nil
}

// ReleaseIdentity calls POST {POOL_SERVICE_URL}/v1/identities/{id}/release.
// Used by revoke and by compensation when a downstream call fails mid-orchestration.
func (c *HTTPClients) ReleaseIdentity(ctx context.Context, tenantID, identityID string) error {
	url := fmt.Sprintf("%s/v1/identities/%s/release", c.PoolURL, identityID)
	return c.do(ctx, "pool-service", http.MethodPost, url, tenantID, nil, nil)
}

// CreateGrant calls POST {GRANT_SERVICE_URL}/v1/grants.
func (c *HTTPClients) CreateGrant(ctx context.Context, tenantID string, req GrantCreateRequest) (Grant, error) {
	var g Grant
	url := fmt.Sprintf("%s/v1/grants", c.GrantURL)
	if err := c.do(ctx, "grant-service", http.MethodPost, url, tenantID, req, &g); err != nil {
		return Grant{}, err
	}
	return g, nil
}

// RevokeGrantsForInstall asks grant-service to revoke every grant bound to installID.
// grant-service exposes POST /v1/grants/{id}/revoke per REQUIREMENTS.md §4 but does not
// list a bulk-by-install endpoint; phase 1 sends a POST to a convention path
// /v1/installs/{install_id}/revoke-grants. grant-service is being implemented in
// parallel — the agreed contract is documented here so grant-service can match it.
func (c *HTTPClients) RevokeGrantsForInstall(ctx context.Context, tenantID, installID string) error {
	url := fmt.Sprintf("%s/v1/installs/%s/revoke-grants", c.GrantURL, installID)
	return c.do(ctx, "grant-service", http.MethodPost, url, tenantID, nil, nil)
}

// RevokeToken forwards a RFC 7009 revocation to grant-service. grant-service is
// responsible for flipping the grant row; broker-service keeps its local token
// cache in sync.
func (c *HTTPClients) RevokeToken(ctx context.Context, tenantID, token string) error {
	url := fmt.Sprintf("%s/v1/revoke", c.GrantURL)
	body := map[string]string{"token": token}
	return c.do(ctx, "grant-service", http.MethodPost, url, tenantID, body, nil)
}
