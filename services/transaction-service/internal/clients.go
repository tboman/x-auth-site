package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
	"github.com/xentranet/x-auth/pkg/tlsx"
)

// defaultClientTimeout is the per-request timeout for all inter-service HTTP calls.
// 5s is conservative for phase 1; slower downstreams surface as 502 to the caller.
const defaultClientTimeout = 5 * time.Second

// DownstreamError wraps failures from a sister service so handlers can uniformly
// translate them to a 502 + structured body.
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

// -----------------------------------------------------------------------------
// Client interfaces (so tests can substitute in-process fakes)
// -----------------------------------------------------------------------------

// RiskEvaluationResult is the slimmed view of a risk-service evaluation. Only the
// fields transaction-service needs are decoded; extra fields are ignored.
//
// Note: risk-service does not return a single `policy_id` — its policy engine
// reports every matching policy as `matched_policies` (ordered by policy
// CreatedAt). transaction-service records the first match as the transaction's
// primary policy id and surfaces the full list on /v1/authorize.
type RiskEvaluationResult struct {
	ID                 string             `json:"id"`
	Tier               string             `json:"tier"`
	Score              float64            `json:"score"`
	Scores             map[string]float64 `json:"scores"`
	Flags              []string           `json:"flags"`
	MatchedPolicies    []string           `json:"matched_policies"`
	SensitivityApplied bool               `json:"sensitivity_applied"`
}

// RiskClient is the subset of risk-service that transaction-service uses.
// Every method takes the request context so a caller disconnect cancels the
// in-flight downstream call instead of letting it run to the client timeout.
type RiskClient interface {
	Evaluate(ctx context.Context, tenantID string, req RiskEvaluateRequest) (RiskEvaluationResult, error)
}

// RiskEvaluateRequest is the body transaction-service sends to risk-service.
// Matches ARCHITECTURE.md §4.2 POST /v1/evaluations.
type RiskEvaluateRequest struct {
	TenantID            string         `json:"tenant_id"`
	UserID              string         `json:"user_id"`
	SessionID           string         `json:"session_id,omitempty"`
	Action              string         `json:"action"`
	Resource            string         `json:"resource,omitempty"`
	ResourceSensitivity string         `json:"resource_sensitivity,omitempty"`
	Signals             map[string]any `json:"signals,omitempty"`
}

// Challenge is the slimmed view of an authenticator-service challenge returned to
// transaction-service. The challenge_data blob per method is opaque at this layer —
// transaction-service forwards it verbatim to clients.
type Challenge struct {
	ID               string            `json:"id"`
	MethodsAvailable []ChallengeMethod `json:"methods_available"`
	ExpiresAt        time.Time         `json:"expires_at"`
}

// ChallengeMethod is one entry in methods_available.
type ChallengeMethod struct {
	Method          string         `json:"method"`
	AuthenticatorID string         `json:"authenticator_id,omitempty"`
	ChallengeData   map[string]any `json:"challenge_data,omitempty"`
	Status          string         `json:"status,omitempty"`
}

// ChallengeVerifyResult is what authenticator-service returns after /challenges/{id}/verify.
type ChallengeVerifyResult struct {
	ChallengeID       string    `json:"challenge_id"`
	Verified          bool      `json:"verified"`
	Method            string    `json:"method,omitempty"`
	AuthenticatorID   string    `json:"authenticator_id,omitempty"`
	Reason            string    `json:"reason,omitempty"`
	AttemptsRemaining *int      `json:"attempts_remaining,omitempty"`
	VerifiedAt        time.Time `json:"verified_at,omitempty"`
}

// AuthenticatorClient is the subset of authenticator-service that transaction-service uses.
type AuthenticatorClient interface {
	CreateChallenge(ctx context.Context, tenantID string, req ChallengeCreateRequest) (Challenge, error)
	VerifyChallenge(ctx context.Context, tenantID, challengeID, method string, response map[string]any) (ChallengeVerifyResult, error)
}

// ChallengeCreateRequest is the body transaction-service sends to authenticator-service.
type ChallengeCreateRequest struct {
	TenantID string         `json:"tenant_id"`
	UserID   string         `json:"user_id"`
	Methods  []string       `json:"methods"`
	Context  map[string]any `json:"context,omitempty"`
}

// Session is the slimmed view of an authentication-service session.
type Session struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id,omitempty"`
	RiskLevel       string    `json:"risk_level"`
	StepUpCompleted bool      `json:"step_up_completed,omitempty"`
	ExpiresAt       time.Time `json:"expires_at"`
	UpdatedAt       time.Time `json:"updated_at,omitempty"`
}

// AuthenticationClient is the subset of authentication-service that transaction-service uses.
type AuthenticationClient interface {
	GetSession(ctx context.Context, tenantID, sessionID string) (Session, error)
	UpdateSession(ctx context.Context, tenantID, sessionID string, req SessionUpdateRequest) (Session, error)
}

// SessionUpdateRequest matches ARCHITECTURE.md §4.3 POST /v1/sessions/{id}/upgrade.
type SessionUpdateRequest struct {
	RiskLevel       string `json:"risk_level,omitempty"`
	StepUpCompleted bool   `json:"step_up_completed,omitempty"`
}

// -----------------------------------------------------------------------------
// HTTP implementation
// -----------------------------------------------------------------------------

// HTTPClients wires concrete HTTP clients for each sister service.
type HTTPClients struct {
	HTTP              *http.Client
	RiskURL           string
	AuthenticationURL string
	AuthenticatorURL  string
}

// NewHTTPClients constructs the inter-service clients with a shared http.Client using
// defaultClientTimeout. A single http.Client is safe for concurrent use.
//
// Transport security (ARCHITECTURE.md §10.3): the client transport comes from
// tlsx.Transport — http.DefaultTransport in plaintext local dev, or a clone
// carrying the TLS_CA_FILE / TLS_CERT_FILE / TLS_KEY_FILE client configuration
// so calls to sister services run over (m)TLS. A partial TLS configuration is
// an error; callers must exit rather than silently fall back to plaintext.
func NewHTTPClients(logger *slog.Logger, riskURL, authenticationURL, authenticatorURL string) (*HTTPClients, error) {
	transport, err := tlsx.Transport(logger)
	if err != nil {
		return nil, err
	}
	return &HTTPClients{
		HTTP:              &http.Client{Timeout: defaultClientTimeout, Transport: transport},
		RiskURL:           riskURL,
		AuthenticationURL: authenticationURL,
		AuthenticatorURL:  authenticatorURL,
	}, nil
}

// do is the shared request helper: marshals body (if any), sets headers, forwards the
// tenant id, decodes the response JSON (if out != nil), and returns a typed
// DownstreamError on non-2xx responses so handlers can uniformly translate to 502.
// The request is bound to ctx so a caller disconnect (or deadline) cancels the
// downstream call immediately; the http.Client timeout remains the upper bound.
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
	// Service-to-service auth: every outbound call targets the callee's
	// /internal/v1 tree, which is guarded by httpx.InternalAuth. Under full mTLS
	// the header is redundant but harmless; with INTERNAL_AUTH_SECRET unset this
	// is a no-op (plaintext local dev).
	httpx.SetInternalAuth(req)

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

// Evaluate calls POST {RISK_SERVICE_URL}/internal/v1/evaluations.
func (c *HTTPClients) Evaluate(ctx context.Context, tenantID string, req RiskEvaluateRequest) (RiskEvaluationResult, error) {
	var out RiskEvaluationResult
	url := c.RiskURL + "/internal/v1/evaluations"
	if err := c.do(ctx, "risk-service", http.MethodPost, url, tenantID, req, &out); err != nil {
		return RiskEvaluationResult{}, err
	}
	return out, nil
}

// CreateChallenge calls POST {AUTHENTICATOR_SERVICE_URL}/internal/v1/challenges.
func (c *HTTPClients) CreateChallenge(ctx context.Context, tenantID string, req ChallengeCreateRequest) (Challenge, error) {
	var out Challenge
	url := c.AuthenticatorURL + "/internal/v1/challenges"
	if err := c.do(ctx, "authenticator-service", http.MethodPost, url, tenantID, req, &out); err != nil {
		return Challenge{}, err
	}
	return out, nil
}

// VerifyChallenge calls POST {AUTHENTICATOR_SERVICE_URL}/internal/v1/challenges/{id}/verify.
func (c *HTTPClients) VerifyChallenge(ctx context.Context, tenantID, challengeID, method string, response map[string]any) (ChallengeVerifyResult, error) {
	var out ChallengeVerifyResult
	url := fmt.Sprintf("%s/internal/v1/challenges/%s/verify", c.AuthenticatorURL, challengeID)
	body := map[string]any{"method": method, "response": response}
	if err := c.do(ctx, "authenticator-service", http.MethodPost, url, tenantID, body, &out); err != nil {
		return ChallengeVerifyResult{}, err
	}
	return out, nil
}

// GetSession calls GET {AUTHENTICATION_SERVICE_URL}/internal/v1/sessions/{id}.
func (c *HTTPClients) GetSession(ctx context.Context, tenantID, sessionID string) (Session, error) {
	var out Session
	url := fmt.Sprintf("%s/internal/v1/sessions/%s", c.AuthenticationURL, sessionID)
	if err := c.do(ctx, "authentication-service", http.MethodGet, url, tenantID, nil, &out); err != nil {
		return Session{}, err
	}
	return out, nil
}

// UpdateSession calls POST {AUTHENTICATION_SERVICE_URL}/internal/v1/sessions/{id}/upgrade.
// authentication-service's upgrade endpoint accepts {risk_level, step_up_completed}.
func (c *HTTPClients) UpdateSession(ctx context.Context, tenantID, sessionID string, req SessionUpdateRequest) (Session, error) {
	var out Session
	url := fmt.Sprintf("%s/internal/v1/sessions/%s/upgrade", c.AuthenticationURL, sessionID)
	if err := c.do(ctx, "authentication-service", http.MethodPost, url, tenantID, req, &out); err != nil {
		return Session{}, err
	}
	return out, nil
}
