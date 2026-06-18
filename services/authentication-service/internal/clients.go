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

// defaultClientTimeout is the per-request budget for outgoing calls to
// authenticator-service. Conservative for phase 1; a slow authenticator call
// should fail fast and let the caller retry.
const defaultClientTimeout = 5 * time.Second

// DownstreamError wraps failures from a sister service so handlers can tell
// "service unavailable" (502) apart from "service said no" (4xx propagated).
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

// AuthenticatorClient is the slim surface of authenticator-service that
// authentication-service calls. Phase 1 only needs two operations:
//
//   - ListAuthenticators so /authorize knows whether a user has any registered
//     credentials before redirecting them to a login screen (TODO(phase-2):
//     actually call this — today /authorize is auto-approve)
//   - VerifyFirstFactor is reserved for when we replace the auto-approve stub
//     with a real login form that POSTs {email, password} here and expects
//     authenticator-service to validate
//
// Defining the interface up front keeps cmd/main.go small and lets tests inject
// a mock.
type AuthenticatorClient interface {
	ListAuthenticators(ctx context.Context, tenantID, userID string) ([]Authenticator, error)
	VerifyFirstFactor(ctx context.Context, tenantID, userID, secret string) error

	// Challenge lifecycle for the /authorize second-factor interlude
	// (acr_values, e.g. SMS OTP). Thin wrappers over authenticator-service's
	// /internal/v1/challenges endpoints.
	EnrollAuthenticator(ctx context.Context, tenantID, userID, method string, metadata map[string]any) (Authenticator, error)
	CreateChallenge(ctx context.Context, tenantID, userID string, methods []string) (ChallengeInfo, error)
	VerifyChallenge(ctx context.Context, tenantID, challengeID string, response map[string]any) (VerifyOutcome, error)

	// WebAuthn (passkey) registration ceremony — drives the register-on-first-use
	// path for fido2 step-up. Begin returns the creation options for
	// navigator.credentials.create(); Finish validates the attestation and
	// persists the new credential, returning the enrolled authenticator.
	WebAuthnRegisterBegin(ctx context.Context, tenantID, userID, name, displayName string) (WebAuthnRegistration, error)
	WebAuthnRegisterFinish(ctx context.Context, tenantID, userID, registrationID string, attestation json.RawMessage) (Authenticator, error)
}

// Authenticator is the slimmed view of an authenticator-service row. Fields we
// don't need are ignored on decode.
type Authenticator struct {
	ID       string         `json:"id"`
	Method   string         `json:"method"` // fido2 | totp | push | sms | magic_link
	Status   string         `json:"status"` // active | disabled
	Verified bool           `json:"verified"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// ChallengeInfo is authenticator-service's dispatch response — what the
// /authorize interlude needs to render a verification prompt. Options carries
// the WebAuthn PublicKeyCredentialRequestOptions for fido2 (empty otherwise).
type ChallengeInfo struct {
	ChallengeID string          `json:"challenge_id"`
	Method      string          `json:"method"`
	Prompt      string          `json:"prompt"`
	ExpiresAt   time.Time       `json:"expires_at"`
	Options     json.RawMessage `json:"options,omitempty"`
}

// VerifyOutcome is the decoded verdict of a challenge verify call. A wrong
// code is an outcome (Verified=false), not an error — terminal/throttle
// states (410, 429) surface as a *DownstreamError instead so callers can
// distinguish "try again" from "start over". AMR carries the method-derived
// authentication-method references the verify actually achieved (e.g. WebAuthn
// with user verification → ["user","pin"]); empty → caller uses its default.
type VerifyOutcome struct {
	Verified bool     `json:"verified"`
	Reason   string   `json:"reason,omitempty"` // invalid_response | max_attempts_exceeded
	AMR      []string `json:"amr,omitempty"`
}

// WebAuthnRegistration is the begin-registration response: the ceremony id to
// echo on finish, plus the creation options for navigator.credentials.create().
type WebAuthnRegistration struct {
	RegistrationID string          `json:"registration_id"`
	Options        json.RawMessage `json:"options"`
}

// HTTPAuthenticatorClient is the production implementation — a thin HTTP wrapper
// around authenticator-service.
type HTTPAuthenticatorClient struct {
	HTTP    *http.Client
	BaseURL string
}

// NewHTTPAuthenticatorClient constructs a client with a shared http.Client and
// the configured defaultClientTimeout. The single http.Client is safe for
// concurrent use across all goroutines.
//
// Transport security (ARCHITECTURE.md §10.3): the client transport comes from
// tlsx.Transport — http.DefaultTransport in plaintext local dev, or a clone
// carrying the TLS_CA_FILE / TLS_CERT_FILE / TLS_KEY_FILE client configuration
// so calls to authenticator-service run over (m)TLS. A partial TLS
// configuration is an error; the caller must exit rather than silently fall
// back to plaintext.
func NewHTTPAuthenticatorClient(logger *slog.Logger, baseURL string) (*HTTPAuthenticatorClient, error) {
	transport, err := tlsx.Transport(logger)
	if err != nil {
		return nil, err
	}
	return &HTTPAuthenticatorClient{
		HTTP:    &http.Client{Timeout: defaultClientTimeout, Transport: transport},
		BaseURL: baseURL,
	}, nil
}

// do is the shared request helper. Marshals body (if any), sets Content-Type,
// forwards X-Tenant-Id, decodes JSON into out (if any), and returns a typed
// DownstreamError on non-2xx responses. The request is bound to ctx so a
// caller disconnect (or deadline) cancels the in-flight downstream call; the
// http.Client's 5s timeout still applies as an upper bound.
func (c *HTTPAuthenticatorClient) do(ctx context.Context, method, url, tenantID string, body, out any) error {
	var r *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return &DownstreamError{Service: "authenticator-service", Err: err}
		}
		r = bytes.NewReader(raw)
	}

	var req *http.Request
	var err error
	if r != nil {
		req, err = http.NewRequestWithContext(ctx, method, url, r)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	if err != nil {
		return &DownstreamError{Service: "authenticator-service", Err: err}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if tenantID != "" {
		req.Header.Set(tenantx.Header, tenantID)
	}
	// Service-to-service auth: outbound calls target authenticator-service's
	// /internal/v1 tree, which is guarded by httpx.InternalAuth. Under full
	// mTLS the header is redundant but harmless; with INTERNAL_AUTH_SECRET
	// unset this is a no-op (plaintext local dev).
	httpx.SetInternalAuth(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return &DownstreamError{Service: "authenticator-service", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return &DownstreamError{Service: "authenticator-service", Status: resp.StatusCode, Body: string(raw)}
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && !errors.Is(err, io.EOF) {
			return &DownstreamError{Service: "authenticator-service", Err: err}
		}
	}
	return nil
}

// ListAuthenticators calls GET /internal/v1/authenticators?user_id={id}&tenant_id={id}.
// The response shape is {"authenticators":[...]} per ARCHITECTURE.md §4.4.
func (c *HTTPAuthenticatorClient) ListAuthenticators(ctx context.Context, tenantID, userID string) ([]Authenticator, error) {
	url := fmt.Sprintf("%s/internal/v1/authenticators?user_id=%s&tenant_id=%s",
		c.BaseURL, userID, tenantID)
	var env struct {
		Authenticators []Authenticator `json:"authenticators"`
	}
	if err := c.do(ctx, http.MethodGet, url, tenantID, nil, &env); err != nil {
		return nil, err
	}
	return env.Authenticators, nil
}

// EnrollAuthenticator calls POST /internal/v1/authenticators — used by the
// OTP interlude to auto-enroll a stub SMS authenticator for users who have
// none (mock-stage convenience; real deployments enroll through a proper
// device-registration journey).
func (c *HTTPAuthenticatorClient) EnrollAuthenticator(ctx context.Context, tenantID, userID, method string, metadata map[string]any) (Authenticator, error) {
	var out Authenticator
	body := map[string]any{"user_id": userID, "method": method}
	if len(metadata) > 0 {
		body["metadata"] = metadata
	}
	if err := c.do(ctx, http.MethodPost, c.BaseURL+"/internal/v1/authenticators", tenantID, body, &out); err != nil {
		return Authenticator{}, err
	}
	return out, nil
}

// CreateChallenge calls POST /internal/v1/challenges — authenticator-service
// selects an enrolled authenticator for one of the requested methods and
// dispatches it (for SMS, the adapter "sends" the OTP).
func (c *HTTPAuthenticatorClient) CreateChallenge(ctx context.Context, tenantID, userID string, methods []string) (ChallengeInfo, error) {
	var out ChallengeInfo
	body := map[string]any{"user_id": userID, "methods": methods}
	if err := c.do(ctx, http.MethodPost, c.BaseURL+"/internal/v1/challenges", tenantID, body, &out); err != nil {
		return ChallengeInfo{}, err
	}
	return out, nil
}

// VerifyChallenge calls POST /internal/v1/challenges/{id}/verify. A 401 from
// authenticator-service means "wrong response" and is decoded into a
// VerifyOutcome rather than returned as an error; 410 (challenge terminal),
// 429 (backoff/lockout), and transport failures come back as errors.
func (c *HTTPAuthenticatorClient) VerifyChallenge(ctx context.Context, tenantID, challengeID string, response map[string]any) (VerifyOutcome, error) {
	var out VerifyOutcome
	url := fmt.Sprintf("%s/internal/v1/challenges/%s/verify", c.BaseURL, challengeID)
	err := c.do(ctx, http.MethodPost, url, tenantID, map[string]any{"response": response}, &out)
	if err != nil {
		var de *DownstreamError
		if errors.As(err, &de) && de.Status == http.StatusUnauthorized {
			// Wrong code: the verdict body rides on the 401.
			if jsonErr := json.Unmarshal([]byte(de.Body), &out); jsonErr == nil {
				return out, nil
			}
		}
		return VerifyOutcome{}, err
	}
	return out, nil
}

// WebAuthnRegisterBegin calls POST /internal/v1/authenticators/webauthn/register/begin.
func (c *HTTPAuthenticatorClient) WebAuthnRegisterBegin(ctx context.Context, tenantID, userID, name, displayName string) (WebAuthnRegistration, error) {
	var out WebAuthnRegistration
	body := map[string]any{"user_id": userID, "name": name, "display_name": displayName}
	url := c.BaseURL + "/internal/v1/authenticators/webauthn/register/begin"
	if err := c.do(ctx, http.MethodPost, url, tenantID, body, &out); err != nil {
		return WebAuthnRegistration{}, err
	}
	return out, nil
}

// WebAuthnRegisterFinish calls POST /internal/v1/authenticators/webauthn/register/finish.
func (c *HTTPAuthenticatorClient) WebAuthnRegisterFinish(ctx context.Context, tenantID, userID, registrationID string, attestation json.RawMessage) (Authenticator, error) {
	var out Authenticator
	body := map[string]any{"user_id": userID, "registration_id": registrationID, "attestation": attestation}
	url := c.BaseURL + "/internal/v1/authenticators/webauthn/register/finish"
	if err := c.do(ctx, http.MethodPost, url, tenantID, body, &out); err != nil {
		return Authenticator{}, err
	}
	return out, nil
}

// VerifyFirstFactor is a phase-1 placeholder. authenticator-service does NOT
// expose a "verify password" endpoint in ARCHITECTURE.md §4.4 — phase 1
// assumes first-factor auth happens in transaction-service, which is why
// POST /v1/sessions takes a pre-authenticated user id. This stub exists so
// cmd/main.go can wire a real client and tests can mock both methods with a
// single interface. TODO(phase-2): replace with the real contract once
// authenticator-service adds a password/verify endpoint.
func (c *HTTPAuthenticatorClient) VerifyFirstFactor(_ context.Context, _, _, _ string) error {
	return errors.New("VerifyFirstFactor not implemented in phase 1")
}
