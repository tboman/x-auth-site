package internal

// id_client.go is the slim client authn uses to drive an id-service mDL
// verification on the user's behalf during self-enrollment: it creates a
// verification (server-side, so the binding to the logged-in user is controlled,
// never client-supplied) and polls it until the wallet responds.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/xentranet/x-auth/pkg/tenantx"
)

// id-service verification status wire values (its API contract).
const (
	idStatusVerified = "verified"
	idStatusFailed   = "failed"
	idStatusExpired  = "expired"
)

// IDVerificationClient is the surface of id-service authn depends on for
// self-enrollment.
type IDVerificationClient interface {
	// Create starts a verification for a tenant and returns its id + the verify
	// URL (the consumer page the wallet opens).
	Create(ctx context.Context, tenantID, purpose string, claims []string, channel string) (id, verifyURL string, err error)
	// Get returns the verification's status and, once verified, the proof token.
	Get(ctx context.Context, tenantID, id string) (status, proofToken string, err error)
}

// HTTPIDClient calls id-service's tenant-scoped /v1/verifications API.
type HTTPIDClient struct {
	BaseURL string
	HTTP    *http.Client
}

// NewHTTPIDClient builds a client for id-service's base (ID_ISSUER). Empty base →
// nil (self-enrollment disabled).
func NewHTTPIDClient(baseURL string) IDVerificationClient {
	if baseURL == "" {
		return nil
	}
	return &HTTPIDClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: defaultClientTimeout},
	}
}

func (c *HTTPIDClient) Create(ctx context.Context, tenantID, purpose string, claims []string, channel string) (string, string, error) {
	reqBody, _ := json.Marshal(map[string]any{
		"purpose": purpose,
		"claims":  claims,
		"channel": channel,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/verifications", bytes.NewReader(reqBody))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(tenantx.Header, tenantID)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", "", &DownstreamError{Service: "id-service", Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
		return "", "", &DownstreamError{Service: "id-service", Status: resp.StatusCode, Body: string(b)}
	}
	var out struct {
		ID        string `json:"id"`
		VerifyURL string `json:"verifyUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", &DownstreamError{Service: "id-service", Err: err}
	}
	if out.ID == "" || out.VerifyURL == "" {
		return "", "", fmt.Errorf("id-service: empty verification response")
	}
	return out.ID, out.VerifyURL, nil
}

func (c *HTTPIDClient) Get(ctx context.Context, tenantID, id string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/verifications/"+id, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set(tenantx.Header, tenantID)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", "", &DownstreamError{Service: "id-service", Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
		return "", "", &DownstreamError{Service: "id-service", Status: resp.StatusCode, Body: string(b)}
	}
	var out struct {
		Status string `json:"status"`
		Result *struct {
			ProofToken string `json:"proofToken"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", &DownstreamError{Service: "id-service", Err: err}
	}
	proof := ""
	if out.Result != nil {
		proof = out.Result.ProofToken
	}
	return out.Status, proof, nil
}
