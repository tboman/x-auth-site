package internal

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// Tests for the /internal/v1/* alias (ARCHITECTURE.md §10.3): the entire /v1
// route tree mounted behind httpx.InternalAuth. The InternalAuth middleware
// reads INTERNAL_AUTH_SECRET at Router-construction time, so every test here
// pins the env with t.Setenv BEFORE calling newTestServer.

// TestInternalAliasChallengeParityDevMode drives the challenge lifecycle
// entirely through /internal/v1 with no secret configured (dev mode) and
// asserts behavior matches the /v1 contract: same status codes, same payload
// shapes, same underlying state (a challenge created internally is readable
// via the public prefix).
func TestInternalAliasChallengeParityDevMode(t *testing.T) {
	t.Setenv(httpx.EnvInternalAuthSecret, "") // force dev mode (open gate)
	srv, _, _ := newTestServer(t)

	enroll(t, srv, "u1", MethodTOTP)

	// POST /internal/v1/challenges — the transaction-service call shape.
	resp := do(t, srv, http.MethodPost, "/internal/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{MethodTOTP},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("internal create: want 201, got %d", resp.StatusCode)
	}
	var disp ChallengeDispatched
	decode(t, resp, &disp)
	if disp.Method != MethodTOTP {
		t.Fatalf("want method totp, got %q", disp.Method)
	}
	if disp.ChallengeID == "" {
		t.Fatal("want a challenge_id")
	}

	// POST /internal/v1/challenges/{id}/verify.
	vResp := do(t, srv, http.MethodPost, "/internal/v1/challenges/"+disp.ChallengeID+"/verify", VerifyRequest{
		Response: map[string]any{"code": "000000"},
	})
	if vResp.StatusCode != http.StatusOK {
		t.Fatalf("internal verify: want 200, got %d", vResp.StatusCode)
	}
	var vr VerifyResponse
	decode(t, vResp, &vr)
	if !vr.Verified {
		t.Fatal("want verified=true via internal alias")
	}

	// Same handlers, same store: the challenge created via /internal/v1 is
	// visible (completed) through the public /v1 prefix.
	gResp := do(t, srv, http.MethodGet, "/v1/challenges/"+disp.ChallengeID, nil)
	var c Challenge
	decode(t, gResp, &c)
	if c.Status != ChallengeStatusCompleted {
		t.Fatalf("want completed via /v1 read, got %q", c.Status)
	}
}

// TestInternalAliasSharedSecret pins the INTERNAL_AUTH_SECRET behavior:
// missing header → structured 401; correct header → 200; the public /v1
// prefix stays open (no internal-auth gate).
func TestInternalAliasSharedSecret(t *testing.T) {
	const secret = "test-internal-secret"
	t.Setenv(httpx.EnvInternalAuthSecret, secret)
	srv, _, _ := newTestServer(t)

	enroll(t, srv, "u1", MethodTOTP)

	// Missing X-Internal-Auth → structured 401.
	resp := do(t, srv, http.MethodGet, "/internal/v1/authenticators?user_id=u1", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 without internal auth, got %d", resp.StatusCode)
	}
	var errBody struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	decode(t, resp, &errBody)
	if errBody.Error != "internal_auth_required" {
		t.Fatalf("want error=internal_auth_required, got %q", errBody.Error)
	}
	if errBody.Message == "" {
		t.Fatal("want a human-readable message on the 401")
	}

	// Wrong secret → 401 too.
	wrong, err := http.NewRequest(http.MethodGet, srv.URL+"/internal/v1/authenticators?user_id=u1", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	wrong.Header.Set("X-Tenant-Id", testTenant)
	wrong.Header.Set(httpx.InternalAuthHeader, "not-the-secret")
	wResp, err := srv.Client().Do(wrong)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	wResp.Body.Close()
	if wResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 with wrong secret, got %d", wResp.StatusCode)
	}

	// Correct header → 200.
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/internal/v1/authenticators?user_id=u1", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Tenant-Id", testTenant)
	req.Header.Set(httpx.InternalAuthHeader, secret)
	okResp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer okResp.Body.Close()
	if okResp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 with correct secret, got %d", okResp.StatusCode)
	}

	// /v1 stays open: no X-Internal-Auth needed even with the secret set.
	open := do(t, srv, http.MethodGet, "/v1/authenticators?user_id=u1", nil)
	open.Body.Close()
	if open.StatusCode != http.StatusOK {
		t.Fatalf("/v1 must stay open, got %d", open.StatusCode)
	}
}

// TestV1InternalOnlyGate pins the V1_INTERNAL_ONLY=true deployment mode: the
// plain /v1 prefix carries the same InternalAuth gate as /internal/v1 (for
// public-ingress deployments with no VPC trust boundary), /healthz stays open
// for probes, and a correct X-Internal-Auth header restores full access.
func TestV1InternalOnlyGate(t *testing.T) {
	const secret = "test-internal-secret"
	t.Setenv(httpx.EnvInternalAuthSecret, secret)
	t.Setenv("V1_INTERNAL_ONLY", "true")
	srv, _, _ := newTestServer(t)

	// /healthz needs no auth — infra probes don't carry the secret.
	hResp, err := srv.Client().Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	hResp.Body.Close()
	if hResp.StatusCode != http.StatusOK {
		t.Fatalf("healthz must stay open, got %d", hResp.StatusCode)
	}

	// /v1 without the header → structured 401, before the tenant gate.
	resp := do(t, srv, http.MethodGet, "/v1/authenticators?user_id=u1", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 on /v1 without internal auth, got %d", resp.StatusCode)
	}
	var errBody struct {
		Error string `json:"error"`
	}
	decode(t, resp, &errBody)
	if errBody.Error != "internal_auth_required" {
		t.Fatalf("want error=internal_auth_required, got %q", errBody.Error)
	}

	// With the header, /v1 behaves exactly as in open mode.
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/authenticators?user_id=u1", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Tenant-Id", testTenant)
	req.Header.Set(httpx.InternalAuthHeader, secret)
	okResp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	okResp.Body.Close()
	if okResp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 on /v1 with correct secret, got %d", okResp.StatusCode)
	}
}

// TestInternalListAuthenticatorsClientContract exercises the exact request
// shape authentication-service's HTTPAuthenticatorClient.ListAuthenticators
// sends — GET /internal/v1/authenticators?user_id={id}&tenant_id={id} with
// X-Tenant-Id forwarded — and asserts the {"authenticators":[...]} envelope
// from ARCHITECTURE.md §4.4.
func TestInternalListAuthenticatorsClientContract(t *testing.T) {
	t.Setenv(httpx.EnvInternalAuthSecret, "") // dev mode; auth covered above
	srv, _, _ := newTestServer(t)

	enrolled := enroll(t, srv, "usr_abc123", MethodTOTP)

	url := srv.URL + "/internal/v1/authenticators?user_id=usr_abc123&tenant_id=" + testTenant
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// Mirror the client: Accept + forwarded X-Tenant-Id, no body.
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Tenant-Id", testTenant)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}

	// Decode as raw JSON first to pin the envelope KEY, not just the struct
	// round-trip — this is what would have caught the old {"items":[...]}
	// shape that authentication-service's client cannot read.
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	rawList, ok := raw["authenticators"]
	if !ok {
		t.Fatalf(`response missing "authenticators" key; got keys %v`, keysOf(raw))
	}
	var items []Authenticator
	if err := json.Unmarshal(rawList, &items); err != nil {
		t.Fatalf("decode authenticators array: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 authenticator, got %d", len(items))
	}
	if items[0].ID != enrolled.ID {
		t.Fatalf("want id %q, got %q", enrolled.ID, items[0].ID)
	}

	// A tenant_id query param that contradicts the header is rejected rather
	// than silently answered from the header's tenant.
	mreq, err := http.NewRequest(http.MethodGet,
		srv.URL+"/internal/v1/authenticators?user_id=usr_abc123&tenant_id=ten_other", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	mreq.Header.Set("X-Tenant-Id", testTenant)
	mResp, err := srv.Client().Do(mreq)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	mResp.Body.Close()
	if mResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 on tenant_id/header mismatch, got %d", mResp.StatusCode)
	}
}

// keysOf returns the keys of a decoded JSON object for failure messages.
func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
