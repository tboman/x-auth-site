package internal

// Tests for the /internal/v1/ alias tree (ARCHITECTURE.md §10.3): the entire
// /v1 route set is also mounted under /internal/v1/ behind
// httpx.InternalAuth. With no INTERNAL_AUTH_SECRET configured (and no mTLS in
// httptest), the alias behaves identically to /v1 — local-dev mode. With the
// secret set, /internal/v1/* requires the X-Internal-Auth header while /v1/*
// stays open for phase-1 back-compat.
//
// Note: httpx.InternalAuth snapshots the secret when the router is built, so
// every test sets the env var (t.Setenv) *before* calling Router().

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// doJSONWithHeaders is doJSON plus arbitrary extra headers (X-Internal-Auth).
func doJSONWithHeaders(t *testing.T, h http.Handler, method, path, tenant string, headers map[string]string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tenant != "" {
		req.Header.Set("X-Tenant-Id", tenant)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func grantBody(installID, token string) map[string]any {
	return map[string]any{
		"install_id":        installID,
		"identity_id":       "identity-1",
		"persona_id":        "persona-1",
		"access_token_hash": HashToken(token),
	}
}

// Dev mode (no secret, no mTLS): /internal/v1/* must behave identically to
// /v1/* — same handlers, same store, same status codes. Exercises exactly the
// paths broker-service calls: POST /internal/v1/grants,
// POST /internal/v1/installs/{id}/revoke-grants, POST /internal/v1/revoke.
func TestInternalAliasDevModeMatchesV1(t *testing.T) {
	t.Setenv(httpx.EnvInternalAuthSecret, "")
	h := newServer(t).Router()

	// POST /internal/v1/grants works without any auth header.
	rec := doJSON(t, h, http.MethodPost, "/internal/v1/grants", testTenant, grantBody("install-1", "tok-internal"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("internal create: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var g Grant
	if err := json.Unmarshal(rec.Body.Bytes(), &g); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if g.Status != StatusActive || g.TenantID != testTenant {
		t.Fatalf("bad grant via alias: %+v", g)
	}

	// Reads cross over: a grant created via /internal/v1 is readable via /v1
	// and vice versa — one store behind one route tree.
	if rec = doJSON(t, h, http.MethodGet, "/v1/grants/"+g.ID, testTenant, nil); rec.Code != http.StatusOK {
		t.Fatalf("read internal-created via /v1: want 200, got %d", rec.Code)
	}
	if rec = doJSON(t, h, http.MethodGet, "/internal/v1/grants/"+g.ID, testTenant, nil); rec.Code != http.StatusOK {
		t.Fatalf("read via /internal/v1: want 200, got %d", rec.Code)
	}

	// POST /internal/v1/revoke (RFC 7009 by-token path used by broker /revoke).
	rec = doJSON(t, h, http.MethodPost, "/internal/v1/revoke", testTenant, map[string]any{"token": "tok-internal"})
	if rec.Code != http.StatusOK {
		t.Fatalf("internal revoke-by-token: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, http.MethodPost, "/v1/introspect", testTenant, map[string]any{"token": "tok-internal"})
	var intro IntrospectResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &intro)
	if intro.Active {
		t.Fatalf("token revoked via alias must be inactive on /v1: %+v", intro)
	}

	// POST /internal/v1/installs/{id}/revoke-grants (broker install cascade).
	rec = doJSON(t, h, http.MethodPost, "/internal/v1/grants", testTenant, grantBody("install-2", "tok-cascade"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed cascade grant: want 201, got %d", rec.Code)
	}
	rec = doJSON(t, h, http.MethodPost, "/internal/v1/installs/install-2/revoke-grants", testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("internal cascade: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var summary struct {
		Total   int `json:"total"`
		Revoked int `json:"revoked"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &summary)
	if summary.Total != 1 || summary.Revoked != 1 {
		t.Fatalf("cascade summary: want total=1 revoked=1, got %+v", summary)
	}

	// Tenant scoping is enforced identically on the alias.
	rec = doJSON(t, h, http.MethodPost, "/internal/v1/grants", "", grantBody("i", "t"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("internal without tenant: want 400, got %d", rec.Code)
	}
}

// With INTERNAL_AUTH_SECRET configured, /internal/v1/* demands the
// X-Internal-Auth header (structured 401 otherwise) while /v1/* stays open.
func TestInternalAliasSharedSecret(t *testing.T) {
	const secret = "test-internal-secret"
	t.Setenv(httpx.EnvInternalAuthSecret, secret)
	h := newServer(t).Router() // router built AFTER Setenv

	// No header → structured 401.
	rec := doJSON(t, h, http.MethodPost, "/internal/v1/grants", testTenant, grantBody("install-1", "tok-sec"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no header: want 401, got %d (%s)", rec.Code, rec.Body.String())
	}
	var errBody struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("401 body is not structured JSON: %v (%s)", err, rec.Body.String())
	}
	if errBody.Error != "internal_auth_required" {
		t.Fatalf("401 error code = %q, want internal_auth_required", errBody.Error)
	}
	if errBody.Message == "" {
		t.Fatal("401 body missing message")
	}

	// Wrong secret → 401.
	rec = doJSONWithHeaders(t, h, http.MethodPost, "/internal/v1/grants", testTenant,
		map[string]string{httpx.InternalAuthHeader: "wrong"}, grantBody("install-1", "tok-sec"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: want 401, got %d", rec.Code)
	}

	// Correct secret → success.
	rec = doJSONWithHeaders(t, h, http.MethodPost, "/internal/v1/grants", testTenant,
		map[string]string{httpx.InternalAuthHeader: secret}, grantBody("install-1", "tok-sec"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("correct secret: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}

	// The guard covers the whole /internal/v1 subtree, not just /grants.
	rec = doJSON(t, h, http.MethodGet, "/internal/v1/audit", testTenant, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("audit no header: want 401, got %d", rec.Code)
	}
	rec = doJSONWithHeaders(t, h, http.MethodGet, "/internal/v1/audit", testTenant,
		map[string]string{httpx.InternalAuthHeader: secret}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit with header: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, http.MethodPost, "/internal/v1/revoke", testTenant, map[string]any{"token": "tok-sec"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoke no header: want 401, got %d", rec.Code)
	}
	rec = doJSONWithHeaders(t, h, http.MethodPost, "/internal/v1/revoke", testTenant,
		map[string]string{httpx.InternalAuthHeader: secret}, map[string]any{"token": "tok-sec"})
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke with header: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	// /v1/* remains open (phase-1 back-compat): no auth header needed.
	rec = doJSON(t, h, http.MethodPost, "/v1/grants", testTenant, grantBody("install-open", "tok-open"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("/v1 with secret configured: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	// /healthz remains unauthenticated.
	if rec = doJSON(t, h, http.MethodGet, "/healthz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("healthz: want 200, got %d", rec.Code)
	}
}
