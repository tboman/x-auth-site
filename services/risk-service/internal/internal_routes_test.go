package internal

// Tests for the /internal/v1/ alias tree (ARCHITECTURE.md §10.3): the entire
// /v1 route set is also mounted under /internal/v1/ behind
// httpx.InternalAuth. With no INTERNAL_AUTH_SECRET configured (and no mTLS in
// httptest), the alias behaves identically to /v1 — local-dev mode. With the
// secret set, /internal/v1/* requires the X-Internal-Auth header while /v1/*
// stays open for phase-1 back-compat.
//
// Note: httpx.InternalAuth snapshots the secret when the router is built, so
// every test sets the env var (t.Setenv) *before* calling newRouter.

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

func lowRiskEvalBody() map[string]any {
	return map[string]any{
		"user_id":              "usr_known",
		"action":               "read.profile",
		"resource_sensitivity": "low",
		"context": map[string]any{
			"device_fingerprint": "fp_known_laptop",
			"ip_address":         "10.0.0.5",
		},
	}
}

// Dev mode (no secret, no mTLS): /internal/v1/* must behave identically to
// /v1/* — same handlers, same status codes, same payload shape.
func TestInternalAliasDevModeMatchesV1(t *testing.T) {
	t.Setenv(httpx.EnvInternalAuthSecret, "")
	h, _ := newRouter(t, midDayClock())

	// POST /internal/v1/evaluations works without any auth header.
	rec := doJSON(t, h, http.MethodPost, "/internal/v1/evaluations", testTenant, lowRiskEvalBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("internal create: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var viaInternal RiskEvaluation
	if err := json.Unmarshal(rec.Body.Bytes(), &viaInternal); err != nil {
		t.Fatalf("decode internal: %v", err)
	}

	// Same request via /v1 yields an identical decision.
	rec = doJSON(t, h, http.MethodPost, "/v1/evaluations", testTenant, lowRiskEvalBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("v1 create: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var viaV1 RiskEvaluation
	if err := json.Unmarshal(rec.Body.Bytes(), &viaV1); err != nil {
		t.Fatalf("decode v1: %v", err)
	}
	if viaInternal.Tier != viaV1.Tier || viaInternal.PolicyDecision != viaV1.PolicyDecision {
		t.Fatalf("alias divergence: internal (tier=%s, decision=%s) vs v1 (tier=%s, decision=%s)",
			viaInternal.Tier, viaInternal.PolicyDecision, viaV1.Tier, viaV1.PolicyDecision)
	}

	// Reads cross over: an evaluation created via /internal/v1 is readable via
	// /v1 and vice versa — it is one store behind one route tree.
	rec = doJSON(t, h, http.MethodGet, "/v1/evaluations/"+viaInternal.ID, testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("read internal-created via /v1: want 200, got %d", rec.Code)
	}
	rec = doJSON(t, h, http.MethodGet, "/internal/v1/evaluations/"+viaV1.ID, testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("read v1-created via /internal/v1: want 200, got %d", rec.Code)
	}

	// Tenant scoping is enforced identically on the alias.
	rec = doJSON(t, h, http.MethodPost, "/internal/v1/evaluations", "", lowRiskEvalBody())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("internal without tenant: want 400, got %d", rec.Code)
	}
}

// Policy CRUD is aliased too — full lifecycle through /internal/v1/policies.
func TestInternalAliasPolicyCRUD(t *testing.T) {
	t.Setenv(httpx.EnvInternalAuthSecret, "")
	h, _ := newRouter(t, midDayClock())

	rec := doJSON(t, h, http.MethodPost, "/internal/v1/policies", testTenant, map[string]any{
		"name": "internal-alias-policy",
		"rules": []map[string]any{{
			"condition": map[string]any{"field": "action", "op": "contains", "value": "transfer."},
			"action":    map[string]any{"tier_floor": "high"},
		}},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var p Policy
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if rec = doJSON(t, h, http.MethodGet, "/internal/v1/policies", testTenant, nil); rec.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", rec.Code)
	}
	if rec = doJSON(t, h, http.MethodGet, "/internal/v1/policies/"+p.ID, testTenant, nil); rec.Code != http.StatusOK {
		t.Fatalf("get: want 200, got %d", rec.Code)
	}
	rec = doJSON(t, h, http.MethodPatch, "/internal/v1/policies/"+p.ID, testTenant, map[string]any{
		"name": "internal-alias-policy-renamed",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if rec = doJSON(t, h, http.MethodDelete, "/internal/v1/policies/"+p.ID, testTenant, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", rec.Code)
	}
}

// With V1_INTERNAL_ONLY=true (the deployed posture: public Cloud Run ingress,
// app-layer gating) the PLAIN /v1/* tree also demands the X-Internal-Auth
// header — otherwise the evaluate/policy write API would be open to the
// internet. /healthz stays unauthenticated.
func TestV1InternalOnlyGate(t *testing.T) {
	const secret = "test-internal-secret"
	t.Setenv(httpx.EnvInternalAuthSecret, secret)
	t.Setenv("V1_INTERNAL_ONLY", "true")
	h, _ := newRouter(t, midDayClock()) // router built AFTER Setenv

	// /v1/* now requires the header.
	rec := doJSON(t, h, http.MethodPost, "/v1/evaluations", testTenant, lowRiskEvalBody())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/v1 no header with gate on: want 401, got %d (%s)", rec.Code, rec.Body.String())
	}
	rec = doJSONWithHeaders(t, h, http.MethodPost, "/v1/evaluations", testTenant,
		map[string]string{httpx.InternalAuthHeader: secret}, lowRiskEvalBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("/v1 with header: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	// /internal/v1/* stays gated as before.
	if rec = doJSON(t, h, http.MethodGet, "/internal/v1/policies", testTenant, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("/internal/v1 no header: want 401, got %d", rec.Code)
	}
	// /healthz is never gated.
	if rec = doJSON(t, h, http.MethodGet, "/healthz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("healthz: want 200, got %d", rec.Code)
	}
}

// With INTERNAL_AUTH_SECRET configured, /internal/v1/* demands the
// X-Internal-Auth header (structured 401 otherwise) while /v1/* stays open.
func TestInternalAliasSharedSecret(t *testing.T) {
	const secret = "test-internal-secret"
	t.Setenv(httpx.EnvInternalAuthSecret, secret)
	h, _ := newRouter(t, midDayClock()) // router built AFTER Setenv

	// No header → structured 401.
	rec := doJSON(t, h, http.MethodPost, "/internal/v1/evaluations", testTenant, lowRiskEvalBody())
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
	rec = doJSONWithHeaders(t, h, http.MethodPost, "/internal/v1/evaluations", testTenant,
		map[string]string{httpx.InternalAuthHeader: "wrong"}, lowRiskEvalBody())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: want 401, got %d", rec.Code)
	}

	// Correct secret → success.
	rec = doJSONWithHeaders(t, h, http.MethodPost, "/internal/v1/evaluations", testTenant,
		map[string]string{httpx.InternalAuthHeader: secret}, lowRiskEvalBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("correct secret: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}

	// The guard covers the whole /internal/v1 subtree, not just evaluations.
	rec = doJSON(t, h, http.MethodGet, "/internal/v1/policies", testTenant, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("policies no header: want 401, got %d", rec.Code)
	}
	rec = doJSONWithHeaders(t, h, http.MethodGet, "/internal/v1/policies", testTenant,
		map[string]string{httpx.InternalAuthHeader: secret}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("policies with header: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	// /v1/* remains open (phase-1 back-compat): no auth header needed.
	rec = doJSON(t, h, http.MethodPost, "/v1/evaluations", testTenant, lowRiskEvalBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("/v1 with secret configured: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	// /healthz remains unauthenticated.
	if rec = doJSON(t, h, http.MethodGet, "/healthz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("healthz: want 200, got %d", rec.Code)
	}
}
