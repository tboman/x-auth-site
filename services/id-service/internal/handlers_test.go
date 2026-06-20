package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/tenantx"
)

func newTestServer(t *testing.T, mgr *Manager) http.Handler {
	t.Helper()
	console, err := NewConsole(mgr, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	return NewHandlers(mgr, console, testLogger()).Router(nil)
}

func TestHealthAndJWKS(t *testing.T) {
	mgr := NewManager(NewMemStorage(), mustInsecureTrust(t), testSigner(t), nil, "https://id.test", time.Minute, testLogger())
	srv := newTestServer(t, mgr)

	for _, path := range []string{"/healthz", "/v1/jwks", "/.well-known/jwks.json"} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200", path, rec.Code)
		}
	}
}

func TestCreateRequiresTenant(t *testing.T) {
	mgr := NewManager(NewMemStorage(), mustInsecureTrust(t), testSigner(t), nil, "https://id.test", time.Minute, testLogger())
	srv := newTestServer(t, mgr)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/verifications", strings.NewReader(`{}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing-tenant create = %d, want 400", rec.Code)
	}
}

func TestCreateAndGet(t *testing.T) {
	mgr := NewManager(NewMemStorage(), mustInsecureTrust(t), testSigner(t), nil, "https://id.test", time.Minute, testLogger())
	srv := newTestServer(t, mgr)

	req := httptest.NewRequest(http.MethodPost, "/v1/verifications", strings.NewReader(`{"purpose":"wire","claims":["given_name"]}`))
	req.Header.Set(tenantx.Header, "ten_demo")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}
	var cr CreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &cr); err != nil {
		t.Fatal(err)
	}
	if cr.ID == "" || !strings.Contains(cr.VerifyURL, "/v/") {
		t.Fatalf("unexpected create response: %+v", cr)
	}

	// Agent GET, tenant-scoped.
	greq := httptest.NewRequest(http.MethodGet, "/v1/verifications/"+cr.ID, nil)
	greq.Header.Set(tenantx.Header, "ten_demo")
	grec := httptest.NewRecorder()
	srv.ServeHTTP(grec, greq)
	if grec.Code != http.StatusOK {
		t.Fatalf("get = %d, want 200", grec.Code)
	}

	// Wrong tenant → 404.
	wreq := httptest.NewRequest(http.MethodGet, "/v1/verifications/"+cr.ID, nil)
	wreq.Header.Set(tenantx.Header, "ten_other")
	wrec := httptest.NewRecorder()
	srv.ServeHTTP(wrec, wreq)
	if wrec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get = %d, want 404", wrec.Code)
	}
}

func TestResponseEndpointVerifies(t *testing.T) {
	fx := buildFixture(t, defaultClaims())
	mgr := managerWithFixture(t, fx, testSigner(t))
	srv := newTestServer(t, mgr)
	ctx := context.Background()

	v, err := mgr.CreateVerification(ctx, "ten_demo", VerifyRequestSpec{})
	if err != nil {
		t.Fatal(err)
	}
	v.ClientID = fx.clientID
	v.ResponseURI = fx.responseURI
	v.Nonce = fx.nonce
	if err := mgr.store.Update(ctx, v); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]any{
		"vp_token":             toBase64URL(fx.response),
		"mdoc_generated_nonce": fx.mdocNonce,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/verifications/"+v.ID+"/response", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("response = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["status"] != StatusVerified {
		t.Fatalf("status = %v, want verified", out["status"])
	}
}

func TestVerifyPageRenders(t *testing.T) {
	fx := buildFixture(t, defaultClaims())
	mgr := managerWithFixture(t, fx, testSigner(t))
	srv := newTestServer(t, mgr)
	v, err := mgr.CreateVerification(context.Background(), "ten_demo", VerifyRequestSpec{Purpose: "Authorize transfer"})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v/"+v.Token, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("verify page = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Verify with Wallet") {
		t.Error("verify page missing call to action")
	}
}
