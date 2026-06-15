package internal

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestLoginChooserRendersMethods pins the hosted /login chooser: a working
// "Continue with Google" link that forwards to the social leg with the caller's
// params. Phone is hidden until the tenant opts in. The workspace name is shown
// when the tenant is registered.
func TestLoginChooserRendersMethods(t *testing.T) {
	r, store := newAdminRouter(t)
	if _, err := store.CreateTenant(Tenant{
		ID: "ten_acme", CompanyName: "Acme Inc", Slug: "acme", OwnerEmail: "o@acme.test", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	// The redirect must be registered for the tenant (open-redirect hardening).
	if err := store.PutClient(OIDCClient{
		ClientID: "cli_acme", TenantID: "ten_acme",
		RedirectURIs: []string{"https://app.acme.com/callback.html"}, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed client: %v", err)
	}

	q := url.Values{
		"tenant_id":    {"ten_acme"},
		"redirect_uri": {"https://app.acme.com/callback.html"},
		"state":        {"st-123"},
	}
	req := httptest.NewRequest(http.MethodGet, "/login?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /login: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()

	// Registered workspace name in the heading.
	if !strings.Contains(body, "Sign in to Acme Inc") {
		t.Errorf("chooser missing workspace name:\n%s", body)
	}
	// Google button forwards to the social leg with the passed-through params.
	for _, want := range []string{
		"/v1/social/google/authorize?",
		"tenant_id=ten_acme",
		url.QueryEscape("https://app.acme.com/callback.html"),
		"state=st-123",
		"Continue with Google",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("chooser missing %q:\n%s", want, body)
		}
	}
	// Phone is per-tenant opt-in (migration 000016) and this tenant has NOT opted
	// in → it must not appear on the chooser.
	if strings.Contains(body, "/login/phone?") || strings.Contains(body, "Continue with phone") {
		t.Errorf("chooser must hide phone sign-in until the tenant opts in:\n%s", body)
	}

	// Opt the tenant in → phone now appears, carrying the same params through.
	if err := store.SetTenantPhoneLogin("ten_acme", true); err != nil {
		t.Fatalf("enable phone: %v", err)
	}
	req2 := httptest.NewRequest(http.MethodGet, "/login?"+q.Encode(), nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	body2 := w2.Body.String()
	if !strings.Contains(body2, "/login/phone?") || !strings.Contains(body2, "Continue with phone") {
		t.Errorf("opted-in chooser must offer phone sign-in:\n%s", body2)
	}
}

// TestLoginChooserValidatesParams rejects missing/invalid required params.
func TestLoginChooserValidatesParams(t *testing.T) {
	r, _ := newAdminRouter(t)
	cases := map[string]string{
		"missing tenant_id":    "/login?redirect_uri=https://app/cb",
		"missing redirect_uri": "/login?tenant_id=ten_acme",
		"relative redirect":    "/login?tenant_id=ten_acme&redirect_uri=/cb",
	}
	for name, target := range cases {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, w.Code)
		}
	}
}

// TestLoginChooserNoRegistryRow falls back to the generic heading when the
// tenant has no registry row, yet still renders the Google link (its redirect
// is registered via a tenant-bound client).
func TestLoginChooserNoRegistryRow(t *testing.T) {
	r, store := newAdminRouter(t)
	if err := store.PutClient(OIDCClient{
		ClientID: "cli_derived", TenantID: "ten_derived",
		RedirectURIs: []string{"https://x.test/cb"}, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/login?tenant_id=ten_derived&redirect_uri=https://x.test/cb", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "Sign in to ") {
		t.Errorf("tenant with no registry row should use generic heading:\n%s", body)
	}
	if !strings.Contains(body, "/v1/social/google/authorize?") {
		t.Errorf("Google link missing:\n%s", body)
	}
}

// TestRedirectHardening pins the open-redirect fix on BOTH entry points: an
// unregistered redirect is rejected, a tenant-registered one is accepted, and a
// same-origin (issuer) console callback is always allowed.
func TestRedirectHardening(t *testing.T) {
	r, store := newAdminRouter(t)
	if err := store.PutClient(OIDCClient{
		ClientID: "cli_acme", TenantID: "ten_acme",
		RedirectURIs: []string{"https://app.acme.com/callback.html"}, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed client: %v", err)
	}

	code := func(target string) int {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	esc := func(u string) string { return url.QueryEscape(u) }

	// Arbitrary attacker host → rejected at BOTH /login and the social leg.
	if c := code("/login?tenant_id=ten_acme&redirect_uri=" + esc("https://evil.com/cb")); c != http.StatusBadRequest {
		t.Errorf("/login open redirect: want 400, got %d", c)
	}
	if c := code("/v1/social/google/authorize?tenant_id=ten_acme&redirect_uri=" + esc("https://evil.com/cb")); c != http.StatusBadRequest {
		t.Errorf("social leg open redirect: want 400, got %d", c)
	}

	// The tenant's own registered redirect → allowed.
	if c := code("/login?tenant_id=ten_acme&redirect_uri=" + esc("https://app.acme.com/callback.html")); c != http.StatusOK {
		t.Errorf("/login registered redirect: want 200, got %d", c)
	}
	if c := code("/v1/social/google/authorize?tenant_id=ten_acme&redirect_uri=" + esc("https://app.acme.com/callback.html")); c != http.StatusFound {
		t.Errorf("social leg registered redirect: want 302, got %d", c)
	}

	// A registered redirect belonging to ANOTHER tenant is NOT accepted here.
	if c := code("/login?tenant_id=ten_other&redirect_uri=" + esc("https://app.acme.com/callback.html")); c != http.StatusBadRequest {
		t.Errorf("cross-tenant redirect: want 400, got %d", c)
	}

	// Same-origin issuer callback (hosted console) → always allowed. Issuer is
	// http://test.local in the test router.
	if c := code("/v1/social/google/authorize?tenant_id=ten_signup&redirect_uri=" + esc("http://test.local/admin/signup/callback")); c != http.StatusFound {
		t.Errorf("same-origin console callback: want 302, got %d", c)
	}
}

// TestQuickstartAuthJSUsesHostedLogin proves the generated auth.js now sends
// login() to the hosted /login chooser instead of hard-coding the social leg.
func TestQuickstartAuthJSUsesHostedLogin(t *testing.T) {
	asset, ok := quickstartAssetByName("auth.js")
	if !ok {
		t.Fatal("auth.js asset not found")
	}
	body, err := renderQuickstart(asset, quickstartParams{
		Issuer: "https://auth.x-auth.com", ClientID: "cli_x", TenantID: "ten_x", Company: "Acme",
	})
	if err != nil {
		t.Fatalf("render auth.js: %v", err)
	}
	js := string(body)
	if !strings.Contains(js, "${OIDC.issuer}/login") {
		t.Errorf("login() must navigate to the hosted /login chooser:\n%s", js)
	}
	// login() no longer builds the social-leg URL directly.
	if strings.Contains(js, "/v1/social/") {
		t.Errorf("auth.js should no longer reference the social leg path directly:\n%s", js)
	}
	// Step-up reuses the existing session by going straight to /authorize, with a
	// login_required fallback to full login.
	if !strings.Contains(js, "export async function stepUp") {
		t.Errorf("auth.js must expose stepUp() for session-reuse step-up:\n%s", js)
	}
	if !strings.Contains(js, "login_required") {
		t.Errorf("auth.js must handle login_required (session-expiry fallback):\n%s", js)
	}
}
