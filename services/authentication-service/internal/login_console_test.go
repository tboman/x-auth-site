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
// params, and a disabled phone option. The workspace name is shown when the
// tenant is registered.
func TestLoginChooserRendersMethods(t *testing.T) {
	r, store := newAdminRouter(t)
	if _, err := store.CreateTenant(Tenant{
		ID: "ten_acme", CompanyName: "Acme Inc", Slug: "acme", OwnerEmail: "o@acme.test", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
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
	// Phone is present but disabled (stub).
	if !strings.Contains(body, "coming soon") || !strings.Contains(body, "disabled") {
		t.Errorf("chooser must show a disabled phone option:\n%s", body)
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

// TestLoginChooserUnregisteredTenant falls back to the generic heading (no
// registry row) but still renders the Google link.
func TestLoginChooserUnregisteredTenant(t *testing.T) {
	r, _ := newAdminRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/login?tenant_id=ten_derived&redirect_uri=https://x.test/cb", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "Sign in to ") {
		t.Errorf("unregistered tenant should use generic heading:\n%s", body)
	}
	if !strings.Contains(body, "/v1/social/google/authorize?") {
		t.Errorf("Google link missing for unregistered tenant:\n%s", body)
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
}
