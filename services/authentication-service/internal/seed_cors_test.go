package internal

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSeedClientsFromEnv(t *testing.T) {
	t.Setenv("OIDC_CLIENTS",
		"cryptofreight-web=https://cryptofreight.org/callback.html,http://localhost:3000/callback.html; other-app=https://other.example/cb")
	store := NewMemStorage()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := SeedClientsFromEnv(store, logger); err != nil {
		t.Fatalf("seed: %v", err)
	}

	c, err := store.GetClient("cryptofreight-web")
	if err != nil {
		t.Fatalf("seeded client not found: %v", err)
	}
	if len(c.RedirectURIs) != 2 || c.RedirectURIs[0] != "https://cryptofreight.org/callback.html" {
		t.Fatalf("redirect URIs = %v", c.RedirectURIs)
	}
	if c.ClientSecretHash != "" {
		t.Fatal("seeded client must be public (no secret)")
	}
	if _, err := store.GetClient("other-app"); err != nil {
		t.Fatalf("second seeded client not found: %v", err)
	}
}

func TestSeedClientsFromEnvRejectsMalformed(t *testing.T) {
	for _, raw := range []string{
		"no-equals-sign",
		"id=not-absolute-uri",
		"id=",
		"=https://x.example/cb",
	} {
		t.Setenv("OIDC_CLIENTS", raw)
		store := NewMemStorage()
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := SeedClientsFromEnv(store, logger); err == nil {
			t.Errorf("OIDC_CLIENTS=%q: expected error, got nil", raw)
		}
	}
}

// TestSeededClientAuthorizes proves a seeded client passes /authorize's
// client + redirect-URI validation end to end.
func TestSeededClientAuthorizes(t *testing.T) {
	t.Setenv("OIDC_CLIENTS", "cryptofreight-web=https://cryptofreight.org/callback.html")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewMemStorage()
	if err := SeedClientsFromEnv(store, logger); err != nil {
		t.Fatalf("seed: %v", err)
	}
	r := Router(Deps{
		Store: store, Logger: logger, Authenticator: &mockAuthenticator{},
		Issuer: "http://test.local", Signer: testSigner,
		DevAutologin: true, // exercises client/redirect validation, not the cookie gate
	})

	q := url.Values{
		"client_id":             {"cryptofreight-web"},
		"redirect_uri":          {"https://cryptofreight.org/callback.html"},
		"tenant_id":             {"ten_cryptofreight"},
		"state":                 {"xyz"},
		"scope":                 {"openid profile email"},
		"code_challenge":        {testPKCEChallenge},
		"code_challenge_method": {"S256"},
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("authorize with seeded client: expected 302, got %d (%s)", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Host != "cryptofreight.org" || loc.Query().Get("code") == "" {
		t.Fatalf("authorize redirect = %q, want cryptofreight.org with a code", loc.String())
	}
}

func newCORSRouter(t *testing.T, origins []string) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return Router(Deps{
		Store: NewMemStorage(), Logger: logger, Authenticator: &mockAuthenticator{},
		Issuer: "http://test.local", Signer: testSigner, CORSOrigins: origins,
	})
}

func TestCORSPreflightAllowedOrigin(t *testing.T) {
	r := newCORSRouter(t, []string{"https://cryptofreight.org"})

	req := httptest.NewRequest(http.MethodOptions, "/token", nil)
	req.Header.Set("Origin", "https://cryptofreight.org")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight: expected 204, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://cryptofreight.org" {
		t.Fatalf("Allow-Origin = %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") {
		t.Fatalf("Allow-Headers = %q, want Authorization included", got)
	}
}

func TestCORSDisallowedOriginGetsNoHeaders(t *testing.T) {
	r := newCORSRouter(t, []string{"https://cryptofreight.org"})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("discovery: expected 200, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Allow-Origin = %q for disallowed origin, want empty", got)
	}
}

func TestCORSActualRequestCarriesHeader(t *testing.T) {
	r := newCORSRouter(t, []string{"https://cryptofreight.org"})

	// Even an error response must carry the CORS header, or the browser hides
	// the error body from the SPA.
	req := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader("grant_type=authorization_code&code=nope"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://cryptofreight.org")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://cryptofreight.org" {
		t.Fatalf("Allow-Origin = %q on /token response", got)
	}
}

func TestCORSDisabledByDefault(t *testing.T) {
	r := newCORSRouter(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://cryptofreight.org")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Allow-Origin = %q with no origins configured, want empty", got)
	}
}
