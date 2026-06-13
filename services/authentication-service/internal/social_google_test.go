package internal

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// newSocialRouter wires a Router whose google provider runs the real OAuth2
// handshake against the given endpoints. Other providers stay stubs.
func newSocialRouter(t *testing.T, cfg SocialProviderConfig) (http.Handler, Storage) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewMemStorage()
	// The social leg now rejects unregistered redirect URIs (open-redirect
	// hardening), so register the redirect the test flows use for ten_acme.
	if err := store.PutClient(OIDCClient{
		ClientID: "cli_acme", TenantID: "ten_acme",
		RedirectURIs: []string{"http://app.acme.test/cb"}, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	r := Router(Deps{
		Store:           store,
		Logger:          logger,
		Authenticator:   &mockAuthenticator{},
		Issuer:          "http://test.local",
		Signer:          testSigner,
		SocialProviders: map[string]SocialProviderConfig{"google": cfg},
	})
	return r, store
}

// fakeGoogle is an httptest server standing in for Google's token + userinfo
// endpoints. It asserts the back-channel request shapes and returns a fixed
// profile.
func fakeGoogle(t *testing.T) (*httptest.Server, SocialProviderConfig) {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("token: bad form: %v", err)
		}
		if got := r.PostForm.Get("grant_type"); got != "authorization_code" {
			t.Errorf("token: grant_type = %q", got)
		}
		if got := r.PostForm.Get("code"); got != "provider-code-1" {
			t.Errorf("token: code = %q", got)
		}
		if got := r.PostForm.Get("client_id"); got != "test-client-id" {
			t.Errorf("token: client_id = %q", got)
		}
		if got := r.PostForm.Get("client_secret"); got != "test-client-secret" {
			t.Errorf("token: client_secret = %q", got)
		}
		if got := r.PostForm.Get("redirect_uri"); got != "http://test.local/v1/social/google/callback" {
			t.Errorf("token: redirect_uri = %q", got)
		}
		// RFC 7636 §4.1: verifier is 43..128 chars. We mint 64.
		if v := r.PostForm.Get("code_verifier"); len(v) < 43 {
			t.Errorf("token: code_verifier too short: %q", v)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "provider-access-token",
			"token_type":   "Bearer",
		})
	})

	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer provider-access-token" {
			t.Errorf("userinfo: Authorization = %q", got)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"sub":            "google-sub-123",
			"email":          "carol@example.com",
			"email_verified": true,
			"name":           "Carol Real",
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv, SocialProviderConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		AuthURL:      "https://provider.test/auth",
		TokenURL:     srv.URL + "/token",
		UserinfoURL:  srv.URL + "/userinfo",
	}
}

// startRealAuthorize drives /v1/social/google/authorize and returns the
// parsed provider redirect.
func startRealAuthorize(t *testing.T, r http.Handler) *url.URL {
	t.Helper()
	authURL := "/v1/social/google/authorize?" + url.Values{
		"tenant_id":    {"ten_acme"},
		"redirect_uri": {"http://app.acme.test/cb"},
		"state":        {"caller-state-1"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d (%s)", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("authorize: bad Location: %v", err)
	}
	return loc
}

func TestSocialGoogleRealAuthorizeRedirectsToProvider(t *testing.T) {
	_, cfg := fakeGoogle(t)
	r, _ := newSocialRouter(t, cfg)

	loc := startRealAuthorize(t, r)

	if loc.Host != "provider.test" || loc.Path != "/auth" {
		t.Fatalf("authorize: redirected to %q, want provider.test/auth", loc.String())
	}
	q := loc.Query()
	if got := q.Get("client_id"); got != "test-client-id" {
		t.Errorf("client_id = %q", got)
	}
	if got := q.Get("response_type"); got != "code" {
		t.Errorf("response_type = %q", got)
	}
	if got := q.Get("redirect_uri"); got != "http://test.local/v1/social/google/callback" {
		t.Errorf("redirect_uri = %q", got)
	}
	if got := q.Get("scope"); got != "openid email profile" {
		t.Errorf("scope = %q", got)
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q", got)
	}
	if q.Get("code_challenge") == "" {
		t.Error("code_challenge missing")
	}
	// The state we hand the provider is our own nonce, never the caller's.
	if st := q.Get("state"); st == "" || st == "caller-state-1" {
		t.Errorf("provider state = %q, want a fresh nonce", st)
	}
}

func TestSocialGoogleRealCallbackRoundTrip(t *testing.T) {
	_, cfg := fakeGoogle(t)
	r, store := newSocialRouter(t, cfg)

	state := startRealAuthorize(t, r).Query().Get("state")

	cbURL := "/v1/social/google/callback?" + url.Values{
		"code":  {"provider-code-1"},
		"state": {state},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, cbURL, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d (%s)", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("callback: bad Location: %v", err)
	}
	if loc.Host != "app.acme.test" {
		t.Fatalf("callback: redirected to %q, want the caller's redirect_uri", loc.String())
	}
	q := loc.Query()
	if q.Get("session_id") == "" || q.Get("user_id") == "" {
		t.Fatalf("callback: missing session_id/user_id in %q", loc.String())
	}
	if got := q.Get("state"); got != "caller-state-1" {
		t.Errorf("callback: state = %q, want the caller's original state", got)
	}

	// The provider profile — not a canned stub — must have been upserted.
	user, err := store.GetUserByEmail("ten_acme", "carol@example.com")
	if err != nil {
		t.Fatalf("user not upserted from provider profile: %v", err)
	}
	if user.Name != "Carol Real" {
		t.Errorf("user.Name = %q", user.Name)
	}
	if user.ID != q.Get("user_id") {
		t.Errorf("redirect user_id = %q, stored user = %q", q.Get("user_id"), user.ID)
	}

	// State nonces are single-use: replaying the callback must fail.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, cbURL, nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("callback replay: expected 400, got %d", w.Code)
	}
}

func TestSocialGoogleRealCallbackRejectsUnknownState(t *testing.T) {
	_, cfg := fakeGoogle(t)
	r, _ := newSocialRouter(t, cfg)

	req := httptest.NewRequest(http.MethodGet,
		"/v1/social/google/callback?code=provider-code-1&state=never-issued", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown state, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestSocialGoogleRealCallbackConsentDenied(t *testing.T) {
	_, cfg := fakeGoogle(t)
	r, _ := newSocialRouter(t, cfg)

	state := startRealAuthorize(t, r).Query().Get("state")

	cbURL := "/v1/social/google/callback?" + url.Values{
		"error": {"access_denied"},
		"state": {state},
	}.Encode()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, cbURL, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 back to caller on consent denial, got %d (%s)", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Host != "app.acme.test" {
		t.Fatalf("redirected to %q, want the caller's redirect_uri", loc.String())
	}
	if got := loc.Query().Get("error"); got != "access_denied" {
		t.Errorf("error = %q", got)
	}
	if got := loc.Query().Get("state"); got != "caller-state-1" {
		t.Errorf("state = %q", got)
	}
}

func TestSocialGoogleRealCallbackProviderFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	cfg := SocialProviderConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		AuthURL:      "https://provider.test/auth",
		TokenURL:     srv.URL + "/token",
		UserinfoURL:  srv.URL + "/userinfo",
	}
	r, _ := newSocialRouter(t, cfg)

	state := startRealAuthorize(t, r).Query().Get("state")

	cbURL := "/v1/social/google/callback?" + url.Values{
		"code":  {"provider-code-1"},
		"state": {state},
	}.Encode()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, cbURL, nil))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 when the provider exchange fails, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestSocialUnconfiguredProviderKeepsStub(t *testing.T) {
	// google is configured for the real flow; github is not and must keep the
	// phase-1 stub behaviour (redirect to our own callback with a mock code).
	_, cfg := fakeGoogle(t)
	r, _ := newSocialRouter(t, cfg)

	authURL := "/v1/social/github/authorize?" + url.Values{
		"tenant_id":    {"ten_acme"},
		"redirect_uri": {"http://app.acme.test/cb"},
	}.Encode()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authURL, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("stub authorize: expected 302, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Host != "test.local" || !strings.HasSuffix(loc.Path, "/v1/social/github/callback") {
		t.Fatalf("stub authorize: redirected to %q, want our own github callback", loc.String())
	}
	if loc.Query().Get("code") == "" {
		t.Fatal("stub authorize: no mock code in redirect")
	}
}
