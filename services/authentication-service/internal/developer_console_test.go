package internal

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func createDeveloperSession(t *testing.T, store Storage) Session {
	t.Helper()
	now := time.Now().UTC()
	u, err := store.CreateUser(User{
		ID:        "usr_dev",
		TenantID:  devConsoleTenantID,
		Email:     "dev@example.com",
		Name:      "Dev User",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create developer user: %v", err)
	}
	s, err := store.CreateSession(Session{
		ID:              "ses_dev",
		TenantID:        devConsoleTenantID,
		UserID:          u.ID,
		RiskLevel:       RiskLow,
		StepUpCompleted: false,
		CreatedAt:       now,
		UpdatedAt:       now,
		ExpiresAt:       now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create developer session: %v", err)
	}
	return s
}

func TestDeveloperConsoleSignedOutShowsGoogleLogin(t *testing.T) {
	r, _ := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/dev", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /dev: expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `href="/dev/login/google"`) {
		t.Fatalf("GET /dev signed-out page missing Google login link:\n%s", w.Body.String())
	}
}

func TestDeveloperSocialCallbackSetsSessionCookie(t *testing.T) {
	r, store := newTestRouter(t)
	sess := createDeveloperSession(t, store)

	req := httptest.NewRequest(http.MethodGet, "/dev/social/callback?session_id="+url.QueryEscape(sess.ID)+"&state=s1", nil)
	req.AddCookie(&http.Cookie{Name: devConsoleStateCookie, Value: "s1"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d (%s)", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Location"); got != "/dev" {
		t.Fatalf("callback Location = %q", got)
	}
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == devConsoleSessionCookie && c.Value == sess.ID && c.HttpOnly {
			found = true
		}
	}
	if !found {
		t.Fatalf("callback did not set HttpOnly %s cookie: %#v", devConsoleSessionCookie, w.Result().Cookies())
	}
}

func TestDeveloperRegisterClientAndStartOIDCWithACR(t *testing.T) {
	r, store := newTestRouter(t)
	sess := createDeveloperSession(t, store)
	redirectURI := "http://test.local/dev/oidc/callback"

	form := url.Values{}
	form.Set("client_id", "dev-web")
	form.Set("redirect_uris", redirectURI)
	req := httptest.NewRequest(http.MethodPost, "/dev/clients", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: devConsoleSessionCookie, Value: sess.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("register client: expected 302, got %d (%s)", w.Code, w.Body.String())
	}

	c, err := store.GetClient("dev-web")
	if err != nil {
		t.Fatalf("registered client not found: %v", err)
	}
	if len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != redirectURI {
		t.Fatalf("redirect URIs = %#v", c.RedirectURIs)
	}

	req = httptest.NewRequest(http.MethodGet, "/dev/oidc/start?client_id=dev-web&acr=sms", nil)
	req.AddCookie(&http.Cookie{Name: devConsoleSessionCookie, Value: sess.ID})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("start oidc: expected 302, got %d (%s)", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	q := loc.Query()
	if loc.Path != "/authorize" {
		t.Fatalf("Location path = %q", loc.Path)
	}
	if q.Get("client_id") != "dev-web" || q.Get("redirect_uri") != redirectURI {
		t.Fatalf("bad authorize client/redirect query: %s", loc.RawQuery)
	}
	if q.Get("acr_values") != ACRSMSOTP {
		t.Fatalf("acr_values = %q, want %q", q.Get("acr_values"), ACRSMSOTP)
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("PKCE challenge missing from authorize URL: %s", loc.RawQuery)
	}
}

func TestDeveloperRegisteredClientCompletesOIDCRoundTrip(t *testing.T) {
	store := NewMemStorage()
	sess := createDeveloperSession(t, store)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srv := httptest.NewUnstartedServer(nil)
	issuer := "http://" + srv.Listener.Addr().String()
	r := Router(Deps{
		Store:         store,
		Logger:        logger,
		Authenticator: &mockAuthenticator{},
		Issuer:        issuer,
		Signer:        testSigner,
	})
	srv.Config.Handler = r
	srv.Start()
	defer srv.Close()

	if err := store.PutClient(OIDCClient{
		ClientID:         "roundtrip-web",
		ClientSecretHash: "",
		RedirectURIs:     []string{issuer + "/dev/oidc/callback"},
		CreatedAt:        time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed client: %v", err)
	}

	client := srv.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	req, _ := http.NewRequest(http.MethodGet, issuer+"/dev/oidc/start?client_id=roundtrip-web", nil)
	req.AddCookie(&http.Cookie{Name: devConsoleSessionCookie, Value: sess.ID})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("start oidc: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start oidc status = %d", resp.StatusCode)
	}

	resp, err = client.Get(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status = %d (%s)", resp.StatusCode, string(body))
	}

	resp, err = client.Get(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("dev callback: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dev callback status = %d (%s)", resp.StatusCode, string(body))
	}
	got := string(body)
	for _, want := range []string{"OIDC round trip complete", "id_token_claims", "access_token_claims", "roundtrip-web"} {
		if !strings.Contains(got, want) {
			t.Fatalf("callback body missing %q:\n%s", want, got)
		}
	}
}
