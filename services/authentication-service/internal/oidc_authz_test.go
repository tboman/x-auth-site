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

	"github.com/xentranet/x-auth/pkg/jwtx"
)

// The transaction_id from /v1/advice, carried into /authorize, is echoed on the
// final callback (alongside code+state) and recorded on the minted auth code.
func TestAuthorizeEchoesTransactionId(t *testing.T) {
	r, store := secureAuthzRouter(t)
	sess := seedAuthzSession(t, store, "ten_bound", "real@bound.test")
	req := authzReq(url.Values{"transaction_id": {"txn_abc123"}})
	req.AddCookie(&http.Cookie{Name: AuthzSessionCookie, Value: sess.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("transaction_id") != "txn_abc123" {
		t.Fatalf("final redirect missing transaction_id: %q", loc.String())
	}
	ac, err := store.ConsumeAuthCode(loc.Query().Get("code"))
	if err != nil || ac.TransactionID != "txn_abc123" {
		t.Fatalf("auth code missing transaction id: %+v err=%v", ac, err)
	}
}

// The transaction_id also rides into the issued id_token as a claim.
func TestIDTokenCarriesTransactionId(t *testing.T) {
	r, store := secureAuthzRouter(t)
	sess := seedAuthzSession(t, store, "ten_bound", "real@bound.test")
	req := authzReq(url.Values{"transaction_id": {"txn_xyz"}})
	req.AddCookie(&http.Cookie{Name: AuthzSessionCookie, Value: sess.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	code := mustQuery(t, w, "code")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"bound-web"},
		"code_verifier": {testPKCEVerifier},
	}
	treq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	treq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tw := httptest.NewRecorder()
	r.ServeHTTP(tw, treq)
	if tw.Code != http.StatusOK {
		t.Fatalf("token: want 200, got %d (%s)", tw.Code, tw.Body.String())
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(tw.Body.Bytes(), &tok); err != nil || tok.IDToken == "" {
		t.Fatalf("no id_token: %v (%s)", err, tw.Body.String())
	}
	verifier, err := jwtx.NewVerifierFromJWKS("http://test.local", testSigner.JWKS())
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	_, extra, err := verifier.Verify(tok.IDToken, time.Now())
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	if extra["transaction_id"] != "txn_xyz" {
		t.Fatalf("id_token transaction_id = %v, want txn_xyz", extra["transaction_id"])
	}
}

func mustQuery(t *testing.T, w *httptest.ResponseRecorder, key string) string {
	t.Helper()
	loc, _ := url.Parse(w.Header().Get("Location"))
	v := loc.Query().Get(key)
	if v == "" {
		t.Fatalf("redirect %q missing %q", loc.String(), key)
	}
	return v
}

// secureAuthzRouter builds a router in production mode (DevAutologin off) with
// one tenant-bound client registered.
func secureAuthzRouter(t *testing.T) (http.Handler, Storage) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewMemStorage()
	if err := store.PutClient(OIDCClient{
		ClientID:     "bound-web",
		TenantID:     "ten_bound",
		RedirectURIs: []string{"https://bound.test/cb"},
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("put client: %v", err)
	}
	r := Router(Deps{
		Store: store, Logger: logger, Authenticator: &mockAuthenticator{},
		Issuer: "http://test.local", Signer: testSigner, // DevAutologin defaults false
	})
	return r, store
}

func authzReq(extra url.Values) *http.Request {
	q := url.Values{
		"client_id":             {"bound-web"},
		"redirect_uri":          {"https://bound.test/cb"},
		"state":                 {"st"},
		"scope":                 {"openid"},
		"code_challenge":        {testPKCEChallenge},
		"code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		q[k] = v
	}
	return httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
}

// seedSession creates a user + live session in a tenant, returning the session.
func seedAuthzSession(t *testing.T, store Storage, tenant, email string) Session {
	t.Helper()
	now := time.Now().UTC()
	u, err := store.CreateUser(User{ID: "usr_" + email, TenantID: tenant, Email: email, Name: email, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	s, err := store.CreateSession(Session{ID: "ses_" + email, TenantID: tenant, UserID: u.ID, RiskLevel: RiskLow, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return s
}

// TestAuthorizeNoCookieLoginRequired: secure mode, no session cookie -> the
// request is bounced to the client with error=login_required.
func TestAuthorizeNoCookieLoginRequired(t *testing.T) {
	r, _ := secureAuthzRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, authzReq(nil))
	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Host != "bound.test" || loc.Query().Get("error") != "login_required" {
		t.Fatalf("want login_required redirect to client, got %q", loc.String())
	}
	if loc.Query().Get("code") != "" {
		t.Fatal("must not mint a code without authentication")
	}
}

// TestAuthorizeForgedUserIDIgnored: in secure mode a user_id param is NOT
// trusted — without a cookie it still fails, even pointing at a real user.
func TestAuthorizeForgedUserIDIgnored(t *testing.T) {
	r, store := secureAuthzRouter(t)
	victim := seedAuthzSession(t, store, "ten_bound", "victim@bound.test")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, authzReq(url.Values{"user_id": {victim.UserID}}))
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "login_required" || loc.Query().Get("code") != "" {
		t.Fatalf("forged user_id must not yield a code: %q", loc.String())
	}
}

// TestAuthorizeWithSessionCookieMintsCode: a valid authz-session cookie
// identifies the user and a code is minted, tenant derived from the client.
func TestAuthorizeWithSessionCookieMintsCode(t *testing.T) {
	r, store := secureAuthzRouter(t)
	sess := seedAuthzSession(t, store, "ten_bound", "real@bound.test")

	req := authzReq(nil)
	req.AddCookie(&http.Cookie{Name: AuthzSessionCookie, Value: sess.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d (%s)", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")
	if loc.Host != "bound.test" || code == "" {
		t.Fatalf("want a code, got %q", loc.String())
	}
	// The minted auth code carries the cookie's user + the client's tenant.
	ac, err := store.ConsumeAuthCode(code)
	if err != nil {
		t.Fatalf("consume code: %v", err)
	}
	if ac.UserID != sess.UserID || ac.TenantID != "ten_bound" {
		t.Fatalf("code bound wrong: user=%s tenant=%s", ac.UserID, ac.TenantID)
	}
}

// TestAuthorizeTenantMismatchRejected: a tenant_id param contradicting the
// client's bound tenant is a hard 400.
func TestAuthorizeTenantMismatchRejected(t *testing.T) {
	r, store := secureAuthzRouter(t)
	sess := seedAuthzSession(t, store, "ten_bound", "real@bound.test")
	req := authzReq(url.Values{"tenant_id": {"ten_other"}})
	req.AddCookie(&http.Cookie{Name: AuthzSessionCookie, Value: sess.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("tenant mismatch: want 400, got %d (%s)", w.Code, w.Body.String())
	}
}

// TestAuthorizeCookieWrongTenantRejected: a cookie whose session lives in a
// different tenant than the client is bound to does not authenticate.
func TestAuthorizeCookieWrongTenantRejected(t *testing.T) {
	r, store := secureAuthzRouter(t)
	// Session in a DIFFERENT tenant than the client's ten_bound.
	other := seedAuthzSession(t, store, "ten_elsewhere", "x@elsewhere.test")
	req := authzReq(nil)
	req.AddCookie(&http.Cookie{Name: AuthzSessionCookie, Value: other.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "login_required" {
		t.Fatalf("cross-tenant cookie must not authenticate: %q", loc.String())
	}
}

// TestAuthorizeMatchingTenantParamOK: a tenant_id param that AGREES with the
// client's bound tenant is accepted.
func TestAuthorizeMatchingTenantParamOK(t *testing.T) {
	r, store := secureAuthzRouter(t)
	sess := seedAuthzSession(t, store, "ten_bound", "real@bound.test")
	req := authzReq(url.Values{"tenant_id": {"ten_bound"}})
	req.AddCookie(&http.Cookie{Name: AuthzSessionCookie, Value: sess.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound || url.Values(nil) == nil && w.Header().Get("Location") == "" {
		t.Fatalf("matching tenant param: want 302, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("want a code, got %q", loc.String())
	}
}

// TestSeedClientsParsesTenantPrefix verifies the OIDC_CLIENTS "tenant|uri"
// format binds the seeded client.
func TestSeedClientsParsesTenantPrefix(t *testing.T) {
	t.Setenv("OIDC_CLIENTS", "uf-web=ten_uf|https://uf.test/cb,http://localhost:3000/cb;legacy-web=https://legacy.test/cb")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewMemStorage()
	if err := SeedClientsFromEnv(store, logger); err != nil {
		t.Fatalf("seed: %v", err)
	}
	bound, err := store.GetClient("uf-web")
	if err != nil || bound.TenantID != "ten_uf" || len(bound.RedirectURIs) != 2 {
		t.Fatalf("bound client wrong: %+v err=%v", bound, err)
	}
	legacy, err := store.GetClient("legacy-web")
	if err != nil || legacy.TenantID != "" || len(legacy.RedirectURIs) != 1 {
		t.Fatalf("legacy client should be unbound: %+v err=%v", legacy, err)
	}
}
