package internal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
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

// mockAuthenticator is an in-process stand-in for HTTPAuthenticatorClient. Each
// method is a function field so individual tests can stub precisely the
// behavior they need.
type mockAuthenticator struct {
	ListFn   func(ctx context.Context, tenantID, userID string) ([]Authenticator, error)
	VerifyFn func(ctx context.Context, tenantID, userID, secret string) error
}

func (m *mockAuthenticator) ListAuthenticators(ctx context.Context, t, u string) ([]Authenticator, error) {
	if m.ListFn == nil {
		return nil, nil
	}
	return m.ListFn(ctx, t, u)
}
func (m *mockAuthenticator) VerifyFirstFactor(ctx context.Context, t, u, s string) error {
	if m.VerifyFn == nil {
		return nil
	}
	return m.VerifyFn(ctx, t, u, s)
}

// testSigner is a single RS256 signer shared by every test router — generating
// a 2048-bit key per test would dominate the suite's runtime for no coverage.
var testSigner = func() *jwtx.Signer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("generate test signing key: " + err.Error())
	}
	return jwtx.NewSigner(key)
}()

// newTestRouter wires a fully-assembled Router with an in-memory store. Tests
// reach into the returned Storage to seed state or inspect invariants.
func newTestRouter(t *testing.T) (http.Handler, Storage) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewMemStorage()
	r := Router(Deps{
		Store:         store,
		Logger:        logger,
		Authenticator: &mockAuthenticator{},
		Issuer:        "http://test.local",
		Signer:        testSigner,
	})
	return r, store
}

// verifierFromJWKSEndpoint fetches the service's own JWKS endpoint through the
// router and builds a jwtx.Verifier from the served document — the exact
// consumption path an external service would use.
func verifierFromJWKSEndpoint(t *testing.T, r http.Handler, path string) *jwtx.Verifier {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: expected 200, got %d (%s)", path, w.Code, w.Body.String())
	}
	var set jwtx.JWKS
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil {
		t.Fatalf("%s: invalid JWKS JSON: %v", path, err)
	}
	v, err := jwtx.NewVerifierFromJWKS("http://test.local", set)
	if err != nil {
		t.Fatalf("%s: verifier from served JWKS: %v", path, err)
	}
	return v
}

// --- Health is unauthenticated ---

func TestHealthzNoTenant(t *testing.T) {
	r, _ := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: expected 200, got %d", w.Code)
	}
}

// --- Discovery docs reflect the configured issuer ---

func TestDiscoveryDocs(t *testing.T) {
	r, _ := newTestRouter(t)
	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, w.Code)
		}
		var doc map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s: invalid JSON: %v", path, err)
		}
		if doc["issuer"] != "http://test.local" {
			t.Fatalf("%s: issuer = %v, want http://test.local", path, doc["issuer"])
		}
	}
}

// --- Users CRUD happy path ---

func TestUserCRUD(t *testing.T) {
	r, _ := newTestRouter(t)

	// Create
	body := strings.NewReader(`{"email":"alice@example.com","name":"Alice"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/users", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", "ten_a")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	var created User
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("create: bad JSON: %v", err)
	}
	if !strings.HasPrefix(created.ID, "usr_") {
		t.Fatalf("create: id %q missing usr_ prefix", created.ID)
	}
	if created.TenantID != "ten_a" || created.Email != "alice@example.com" {
		t.Fatalf("create: wrong fields: %+v", created)
	}

	// Read
	req = httptest.NewRequest(http.MethodGet, "/v1/users/"+created.ID, nil)
	req.Header.Set("X-Tenant-Id", "ten_a")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d", w.Code)
	}

	// Read with wrong tenant returns 404 (no cross-tenant leak).
	req = httptest.NewRequest(http.MethodGet, "/v1/users/"+created.ID, nil)
	req.Header.Set("X-Tenant-Id", "ten_b")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get: expected 404, got %d", w.Code)
	}

	// Patch
	req = httptest.NewRequest(http.MethodPatch, "/v1/users/"+created.ID,
		strings.NewReader(`{"name":"Alice Anderson"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", "ten_a")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("patch: expected 200, got %d (%s)", w.Code, w.Body.String())
	}

	// Delete
	req = httptest.NewRequest(http.MethodDelete, "/v1/users/"+created.ID, nil)
	req.Header.Set("X-Tenant-Id", "ten_a")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d", w.Code)
	}
}

// --- User create rejects duplicate emails within a tenant ---

func TestUserDuplicateEmail(t *testing.T) {
	r, _ := newTestRouter(t)
	payload := `{"email":"dup@example.com","name":"X"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", "ten_a")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create: expected 201, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", "ten_a")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate create: expected 409, got %d", w.Code)
	}
}

// --- GET /v1/users keyset pagination ---

func TestUserListPagination(t *testing.T) {
	r, store := newTestRouter(t)

	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		if _, err := store.CreateUser(User{
			ID: fmt.Sprintf("usr_%02d", i), TenantID: "ten_a",
			Email: fmt.Sprintf("u%d@example.com", i), CreatedAt: ts, UpdatedAt: ts,
		}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	// Page 1: newest first, full page carries next_cursor.
	req := httptest.NewRequest(http.MethodGet, "/v1/users?limit=2", nil)
	req.Header.Set("X-Tenant-Id", "ten_a")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("page1: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var page1 ListUsersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &page1); err != nil {
		t.Fatalf("page1: bad JSON: %v", err)
	}
	if len(page1.Users) != 2 {
		t.Fatalf("page1: want 2 users, got %d", len(page1.Users))
	}
	if page1.Users[0].ID != "usr_02" || page1.Users[1].ID != "usr_01" {
		t.Fatalf("page1: wrong order: %s, %s", page1.Users[0].ID, page1.Users[1].ID)
	}
	if page1.NextCursor == "" {
		t.Fatalf("page1: expected next_cursor when page is full")
	}

	// Page 2 via cursor: strictly older users only; short page emits no cursor.
	req = httptest.NewRequest(http.MethodGet,
		"/v1/users?limit=2&cursor="+url.QueryEscape(page1.NextCursor), nil)
	req.Header.Set("X-Tenant-Id", "ten_a")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("page2: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var page2 ListUsersResponse
	_ = json.Unmarshal(w.Body.Bytes(), &page2)
	if len(page2.Users) != 1 || page2.Users[0].ID != "usr_00" {
		t.Fatalf("page2: want only usr_00, got %+v", page2.Users)
	}
	if page2.NextCursor != "" {
		t.Fatalf("page2: final short page should not emit a cursor")
	}
}

// --- GET /v1/users rejects malformed limit / cursor ---

func TestUserListInvalidParams(t *testing.T) {
	r, _ := newTestRouter(t)
	for _, tc := range []struct{ query, wantCode string }{
		{"limit=abc", "invalid_limit"},
		{"limit=0", "invalid_limit"},
		{"limit=-5", "invalid_limit"},
		{"cursor=not-a-timestamp", "invalid_cursor"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/v1/users?"+tc.query, nil)
		req.Header.Set("X-Tenant-Id", "ten_a")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d", tc.query, w.Code)
		}
		if !strings.Contains(w.Body.String(), tc.wantCode) {
			t.Fatalf("%s: body %q missing error code %q", tc.query, w.Body.String(), tc.wantCode)
		}
	}
}

// --- PurgeExpired sweeps dead artefacts and keeps live ones (mem) ---

func TestPurgeExpiredMem(t *testing.T) {
	r, store := newTestRouter(t)
	now := time.Now().UTC()

	// Mint a real token pair via /authorize -> /token so we can prove a purged
	// token stops authenticating end-to-end.
	authURL := "/authorize?" + url.Values{
		"client_id":    {DefaultClientID},
		"redirect_uri": {"http://localhost:3000/callback"},
		"tenant_id":    {"ten_a"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {DefaultClientID}}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("token: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &tok)

	// Sanity: the access token authenticates before the purge.
	req = httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("userinfo before purge: expected 200, got %d", w.Code)
	}

	// Force-expire the access token record (PutToken upserts by hash).
	rec, err := store.GetTokenByHash(HashToken(tok.AccessToken))
	if err != nil {
		t.Fatalf("get access token record: %v", err)
	}
	rec.ExpiresAt = now.Add(-time.Minute)
	if err := store.PutToken(rec); err != nil {
		t.Fatalf("expire access token: %v", err)
	}

	// Seed the remaining purge candidates and survivors directly.
	if err := store.PutAuthCode(AuthCode{
		Code: "stale-code", ClientID: DefaultClientID, TenantID: "ten_a", UserID: "usr_x",
		RedirectURI: "http://localhost:3000/callback",
		CreatedAt:   now.Add(-time.Duration(AuthCodeTTLSeconds+60) * time.Second),
	}); err != nil {
		t.Fatalf("seed stale code: %v", err)
	}
	if err := store.PutAuthCode(AuthCode{
		Code: "fresh-code", ClientID: DefaultClientID, TenantID: "ten_a", UserID: "usr_x",
		RedirectURI: "http://localhost:3000/callback", CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed fresh code: %v", err)
	}
	// Dead session: expired longer ago than the refresh-token grace window.
	if _, err := store.CreateSession(Session{
		ID: "ses_dead", TenantID: "ten_a", UserID: "usr_x", RiskLevel: RiskLow,
		CreatedAt: now.Add(-48 * time.Hour), UpdatedAt: now.Add(-48 * time.Hour),
		ExpiresAt: now.Add(-time.Duration(RefreshTokenTTLSeconds)*time.Second - time.Hour),
	}); err != nil {
		t.Fatalf("seed dead session: %v", err)
	}
	// Recently-expired session: within the grace window — must survive (a live
	// refresh token may still legitimately reference it).
	if _, err := store.CreateSession(Session{
		ID: "ses_recent", TenantID: "ten_a", UserID: "usr_x", RiskLevel: RiskLow,
		CreatedAt: now.Add(-2 * time.Hour), UpdatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("seed recent session: %v", err)
	}

	// Expect exactly: expired access token + stale code + dead session = 3.
	// (The refresh token and the OIDC-flow session are live and must survive.)
	removed, err := store.PurgeExpired(now)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if removed != 3 {
		t.Fatalf("removed = %d, want 3", removed)
	}

	// Purged artefacts are gone...
	if _, err := store.GetTokenByHash(HashToken(tok.AccessToken)); err != ErrNotFound {
		t.Fatalf("expired access token should be purged, got %v", err)
	}
	if _, err := store.ConsumeAuthCode("stale-code"); err != ErrNotFound {
		t.Fatalf("stale code should be purged, got %v", err)
	}
	if _, err := store.GetSession("ten_a", "ses_dead"); err != ErrNotFound {
		t.Fatalf("dead session should be purged, got %v", err)
	}

	// ...live ones are kept.
	if _, err := store.GetTokenByHash(HashToken(tok.RefreshToken)); err != nil {
		t.Fatalf("live refresh token should be kept: %v", err)
	}
	if _, err := store.ConsumeAuthCode("fresh-code"); err != nil {
		t.Fatalf("fresh code should be kept: %v", err)
	}
	if _, err := store.GetSession("ten_a", "ses_recent"); err != nil {
		t.Fatalf("recently expired session should be kept (grace window): %v", err)
	}

	// And the purged access token no longer authenticates.
	req = httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo after purge: expected 401, got %d", w.Code)
	}
}

// --- Sessions CRUD lifecycle ---

func TestSessionLifecycle(t *testing.T) {
	r, store := newTestRouter(t)

	// Seed a user directly so we can focus on session semantics.
	u, _ := store.CreateUser(User{ID: "usr_alice", TenantID: "ten_a", Email: "a@e.com"})

	// Create session
	body := strings.NewReader(`{"user_id":"` + u.ID + `","risk_level":"low","step_up_completed":false}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", "ten_a")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create session: expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	var sess Session
	if err := json.Unmarshal(w.Body.Bytes(), &sess); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if !strings.HasPrefix(sess.ID, "ses_") {
		t.Fatalf("session id %q missing ses_ prefix", sess.ID)
	}
	originalExpiry := sess.ExpiresAt

	// Refresh bumps expires_at forward.
	req = httptest.NewRequest(http.MethodPost, "/v1/sessions/"+sess.ID+"/refresh", nil)
	req.Header.Set("X-Tenant-Id", "ten_a")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: expected 200, got %d", w.Code)
	}
	var refreshed Session
	_ = json.Unmarshal(w.Body.Bytes(), &refreshed)
	if !refreshed.ExpiresAt.After(originalExpiry) && !refreshed.ExpiresAt.Equal(originalExpiry) {
		t.Fatalf("refresh: expiry moved backwards")
	}

	// Upgrade flips step_up_completed and lowers risk.
	body = strings.NewReader(`{"risk_level":"low","step_up_completed":true}`)
	req = httptest.NewRequest(http.MethodPost, "/v1/sessions/"+sess.ID+"/upgrade", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", "ten_a")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("upgrade: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var upgraded Session
	_ = json.Unmarshal(w.Body.Bytes(), &upgraded)
	if !upgraded.StepUpCompleted {
		t.Fatalf("upgrade: step_up_completed not set")
	}

	// Invalidate — returns 204, then refresh should 409.
	req = httptest.NewRequest(http.MethodPost, "/v1/sessions/"+sess.ID+"/invalidate", nil)
	req.Header.Set("X-Tenant-Id", "ten_a")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("invalidate: expected 204, got %d", w.Code)
	}

	// Invalidating twice is a no-op.
	req = httptest.NewRequest(http.MethodPost, "/v1/sessions/"+sess.ID+"/invalidate", nil)
	req.Header.Set("X-Tenant-Id", "ten_a")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("second invalidate: expected 204, got %d", w.Code)
	}

	// Refresh on invalidated session is 409.
	req = httptest.NewRequest(http.MethodPost, "/v1/sessions/"+sess.ID+"/refresh", nil)
	req.Header.Set("X-Tenant-Id", "ten_a")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("refresh after invalidate: expected 409, got %d", w.Code)
	}
}

// --- Session create rejects unknown user_id ---

func TestSessionCreateRejectsUnknownUser(t *testing.T) {
	r, _ := newTestRouter(t)
	body := strings.NewReader(`{"user_id":"usr_ghost"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", "ten_a")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown user, got %d", w.Code)
	}
}

// --- /v1 routes require the tenant header ---

func TestV1RoutesRequireTenantHeader(t *testing.T) {
	r, _ := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/users/usr_anything", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without tenant header, got %d", w.Code)
	}
}

// --- /authorize -> /token happy path mints a JWT access token + a session ---

func TestAuthorizeToTokenHappyPath(t *testing.T) {
	r, store := newTestRouter(t)

	authURL := "/authorize?" + url.Values{
		"client_id":    {DefaultClientID},
		"redirect_uri": {"http://localhost:3000/callback"},
		"state":        {"state-1"},
		"scope":        {"openid profile email"},
		"nonce":        {"n-42"},
		"tenant_id":    {"ten_a"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d (%s)", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("authorize: bad Location header: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize: no code in redirect")
	}
	if loc.Query().Get("state") != "state-1" {
		t.Fatalf("authorize: state not echoed")
	}

	// POST /token
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"client_id":    {DefaultClientID},
		"redirect_uri": {"http://localhost:3000/callback"},
	}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("token: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var tokResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tokResp); err != nil {
		t.Fatalf("token: bad JSON: %v", err)
	}
	if tokResp.AccessToken == "" || tokResp.RefreshToken == "" {
		t.Fatalf("token: empty tokens: %+v", tokResp)
	}
	if tokResp.TokenType != "Bearer" || tokResp.ExpiresIn != AccessTokenTTLSeconds {
		t.Fatalf("token: wrong metadata: %+v", tokResp)
	}

	// Access token is a compact 3-part JWS; refresh token stays opaque.
	if parts := strings.Split(tokResp.AccessToken, "."); len(parts) != 3 {
		t.Fatalf("access token is not a 3-part JWS: %q", tokResp.AccessToken)
	}
	if strings.Contains(tokResp.RefreshToken, ".") {
		t.Fatalf("refresh token should stay opaque, got %q", tokResp.RefreshToken)
	}

	// Storage should contain exactly one access token and one refresh token, both
	// stored under their SHA-256 hashes (not plaintext).
	accessRec, err := store.GetTokenByHash(HashToken(tokResp.AccessToken))
	if err != nil {
		t.Fatalf("access token not stored under hash: %v", err)
	}
	if _, err := store.GetTokenByHash(HashToken(tokResp.RefreshToken)); err != nil {
		t.Fatalf("refresh token not stored under hash: %v", err)
	}

	// The access token must verify against the service's own published JWKS,
	// the way any sister service would consume it.
	now := time.Now().UTC()
	v := verifierFromJWKSEndpoint(t, r, "/v1/auth/jwks")
	claims, _, err := v.Verify(tokResp.AccessToken, now)
	if err != nil {
		t.Fatalf("access token does not verify against /v1/auth/jwks: %v", err)
	}
	if !strings.HasPrefix(claims.Sub, "usr_") {
		t.Fatalf("sub = %q, want usr_ prefix", claims.Sub)
	}
	if claims.Aud != DefaultClientID {
		t.Fatalf("aud = %q, want %q", claims.Aud, DefaultClientID)
	}
	if claims.TenantID != "ten_a" {
		t.Fatalf("tenant_id = %q, want ten_a", claims.TenantID)
	}
	if claims.SessionID != accessRec.SessionID || !strings.HasPrefix(claims.SessionID, "ses_") {
		t.Fatalf("session_id = %q, stored record has %q", claims.SessionID, accessRec.SessionID)
	}
	if claims.Scope != "openid profile email" {
		t.Fatalf("scope = %q", claims.Scope)
	}
	if got, want := claims.Exp, now.Add(time.Duration(AccessTokenTTLSeconds)*time.Second).Unix(); got < want-30 || got > want+30 {
		t.Fatalf("exp = %d, want ~%d (1h TTL)", got, want)
	}

	// scope contained "openid", so an id_token must be present, signed by the
	// same key, and carry the nonce from the original /authorize request.
	if tokResp.IDToken == "" {
		t.Fatalf("id_token missing for openid scope")
	}
	idClaims, _, err := v.Verify(tokResp.IDToken, now)
	if err != nil {
		t.Fatalf("id_token does not verify: %v", err)
	}
	if idClaims.Nonce != "n-42" {
		t.Fatalf("id_token nonce = %q, want n-42", idClaims.Nonce)
	}
	if idClaims.Sub != claims.Sub || idClaims.Aud != DefaultClientID {
		t.Fatalf("id_token sub/aud mismatch: %+v", idClaims)
	}

	// /userinfo
	req = httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("userinfo: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var info map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &info)
	if info["email"] != "dev@example.com" {
		t.Fatalf("userinfo: wrong email: %v", info)
	}
}

// --- /token rejects code replay (auth codes are one-shot) ---

func TestTokenCodeReplay(t *testing.T) {
	r, _ := newTestRouter(t)

	authURL := "/authorize?" + url.Values{
		"client_id":    {DefaultClientID},
		"redirect_uri": {"http://localhost:3000/callback"},
		"tenant_id":    {"ten_a"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {DefaultClientID}}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first exchange: expected 200, got %d", w.Code)
	}

	// Replay same code.
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("replay: expected 400, got %d", w.Code)
	}
}

// --- /token refresh rotates tokens and revokes the old refresh ---

func TestTokenRefreshRotation(t *testing.T) {
	r, store := newTestRouter(t)

	// Obtain an initial token pair through /authorize -> /token.
	authURL := "/authorize?" + url.Values{
		"client_id":    {DefaultClientID},
		"redirect_uri": {"http://localhost:3000/callback"},
		"tenant_id":    {"ten_a"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {DefaultClientID}}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var first struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &first)

	// Refresh grant.
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first.RefreshToken}}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var second struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &second)
	if second.RefreshToken == first.RefreshToken {
		t.Fatalf("refresh token not rotated")
	}
	if second.AccessToken == first.AccessToken {
		t.Fatalf("access token not rotated")
	}

	// The refreshed access token is a fresh JWT that verifies against the JWKS.
	if parts := strings.Split(second.AccessToken, "."); len(parts) != 3 {
		t.Fatalf("refreshed access token is not a 3-part JWS: %q", second.AccessToken)
	}
	v := verifierFromJWKSEndpoint(t, r, "/.well-known/jwks.json")
	claims, _, err := v.Verify(second.AccessToken, time.Now().UTC())
	if err != nil {
		t.Fatalf("refreshed access token does not verify: %v", err)
	}
	if claims.TenantID != "ten_a" || !strings.HasPrefix(claims.SessionID, "ses_") {
		t.Fatalf("refreshed token claims wrong: %+v", claims)
	}

	// Old refresh should now be revoked.
	old, _ := store.GetTokenByHash(HashToken(first.RefreshToken))
	if old.RevokedAt == nil {
		t.Fatalf("old refresh token not marked revoked")
	}

	// Replaying the old refresh should fail.
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("old refresh replay: expected 400, got %d", w.Code)
	}
}

// --- /revoke always 200 per RFC 7009, marks token revoked ---

func TestRevokeAlways200(t *testing.T) {
	r, store := newTestRouter(t)

	// Valid token round-trip.
	authURL := "/authorize?" + url.Values{
		"client_id":    {DefaultClientID},
		"redirect_uri": {"http://localhost:3000/callback"},
		"tenant_id":    {"ten_a"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {DefaultClientID}}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &tok)

	// Revoke.
	rev := url.Values{"token": {tok.AccessToken}}
	req = httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(rev.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke known: expected 200, got %d", w.Code)
	}
	stored, _ := store.GetTokenByHash(HashToken(tok.AccessToken))
	if stored.RevokedAt == nil {
		t.Fatalf("token not revoked in storage")
	}

	// Unknown token still 200 (no existence leak).
	rev = url.Values{"token": {"totally-unknown"}}
	req = httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(rev.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke unknown: expected 200, got %d", w.Code)
	}

	// /userinfo with revoked token returns 401.
	req = httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo with revoked: expected 401, got %d", w.Code)
	}
}

// --- JWKS is served at the canonical route and the well-known alias ---

func TestJWKSEndpoints(t *testing.T) {
	r, _ := newTestRouter(t)

	var bodies []string
	for _, path := range []string{"/v1/auth/jwks", "/.well-known/jwks.json"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, w.Code)
		}
		var set jwtx.JWKS
		if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil {
			t.Fatalf("%s: invalid JWKS: %v", path, err)
		}
		if len(set.Keys) != 1 {
			t.Fatalf("%s: want 1 key, got %d", path, len(set.Keys))
		}
		k := set.Keys[0]
		if k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" || k.Kid == "" || k.N == "" || k.E == "" {
			t.Fatalf("%s: malformed JWK: %+v", path, k)
		}
		bodies = append(bodies, w.Body.String())
	}
	if bodies[0] != bodies[1] {
		t.Fatalf("canonical route and alias serve different key sets")
	}

	// Discovery documents must advertise the alias as jwks_uri.
	for _, path := range []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var doc map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &doc)
		if doc["jwks_uri"] != "http://test.local/.well-known/jwks.json" {
			t.Fatalf("%s: jwks_uri = %v", path, doc["jwks_uri"])
		}
	}
}

// --- /userinfo hybrid validation: crypto-valid JWT with a revoked record is 401 ---

func TestUserInfoRejectsRevokedButCryptoValidJWT(t *testing.T) {
	r, store := newTestRouter(t)

	authURL := "/authorize?" + url.Values{
		"client_id":    {DefaultClientID},
		"redirect_uri": {"http://localhost:3000/callback"},
		"tenant_id":    {"ten_a"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	loc, _ := url.Parse(w.Header().Get("Location"))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "client_id": {DefaultClientID}}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &tok)

	// Revoke the stored record directly. The JWT itself remains
	// cryptographically valid — prove it, then prove /userinfo still rejects.
	if err := store.RevokeTokenByHash(HashToken(tok.AccessToken)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	v := verifierFromJWKSEndpoint(t, r, "/v1/auth/jwks")
	if _, _, err := v.Verify(tok.AccessToken, time.Now().UTC()); err != nil {
		t.Fatalf("precondition: revoked JWT should still verify cryptographically, got %v", err)
	}

	req = httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo with revoked record: expected 401, got %d (%s)", w.Code, w.Body.String())
	}
}

// --- /userinfo rejects a token signed by a different key ---

func TestUserInfoRejectsForeignlySignedJWT(t *testing.T) {
	r, store := newTestRouter(t)

	// Seed a real user + session so only the signature can be at fault.
	u, _ := store.CreateUser(User{ID: "usr_mallory", TenantID: "ten_a", Email: "m@e.com"})
	now := time.Now().UTC()

	foreignKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate foreign key: %v", err)
	}
	forged, err := jwtx.NewSigner(foreignKey).Sign(jwtx.Claims{
		Sub:       u.ID,
		Iss:       "http://test.local",
		Aud:       DefaultClientID,
		Exp:       now.Add(time.Hour).Unix(),
		Iat:       now.Unix(),
		TenantID:  "ten_a",
		Scope:     "openid",
		SessionID: "ses_forged",
	}, nil)
	if err != nil {
		t.Fatalf("sign with foreign key: %v", err)
	}
	// Even plant a matching stored record: the signature check alone must fail it.
	if err := store.PutToken(Token{
		TokenHash: HashToken(forged), SessionID: "ses_forged", UserID: u.ID,
		TenantID: "ten_a", TokenType: TokenTypeAccess, Scope: "openid",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("plant token record: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+forged)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo with foreign-key JWT: expected 401, got %d (%s)", w.Code, w.Body.String())
	}
}

// --- /authorize rejects unregistered redirect_uri ---

func TestAuthorizeRejectsUnregisteredRedirect(t *testing.T) {
	r, _ := newTestRouter(t)
	bad := "/authorize?" + url.Values{
		"client_id":    {DefaultClientID},
		"redirect_uri": {"https://evil.example.com/cb"},
		"tenant_id":    {"ten_a"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, bad, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unregistered redirect, got %d", w.Code)
	}
}

// --- Social login stub: authorize -> callback lands with session in redirect ---

func TestSocialLoginStub(t *testing.T) {
	r, store := newTestRouter(t)

	// /v1/social/google/authorize
	authURL := "/v1/social/google/authorize?" + url.Values{
		"tenant_id":    {"ten_a"},
		"redirect_uri": {"http://app.example.com/cb"},
		"state":        {"s-42"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("social authorize: expected 302, got %d (%s)", w.Code, w.Body.String())
	}
	// Location should point at our own callback with a code + state.
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("bad Location: %v", err)
	}
	if !strings.HasSuffix(loc.Path, "/v1/social/google/callback") {
		t.Fatalf("social authorize: Location path = %q", loc.Path)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("social authorize: no code in redirect")
	}

	// Follow the callback.
	cbURL := "/v1/social/google/callback?" + url.Values{
		"code":  {code},
		"state": {"s-42"},
	}.Encode()
	req = httptest.NewRequest(http.MethodGet, cbURL, nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("social callback: expected 302, got %d (%s)", w.Code, w.Body.String())
	}
	finalLoc, _ := url.Parse(w.Header().Get("Location"))
	if finalLoc.Host != "app.example.com" {
		t.Fatalf("social callback: redirected to wrong host %q", finalLoc.Host)
	}
	sessID := finalLoc.Query().Get("session_id")
	if sessID == "" {
		t.Fatalf("social callback: no session_id in redirect")
	}
	// Session and user should be persisted.
	sess, err := store.GetSession("ten_a", sessID)
	if err != nil {
		t.Fatalf("session not stored: %v", err)
	}
	if sess.UserID == "" {
		t.Fatalf("session has no user_id")
	}
}

// --- Social callback rejects unknown code ---

func TestSocialCallbackUnknownCode(t *testing.T) {
	r, _ := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/social/google/callback?code=bogus", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown code, got %d", w.Code)
	}
}

// --- Social: unsupported provider is rejected ---

func TestSocialUnsupportedProvider(t *testing.T) {
	r, _ := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet,
		"/v1/social/yahoo/authorize?tenant_id=t&redirect_uri=http://x/cb", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unsupported provider: expected 400, got %d", w.Code)
	}
}

// --- DownstreamError wraps errors ---

func TestDownstreamErrorUnwrap(t *testing.T) {
	inner := errors.New("boom")
	e := &DownstreamError{Service: "x", Err: inner}
	if !errors.Is(e, inner) {
		t.Fatalf("DownstreamError does not unwrap inner error")
	}
}

// --- HashToken is deterministic ---

func TestHashTokenDeterministic(t *testing.T) {
	a := HashToken("hello")
	b := HashToken("hello")
	if a != b {
		t.Fatalf("HashToken non-deterministic: %q vs %q", a, b)
	}
	if HashToken("hello") == HashToken("world") {
		t.Fatalf("HashToken collision on trivial inputs")
	}
	if len(a) != 64 {
		t.Fatalf("HashToken output length = %d, want 64", len(a))
	}
}
