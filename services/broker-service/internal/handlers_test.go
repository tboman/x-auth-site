package internal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/jwtx"
)

// testIssuer is the issuer wired into every test router — it doubles as the
// expected `iss` claim in minted access tokens.
const testIssuer = "http://test.local"

// testVerifier is the PKCE code_verifier used by the code-flow tests — 43
// characters, the RFC 7636 §4.1 minimum length.
const testVerifier = "0123456789-0123456789-0123456789-0123456789"

// s256Challenge computes the PKCE S256 code challenge independently of the
// production helper (crypto/sha256 + base64url-without-padding per RFC 7636
// §4.2), so a bug in the handler's derivation cannot self-verify.
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// testSigningKey returns a process-wide RSA key for test routers. Generated once:
// 2048-bit keygen per test would dominate the suite's runtime for no extra coverage.
var testSigningKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("generate test signing key: " + err.Error())
	}
	return key
})

// mockClients is an in-process stand-in for HTTPClients. Each method is backed by
// a function field so individual tests can stub the specific behavior they need
// (success, 404, 502) without a real network.
type mockClients struct {
	mu sync.Mutex

	GetPersonaFn             func(ctx context.Context, tenantID, personaID string) (Persona, error)
	ClaimIdentityFn          func(ctx context.Context, tenantID, poolID, personaID, installID string) (Identity, error)
	ReleaseIdentityFn        func(ctx context.Context, tenantID, identityID string) error
	CreateGrantFn            func(ctx context.Context, tenantID string, req GrantCreateRequest) (Grant, error)
	RevokeGrantsForInstallFn func(ctx context.Context, tenantID, installID string) error
	RevokeTokenFn            func(ctx context.Context, tenantID, token string) error

	// Call counters for assertions.
	ReleaseCalls int
	RevokeCalls  int
}

func (m *mockClients) GetPersona(ctx context.Context, t, p string) (Persona, error) {
	return m.GetPersonaFn(ctx, t, p)
}
func (m *mockClients) ClaimIdentity(ctx context.Context, t, pool, p, ins string) (Identity, error) {
	return m.ClaimIdentityFn(ctx, t, pool, p, ins)
}
func (m *mockClients) ReleaseIdentity(ctx context.Context, t, id string) error {
	m.mu.Lock()
	m.ReleaseCalls++
	m.mu.Unlock()
	if m.ReleaseIdentityFn == nil {
		return nil
	}
	return m.ReleaseIdentityFn(ctx, t, id)
}
func (m *mockClients) CreateGrant(ctx context.Context, t string, r GrantCreateRequest) (Grant, error) {
	return m.CreateGrantFn(ctx, t, r)
}
func (m *mockClients) RevokeGrantsForInstall(ctx context.Context, t, ins string) error {
	m.mu.Lock()
	m.RevokeCalls++
	m.mu.Unlock()
	if m.RevokeGrantsForInstallFn == nil {
		return nil
	}
	return m.RevokeGrantsForInstallFn(ctx, t, ins)
}
func (m *mockClients) RevokeToken(ctx context.Context, t, tok string) error {
	if m.RevokeTokenFn == nil {
		return nil
	}
	return m.RevokeTokenFn(ctx, t, tok)
}

// newTestRouter wires a broker Router with an in-memory store and the supplied mock.
// Helper keeps each test case compact.
func newTestRouter(t *testing.T, mc *mockClients) (http.Handler, Storage) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewMemStorage()
	key := testSigningKey()
	r := Router(Deps{
		Store:      store,
		Logger:     logger,
		Clients:    mc,
		Issuer:     testIssuer,
		Signer:     jwtx.NewSigner(key),
		Verifier:   jwtx.NewVerifier(testIssuer, &key.PublicKey),
		JWTIssuer:  testIssuer,
		DefaultTTL: 900,
	})
	return r, store
}

// fetchJWKSVerifier GETs /.well-known/jwks.json from the router and builds a
// jwtx.Verifier from the served document — exactly what an external resource
// server consuming the discovery jwks_uri would do.
func fetchJWKSVerifier(t *testing.T, r http.Handler) *jwtx.Verifier {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("jwks: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var set jwtx.JWKS
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil {
		t.Fatalf("jwks: invalid JSON: %v", err)
	}
	v, err := jwtx.NewVerifierFromJWKS(testIssuer, set)
	if err != nil {
		t.Fatalf("jwks: verifier construction failed: %v", err)
	}
	return v
}

// --- Happy path: /authorize -> /token -> install is active ---

func TestAuthorizeToTokenHappyPath(t *testing.T) {
	var grantReq GrantCreateRequest
	mc := &mockClients{
		GetPersonaFn: func(_ context.Context, tenantID, personaID string) (Persona, error) {
			return Persona{
				ID:       personaID,
				TenantID: tenantID,
				Name:     "read-only",
				Scopes:   []string{"read:docs"},
				TokenTTL: 600,
			}, nil
		},
		ClaimIdentityFn: func(_ context.Context, tenantID, poolID, personaID, installID string) (Identity, error) {
			return Identity{
				ID:        "id-123",
				PoolID:    poolID,
				SubjectID: "subject-abc",
				Status:    "claimed",
			}, nil
		},
		CreateGrantFn: func(_ context.Context, tenantID string, req GrantCreateRequest) (Grant, error) {
			grantReq = req
			return Grant{ID: "grant-1", Status: "active", InstallID: req.InstallID}, nil
		},
	}
	r, store := newTestRouter(t, mc)

	// GET /authorize — PKCE is mandatory, so the challenge rides along.
	authURL := "/authorize?" + url.Values{
		"client_id":             {"client-xyz"},
		"redirect_uri":          {"https://app.example.com/cb"},
		"state":                 {"state-1"},
		"scope":                 {"openid mcp"},
		"persona_id":            {"persona-1"},
		"pool_id":               {"pool-1"},
		"tenant_id":             {"tenant-1"},
		"runtime":               {"claude"},
		"code_challenge":        {s256Challenge(testVerifier)},
		"code_challenge_method": {"S256"},
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
		t.Fatalf("authorize: no code in redirect: %s", loc.String())
	}
	if loc.Query().Get("state") != "state-1" {
		t.Fatalf("authorize: state not echoed: %s", loc.String())
	}

	// POST /token — must present the code_verifier matching the challenge.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"client-xyz"},
		"code_verifier": {testVerifier},
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
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tokResp); err != nil {
		t.Fatalf("token: invalid JSON: %v", err)
	}
	if tokResp.AccessToken == "" || tokResp.RefreshToken == "" {
		t.Fatalf("token: empty tokens in response: %+v", tokResp)
	}
	if tokResp.TokenType != "Bearer" {
		t.Fatalf("token: token_type=%q", tokResp.TokenType)
	}
	if tokResp.ExpiresIn != 600 {
		t.Fatalf("token: expires_in=%d, want 600 from persona.TokenTTL", tokResp.ExpiresIn)
	}

	// Access token must be a compact JWS (header.payload.signature); the refresh
	// token stays an opaque UUID with no JWT structure.
	if parts := strings.Split(tokResp.AccessToken, "."); len(parts) != 3 {
		t.Fatalf("access_token is not a 3-part JWS: %q", tokResp.AccessToken)
	}
	if strings.Contains(tokResp.RefreshToken, ".") || len(tokResp.RefreshToken) != 36 {
		t.Fatalf("refresh_token should remain an opaque UUID: %q", tokResp.RefreshToken)
	}

	// The JWT must verify against the JWKS this service serves at the discovery
	// jwks_uri, with the full claim set bound to the install triple.
	v := fetchJWKSVerifier(t, r)
	claimsStd, raw, err := v.Verify(tokResp.AccessToken, time.Now().UTC())
	if err != nil {
		t.Fatalf("access token does not verify against served JWKS: %v", err)
	}
	installs0, _ := store.ListInstalls("tenant-1", 0, time.Time{})
	if len(installs0) != 1 {
		t.Fatalf("expected 1 install, got %d", len(installs0))
	}
	installID := installs0[0].ID
	if claimsStd.Sub != "subject-abc" {
		t.Fatalf("jwt sub = %q, want identity subject_id subject-abc", claimsStd.Sub)
	}
	if claimsStd.Iss != testIssuer {
		t.Fatalf("jwt iss = %q, want %q", claimsStd.Iss, testIssuer)
	}
	if claimsStd.Aud != "client-xyz" {
		t.Fatalf("jwt aud = %q, want DCR client id client-xyz", claimsStd.Aud)
	}
	if claimsStd.TenantID != "tenant-1" {
		t.Fatalf("jwt tenant_id = %q, want tenant-1", claimsStd.TenantID)
	}
	if claimsStd.Scope != "read:docs" {
		t.Fatalf("jwt scope = %q, want persona scopes read:docs", claimsStd.Scope)
	}
	if raw["install_id"] != installID {
		t.Fatalf("jwt install_id = %v, want %s", raw["install_id"], installID)
	}
	if raw["persona_id"] != "persona-1" {
		t.Fatalf("jwt persona_id = %v, want persona-1", raw["persona_id"])
	}
	if raw["identity_id"] != "id-123" {
		t.Fatalf("jwt identity_id = %v, want id-123", raw["identity_id"])
	}
	// exp must reflect the persona TokenTTL (600s) from roughly now.
	expIn := claimsStd.Exp - claimsStd.Iat
	if expIn != 600 {
		t.Fatalf("jwt exp-iat = %d, want 600 (persona TokenTTL)", expIn)
	}
	if got := time.Unix(claimsStd.Exp, 0); got.Before(time.Now().Add(9*time.Minute)) || got.After(time.Now().Add(11*time.Minute)) {
		t.Fatalf("jwt exp = %v not ~10m from now", got)
	}

	// The grant must carry SHA-256 hex digests over the full token strings as
	// issued — i.e. the hash sent to grant-service is hashToken(<the JWT string>)
	// for the access token — never the plaintext tokens.
	if grantReq.AccessTokenHash != hashToken(tokResp.AccessToken) {
		t.Fatalf("grant access_token_hash = %q, want hashToken(<JWT string>)", grantReq.AccessTokenHash)
	}
	if grantReq.RefreshTokenHash != hashToken(tokResp.RefreshToken) {
		t.Fatalf("grant refresh_token_hash = %q, want hashToken(refresh_token)", grantReq.RefreshTokenHash)
	}
	if grantReq.AccessTokenHash == tokResp.AccessToken || strings.Contains(grantReq.AccessTokenHash, tokResp.AccessToken) {
		t.Fatalf("grant access_token_hash leaks the plaintext token: %q", grantReq.AccessTokenHash)
	}

	// Introspection round-trip: the issued bearer token resolves via /userinfo.
	req = httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("userinfo: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var claims map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &claims); err != nil {
		t.Fatalf("userinfo: invalid JSON: %v", err)
	}
	if claims["sub"] != "subject-abc" {
		t.Fatalf("userinfo: sub = %v, want subject-abc", claims["sub"])
	}

	// Install should now be active with the claimed identity id filled in.
	installs, _ := store.ListInstalls("tenant-1", 0, time.Time{})
	if len(installs) != 1 {
		t.Fatalf("expected 1 install, got %d", len(installs))
	}
	got := installs[0]
	if got.Status != InstallStatusActive {
		t.Fatalf("install status = %q, want active", got.Status)
	}
	if got.IdentityID != "id-123" {
		t.Fatalf("install identity_id = %q, want id-123", got.IdentityID)
	}
	if got.PersonaID != "persona-1" || got.ClientID != "client-xyz" || got.Runtime != "claude" {
		t.Fatalf("install fields wrong: %+v", got)
	}

	// GET /v1/installs/{id} should return the install.
	req = httptest.NewRequest(http.MethodGet, "/v1/installs/"+got.ID, nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("install get: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
}

// --- /userinfo hybrid verification: crypto check is independent of the store ---

// A token signed by a *different* key must be rejected even when a matching
// record exists in the local store — proving the cryptographic half of the
// hybrid check fires on its own.
func TestUserInfoRejectsForeignSignedJWT(t *testing.T) {
	r, store := newTestRouter(t, &mockClients{})

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate foreign key: %v", err)
	}
	now := time.Now().UTC()
	foreign, err := jwtx.NewSigner(otherKey).Sign(jwtx.Claims{
		Sub: "subject-abc", Iss: testIssuer, Aud: "client-xyz",
		Exp: now.Add(10 * time.Minute).Unix(), Iat: now.Unix(),
		TenantID: "tenant-1", Scope: "read:docs",
	}, nil)
	if err != nil {
		t.Fatalf("sign foreign token: %v", err)
	}
	// Seed a store record for it so only the signature check can reject.
	_ = store.PutToken(TokenRecord{
		AccessToken: foreign, InstallID: "ins-x", PersonaID: "p", IdentityID: "i",
		Subject: "subject-abc", Scope: "read:docs", TenantID: "tenant-1",
		ExpiresAt: now.Add(10 * time.Minute),
	})

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+foreign)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo with foreign-signed JWT: expected 401, got %d (%s)", w.Code, w.Body.String())
	}
}

// A revoked token must be rejected even though its signature and time window are
// still cryptographically valid — proving the stored-record (deny-list) half of
// the hybrid check fires on its own.
func TestUserInfoRejectsRevokedButValidJWT(t *testing.T) {
	mc := &mockClients{
		GetPersonaFn: func(_ context.Context, tenantID, personaID string) (Persona, error) {
			return Persona{ID: personaID, TenantID: tenantID, Scopes: []string{"mcp"}, TokenTTL: 600}, nil
		},
		ClaimIdentityFn: func(_ context.Context, tenantID, poolID, personaID, installID string) (Identity, error) {
			return Identity{ID: "id-1", PoolID: poolID, SubjectID: "s-1", Status: "claimed"}, nil
		},
		CreateGrantFn: func(_ context.Context, tenantID string, req GrantCreateRequest) (Grant, error) {
			return Grant{ID: "g-1", Status: "active", InstallID: req.InstallID}, nil
		},
	}
	r, store := newTestRouter(t, mc)

	code := "code-revoke-flow"
	_ = store.PutAuthCode(AuthCode{
		Code: code, TenantID: "t", Runtime: "claude",
		PersonaID: "p", PoolID: "pl", ClientID: "c",
		CodeChallenge: s256Challenge(testVerifier),
	})
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {testVerifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("token: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &tok)

	// Sanity: still cryptographically valid right now.
	v := fetchJWKSVerifier(t, r)
	if _, _, err := v.Verify(tok.AccessToken, time.Now().UTC()); err != nil {
		t.Fatalf("freshly issued token must verify: %v", err)
	}

	// Revoke, then /userinfo with the same (still-valid) JWT must 401.
	form = url.Values{"token": {tok.AccessToken}}
	req = httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo with revoked token: expected 401, got %d (%s)", w.Code, w.Body.String())
	}
}

// --- Failure: grant-service returns an error, compensation releases identity ---

func TestTokenGrantFailureReleasesIdentity(t *testing.T) {
	mc := &mockClients{
		GetPersonaFn: func(_ context.Context, tenantID, personaID string) (Persona, error) {
			return Persona{ID: personaID, TenantID: tenantID, Scopes: []string{"mcp"}, TokenTTL: 600}, nil
		},
		ClaimIdentityFn: func(_ context.Context, tenantID, poolID, personaID, installID string) (Identity, error) {
			return Identity{ID: "id-77", PoolID: poolID, SubjectID: "s-77", Status: "claimed"}, nil
		},
		CreateGrantFn: func(_ context.Context, tenantID string, req GrantCreateRequest) (Grant, error) {
			return Grant{}, &DownstreamError{Service: "grant-service", Status: 503, Body: "down"}
		},
	}
	r, store := newTestRouter(t, mc)

	// Seed an auth code directly (short-circuit /authorize for this test).
	code := "code-deadbeef"
	_ = store.PutAuthCode(AuthCode{
		Code: code, TenantID: "tenant-x", Runtime: "custom",
		PersonaID: "p", PoolID: "pl", ClientID: "c",
		RedirectURI:   "https://x/cb",
		CodeChallenge: s256Challenge(testVerifier),
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {testVerifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("token: expected 502, got %d (%s)", w.Code, w.Body.String())
	}
	if mc.ReleaseCalls != 1 {
		t.Fatalf("expected compensation release call, got %d", mc.ReleaseCalls)
	}
	// Install should exist but be revoked.
	installs, _ := store.ListInstalls("tenant-x", 0, time.Time{})
	if len(installs) != 1 {
		t.Fatalf("expected 1 install, got %d", len(installs))
	}
	if installs[0].Status != InstallStatusRevoked {
		t.Fatalf("install status = %q, want revoked", installs[0].Status)
	}
}

// --- Failure: persona-service 404 means the caller misconfigured ---

func TestTokenPersonaNotFoundReturns400(t *testing.T) {
	mc := &mockClients{
		GetPersonaFn: func(_ context.Context, tenantID, personaID string) (Persona, error) {
			return Persona{}, &DownstreamError{Service: "persona-service", Status: 404}
		},
	}
	r, store := newTestRouter(t, mc)
	code := "code-persona-404"
	_ = store.PutAuthCode(AuthCode{
		Code: code, TenantID: "t", Runtime: "claude",
		PersonaID: "missing", PoolID: "pl", ClientID: "c",
		CodeChallenge: s256Challenge(testVerifier),
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {testVerifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (%s)", w.Code, w.Body.String())
	}
}

// --- /authorize validates required params ---

func TestAuthorizeMissingParams(t *testing.T) {
	r, _ := newTestRouter(t, &mockClients{})

	// Missing client_id.
	req := httptest.NewRequest(http.MethodGet, "/authorize?persona_id=p&pool_id=pl&tenant_id=t&redirect_uri=https://x/cb", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 missing client_id, got %d", w.Code)
	}

	// Bad redirect_uri (not absolute) — PKCE params valid so the redirect check fires.
	bad := "/authorize?" + url.Values{
		"client_id": {"c"}, "redirect_uri": {"/relative"},
		"persona_id": {"p"}, "pool_id": {"pl"}, "tenant_id": {"t"},
		"code_challenge": {s256Challenge(testVerifier)}, "code_challenge_method": {"S256"},
	}.Encode()
	req = httptest.NewRequest(http.MethodGet, bad, nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 bad redirect_uri, got %d", w.Code)
	}
}

// --- /authorize enforces PKCE: S256 challenge is mandatory ---

func TestAuthorizePKCERequired(t *testing.T) {
	r, _ := newTestRouter(t, &mockClients{})

	base := url.Values{
		"client_id": {"c"}, "redirect_uri": {"https://x/cb"},
		"persona_id": {"p"}, "pool_id": {"pl"}, "tenant_id": {"t"},
	}

	cases := []struct {
		name      string
		challenge string
		method    string
	}{
		{"missing code_challenge", "", "S256"},
		{"plain method", s256Challenge(testVerifier), "plain"},
		{"missing method (RFC 7636 default is plain)", s256Challenge(testVerifier), ""},
	}
	for _, tc := range cases {
		q := url.Values{}
		for k, v := range base {
			q[k] = v
		}
		if tc.challenge != "" {
			q.Set("code_challenge", tc.challenge)
		}
		if tc.method != "" {
			q.Set("code_challenge_method", tc.method)
		}
		req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d (%s)", tc.name, w.Code, w.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["error"] != "invalid_request" {
			t.Fatalf("%s: error = %v, want invalid_request", tc.name, resp["error"])
		}
	}
}

// --- /token enforces PKCE: code_verifier required and must match ---

// pkceTokenMocks returns a mock set that would let the orchestration succeed —
// the PKCE failures under test must reject before any of it runs.
func pkceTokenMocks() *mockClients {
	return &mockClients{
		GetPersonaFn: func(_ context.Context, tenantID, personaID string) (Persona, error) {
			return Persona{ID: personaID, TenantID: tenantID, Scopes: []string{"mcp"}, TokenTTL: 60}, nil
		},
		ClaimIdentityFn: func(_ context.Context, tenantID, poolID, personaID, installID string) (Identity, error) {
			return Identity{ID: "id-1", PoolID: poolID, SubjectID: "s"}, nil
		},
		CreateGrantFn: func(_ context.Context, tenantID string, req GrantCreateRequest) (Grant, error) {
			return Grant{ID: "g"}, nil
		},
	}
}

func TestTokenWrongVerifierIsInvalidGrant(t *testing.T) {
	r, store := newTestRouter(t, pkceTokenMocks())

	code := "code-pkce-wrong"
	_ = store.PutAuthCode(AuthCode{
		Code: code, TenantID: "t", Runtime: "claude",
		PersonaID: "p", PoolID: "pl", ClientID: "c",
		CodeChallenge: s256Challenge(testVerifier),
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {"definitely-not-the-right-verifier-aaaaaaaaa"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("wrong verifier: expected 400, got %d (%s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier: error = %v, want invalid_grant", resp["error"])
	}

	// The code was consumed by the failed attempt — replay with the *correct*
	// verifier must also fail (one-shot codes are burned, not retried).
	form.Set("code_verifier", testVerifier)
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("replay after failed PKCE: expected 400, got %d", w.Code)
	}
}

func TestTokenMissingVerifierRejectedBeforeCodeBurn(t *testing.T) {
	r, store := newTestRouter(t, pkceTokenMocks())

	code := "code-pkce-missing"
	_ = store.PutAuthCode(AuthCode{
		Code: code, TenantID: "t", Runtime: "claude",
		PersonaID: "p", PoolID: "pl", ClientID: "c",
		CodeChallenge: s256Challenge(testVerifier),
	})

	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing verifier: expected 400, got %d (%s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "invalid_request" {
		t.Fatalf("missing verifier: error = %v, want invalid_request", resp["error"])
	}

	// The missing-verifier check fires before the one-shot consume, so a retry
	// with the proper verifier still succeeds.
	form.Set("code_verifier", testVerifier)
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("retry with verifier: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
}

// A direct-seeded code with no stored challenge must be unusable — there is no
// PKCE-optional path left.
func TestTokenCodeWithoutChallengeIsInvalidGrant(t *testing.T) {
	r, store := newTestRouter(t, pkceTokenMocks())

	code := "code-pre-pkce"
	_ = store.PutAuthCode(AuthCode{
		Code: code, TenantID: "t", Runtime: "claude",
		PersonaID: "p", PoolID: "pl", ClientID: "c",
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {testVerifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("challenge-less code: expected 400, got %d (%s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "invalid_grant" {
		t.Fatalf("challenge-less code: error = %v, want invalid_grant", resp["error"])
	}
}

// --- /token: code replay rejected ---

func TestTokenCodeReplay(t *testing.T) {
	mc := &mockClients{
		GetPersonaFn: func(_ context.Context, tenantID, personaID string) (Persona, error) {
			return Persona{ID: personaID, TenantID: tenantID, TokenTTL: 60}, nil
		},
		ClaimIdentityFn: func(_ context.Context, tenantID, poolID, personaID, installID string) (Identity, error) {
			return Identity{ID: "id-1", PoolID: poolID, SubjectID: "s"}, nil
		},
		CreateGrantFn: func(_ context.Context, tenantID string, req GrantCreateRequest) (Grant, error) {
			return Grant{ID: "g"}, nil
		},
	}
	r, store := newTestRouter(t, mc)

	code := "code-once"
	_ = store.PutAuthCode(AuthCode{
		Code: code, TenantID: "t", Runtime: "cursor",
		PersonaID: "p", PoolID: "pl", ClientID: "c",
		CodeChallenge: s256Challenge(testVerifier),
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {testVerifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first token: expected 200, got %d", w.Code)
	}

	// Replay same code.
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("replayed token: expected 400, got %d", w.Code)
	}
}

// --- /v1/installs requires tenant header ---

func TestInstallsRequireTenantHeader(t *testing.T) {
	r, _ := newTestRouter(t, &mockClients{})
	req := httptest.NewRequest(http.MethodGet, "/v1/installs/any-id", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without tenant header, got %d", w.Code)
	}
}

// --- GET /v1/installs: keyset pagination ---

// seedInstalls inserts n installs for tenantID with strictly increasing CreatedAt
// (1s apart) and predictable ids ins-0..ins-(n-1).
func seedInstalls(t *testing.T, store Storage, tenantID string, n int) time.Time {
	t.Helper()
	base := time.Now().UTC().Add(-time.Duration(n) * time.Minute).Truncate(time.Millisecond)
	for k := 0; k < n; k++ {
		ts := base.Add(time.Duration(k) * time.Second)
		if _, err := store.CreateInstall(Install{
			ID: fmt.Sprintf("ins-%d", k), TenantID: tenantID, Runtime: RuntimeClaude,
			PersonaID: "p", ClientID: "c", Status: InstallStatusPending,
			CreatedAt: ts, UpdatedAt: ts,
		}); err != nil {
			t.Fatalf("seed install %d: %v", k, err)
		}
	}
	return base
}

func TestListInstallsTwoPageWalk(t *testing.T) {
	r, store := newTestRouter(t, &mockClients{})
	seedInstalls(t, store, "tenant-1", 3)

	// Page 1: newest two, full page -> cursor emitted.
	req := httptest.NewRequest(http.MethodGet, "/v1/installs?limit=2", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list page 1: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var page1 InstallListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &page1); err != nil {
		t.Fatalf("list page 1: invalid JSON: %v", err)
	}
	if len(page1.Installs) != 2 {
		t.Fatalf("page 1: want 2 installs, got %d", len(page1.Installs))
	}
	if page1.Installs[0].ID != "ins-2" || page1.Installs[1].ID != "ins-1" {
		t.Fatalf("page 1 not newest-first: %s, %s", page1.Installs[0].ID, page1.Installs[1].ID)
	}
	if page1.NextCursor == "" {
		t.Fatal("page 1: expected next_cursor when page is full")
	}

	// Page 2: strictly older than the cursor.
	req = httptest.NewRequest(http.MethodGet, "/v1/installs?limit=2&cursor="+url.QueryEscape(page1.NextCursor), nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list page 2: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var page2 InstallListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &page2); err != nil {
		t.Fatalf("list page 2: invalid JSON: %v", err)
	}
	if len(page2.Installs) != 1 || page2.Installs[0].ID != "ins-0" {
		t.Fatalf("page 2: want [ins-0], got %+v", page2.Installs)
	}
	if page2.NextCursor != "" {
		t.Fatalf("page 2: final partial page should not emit a cursor, got %q", page2.NextCursor)
	}
}

func TestListInstallsInvalidParams(t *testing.T) {
	r, _ := newTestRouter(t, &mockClients{})
	cases := []struct {
		query    string
		wantCode string
	}{
		{"limit=0", "invalid_limit"},
		{"limit=-3", "invalid_limit"},
		{"limit=abc", "invalid_limit"},
		{"cursor=not-a-timestamp", "invalid_cursor"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/v1/installs?"+tc.query, nil)
		req.Header.Set("X-Tenant-Id", "tenant-1")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d (%s)", tc.query, w.Code, w.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["error"] != tc.wantCode {
			t.Fatalf("%s: error = %v, want %s", tc.query, resp["error"], tc.wantCode)
		}
	}
}

// --- MemStorage.PurgeExpired removes expired artifacts, keeps live ones ---

func TestMemPurgeExpired(t *testing.T) {
	store := NewMemStorage()
	now := time.Now().UTC()

	// Tokens: one expired, one live.
	_ = store.PutToken(TokenRecord{
		AccessToken: "tok-expired", InstallID: "i1", TenantID: "t",
		ExpiresAt: now.Add(-time.Minute),
	})
	_ = store.PutToken(TokenRecord{
		AccessToken: "tok-live", InstallID: "i1", TenantID: "t",
		ExpiresAt: now.Add(10 * time.Minute),
	})

	// Auth codes: one past the AuthCodeTTLSeconds window, one fresh.
	_ = store.PutAuthCode(AuthCode{
		Code: "code-expired", TenantID: "t", Runtime: RuntimeClaude,
		PersonaID: "p", ClientID: "c",
		CreatedAt: now.Add(-time.Duration(AuthCodeTTLSeconds+60) * time.Second),
	})
	_ = store.PutAuthCode(AuthCode{
		Code: "code-live", TenantID: "t", Runtime: RuntimeClaude,
		PersonaID: "p", ClientID: "c",
		CreatedAt: now,
	})

	removed, err := store.PurgeExpired(now)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2 (one token + one code)", removed)
	}

	if _, err := store.GetToken("tok-expired"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired token should be gone, got %v", err)
	}
	if _, err := store.GetToken("tok-live"); err != nil {
		t.Fatalf("live token should survive the purge: %v", err)
	}
	if _, err := store.ConsumeAuthCode("code-expired"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired code should be gone, got %v", err)
	}
	if _, err := store.ConsumeAuthCode("code-live"); err != nil {
		t.Fatalf("live code should survive the purge: %v", err)
	}

	// Idempotent: a second sweep finds nothing.
	removed, err = store.PurgeExpired(now)
	if err != nil || removed != 0 {
		t.Fatalf("second purge: removed=%d err=%v, want 0/nil", removed, err)
	}
}

// --- Install revoke cascades to grants and identity release ---

func TestInstallRevokeCascades(t *testing.T) {
	mc := &mockClients{}
	r, store := newTestRouter(t, mc)

	// Seed an active install directly.
	ins, _ := store.CreateInstall(Install{
		ID: "ins-1", TenantID: "t", Runtime: "claude",
		PersonaID: "p", ClientID: "c", IdentityID: "id-99",
		Status: InstallStatusActive,
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/installs/"+ins.ID+"/revoke", nil)
	req.Header.Set("X-Tenant-Id", "t")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("revoke: expected 204, got %d (%s)", w.Code, w.Body.String())
	}
	if mc.RevokeCalls != 1 {
		t.Fatalf("expected grant revoke call, got %d", mc.RevokeCalls)
	}
	if mc.ReleaseCalls != 1 {
		t.Fatalf("expected identity release call, got %d", mc.ReleaseCalls)
	}
	got, _ := store.GetInstall("t", ins.ID)
	if got.Status != InstallStatusRevoked {
		t.Fatalf("install status after revoke = %q, want revoked", got.Status)
	}

	// Idempotent second revoke.
	req = httptest.NewRequest(http.MethodPost, "/v1/installs/"+ins.ID+"/revoke", nil)
	req.Header.Set("X-Tenant-Id", "t")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("second revoke: expected 204, got %d", w.Code)
	}
}

// --- DCR returns a client_id/client_secret pair ---

func TestDCRRegisterReturnsCredentials(t *testing.T) {
	r, _ := newTestRouter(t, &mockClients{})
	body := strings.NewReader(`{"redirect_uris":["https://x/cb"],"client_name":"Example"}`)
	req := httptest.NewRequest(http.MethodPost, "/register", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("register: invalid JSON: %v", err)
	}
	if resp["client_id"] == nil || resp["client_secret"] == nil {
		t.Fatalf("register: missing creds: %v", resp)
	}
	// Input metadata is echoed back.
	if resp["client_name"] != "Example" {
		t.Fatalf("register: client_name not echoed: %v", resp["client_name"])
	}
}

// --- Healthz is tenant-free ---

func TestHealthzNoTenant(t *testing.T) {
	r, _ := newTestRouter(t, &mockClients{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: expected 200, got %d", w.Code)
	}
}

// --- Discovery docs carry the configured issuer ---

func TestDiscoveryDocs(t *testing.T) {
	r, _ := newTestRouter(t, &mockClients{})
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
		if doc["issuer"] != testIssuer {
			t.Fatalf("%s: issuer = %v, want %s", path, doc["issuer"], testIssuer)
		}
		if doc["jwks_uri"] != testIssuer+"/.well-known/jwks.json" {
			t.Fatalf("%s: jwks_uri = %v, want %s/.well-known/jwks.json", path, doc["jwks_uri"], testIssuer)
		}
		// PKCE: the advertised method list must be exactly ["S256"] — plain is
		// not supported and /authorize enforces what is advertised here.
		methods, ok := doc["code_challenge_methods_supported"].([]any)
		if !ok || len(methods) != 1 || methods[0] != "S256" {
			t.Fatalf("%s: code_challenge_methods_supported = %v, want [S256]",
				path, doc["code_challenge_methods_supported"])
		}
	}
}

// --- Sanity: DownstreamError Unwrap ---

func TestDownstreamErrorUnwrap(t *testing.T) {
	inner := errors.New("boom")
	e := &DownstreamError{Service: "x", Err: inner}
	if !errors.Is(e, inner) {
		t.Fatalf("DownstreamError does not unwrap inner error")
	}
}

// --- hashToken is a real SHA-256 hex digest ---

func TestHashTokenDigest(t *testing.T) {
	h := hashToken("some-opaque-token")
	if len(h) != 64 {
		t.Fatalf("hashToken length = %d, want 64 hex chars", len(h))
	}
	if _, err := hex.DecodeString(h); err != nil {
		t.Fatalf("hashToken output is not valid hex: %q (%v)", h, err)
	}
	if strings.Contains(h, "some-opaque-token") || strings.HasPrefix(h, "stub-hash:") {
		t.Fatalf("hashToken leaks plaintext or stub prefix: %q", h)
	}
	if h != hashToken("some-opaque-token") {
		t.Fatalf("hashToken is not deterministic")
	}
	if h == hashToken("another-token") {
		t.Fatalf("hashToken collided on trivially different inputs")
	}
}

// --- HTTPClients propagate context cancellation to downstream calls ---

func TestClientContextCancellation(t *testing.T) {
	// Downstream stub that would answer successfully — the cancelled context must
	// abort the call before this response is consumed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Persona{ID: "p"})
	}))
	defer srv.Close()

	c := NewHTTPClients(nil, srv.URL, srv.URL, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	_, err := c.GetPersona(ctx, "t", "p")
	if err == nil {
		t.Fatalf("GetPersona with cancelled context: expected error, got nil")
	}
	var dse *DownstreamError
	if !errors.As(err, &dse) {
		t.Fatalf("expected DownstreamError, got %T (%v)", err, err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected error to wrap context.Canceled, got %v", err)
	}
}

// --- HTTPClients hit the /internal/v1 trees and carry X-Internal-Auth ---

// TestClientInternalAuthAndPaths spins up one fake downstream standing in for all
// three sister services and drives every HTTPClients method through it, asserting
// (a) each call targets the service-to-service /internal/v1/ tree (ARCHITECTURE.md
// §10.3) and (b) every outbound request carries the X-Internal-Auth shared secret
// when INTERNAL_AUTH_SECRET is set.
func TestClientInternalAuthAndPaths(t *testing.T) {
	t.Setenv(httpx.EnvInternalAuthSecret, "test-internal-secret")

	type seen struct {
		method, path, auth string
	}
	var got []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, seen{r.Method, r.URL.Path, r.Header.Get(httpx.InternalAuthHeader)})
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "x"})
	}))
	defer srv.Close()

	c := NewHTTPClients(nil, srv.URL, srv.URL, srv.URL)
	ctx := context.Background()

	if _, err := c.GetPersona(ctx, "t", "p1"); err != nil {
		t.Fatalf("GetPersona: %v", err)
	}
	if _, err := c.ClaimIdentity(ctx, "t", "pl1", "p1", "ins1"); err != nil {
		t.Fatalf("ClaimIdentity: %v", err)
	}
	if err := c.ReleaseIdentity(ctx, "t", "id1"); err != nil {
		t.Fatalf("ReleaseIdentity: %v", err)
	}
	if _, err := c.CreateGrant(ctx, "t", GrantCreateRequest{InstallID: "ins1"}); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	if err := c.RevokeGrantsForInstall(ctx, "t", "ins1"); err != nil {
		t.Fatalf("RevokeGrantsForInstall: %v", err)
	}
	if err := c.RevokeToken(ctx, "t", "tok"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	want := []seen{
		{http.MethodGet, "/internal/v1/personas/p1", "test-internal-secret"},
		{http.MethodPost, "/internal/v1/pools/pl1/claim", "test-internal-secret"},
		{http.MethodPost, "/internal/v1/identities/id1/release", "test-internal-secret"},
		{http.MethodPost, "/internal/v1/grants", "test-internal-secret"},
		{http.MethodPost, "/internal/v1/installs/ins1/revoke-grants", "test-internal-secret"},
		{http.MethodPost, "/internal/v1/revoke", "test-internal-secret"},
	}
	if len(got) != len(want) {
		t.Fatalf("downstream saw %d requests, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("call %d: got %+v, want %+v", i, got[i], w)
		}
	}
}

// --- Revoke cascade survives a caller that disconnected mid-request ---

func TestInstallRevokeCascadeSurvivesCancelledRequest(t *testing.T) {
	var grantsCtxErr, releaseCtxErr error
	mc := &mockClients{
		RevokeGrantsForInstallFn: func(ctx context.Context, _, _ string) error {
			grantsCtxErr = ctx.Err()
			return nil
		},
		ReleaseIdentityFn: func(ctx context.Context, _, _ string) error {
			releaseCtxErr = ctx.Err()
			return nil
		},
	}
	r, store := newTestRouter(t, mc)

	ins, _ := store.CreateInstall(Install{
		ID: "ins-cancel", TenantID: "t", Runtime: "claude",
		PersonaID: "p", ClientID: "c", IdentityID: "id-55",
		Status: InstallStatusActive,
	})

	// Simulate the caller disconnecting: the request context is already cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/v1/installs/"+ins.ID+"/revoke", nil).WithContext(ctx)
	req.Header.Set("X-Tenant-Id", "t")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if mc.RevokeCalls != 1 || mc.ReleaseCalls != 1 {
		t.Fatalf("cascade calls = revoke:%d release:%d, want 1/1", mc.RevokeCalls, mc.ReleaseCalls)
	}
	if grantsCtxErr != nil {
		t.Fatalf("RevokeGrantsForInstall received cancelled context: %v", grantsCtxErr)
	}
	if releaseCtxErr != nil {
		t.Fatalf("ReleaseIdentity received cancelled context: %v", releaseCtxErr)
	}
}
