package internal

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

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
	r := Router(Deps{
		Store:      store,
		Logger:     logger,
		Clients:    mc,
		Issuer:     "http://test.local",
		DefaultTTL: 900,
	})
	return r, store
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

	// GET /authorize
	authURL := "/authorize?" + url.Values{
		"client_id":    {"client-xyz"},
		"redirect_uri": {"https://app.example.com/cb"},
		"state":        {"state-1"},
		"scope":        {"openid mcp"},
		"persona_id":   {"persona-1"},
		"pool_id":      {"pool-1"},
		"tenant_id":    {"tenant-1"},
		"runtime":      {"claude"},
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

	// POST /token
	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
		"client_id":  {"client-xyz"},
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

	// The grant must carry SHA-256 hex digests, never the plaintext tokens.
	if grantReq.AccessTokenHash != hashToken(tokResp.AccessToken) {
		t.Fatalf("grant access_token_hash = %q, want hashToken(access_token)", grantReq.AccessTokenHash)
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
	installs, _ := store.ListInstalls("tenant-1")
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
		RedirectURI: "https://x/cb",
	})

	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
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
	installs, _ := store.ListInstalls("tenant-x")
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
	})

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}}
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

	// Bad redirect_uri (not absolute).
	bad := "/authorize?" + url.Values{
		"client_id": {"c"}, "redirect_uri": {"/relative"},
		"persona_id": {"p"}, "pool_id": {"pl"}, "tenant_id": {"t"},
	}.Encode()
	req = httptest.NewRequest(http.MethodGet, bad, nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 bad redirect_uri, got %d", w.Code)
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
	})

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}}
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
		if doc["issuer"] != "http://test.local" {
			t.Fatalf("%s: issuer = %v, want http://test.local", path, doc["issuer"])
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

	c := NewHTTPClients(srv.URL, srv.URL, srv.URL)
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
