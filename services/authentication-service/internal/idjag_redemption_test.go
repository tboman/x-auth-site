package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/jwtx"
)

// redemptionFixture builds a router + store where X-Auth is the RESOURCE
// authorization server: a tenant-bound public client ("the requesting app"),
// and a trusted-IdP registry entry for the test signer's issuer whose JWKS URI
// points at a live httptest server serving the router's own JWKS document —
// the exact remote-fetch path a real external IdP would exercise.
func redemptionFixture(t *testing.T) (http.Handler, Storage, string) {
	t.Helper()
	r, store := newTestRouter(t)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	jwksURI := srv.URL + "/.well-known/jwks.json"

	now := time.Now().UTC()
	if err := store.PutClient(OIDCClient{ClientID: "cli_agent", TenantID: "ten_res", CreatedAt: now}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	if err := store.CreateTrustedIDP(TrustedIDP{
		ID: "idp_1", TenantID: "ten_res", Name: "Test IdP", Issuer: "http://test.local",
		JWKSURI: jwksURI, Enabled: true, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed trusted idp: %v", err)
	}
	return r, store, jwksURI
}

// mintAssertion signs an ID-JAG the way a standards-following IdP would:
// typ oauth-id-jag+jwt, aud = the resource AS's issuer identifier, client_id =
// the requesting app's client at the resource AS. overrides mutates the claims
// before signing.
func mintAssertion(t *testing.T, scope string, overrides func(*jwtx.Claims, map[string]any)) string {
	t.Helper()
	now := time.Now().UTC()
	claims := jwtx.Claims{
		Sub: "usr_alice", Iss: "http://test.local", Aud: "http://test.local",
		Exp: now.Add(IDJAGTTLSeconds * time.Second).Unix(), Iat: now.Unix(),
		JTI: uuid.NewString(), TenantID: "ten_idp", Scope: scope,
	}
	extra := map[string]any{"client_id": "cli_agent"}
	if overrides != nil {
		overrides(&claims, extra)
	}
	assertion, err := testSigner.SignTyped(claims, extra, IDJAGTypeHeader)
	if err != nil {
		t.Fatalf("mint assertion: %v", err)
	}
	return assertion
}

func baseRedemptionForm(assertion string) url.Values {
	return url.Values{
		"grant_type": {GrantTypeJWTBearer},
		"assertion":  {assertion},
		"client_id":  {"cli_agent"},
	}
}

func TestIDJAGRedemptionHappyPath(t *testing.T) {
	r, store, _ := redemptionFixture(t)
	assertion := mintAssertion(t, "crm.read crm.write", nil)

	w := tokenExchange(t, r, baseRedemptionForm(assertion))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", resp["token_type"])
	}
	if int(resp["expires_in"].(float64)) != AccessTokenTTLSeconds {
		t.Errorf("expires_in = %v, want %d", resp["expires_in"], AccessTokenTTLSeconds)
	}
	if resp["scope"] != "crm.read crm.write" {
		t.Errorf("scope = %v, want the assertion's scopes", resp["scope"])
	}
	// The draft: the ID-JAG replaces the refresh token — none may be returned.
	if _, ok := resp["refresh_token"]; ok {
		t.Errorf("response must not contain a refresh_token")
	}

	// The minted access token is a normal X-Auth bearer: verifiable against our
	// JWKS, typ JWT, audience = the requesting client, tenant = the client's
	// workspace — and present on the deny list for revocation.
	access := resp["access_token"].(string)
	v := verifierFromJWKSEndpoint(t, r, "/.well-known/jwks.json")
	claims, _, err := v.Verify(access, time.Now().UTC())
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if claims.Sub != "usr_alice" || claims.Aud != "cli_agent" || claims.TenantID != "ten_res" {
		t.Errorf("claims = sub %q aud %q tenant %q", claims.Sub, claims.Aud, claims.TenantID)
	}
	hdr := decodeJOSEHeader(t, access)
	if hdr["typ"] != "JWT" {
		t.Errorf("header typ = %v, want JWT (an access token, not another grant)", hdr["typ"])
	}
	tok, err := store.GetTokenByHash(HashToken(access))
	if err != nil || tok.TokenType != TokenTypeAccess {
		t.Fatalf("access token record missing: %v %+v", err, tok)
	}
}

func TestIDJAGRedemptionReplayRejected(t *testing.T) {
	r, _, _ := redemptionFixture(t)
	assertion := mintAssertion(t, "crm.read", nil)

	if w := tokenExchange(t, r, baseRedemptionForm(assertion)); w.Code != http.StatusOK {
		t.Fatalf("first redemption: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	// Single-use jti: presenting the same assertion twice is a replay.
	w := tokenExchange(t, r, baseRedemptionForm(assertion))
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_grant")
}

func TestIDJAGRedemptionRejectsPlainJWT(t *testing.T) {
	r, _, _ := redemptionFixture(t)
	now := time.Now().UTC()
	// A typ:JWT token (access/ID token) is not an authorization grant.
	plain, err := testSigner.Sign(jwtx.Claims{
		Sub: "usr_alice", Iss: "http://test.local", Aud: "http://test.local",
		Exp: now.Add(time.Hour).Unix(), Iat: now.Unix(), JTI: uuid.NewString(),
	}, map[string]any{"client_id": "cli_agent"})
	if err != nil {
		t.Fatalf("mint plain JWT: %v", err)
	}
	w := tokenExchange(t, r, baseRedemptionForm(plain))
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_grant")
}

func TestIDJAGRedemptionUntrustedIssuer(t *testing.T) {
	r, _, _ := redemptionFixture(t)
	assertion := mintAssertion(t, "crm.read", func(c *jwtx.Claims, _ map[string]any) {
		c.Iss = "http://evil.local"
	})
	w := tokenExchange(t, r, baseRedemptionForm(assertion))
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_grant")
}

func TestIDJAGRedemptionDisabledIdP(t *testing.T) {
	r, store, _ := redemptionFixture(t)
	if err := store.SetTrustedIDPEnabled("ten_res", "idp_1", false); err != nil {
		t.Fatalf("disable idp: %v", err)
	}
	w := tokenExchange(t, r, baseRedemptionForm(mintAssertion(t, "crm.read", nil)))
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_grant")
}

func TestIDJAGRedemptionWrongAudience(t *testing.T) {
	r, _, _ := redemptionFixture(t)
	assertion := mintAssertion(t, "crm.read", func(c *jwtx.Claims, _ map[string]any) {
		c.Aud = "https://some-other-as.example"
	})
	w := tokenExchange(t, r, baseRedemptionForm(assertion))
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_grant")
}

func TestIDJAGRedemptionClientMismatch(t *testing.T) {
	r, store, _ := redemptionFixture(t)
	if err := store.PutClient(OIDCClient{ClientID: "cli_other", TenantID: "ten_res", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("seed second client: %v", err)
	}
	// The assertion names cli_agent; cli_other must not be able to redeem it.
	form := baseRedemptionForm(mintAssertion(t, "crm.read", nil))
	form.Set("client_id", "cli_other")
	w := tokenExchange(t, r, form)
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_grant")
}

func TestIDJAGRedemptionUnknownClient(t *testing.T) {
	r, _, _ := redemptionFixture(t)
	form := baseRedemptionForm(mintAssertion(t, "crm.read", nil))
	form.Set("client_id", "cli_ghost")
	w := tokenExchange(t, r, form)
	assertOAuthError(t, w, http.StatusUnauthorized, "invalid_client")
}

func TestIDJAGRedemptionUnboundClient(t *testing.T) {
	r, _, _ := redemptionFixture(t)
	// The seeded dev client has no tenant — no trusted-IdP policy can apply.
	form := baseRedemptionForm(mintAssertion(t, "crm.read", func(_ *jwtx.Claims, extra map[string]any) {
		extra["client_id"] = DefaultClientID
	}))
	form.Set("client_id", DefaultClientID)
	w := tokenExchange(t, r, form)
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_grant")
}

func TestIDJAGRedemptionScopeCap(t *testing.T) {
	r, store, jwksURI := redemptionFixture(t)
	if err := store.DeleteTrustedIDP("ten_res", "idp_1"); err != nil {
		t.Fatalf("reset idp: %v", err)
	}
	// Re-register with a cap: local policy narrows what the IdP granted.
	if err := store.CreateTrustedIDP(TrustedIDP{
		ID: "idp_capped", TenantID: "ten_res", Name: "Capped IdP", Issuer: "http://test.local",
		JWKSURI: jwksURI, Scopes: []string{"crm.read"},
		Enabled: true, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed capped idp: %v", err)
	}

	w := tokenExchange(t, r, baseRedemptionForm(mintAssertion(t, "crm.read crm.write", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Scope string `json:"scope"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Scope != "crm.read" {
		t.Errorf("scope = %q, want the registry cap crm.read", resp.Scope)
	}
}

func TestIDJAGRedemptionScopeParam(t *testing.T) {
	r, _, _ := redemptionFixture(t)

	// A scope parameter may narrow the assertion's grant…
	form := baseRedemptionForm(mintAssertion(t, "crm.read crm.write", nil))
	form.Set("scope", "crm.read")
	w := tokenExchange(t, r, form)
	if w.Code != http.StatusOK {
		t.Fatalf("narrowing: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Scope string `json:"scope"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Scope != "crm.read" {
		t.Errorf("scope = %q, want crm.read", resp.Scope)
	}

	// …but never exceed it.
	form = baseRedemptionForm(mintAssertion(t, "crm.read", nil))
	form.Set("scope", "crm.admin")
	w = tokenExchange(t, r, form)
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_scope")
}

func TestIDJAGRedemptionMissingAssertion(t *testing.T) {
	r, _, _ := redemptionFixture(t)
	w := tokenExchange(t, r, url.Values{"grant_type": {GrantTypeJWTBearer}, "client_id": {"cli_agent"}})
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_request")
}

// TestDiscoveryAdvertisesXAARedemption pins the metadata the draft asks a
// resource authorization server to publish: the jwt-bearer grant plus the
// id-jag grant profile, on both discovery documents.
func TestDiscoveryAdvertisesXAARedemption(t *testing.T) {
	r, _ := newTestRouter(t)
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, w.Code)
		}
		var doc struct {
			GrantTypes    []string `json:"grant_types_supported"`
			GrantProfiles []string `json:"authorization_grant_profiles_supported"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s: bad JSON: %v", path, err)
		}
		if !containsString(doc.GrantTypes, GrantTypeJWTBearer) {
			t.Errorf("%s: grant_types_supported %v missing %s", path, doc.GrantTypes, GrantTypeJWTBearer)
		}
		if !containsString(doc.GrantProfiles, IDJAGGrantProfile) {
			t.Errorf("%s: authorization_grant_profiles_supported %v missing %s", path, doc.GrantProfiles, IDJAGGrantProfile)
		}
	}
}

func containsString(haystack []string, want string) bool {
	for _, s := range haystack {
		if s == want {
			return true
		}
	}
	return false
}

// TestXAAEndToEndSelfFederation drives the FULL Cross-App Access loop with
// X-Auth on both sides of the trust: (1) the IdP mints an ID-JAG via RFC 8693
// token exchange for an allow-listed resource, (2) the resource authorization
// server redeems it via RFC 7523 jwt-bearer for a Bearer access token, (3) the
// access token works against /userinfo, and (4) the assertion cannot be
// redeemed twice.
func TestXAAEndToEndSelfFederation(t *testing.T) {
	r, store := newTestRouter(t)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	const (
		tenant   = "ten_acme"
		userID   = "usr_alice"
		clientID = "cli_agent"
		// The resource is X-Auth itself: its resource URI is the resource AS's
		// issuer identifier, so the minted assertion's aud lands on this server.
		resource = "http://test.local"
	)
	now := time.Now().UTC()

	// IdP side: the tenant allow-lists the resource for issuance.
	if err := store.CreateMCPServer(MCPServer{
		ID: "mcp_self", TenantID: tenant, Name: "X-Auth itself", ResourceURI: resource,
		Scopes: []string{"crm.read", "crm.write"}, Enabled: true, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed MCP server: %v", err)
	}
	// Resource side: same workspace registers the requesting app and trusts the
	// IdP (itself), with the JWKS fetched over live HTTP.
	if err := store.PutClient(OIDCClient{ClientID: clientID, TenantID: tenant, CreatedAt: now}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	if err := store.CreateTrustedIDP(TrustedIDP{
		ID: "idp_self", TenantID: tenant, Name: "X-Auth (self)", Issuer: "http://test.local",
		JWKSURI: srv.URL + "/.well-known/jwks.json", Enabled: true, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed trusted idp: %v", err)
	}
	// A local user so /userinfo can resolve the redeemed token's subject.
	if _, err := store.CreateUser(User{ID: userID, TenantID: tenant, Email: "alice@acme.test", Name: "Alice", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// The requesting app's existing user session at the IdP: a stored access token.
	subject, err := testSigner.Sign(jwtx.Claims{
		Sub: userID, Iss: "http://test.local", Aud: clientID,
		Exp: now.Add(time.Hour).Unix(), Iat: now.Unix(), TenantID: tenant,
		Scope: "openid", SessionID: "ses_x",
	}, nil)
	if err != nil {
		t.Fatalf("mint subject token: %v", err)
	}
	if err := store.PutToken(Token{
		TokenHash: HashToken(subject), SessionID: "ses_x", UserID: userID, TenantID: tenant,
		ClientID: clientID, TokenType: TokenTypeAccess, Scope: "openid",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("store subject token: %v", err)
	}

	// Leg 1 — RFC 8693 token exchange: subject token â†’ ID-JAG.
	exchange := baseExchangeForm(subject, resource)
	exchange.Set("scope", "crm.read")
	w := tokenExchange(t, r, exchange)
	if w.Code != http.StatusOK {
		t.Fatalf("issuance: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var issued struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatalf("issuance: bad JSON: %v", err)
	}

	// Leg 2 — RFC 7523 jwt-bearer: ID-JAG â†’ Bearer access token.
	redeem := url.Values{
		"grant_type": {GrantTypeJWTBearer},
		"assertion":  {issued.AccessToken},
		"client_id":  {clientID},
	}
	w = tokenExchange(t, r, redeem)
	if w.Code != http.StatusOK {
		t.Fatalf("redemption: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var redeemed struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &redeemed); err != nil {
		t.Fatalf("redemption: bad JSON: %v", err)
	}
	if redeemed.TokenType != "Bearer" || redeemed.Scope != "crm.read" {
		t.Errorf("redeemed = type %q scope %q, want Bearer / crm.read", redeemed.TokenType, redeemed.Scope)
	}

	// Leg 3 — the redeemed token is a first-class bearer: /userinfo resolves it.
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+redeemed.AccessToken)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/userinfo: expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var ui struct {
		Sub string `json:"sub"`
	}
	json.Unmarshal(rec.Body.Bytes(), &ui)
	if ui.Sub != userID {
		t.Errorf("/userinfo sub = %q, want %q", ui.Sub, userID)
	}

	// Leg 4 — the assertion is single-use.
	w = tokenExchange(t, r, redeem)
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_grant")
}
