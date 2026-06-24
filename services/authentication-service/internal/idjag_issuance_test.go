package internal

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/jwtx"
)

// idjagFixture builds a router + store with one tenant, one enabled MCP server,
// and a freshly minted, stored access token for a user in that tenant — the
// subject token a requesting app would present. Returns the token plaintext and
// the resource URI / client_id baked into it.
func idjagFixture(t *testing.T) (http.Handler, Storage, string, string, string) {
	t.Helper()
	r, store := newTestRouter(t)

	const (
		tenant   = "ten_acme"
		userID   = "usr_alice"
		clientID = "cli_agent"
		resource = "https://mcp.acme.com"
	)
	if err := store.CreateMCPServer(MCPServer{
		ID: "mcp_1", TenantID: tenant, Name: "Acme CRM", ResourceURI: resource,
		Scopes: []string{"crm.read", "crm.write"}, Enabled: true, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed MCP server: %v", err)
	}

	// Mint an access token exactly as issueTokenPair would (iss must match the
	// router's verifier issuer, "http://test.local"), and persist its record so
	// the deny-list lookup in handleTokenExchange finds it.
	now := time.Now().UTC()
	access, err := testSigner.Sign(jwtx.Claims{
		Sub: userID, Iss: "http://test.local", Aud: clientID,
		Exp: now.Add(time.Hour).Unix(), Iat: now.Unix(), TenantID: tenant,
		Scope: "openid", SessionID: "ses_x",
	}, nil)
	if err != nil {
		t.Fatalf("mint subject token: %v", err)
	}
	if err := store.PutToken(Token{
		TokenHash: HashToken(access), SessionID: "ses_x", UserID: userID, TenantID: tenant,
		ClientID: clientID, TokenType: TokenTypeAccess, Scope: "openid",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("store subject token: %v", err)
	}
	return r, store, access, resource, clientID
}

func tokenExchange(t *testing.T, r http.Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func baseExchangeForm(subjectToken, resource string) url.Values {
	return url.Values{
		"grant_type":           {GrantTypeTokenExchange},
		"requested_token_type": {TokenTypeIDJAG},
		"subject_token":        {subjectToken},
		"subject_token_type":   {TokenTypeAccessToken},
		"resource":             {resource},
	}
}

func TestIDJAGIssuanceHappyPath(t *testing.T) {
	r, _, access, resource, clientID := idjagFixture(t)

	form := baseExchangeForm(access, resource)
	form.Set("scope", "crm.read")
	w := tokenExchange(t, r, form)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}

	var resp struct {
		IssuedTokenType string `json:"issued_token_type"`
		AccessToken     string `json:"access_token"`
		TokenType       string `json:"token_type"`
		ExpiresIn       int    `json:"expires_in"`
		Scope           string `json:"scope"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp.IssuedTokenType != TokenTypeIDJAG {
		t.Errorf("issued_token_type = %q, want %q", resp.IssuedTokenType, TokenTypeIDJAG)
	}
	if resp.TokenType != "N_A" {
		t.Errorf("token_type = %q, want N_A", resp.TokenType)
	}
	if resp.ExpiresIn != IDJAGTTLSeconds {
		t.Errorf("expires_in = %d, want %d", resp.ExpiresIn, IDJAGTTLSeconds)
	}
	if resp.Scope != "crm.read" {
		t.Errorf("scope = %q, want crm.read", resp.Scope)
	}

	// The assertion verifies against our own JWKS, with the resource as audience.
	v := verifierFromJWKSEndpoint(t, r, "/.well-known/jwks.json")
	claims, raw, err := v.Verify(resp.AccessToken, time.Now().UTC())
	if err != nil {
		t.Fatalf("verify ID-JAG: %v", err)
	}
	if claims.Aud != resource {
		t.Errorf("aud = %q, want resource %q", claims.Aud, resource)
	}
	if claims.Sub != "usr_alice" {
		t.Errorf("sub = %q, want usr_alice", claims.Sub)
	}
	if claims.Scope != "crm.read" {
		t.Errorf("scope claim = %q, want crm.read", claims.Scope)
	}
	if raw["client_id"] != clientID {
		t.Errorf("client_id claim = %v, want %q", raw["client_id"], clientID)
	}

	// And it carries the ID-JAG media type in the JOSE header.
	hdr := decodeJOSEHeader(t, resp.AccessToken)
	if hdr["typ"] != IDJAGTypeHeader {
		t.Errorf("header typ = %v, want %q", hdr["typ"], IDJAGTypeHeader)
	}
}

func TestIDJAGEmptyScopeInheritsAuthorized(t *testing.T) {
	r, _, access, resource, _ := idjagFixture(t)
	// No scope requested → inherits the server's full authorized set.
	w := tokenExchange(t, r, baseExchangeForm(access, resource))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Scope string `json:"scope"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Scope != "crm.read crm.write" {
		t.Errorf("scope = %q, want full authorized set", resp.Scope)
	}
}

func TestIDJAGUnauthorizedResource(t *testing.T) {
	r, _, access, _, _ := idjagFixture(t)
	w := tokenExchange(t, r, baseExchangeForm(access, "https://mcp.evil.com"))
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_target")
}

func TestIDJAGDisabledResource(t *testing.T) {
	r, store, access, resource, _ := idjagFixture(t)
	if err := store.SetMCPServerEnabled("ten_acme", "mcp_1", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	w := tokenExchange(t, r, baseExchangeForm(access, resource))
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_target")
}

func TestIDJAGScopeExceedsAuthorized(t *testing.T) {
	r, _, access, resource, _ := idjagFixture(t)
	form := baseExchangeForm(access, resource)
	form.Set("scope", "crm.read crm.admin") // crm.admin not authorized
	w := tokenExchange(t, r, form)
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_scope")
}

func TestIDJAGBadSubjectToken(t *testing.T) {
	r, _, _, resource, _ := idjagFixture(t)
	w := tokenExchange(t, r, baseExchangeForm("not.a.jwt", resource))
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_grant")
}

func TestIDJAGRevokedSubjectToken(t *testing.T) {
	r, store, access, resource, _ := idjagFixture(t)
	if err := store.RevokeTokenByHash(HashToken(access)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	w := tokenExchange(t, r, baseExchangeForm(access, resource))
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_grant")
}

func TestIDJAGClientSubstitutionBlocked(t *testing.T) {
	r, store, access, resource, _ := idjagFixture(t)
	// A confidential client that authenticates as someone OTHER than the subject
	// token's aud must be rejected.
	if err := store.PutClient(OIDCClient{
		ClientID: "cli_other", ClientSecretHash: HashToken("s3cret"), TenantID: "ten_acme",
	}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	form := baseExchangeForm(access, resource)
	form.Set("client_id", "cli_other")
	form.Set("client_secret", "s3cret")
	w := tokenExchange(t, r, form)
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_grant")
}

func TestIDJAGWrongRequestedType(t *testing.T) {
	r, _, access, resource, _ := idjagFixture(t)
	form := baseExchangeForm(access, resource)
	form.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	w := tokenExchange(t, r, form)
	assertOAuthError(t, w, http.StatusBadRequest, "invalid_request")
}

// assertOAuthError checks the response is the given HTTP status and OAuth error code.
func assertOAuthError(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status = %d, want %d (%s)", w.Code, status, w.Body.String())
	}
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("bad error JSON: %v (%s)", err, w.Body.String())
	}
	if e.Error != code {
		t.Errorf("error = %q, want %q (%s)", e.Error, code, w.Body.String())
	}
}

// decodeJOSEHeader returns the parsed JOSE header of a compact JWS.
func decodeJOSEHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a compact JWS: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return h
}
