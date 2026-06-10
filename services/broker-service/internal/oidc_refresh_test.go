package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// tokenJSON is the standard /token response body shared by both grant types.
type tokenJSON struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// postToken POSTs a form to /token and returns the recorder.
func postToken(t *testing.T, r http.Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// postRefresh runs a refresh_token grant for the given refresh token.
func postRefresh(t *testing.T, r http.Handler, refreshToken, clientID string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	return postToken(t, r, form)
}

// refreshTestMocks returns a mock set with a working persona/pool/grant chain
// that records every CreateGrant request. Tests mutate the Fn fields to inject
// failures mid-flow.
func refreshTestMocks() (*mockClients, *[]GrantCreateRequest) {
	grants := &[]GrantCreateRequest{}
	mc := &mockClients{
		GetPersonaFn: func(_ context.Context, tenantID, personaID string) (Persona, error) {
			return Persona{
				ID: personaID, TenantID: tenantID, Name: "agent",
				Scopes: []string{"mcp"}, TokenTTL: 600,
			}, nil
		},
		ClaimIdentityFn: func(_ context.Context, _, poolID, _, _ string) (Identity, error) {
			return Identity{ID: "id-1", PoolID: poolID, SubjectID: "subject-1", Status: "claimed"}, nil
		},
		CreateGrantFn: func(_ context.Context, _ string, req GrantCreateRequest) (Grant, error) {
			*grants = append(*grants, req)
			return Grant{ID: "g-" + uuid.NewString(), Status: "active", InstallID: req.InstallID}, nil
		},
	}
	return mc, grants
}

// issueViaCodeGrant seeds an auth code and runs the full authorization_code
// exchange, returning the issued token pair.
func issueViaCodeGrant(t *testing.T, r http.Handler, store Storage, tenantID, clientID string) tokenJSON {
	t.Helper()
	code := uuid.NewString()
	if err := store.PutAuthCode(AuthCode{
		Code: code, TenantID: tenantID, Runtime: RuntimeClaude,
		PersonaID: "persona-1", PoolID: "pool-1", ClientID: clientID,
		Scope: "mcp", CodeChallenge: s256Challenge(testVerifier),
	}); err != nil {
		t.Fatalf("seed auth code: %v", err)
	}
	w := postToken(t, r, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"code_verifier": {testVerifier},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("code grant: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var tok tokenJSON
	if err := json.Unmarshal(w.Body.Bytes(), &tok); err != nil {
		t.Fatalf("code grant: invalid JSON: %v", err)
	}
	return tok
}

// errorCode decodes the structured error body and returns the "error" field.
func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("error body is not JSON: %v (%s)", err, w.Body.String())
	}
	code, _ := resp["error"].(string)
	return code
}

// --- Happy path: rotation mints a fresh pair, records a second grant, and ---
// --- leaves the old access token alive until its own expiry              ---

func TestRefreshGrantHappyPath(t *testing.T) {
	mc, grants := refreshTestMocks()
	r, store := newTestRouter(t, mc)

	first := issueViaCodeGrant(t, r, store, "tenant-1", "client-xyz")
	v := fetchJWKSVerifier(t, r)
	oldClaims, _, err := v.Verify(first.AccessToken, time.Now().UTC())
	if err != nil {
		t.Fatalf("first access token must verify: %v", err)
	}

	w := postRefresh(t, r, first.RefreshToken, "client-xyz")
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var second tokenJSON
	if err := json.Unmarshal(w.Body.Bytes(), &second); err != nil {
		t.Fatalf("refresh: invalid JSON: %v", err)
	}
	if second.TokenType != "Bearer" || second.ExpiresIn != 600 || second.Scope != "mcp" {
		t.Fatalf("refresh response shape wrong: %+v", second)
	}

	// New access token: a fresh 3-part JWS that verifies against the served JWKS.
	if second.AccessToken == first.AccessToken {
		t.Fatal("refresh must mint a NEW access token")
	}
	if parts := strings.Split(second.AccessToken, "."); len(parts) != 3 {
		t.Fatalf("refreshed access_token is not a 3-part JWS: %q", second.AccessToken)
	}
	newClaims, raw, err := v.Verify(second.AccessToken, time.Now().UTC())
	if err != nil {
		t.Fatalf("refreshed access token does not verify against served JWKS: %v", err)
	}
	if newClaims.JTI == "" || newClaims.JTI == oldClaims.JTI {
		t.Fatalf("refresh must mint a fresh jti: old=%q new=%q", oldClaims.JTI, newClaims.JTI)
	}
	if newClaims.Exp <= newClaims.Iat || newClaims.Exp-newClaims.Iat != 600 {
		t.Fatalf("refreshed exp-iat = %d, want 600 (persona TokenTTL)", newClaims.Exp-newClaims.Iat)
	}
	if newClaims.Sub != oldClaims.Sub || newClaims.Sub != "subject-1" {
		t.Fatalf("sub must be stable across rotation: old=%q new=%q", oldClaims.Sub, newClaims.Sub)
	}
	if newClaims.Aud != "client-xyz" || newClaims.TenantID != "tenant-1" {
		t.Fatalf("aud/tenant wrong: %+v", newClaims)
	}
	installs, _ := store.ListInstalls("tenant-1", 0, time.Time{})
	if len(installs) != 1 {
		t.Fatalf("expected 1 install, got %d", len(installs))
	}
	if raw["install_id"] != installs[0].ID || raw["identity_id"] != "id-1" || raw["persona_id"] != "persona-1" {
		t.Fatalf("install-binding extras wrong: %+v", raw)
	}

	// New refresh token: a new opaque UUID, not a JWT.
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("refresh must rotate the refresh token")
	}
	if strings.Contains(second.RefreshToken, ".") || len(second.RefreshToken) != 36 {
		t.Fatalf("refresh_token should remain an opaque UUID: %q", second.RefreshToken)
	}

	// A second grant was recorded carrying hashes of the NEW tokens.
	if len(*grants) != 2 {
		t.Fatalf("expected 2 grants recorded (code + refresh), got %d", len(*grants))
	}
	g := (*grants)[1]
	if g.AccessTokenHash != hashToken(second.AccessToken) {
		t.Fatalf("second grant access_token_hash = %q, want hashToken(new JWT)", g.AccessTokenHash)
	}
	if g.RefreshTokenHash != hashToken(second.RefreshToken) {
		t.Fatalf("second grant refresh_token_hash = %q, want hashToken(new refresh)", g.RefreshTokenHash)
	}
	if g.InstallID != installs[0].ID || g.IdentityID != "id-1" || g.TTLSeconds != 600 {
		t.Fatalf("second grant binding wrong: %+v", g)
	}

	// Standard OAuth: the OLD access token stays valid until its own exp.
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+first.AccessToken)
	uw := httptest.NewRecorder()
	r.ServeHTTP(uw, req)
	if uw.Code != http.StatusOK {
		t.Fatalf("old access token should still pass /userinfo until expiry: got %d (%s)", uw.Code, uw.Body.String())
	}

	// The old record is marked rotated, the new one is live.
	oldRec, err := store.GetToken(first.AccessToken)
	if err != nil || oldRec.RotatedAt == nil {
		t.Fatalf("old record should exist with RotatedAt set: rec=%+v err=%v", oldRec, err)
	}
	newRec, err := store.GetTokenByRefresh(second.RefreshToken)
	if err != nil || newRec.RotatedAt != nil {
		t.Fatalf("new record should be live (RotatedAt nil): rec=%+v err=%v", newRec, err)
	}
}

// --- Replay: presenting a rotated-out refresh token revokes the install ---

func TestRefreshReplayRevokesInstall(t *testing.T) {
	mc, _ := refreshTestMocks()
	r, store := newTestRouter(t, mc)

	first := issueViaCodeGrant(t, r, store, "tenant-1", "client-xyz")

	// Legitimate rotation.
	w := postRefresh(t, r, first.RefreshToken, "client-xyz")
	if w.Code != http.StatusOK {
		t.Fatalf("first refresh: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var second tokenJSON
	_ = json.Unmarshal(w.Body.Bytes(), &second)

	// Replay the OLD refresh token: theft signal — 400 invalid_grant and the
	// whole install is revoked (§10.1: the broker's family == the install).
	w = postRefresh(t, r, first.RefreshToken, "client-xyz")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("replay: expected 400, got %d (%s)", w.Code, w.Body.String())
	}
	if errorCode(t, w) != "invalid_grant" {
		t.Fatalf("replay: error = %q, want invalid_grant", errorCode(t, w))
	}
	if mc.RevokeCalls != 1 {
		t.Fatalf("replay must cascade grant revocation: RevokeCalls = %d, want 1", mc.RevokeCalls)
	}
	if mc.ReleaseCalls != 1 {
		t.Fatalf("replay must release the identity: ReleaseCalls = %d, want 1", mc.ReleaseCalls)
	}
	installs, _ := store.ListInstalls("tenant-1", 0, time.Time{})
	if len(installs) != 1 || installs[0].Status != InstallStatusRevoked {
		t.Fatalf("install should be revoked after replay: %+v", installs)
	}

	// The replacement refresh token died with the install too.
	w = postRefresh(t, r, second.RefreshToken, "client-xyz")
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "invalid_grant" {
		t.Fatalf("new refresh token must be dead after replay revocation: %d %s", w.Code, w.Body.String())
	}
}

// --- Revoked install: refresh denied ---

func TestRefreshDeniedForRevokedInstall(t *testing.T) {
	mc, _ := refreshTestMocks()
	r, store := newTestRouter(t, mc)

	tok := issueViaCodeGrant(t, r, store, "tenant-1", "client-xyz")
	installs, _ := store.ListInstalls("tenant-1", 0, time.Time{})

	req := httptest.NewRequest(http.MethodPost, "/v1/installs/"+installs[0].ID+"/revoke", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("revoke install: expected 204, got %d", w.Code)
	}

	rw := postRefresh(t, r, tok.RefreshToken, "client-xyz")
	if rw.Code != http.StatusBadRequest || errorCode(t, rw) != "invalid_grant" {
		t.Fatalf("revoked install must not refresh: %d %s", rw.Code, rw.Body.String())
	}
}

// --- Input validation: unknown token, missing token, client mismatch ---

func TestRefreshUnknownTokenIsInvalidGrant(t *testing.T) {
	mc, _ := refreshTestMocks()
	r, _ := newTestRouter(t, mc)
	w := postRefresh(t, r, uuid.NewString(), "")
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "invalid_grant" {
		t.Fatalf("unknown refresh token: want 400 invalid_grant, got %d %s", w.Code, w.Body.String())
	}
}

func TestRefreshMissingTokenIsInvalidRequest(t *testing.T) {
	mc, _ := refreshTestMocks()
	r, _ := newTestRouter(t, mc)
	w := postToken(t, r, url.Values{"grant_type": {"refresh_token"}})
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "invalid_request" {
		t.Fatalf("missing refresh_token: want 400 invalid_request, got %d %s", w.Code, w.Body.String())
	}
}

func TestRefreshClientIDMismatchIsInvalidClient(t *testing.T) {
	mc, _ := refreshTestMocks()
	r, store := newTestRouter(t, mc)
	tok := issueViaCodeGrant(t, r, store, "tenant-1", "client-xyz")

	w := postRefresh(t, r, tok.RefreshToken, "someone-else")
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "invalid_client" {
		t.Fatalf("client_id mismatch: want 400 invalid_client, got %d %s", w.Code, w.Body.String())
	}

	// The failed attempt must not have burned the refresh token.
	w = postRefresh(t, r, tok.RefreshToken, "client-xyz")
	if w.Code != http.StatusOK {
		t.Fatalf("refresh after client mismatch: want 200, got %d (%s)", w.Code, w.Body.String())
	}
}

// --- Persona deleted since install: refresh denied ---

func TestRefreshPersonaGoneIsInvalidGrant(t *testing.T) {
	mc, _ := refreshTestMocks()
	r, store := newTestRouter(t, mc)
	tok := issueViaCodeGrant(t, r, store, "tenant-1", "client-xyz")

	mc.GetPersonaFn = func(_ context.Context, _, _ string) (Persona, error) {
		return Persona{}, &DownstreamError{Service: "persona-service", Status: http.StatusNotFound}
	}
	w := postRefresh(t, r, tok.RefreshToken, "client-xyz")
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "invalid_grant" {
		t.Fatalf("persona 404: want 400 invalid_grant, got %d %s", w.Code, w.Body.String())
	}
}

// --- grant-service outage: 502, nothing rotated, original token still works ---

func TestRefreshGrantServiceDownKeepsOldTokenUsable(t *testing.T) {
	mc, grants := refreshTestMocks()
	r, store := newTestRouter(t, mc)
	tok := issueViaCodeGrant(t, r, store, "tenant-1", "client-xyz")

	workingCreateGrant := mc.CreateGrantFn
	mc.CreateGrantFn = func(_ context.Context, _ string, _ GrantCreateRequest) (Grant, error) {
		return Grant{}, &DownstreamError{Service: "grant-service", Status: 503, Body: "down"}
	}
	w := postRefresh(t, r, tok.RefreshToken, "client-xyz")
	if w.Code != http.StatusBadGateway {
		t.Fatalf("grant-service down: want 502, got %d (%s)", w.Code, w.Body.String())
	}

	// Nothing rotated: the record is unmarked and the SAME refresh token works
	// once grant-service is back.
	rec, err := store.GetTokenByRefresh(tok.RefreshToken)
	if err != nil || rec.RotatedAt != nil {
		t.Fatalf("failed refresh must not rotate: rec=%+v err=%v", rec, err)
	}
	mc.CreateGrantFn = workingCreateGrant
	w = postRefresh(t, r, tok.RefreshToken, "client-xyz")
	if w.Code != http.StatusOK {
		t.Fatalf("retry after outage: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	if len(*grants) != 2 {
		t.Fatalf("expected 2 successful grants (code + retried refresh), got %d", len(*grants))
	}
}

// --- Unknown grant types stay rejected ---

func TestTokenUnsupportedGrantType(t *testing.T) {
	mc, _ := refreshTestMocks()
	r, _ := newTestRouter(t, mc)
	w := postToken(t, r, url.Values{"grant_type": {"client_credentials"}})
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "unsupported_grant_type" {
		t.Fatalf("client_credentials: want 400 unsupported_grant_type, got %d %s", w.Code, w.Body.String())
	}
}

// --- Discovery honesty: grant_types_supported matches what /token implements ---

func TestDiscoveryGrantTypesAreHonest(t *testing.T) {
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
		got, ok := doc["grant_types_supported"].([]any)
		if !ok || len(got) != 2 || got[0] != "authorization_code" || got[1] != "refresh_token" {
			t.Fatalf("%s: grant_types_supported = %v, want [authorization_code refresh_token]",
				path, doc["grant_types_supported"])
		}
	}
}
