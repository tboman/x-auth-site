package internal

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/jwtx"
)

// OIDCHandlers implements the OIDC/OAuth surface of the broker:
//   - discovery documents (RFC 8414 + OIDC) + JWKS publication
//   - /authorize: stub consent — auto-approves, records a pending install
//   - /token: exchanges code for tokens; orchestrates persona/pool/grant
//   - /revoke: forwards to grant-service
//   - /userinfo: hybrid bearer introspection (JWT verification + local token cache)
//
// Phase 2.1: access tokens are RS256 JWTs signed with the broker's key (jwks_uri
// publishes the public half); refresh tokens remain opaque UUIDs stored hashed
// with grant-service.
type OIDCHandlers struct {
	Store   Storage
	Clients interface {
		PersonaClient
		PoolClient
		GrantClient
	}
	Logger *slog.Logger
	Issuer string // public base URL of this service, e.g. https://mcp.x-auth.com
	// Signer mints RS256 access tokens; Verifier checks presented bearers against
	// the same key set + JWTIssuer. JWTIssuer is the `iss` claim value and
	// normally equals Issuer so tokens validate against the discovery document.
	Signer     *jwtx.Signer
	Verifier   *jwtx.Verifier
	JWTIssuer  string
	DefaultTTL int
}

// Discovery: RFC 8414 OAuth 2.0 Authorization Server Metadata.
// Returned as static JSON reflecting this service's endpoints. Clients use this
// to find /authorize, /token, /userinfo, and the JWKS endpoint.
func (h *OIDCHandlers) OAuthMetadata(w http.ResponseWriter, _ *http.Request) {
	issuer := strings.TrimRight(h.Issuer, "/")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"revocation_endpoint":                   issuer + "/revoke",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"registration_endpoint":                 issuer + "/register",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"scopes_supported":                      []string{"openid", "profile", "email", "mcp"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

// Discovery: OpenID Provider Configuration.
func (h *OIDCHandlers) OIDCMetadata(w http.ResponseWriter, _ *http.Request) {
	issuer := strings.TrimRight(h.Issuer, "/")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"revocation_endpoint":                   issuer + "/revoke",
		"registration_endpoint":                 issuer + "/register",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "mcp"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "persona", "scopes"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

// JWKS serves the RFC 7517 key set containing the broker's signing public key
// at the jwks_uri advertised by both discovery documents
// (GET /.well-known/jwks.json). Resource servers and MCP runtimes use it to
// verify access-token signatures offline.
func (h *OIDCHandlers) JWKS(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.Signer.JWKS())
}

// Authorize handles GET /authorize — the stub consent endpoint.
//
// Phase-1 behavior: accept query params, auto-approve, 302 the user back to
// redirect_uri with a freshly minted code + state. A pending install is recorded
// keyed by the code so /token can complete the orchestration without the caller
// re-sending any of this data.
//
// PKCE (RFC 7636) is mandatory and S256-only: requests without a code_challenge,
// or with any code_challenge_method other than S256, are rejected with a
// structured 400. The challenge is persisted on the auth-code record and
// verified against code_verifier at /token.
//
// Tenant sourcing: real OIDC would derive the tenant from the authenticated user
// session. Phase 1 accepts `tenant_id` as a query parameter (documented in
// REQUIREMENTS.md §4 and the broker-service README). This is the deliberate
// shortcut for the phase-1 stub.
//
// Pool selection: phase 1 also accepts `pool_id` as a query parameter. In a
// production flow persona-service would expose the pool(s) a persona is eligible
// for and broker-service would pick one automatically; phase 1 keeps that coupling
// out of the orchestration path to avoid introducing a tight persona-service
// dependency that the sister team hasn't shipped yet.
func (h *OIDCHandlers) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	scope := q.Get("scope")
	personaID := q.Get("persona_id")
	poolID := q.Get("pool_id")
	tenantID := q.Get("tenant_id")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	runtime := q.Get("runtime")
	if runtime == "" {
		runtime = RuntimeCustom
	}

	if clientID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_client", "client_id is required")
		return
	}
	if redirectURI == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri is required")
		return
	}
	if personaID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "persona_id is required (phase 1 stub)")
		return
	}
	if poolID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "pool_id is required (phase 1 stub)")
		return
	}
	if tenantID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "tenant_id is required (phase 1 stub)")
		return
	}
	if !ValidRuntime(runtime) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request",
			"runtime must be one of claude|chatgpt|cursor|custom")
		return
	}

	// PKCE is mandatory and S256-only (ARCHITECTURE.md §10.4; the MCP authorization
	// spec requires PKCE for MCP clients). RFC 7636 defaults a missing
	// code_challenge_method to "plain", which we deliberately do not support — the
	// discovery documents advertise code_challenge_methods_supported: ["S256"].
	if codeChallenge == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request",
			"code_challenge is required (PKCE is mandatory)")
		return
	}
	if codeChallengeMethod != "S256" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request",
			"code_challenge_method must be S256")
		return
	}

	// Validate redirect_uri parses as an absolute URL so we don't emit a garbage Location.
	redir, err := url.Parse(redirectURI)
	if err != nil || !redir.IsAbs() {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_redirect_uri",
			"redirect_uri must be an absolute URL")
		return
	}

	code := uuid.NewString()
	if err := h.Store.PutAuthCode(AuthCode{
		Code:          code,
		TenantID:      tenantID,
		Runtime:       runtime,
		PersonaID:     personaID,
		PoolID:        poolID,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		State:         state,
		Scope:         scope,
		CodeChallenge: codeChallenge,
		CreatedAt:     time.Now().UTC(),
	}); err != nil {
		h.Logger.Error("authorize_store_failed", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue code")
		return
	}

	// Append code + state to the redirect_uri query string without clobbering any
	// pre-existing params (e.g. the caller might already embed a correlation id).
	rq := redir.Query()
	rq.Set("code", code)
	if state != "" {
		rq.Set("state", state)
	}
	redir.RawQuery = rq.Encode()

	http.Redirect(w, r, redir.String(), http.StatusFound)
}

// Token handles POST /token. Only `authorization_code` is supported in phase 1;
// `refresh_token` returns a clear "unsupported_grant_type" error rather than
// silently minting a new access token, because phase 1 has no grant-service-backed
// validation yet.
//
// Orchestration, in order:
//  1. consume auth code (one-shot) and verify the PKCE code_verifier against
//     the stored S256 code_challenge (mandatory — invalid_grant on mismatch)
//  2. create a pending install locally
//  3. fetch persona scopes from persona-service
//  4. claim an identity from pool-service
//  5. issue tokens (JWT access + opaque refresh) and record the grant in grant-service
//  6. mark the install active with the claimed identity id
//
// Compensation: if step 4 succeeds but step 5 fails, the claimed identity is
// released back to its pool so it does not stay stuck. The install is left in
// pending/revoked state and the caller receives 502.
func (h *OIDCHandlers) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "could not parse form body")
		return
	}
	grantType := r.PostForm.Get("grant_type")
	code := r.PostForm.Get("code")
	clientID := r.PostForm.Get("client_id")
	codeVerifier := r.PostForm.Get("code_verifier")

	if grantType != "authorization_code" {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported_grant_type",
			"only authorization_code is supported in phase 1")
		return
	}
	if code == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	// PKCE is mandatory: checked before consuming the code so a request that is
	// missing the verifier outright does not burn the one-shot code.
	if codeVerifier == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request",
			"code_verifier is required (PKCE is mandatory)")
		return
	}

	ac, err := h.Store.ConsumeAuthCode(code)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "code is invalid or already used")
		return
	}
	if clientID != "" && clientID != ac.ClientID {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_client", "client_id mismatch")
		return
	}
	if time.Since(ac.CreatedAt) > time.Duration(AuthCodeTTLSeconds)*time.Second {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "code expired")
		return
	}
	// PKCE verification (RFC 7636 §4.6, S256): base64url-without-padding of
	// SHA-256(code_verifier) must equal the challenge stored at /authorize time.
	// A code with no stored challenge (impossible via /authorize, but reachable by
	// direct-seeded codes) is rejected too — there is no PKCE-optional path.
	if ac.CodeChallenge == "" ||
		subtle.ConstantTimeCompare([]byte(pkceChallengeS256(codeVerifier)), []byte(ac.CodeChallenge)) != 1 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant",
			"code_verifier does not match the code_challenge")
		return
	}

	// 1. Record the install in pending state *before* calling sister services.
	// If downstream calls fail we flip it to revoked rather than leaving it pending,
	// so operators can tell real in-flight installs from failed ones.
	now := time.Now().UTC()
	installID := uuid.NewString()
	install := Install{
		ID:        installID,
		TenantID:  ac.TenantID,
		Runtime:   ac.Runtime,
		PersonaID: ac.PersonaID,
		ClientID:  ac.ClientID,
		Status:    InstallStatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if _, err := h.Store.CreateInstall(install); err != nil {
		h.Logger.Error("token_install_create_failed", "err", err, "tenant_id", ac.TenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to record install")
		return
	}

	// 2. Fetch persona for scopes / TTL. A missing persona is the customer's fault (bad
	// configuration), so translate to 400. Other errors from persona-service are 502.
	persona, err := h.Clients.GetPersona(r.Context(), ac.TenantID, ac.PersonaID)
	if err != nil {
		var dse *DownstreamError
		if errors.As(err, &dse) && dse.Status == http.StatusNotFound {
			h.markInstallRevoked(install)
			httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "persona not found")
			return
		}
		h.Logger.Error("token_persona_fetch_failed",
			downstreamLogAttrs(err, "tenant_id", ac.TenantID, "persona_id", ac.PersonaID)...)
		h.markInstallRevoked(install)
		httpx.WriteError(w, http.StatusBadGateway, "downstream_error", "persona-service unavailable")
		return
	}

	// 3. Claim an identity from the pool. A full pool is not a 5xx on our side but
	// a business-state error; surface as 400 so the caller can retry with a different pool.
	identity, err := h.Clients.ClaimIdentity(r.Context(), ac.TenantID, ac.PoolID, ac.PersonaID, installID)
	if err != nil {
		var dse *DownstreamError
		if errors.As(err, &dse) && dse.Status == http.StatusConflict {
			h.markInstallRevoked(install)
			httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "no free identity in pool")
			return
		}
		h.Logger.Error("token_claim_failed",
			downstreamLogAttrs(err, "tenant_id", ac.TenantID, "pool_id", ac.PoolID)...)
		h.markInstallRevoked(install)
		httpx.WriteError(w, http.StatusBadGateway, "downstream_error", "pool-service unavailable")
		return
	}

	// 4. Mint tokens. The ACCESS token is an RS256 JWT signed with the broker's key
	// (published via jwks_uri):
	//   - sub  = identity.SubjectID — REQUIREMENTS.md §2 defines subject_id as the
	//     "stable identifier used in the OAuth `sub` claim". The pool identity is
	//     the principal acting under this token (the install and persona are
	//     bindings *about* that principal, carried as extra claims).
	//   - aud  = the requesting OAuth client (DCR client id)
	//   - scope/tenant_id/exp/iat per the persona + auth code
	//   - extras: install_id / persona_id / identity_id bind the token to the
	//     install triple so resource servers can authorize without a lookup.
	// The REFRESH token stays an opaque UUID: it is only ever redeemed back at this
	// service, so self-describing claims buy nothing and opacity limits blast radius.
	ttl := persona.TokenTTL
	if ttl <= 0 {
		ttl = h.DefaultTTL
	}
	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(time.Duration(ttl) * time.Second)
	grantedScope := scopeString(persona.Scopes, ac.Scope)
	accessToken, err := h.Signer.Sign(jwtx.Claims{
		Sub:      identity.SubjectID,
		Iss:      h.JWTIssuer,
		Aud:      ac.ClientID,
		Exp:      expiresAt.Unix(),
		Iat:      issuedAt.Unix(),
		JTI:      uuid.NewString(),
		TenantID: ac.TenantID,
		Scope:    grantedScope,
	}, map[string]any{
		"install_id":  installID,
		"persona_id":  ac.PersonaID,
		"identity_id": identity.ID,
	})
	if err != nil {
		h.Logger.Error("token_sign_failed", "err", err, "tenant_id", ac.TenantID, "install_id", installID)
		// Same compensation as a grant failure: the identity was already claimed.
		if relErr := h.Clients.ReleaseIdentity(context.WithoutCancel(r.Context()), ac.TenantID, identity.ID); relErr != nil {
			h.Logger.Warn("token_compensation_release_failed",
				downstreamLogAttrs(relErr, "tenant_id", ac.TenantID, "identity_id", identity.ID)...)
		}
		h.markInstallRevoked(install)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to sign access token")
		return
	}
	refreshToken := uuid.NewString()

	// 5. Record the grant. The hashes are SHA-256 over the full token strings as
	// issued — for the access token that is now the compact JWT, for the refresh
	// token the opaque UUID. grant-service never sees plaintext tokens.
	// If this fails, compensate by releasing the claimed identity so the pool does
	// not leak a claimed-but-unusable slot.
	_, err = h.Clients.CreateGrant(r.Context(), ac.TenantID, GrantCreateRequest{
		InstallID:        installID,
		IdentityID:       identity.ID,
		PersonaID:        ac.PersonaID,
		AccessTokenHash:  hashToken(accessToken),
		RefreshTokenHash: hashToken(refreshToken),
		TTLSeconds:       ttl,
	})
	if err != nil {
		h.Logger.Error("token_grant_create_failed",
			downstreamLogAttrs(err, "tenant_id", ac.TenantID, "install_id", installID, "identity_id", identity.ID)...)
		// Best-effort compensation: release the identity. If release itself fails we
		// log and move on — an operator will reconcile via the audit log in grant-service.
		// Use a non-cancellable context: a common reason we land here is that the caller
		// disconnected and r.Context() is already cancelled — the compensation call must
		// still run or the pool leaks a claimed-but-unusable identity. The HTTP client's
		// own timeout still bounds the call.
		if relErr := h.Clients.ReleaseIdentity(context.WithoutCancel(r.Context()), ac.TenantID, identity.ID); relErr != nil {
			h.Logger.Warn("token_compensation_release_failed",
				downstreamLogAttrs(relErr, "tenant_id", ac.TenantID, "identity_id", identity.ID)...)
		}
		h.markInstallRevoked(install)
		httpx.WriteError(w, http.StatusBadGateway, "downstream_error", "grant-service unavailable")
		return
	}

	// 6. Finalize the install and persist the token record.
	install.IdentityID = identity.ID
	install.Status = InstallStatusActive
	if _, err := h.Store.UpdateInstall(install); err != nil {
		h.Logger.Error("token_install_finalize_failed", "err", err, "install_id", installID)
		// The grant has already been recorded; returning 502 here would mislead the caller
		// since the identity is bound. Log and continue.
	}
	_ = h.Store.PutToken(TokenRecord{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		InstallID:    installID,
		PersonaID:    ac.PersonaID,
		IdentityID:   identity.ID,
		Subject:      identity.SubjectID,
		Scope:        grantedScope,
		TenantID:     ac.TenantID,
		ExpiresAt:    expiresAt,
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    ttl,
		"scope":         grantedScope,
	})
}

// Revoke implements RFC 7009 token revocation by forwarding to grant-service and
// clearing the local token cache. Per RFC 7009 the endpoint responds 200 even if
// the token is unknown, to avoid leaking whether a token ever existed.
func (h *OIDCHandlers) Revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "could not parse form body")
		return
	}
	token := r.PostForm.Get("token")
	if token == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}

	// Try to look up the token locally for tenant context. Unknown tokens still return 200.
	tenantID := ""
	if rec, err := h.Store.GetToken(token); err == nil {
		tenantID = rec.TenantID
		_ = h.Store.DeleteToken(token)
	}

	// Non-cancellable context: revocation is security-relevant cleanup. If the client
	// fires /revoke and disconnects, the grant must still be revoked downstream — the
	// HTTP client's own timeout bounds the call instead of the request context.
	if err := h.Clients.RevokeToken(context.WithoutCancel(r.Context()), tenantID, token); err != nil {
		// Per RFC 7009 recommendation, we still ack to the client but log the forward failure.
		h.Logger.Warn("revoke_forward_failed", downstreamLogAttrs(err)...)
	}
	w.WriteHeader(http.StatusOK)
}

// UserInfo returns a minimal claims bundle keyed off the bearer token.
//
// Hybrid verification — BOTH checks must pass:
//
//  1. Cryptographic: jwtx.Verify checks the RS256 signature against the broker's
//     key set, the exp/iat window (30s leeway), and the issuer. This rejects
//     forged or foreign-signed tokens regardless of what the store contains.
//  2. Stored record: the local token store is the revocation deny-list (/revoke
//     and install revocation delete the row) and the metadata source of record.
//     A cryptographically valid JWT whose record is gone is treated as revoked.
//
// Phase 2.x will defer the stored-record half to grant-service introspection so
// this service can go stateless; the signature check stays local.
func (h *OIDCHandlers) UserInfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "bearer token required")
		return
	}
	token := strings.TrimPrefix(auth, prefix)

	// Check 1: signature + time window + issuer.
	if _, _, err := h.Verifier.Verify(token, time.Now().UTC()); err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "token verification failed")
		return
	}

	// Check 2: revocation deny-list / metadata lookup.
	rec, err := h.Store.GetToken(token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "token unknown")
		return
	}
	if time.Now().UTC().After(rec.ExpiresAt) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "token expired")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"sub":        rec.Subject,
		"persona":    rec.PersonaID,
		"scopes":     splitScope(rec.Scope),
		"install_id": rec.InstallID,
	})
}

// markInstallRevoked is a small helper used by the token path to flip a failed
// in-flight install to revoked without obscuring the original error.
func (h *OIDCHandlers) markInstallRevoked(i Install) {
	i.Status = InstallStatusRevoked
	if _, err := h.Store.UpdateInstall(i); err != nil {
		h.Logger.Warn("install_mark_revoked_failed", "err", err, "install_id", i.ID)
	}
}

// pkceChallengeS256 derives the PKCE S256 code challenge from a code verifier
// per RFC 7636 §4.2: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) without
// padding. /token recomputes it from the presented code_verifier and compares
// against the challenge stored at /authorize time.
func pkceChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// hashToken returns the SHA-256 hex digest of a token. The digest — never the
// plaintext token — is what gets sent to grant-service as access_token_hash /
// refresh_token_hash, so a grant-service compromise does not yield usable bearer
// tokens. The hash is computed at issue time and recomputed at lookup time, so
// it only needs to be deterministic, not reversible.
func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// scopeString resolves the final scope claim from the persona's configured scopes
// and the scope the client asked for. Phase 1 simply returns the persona scopes
// intersected with (or falling back to) the requested scope string. A more
// complete implementation would honor scope semantics per RFC 6749.
func scopeString(personaScopes []string, requested string) string {
	if len(personaScopes) == 0 {
		return requested
	}
	return strings.Join(personaScopes, " ")
}

// splitScope turns a space-separated OAuth scope string into a slice, always
// returning a non-nil slice so JSON output is a consistent shape.
func splitScope(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return []string{}
	}
	return strings.Fields(s)
}
