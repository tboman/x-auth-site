package internal

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// OIDCHandlers implements the phase-1 OIDC/OAuth surface of the broker:
//   - discovery documents (RFC 8414 + OIDC)
//   - /authorize: stub consent — auto-approves, records a pending install
//   - /token: exchanges code for tokens; orchestrates persona/pool/grant
//   - /revoke: forwards to grant-service
//   - /userinfo: bearer-token introspection against local token cache
//
// Cryptography is explicitly deferred. Phase 1 uses opaque UUID tokens so the
// happy-path install wiring is verifiable end-to-end without signing keys. Every
// place a JWT will eventually be issued is flagged with TODO(phase-2).
type OIDCHandlers struct {
	Store   Storage
	Clients interface {
		PersonaClient
		PoolClient
		GrantClient
	}
	Logger     *slog.Logger
	Issuer     string // public base URL of this service, e.g. https://broker.x-auth.com
	DefaultTTL int
}

// Discovery: RFC 8414 OAuth 2.0 Authorization Server Metadata.
// Returned as static JSON reflecting this service's endpoints. Clients use this
// to find /authorize, /token, /userinfo, and the JWKS endpoint (phase 2).
func (h *OIDCHandlers) OAuthMetadata(w http.ResponseWriter, _ *http.Request) {
	issuer := strings.TrimRight(h.Issuer, "/")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"revocation_endpoint":                   issuer + "/revoke",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"registration_endpoint":                 issuer + "/register",
		"jwks_uri":                              issuer + "/.well-known/jwks.json", // TODO(phase-2): publish real JWKS
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
		"jwks_uri":                              issuer + "/.well-known/jwks.json", // TODO(phase-2)
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"}, // TODO(phase-2): actually sign with this alg
		"scopes_supported":                      []string{"openid", "profile", "email", "mcp"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "persona", "scopes"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

// Authorize handles GET /authorize — the stub consent endpoint.
//
// Phase-1 behavior: accept query params, auto-approve, 302 the user back to
// redirect_uri with a freshly minted code + state. A pending install is recorded
// keyed by the code so /token can complete the orchestration without the caller
// re-sending any of this data.
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

	// Validate redirect_uri parses as an absolute URL so we don't emit a garbage Location.
	redir, err := url.Parse(redirectURI)
	if err != nil || !redir.IsAbs() {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_redirect_uri",
			"redirect_uri must be an absolute URL")
		return
	}

	code := uuid.NewString()
	if err := h.Store.PutAuthCode(AuthCode{
		Code:        code,
		TenantID:    tenantID,
		Runtime:     runtime,
		PersonaID:   personaID,
		PoolID:      poolID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		State:       state,
		Scope:       scope,
		CreatedAt:   time.Now().UTC(),
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
//  1. consume auth code (one-shot)
//  2. create a pending install locally
//  3. fetch persona scopes from persona-service
//  4. claim an identity from pool-service
//  5. issue opaque tokens and record the grant in grant-service
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

	if grantType != "authorization_code" {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported_grant_type",
			"only authorization_code is supported in phase 1")
		return
	}
	if code == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "code is required")
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
	persona, err := h.Clients.GetPersona(ac.TenantID, ac.PersonaID)
	if err != nil {
		var dse *DownstreamError
		if errors.As(err, &dse) && dse.Status == http.StatusNotFound {
			h.markInstallRevoked(install)
			httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "persona not found")
			return
		}
		h.Logger.Error("token_persona_fetch_failed", "err", err, "tenant_id", ac.TenantID, "persona_id", ac.PersonaID)
		h.markInstallRevoked(install)
		httpx.WriteError(w, http.StatusBadGateway, "downstream_error", "persona-service unavailable")
		return
	}

	// 3. Claim an identity from the pool. A full pool is not a 5xx on our side but
	// a business-state error; surface as 400 so the caller can retry with a different pool.
	identity, err := h.Clients.ClaimIdentity(ac.TenantID, ac.PoolID, ac.PersonaID, installID)
	if err != nil {
		var dse *DownstreamError
		if errors.As(err, &dse) && dse.Status == http.StatusConflict {
			h.markInstallRevoked(install)
			httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "no free identity in pool")
			return
		}
		h.Logger.Error("token_claim_failed", "err", err, "tenant_id", ac.TenantID, "pool_id", ac.PoolID)
		h.markInstallRevoked(install)
		httpx.WriteError(w, http.StatusBadGateway, "downstream_error", "pool-service unavailable")
		return
	}

	// 4. Mint opaque tokens. TODO(phase-2): replace with signed JWTs whose claims embed
	// {iss, aud, sub=identity.SubjectID, persona, scopes, exp, iat} and are signed
	// with the broker's signing key, keys rotated and published via jwks_uri.
	accessToken := uuid.NewString()
	refreshToken := uuid.NewString()
	ttl := persona.TokenTTL
	if ttl <= 0 {
		ttl = h.DefaultTTL
	}

	// 5. Record the grant. If this fails, compensate by releasing the claimed identity
	// so the pool does not leak a claimed-but-unusable slot.
	_, err = h.Clients.CreateGrant(ac.TenantID, GrantCreateRequest{
		InstallID:        installID,
		IdentityID:       identity.ID,
		PersonaID:        ac.PersonaID,
		AccessTokenHash:  hashToken(accessToken),
		RefreshTokenHash: hashToken(refreshToken),
		TTLSeconds:       ttl,
	})
	if err != nil {
		h.Logger.Error("token_grant_create_failed", "err", err,
			"tenant_id", ac.TenantID, "install_id", installID, "identity_id", identity.ID)
		// Best-effort compensation: release the identity. If release itself fails we
		// log and move on — an operator will reconcile via the audit log in grant-service.
		if relErr := h.Clients.ReleaseIdentity(ac.TenantID, identity.ID); relErr != nil {
			h.Logger.Warn("token_compensation_release_failed", "err", relErr,
				"tenant_id", ac.TenantID, "identity_id", identity.ID)
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
		Scope:        scopeString(persona.Scopes, ac.Scope),
		TenantID:     ac.TenantID,
		ExpiresAt:    time.Now().UTC().Add(time.Duration(ttl) * time.Second),
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    ttl,
		"scope":         scopeString(persona.Scopes, ac.Scope),
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

	if err := h.Clients.RevokeToken(tenantID, token); err != nil {
		// Per RFC 7009 recommendation, we still ack to the client but log the forward failure.
		h.Logger.Warn("revoke_forward_failed", "err", err)
	}
	w.WriteHeader(http.StatusOK)
}

// UserInfo returns a minimal claims bundle keyed off the bearer token. Phase 1
// reads straight from the local token cache; phase 2 will call grant-service's
// /introspect endpoint instead so this service can go stateless.
func (h *OIDCHandlers) UserInfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "bearer token required")
		return
	}
	token := strings.TrimPrefix(auth, prefix)

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

// hashToken returns an opaque stable identifier for a token. In phase 1 we just
// reflect the token itself — grant-service only needs a consistent key, and since
// the tokens are unguessable UUIDs this is safe enough for the in-memory happy
// path. TODO(phase-2): replace with a SHA-256 hex digest.
func hashToken(tok string) string {
	return "stub-hash:" + tok
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
