package internal

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// OIDCHandlers implements the phase-1 public OIDC/OAuth surface of
// authentication-service:
//
//   - discovery documents (RFC 8414 + OpenID Connect Discovery)
//   - /authorize: auto-approve stub — records an auth code bound to a dev user
//   - /token: exchanges code for opaque access + refresh tokens, issues a session
//   - /refresh (as grant_type=refresh_token on /token): rotates both tokens
//   - /revoke: RFC 7009 revocation — stamps RevokedAt on the token record
//   - /userinfo: returns {sub, email, name} for a valid bearer
//
// Phase 1 uses opaque UUID tokens stored as SHA-256 hex hashes — plaintext
// tokens are never persisted. Every phase-2 shortcut is flagged inline.
type OIDCHandlers struct {
	Store  Storage
	Logger *slog.Logger
	Issuer string // public base URL, e.g. https://auth.x-auth.com
}

// OAuthMetadata serves RFC 8414 OAuth 2.0 Authorization Server Metadata.
// Returned as static JSON reflecting this service's endpoints.
func (h *OIDCHandlers) OAuthMetadata(w http.ResponseWriter, _ *http.Request) {
	issuer := strings.TrimRight(h.Issuer, "/")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"revocation_endpoint":                   issuer + "/revoke",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/.well-known/jwks.json", // TODO(phase-2): publish real JWKS
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

// OIDCMetadata serves the OpenID Provider Configuration document.
func (h *OIDCHandlers) OIDCMetadata(w http.ResponseWriter, _ *http.Request) {
	issuer := strings.TrimRight(h.Issuer, "/")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"revocation_endpoint":                   issuer + "/revoke",
		"jwks_uri":                              issuer + "/.well-known/jwks.json", // TODO(phase-2)
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"}, // TODO(phase-2): actually sign with this alg
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "email", "name"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

// Authorize handles GET /authorize — the phase-1 stub consent endpoint.
//
// Phase-1 behaviour: accept query params, auto-approve, 302 the user back to
// redirect_uri with a freshly minted code + state. No real login screen, no
// PKCE enforcement, no consent UI.
//
// Tenant / user sourcing: real OIDC derives tenant + subject from an
// authenticated browser session. Phase 1 accepts `tenant_id` and (optionally)
// `user_id` as query parameters — if user_id is omitted we synthesise a dev
// user at the first authorize call so cURL smoke tests work without a
// pre-seeded user. This shortcut is documented in the README.
// TODO(phase-2): replace with a real login flow backed by authenticator-service.
func (h *OIDCHandlers) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	scope := q.Get("scope")
	nonce := q.Get("nonce")
	tenantID := q.Get("tenant_id")
	userID := q.Get("user_id")

	if clientID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	if redirectURI == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
		return
	}
	if tenantID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "tenant_id is required (phase 1 stub)")
		return
	}

	// Validate the client exists.
	client, err := h.Store.GetClient(clientID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_client", "unknown client_id")
		return
	}

	// Redirect URI must be absolute AND match one of the registered URIs. Strict
	// matching avoids open-redirect vulns.
	redir, err := url.Parse(redirectURI)
	if err != nil || !redir.IsAbs() {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must be an absolute URL")
		return
	}
	if !redirectURIAllowed(redirectURI, client.RedirectURIs) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri not registered for this client")
		return
	}

	// Resolve or synthesise the user. Phase-1 convenience: if user_id is missing,
	// auto-create a dev user so smoke tests can run without prior POST /v1/users.
	var user User
	if userID != "" {
		user, err = h.Store.GetUser(tenantID, userID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "user_id not found in tenant")
			return
		}
	} else {
		devEmail := "dev@example.com"
		user, err = h.Store.GetUserByEmail(tenantID, devEmail)
		if err != nil {
			now := time.Now().UTC()
			user, err = h.Store.CreateUser(User{
				ID:        "usr_" + uuid.NewString(),
				TenantID:  tenantID,
				Email:     devEmail,
				Name:      "Dev User",
				CreatedAt: now,
				UpdatedAt: now,
			})
			if err != nil {
				h.Logger.Error("authorize_auto_user_failed", "err", err, "tenant_id", tenantID)
				httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to provision dev user")
				return
			}
		}
	}

	code := uuid.NewString()
	if err := h.Store.PutAuthCode(AuthCode{
		Code:        code,
		ClientID:    clientID,
		TenantID:    tenantID,
		UserID:      user.ID,
		RedirectURI: redirectURI,
		Scope:       scope,
		State:       state,
		Nonce:       nonce,
		CreatedAt:   time.Now().UTC(),
	}); err != nil {
		h.Logger.Error("authorize_store_failed", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue code")
		return
	}

	// Append code + state to the redirect URI without clobbering pre-existing params.
	rq := redir.Query()
	rq.Set("code", code)
	if state != "" {
		rq.Set("state", state)
	}
	redir.RawQuery = rq.Encode()

	http.Redirect(w, r, redir.String(), http.StatusFound)
}

// Token handles POST /token for both the `authorization_code` and
// `refresh_token` grant types. Accepts client credentials via HTTP Basic or
// form body — phase 1 validates credentials only if the client row has a
// non-empty secret hash, to allow the default public dev client without auth.
// TODO(phase-2): enforce client authentication strictly, support PKCE.
func (h *OIDCHandlers) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "could not parse form body")
		return
	}
	grantType := r.PostForm.Get("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleCodeGrant(w, r)
	case "refresh_token":
		h.handleRefreshGrant(w, r)
	default:
		httpx.WriteError(w, http.StatusBadRequest, "unsupported_grant_type",
			"only authorization_code and refresh_token are supported in phase 1")
	}
}

// handleCodeGrant redeems an authorization code for fresh access + refresh
// tokens and a new session. Session + tokens are always created together so a
// /userinfo request can reliably resolve the token back to a user.
func (h *OIDCHandlers) handleCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.PostForm.Get("code")
	redirectURI := r.PostForm.Get("redirect_uri")
	if code == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	clientID, _, ok := h.extractClientCreds(r)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
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
	// If the client originally declared a redirect_uri on /authorize, it MUST
	// match on /token per OIDC §3.1.3.1. Phase 1 enforces only when the caller
	// sends one (older dev tools omit the param on token exchange).
	if redirectURI != "" && redirectURI != ac.RedirectURI {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	// Mint a session for the authenticated user.
	now := time.Now().UTC()
	sess := Session{
		ID:              "ses_" + uuid.NewString(),
		TenantID:        ac.TenantID,
		UserID:          ac.UserID,
		RiskLevel:       RiskLow, // TODO(phase-2): pull from risk-service context
		StepUpCompleted: false,
		CreatedAt:       now,
		UpdatedAt:       now,
		ExpiresAt:       now.Add(time.Duration(SessionTTLSeconds) * time.Second),
	}
	if _, err := h.Store.CreateSession(sess); err != nil {
		h.Logger.Error("token_session_create_failed", "err", err, "tenant_id", ac.TenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue session")
		return
	}

	accessPlain, refreshPlain, err := h.issueTokenPair(sess, ac.Scope)
	if err != nil {
		h.Logger.Error("token_issue_failed", "err", err, "session_id", sess.ID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue tokens")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessPlain,
		"refresh_token": refreshPlain,
		"token_type":    "Bearer",
		"expires_in":    AccessTokenTTLSeconds,
		"scope":         ac.Scope,
		// TODO(phase-2): issue a signed id_token (JWT with sub/iss/aud/exp/iat/nonce).
		// Phase 1 omits id_token so clients don't start verifying an empty string.
	})
}

// handleRefreshGrant validates a presented refresh token and issues a brand-new
// access + refresh token pair, revoking the old refresh token. Rotating the
// refresh token on every use is a common OAuth hardening (RFC 6749 §10.4).
func (h *OIDCHandlers) handleRefreshGrant(w http.ResponseWriter, r *http.Request) {
	presented := r.PostForm.Get("refresh_token")
	if presented == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	hash := HashToken(presented)
	tok, err := h.Store.GetTokenByHash(hash)
	if err != nil || tok.TokenType != TokenTypeRefresh {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "refresh token not recognised")
		return
	}
	if tok.RevokedAt != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "refresh token revoked")
		return
	}
	if time.Now().UTC().After(tok.ExpiresAt) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}

	sess, err := h.Store.GetSession(tok.TenantID, tok.SessionID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "associated session no longer exists")
		return
	}
	if sess.InvalidatedAt != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "associated session invalidated")
		return
	}

	// Extend the session TTL and rotate tokens.
	sess.ExpiresAt = time.Now().UTC().Add(time.Duration(SessionTTLSeconds) * time.Second)
	if _, err := h.Store.UpdateSession(sess); err != nil {
		h.Logger.Error("refresh_session_update_failed", "err", err, "session_id", sess.ID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to extend session")
		return
	}
	if err := h.Store.RevokeTokenByHash(hash); err != nil {
		h.Logger.Warn("refresh_old_token_revoke_failed", "err", err)
	}

	accessPlain, refreshPlain, err := h.issueTokenPair(sess, tok.Scope)
	if err != nil {
		h.Logger.Error("refresh_issue_failed", "err", err, "session_id", sess.ID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue tokens")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessPlain,
		"refresh_token": refreshPlain,
		"token_type":    "Bearer",
		"expires_in":    AccessTokenTTLSeconds,
		"scope":         tok.Scope,
	})
}

// issueTokenPair creates an access + refresh token record bound to sess.
// Returns the plaintext tokens for the response body; only hashes are stored.
func (h *OIDCHandlers) issueTokenPair(sess Session, scope string) (string, string, error) {
	now := time.Now().UTC()
	accessPlain := uuid.NewString()
	refreshPlain := uuid.NewString()

	accessRec := Token{
		TokenHash: HashToken(accessPlain),
		SessionID: sess.ID,
		UserID:    sess.UserID,
		TenantID:  sess.TenantID,
		TokenType: TokenTypeAccess,
		Scope:     scope,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Duration(AccessTokenTTLSeconds) * time.Second),
	}
	refreshRec := Token{
		TokenHash: HashToken(refreshPlain),
		SessionID: sess.ID,
		UserID:    sess.UserID,
		TenantID:  sess.TenantID,
		TokenType: TokenTypeRefresh,
		Scope:     scope,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Duration(RefreshTokenTTLSeconds) * time.Second),
	}
	if err := h.Store.PutToken(accessRec); err != nil {
		return "", "", err
	}
	if err := h.Store.PutToken(refreshRec); err != nil {
		return "", "", err
	}
	return accessPlain, refreshPlain, nil
}

// Revoke implements RFC 7009 token revocation. Per RFC 7009 §2.2 the endpoint
// returns 200 even if the token is unknown, to avoid leaking whether a token
// ever existed.
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
	hash := HashToken(token)
	if err := h.Store.RevokeTokenByHash(hash); err != nil {
		// Unknown token: still ack 200.
		h.Logger.Info("revoke_unknown_token")
	}
	w.WriteHeader(http.StatusOK)
}

// UserInfo returns minimal OIDC user claims for the bearer. Phase-1 response
// shape: {sub, email, name}. Returns 401 with RFC 6750 WWW-Authenticate
// whenever the bearer is missing, unknown, expired, or revoked.
func (h *OIDCHandlers) UserInfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "bearer token required")
		return
	}
	plain := strings.TrimPrefix(auth, prefix)
	tok, err := h.Store.GetTokenByHash(HashToken(plain))
	if err != nil || tok.TokenType != TokenTypeAccess {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "token unknown")
		return
	}
	if tok.RevokedAt != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "token revoked")
		return
	}
	if time.Now().UTC().After(tok.ExpiresAt) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "token expired")
		return
	}
	user, err := h.Store.GetUser(tok.TenantID, tok.UserID)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "user no longer exists")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"sub":   user.ID,
		"email": user.Email,
		"name":  user.Name,
	})
}

// extractClientCreds pulls client_id/client_secret from HTTP Basic or form body
// and validates them against the stored client. Returns (client_id, client_secret, ok).
//
// Phase 1 rule: if the stored client has no secret hash (ClientSecretHash == "")
// the client is treated as public and authentication is optional. A client with
// a non-empty secret hash MUST be authenticated.
func (h *OIDCHandlers) extractClientCreds(r *http.Request) (string, string, bool) {
	clientID, clientSecret, hasBasic := r.BasicAuth()
	if !hasBasic {
		clientID = r.PostForm.Get("client_id")
		clientSecret = r.PostForm.Get("client_secret")
	}
	if clientID == "" {
		// Some public-client flows (PKCE in phase 2) omit client_id entirely.
		// Phase 1 permits this but the auth code itself still carries the client_id.
		return "", "", true
	}
	client, err := h.Store.GetClient(clientID)
	if err != nil {
		return "", "", false
	}
	if client.ClientSecretHash == "" {
		return clientID, "", true
	}
	if clientSecret == "" || HashToken(clientSecret) != client.ClientSecretHash {
		return "", "", false
	}
	return clientID, clientSecret, true
}

// redirectURIAllowed returns true iff candidate exactly matches one of the
// registered URIs. OAuth 2.0 recommends exact string comparison over substring /
// prefix matching to avoid open-redirect bugs.
func redirectURIAllowed(candidate string, allowed []string) bool {
	for _, a := range allowed {
		if a == candidate {
			return true
		}
	}
	return false
}
