package internal

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/jwtx"
)

// OIDCHandlers implements the public OIDC/OAuth surface of
// authentication-service:
//
//   - discovery documents (RFC 8414 + OpenID Connect Discovery)
//   - /authorize: auto-approve stub — records an auth code bound to a dev
//     user; PKCE (S256 only) is mandatory (§10.4)
//   - /token: exchanges code (+ verified code_verifier) for an RS256 JWT
//     access token + opaque refresh token (+ id_token when scope contains
//     "openid"), issues a session and starts a refresh-token family
//   - /refresh (as grant_type=refresh_token on /token): rotates both tokens
//     within the family; replaying a rotated-out refresh token revokes the
//     entire family (§10.1 theft detection)
//   - /revoke: RFC 7009 revocation — stamps RevokedAt on the token record
//   - /userinfo: returns {sub, email, name} for a valid bearer
//   - /v1/auth/jwks + /.well-known/jwks.json: RFC 7517 key set
//
// Token model (ARCHITECTURE.md §10.1): access and ID tokens are RS256 JWTs
// signed by this service; refresh tokens remain opaque UUIDs. All issued
// tokens are persisted as SHA-256 hex hashes — plaintext is never stored.
type OIDCHandlers struct {
	Store  Storage
	Logger *slog.Logger
	Issuer string // public base URL, e.g. https://auth.x-auth.com

	// Signer mints RS256 access + ID tokens; Verifier checks bearers presented
	// to /userinfo against the same key set. JWTIssuer is the `iss` claim —
	// normally identical to Issuer so tokens match the discovery document.
	Signer    *jwtx.Signer
	Verifier  *jwtx.Verifier
	JWTIssuer string

	// Authenticator drives the second-factor interludes (acr_values, e.g.
	// urn:xauth:otp:sms, urn:xauth:fido2) — challenge create/verify against
	// authenticator-service.
	Authenticator AuthenticatorClient

	// DevAutologin re-enables the legacy /authorize behaviour (trust a user_id
	// parameter, or auto-create a dev user) for local development and tests.
	// OFF in production, where /authorize requires a real authz-session cookie.
	DevAutologin bool

	// Parked /authorize requests awaiting step-up verification, keyed by
	// one-time flow id (see otp.go). Same in-process pattern as the social
	// handshake.
	flowMu   sync.Mutex
	flows    map[string]pendingAuthorize
	flowOnce sync.Once

	// StepUps mirrors the live subset of parked flows so the session-management
	// consoles can show who is mid step-up. Optional (nil is a no-op).
	StepUps *StepUpTracker

	// Protection is the mocked per-session assurance ledger backing the
	// protection-level interface (protection.go). Optional (nil never passes
	// through, so every protection request challenges).
	Protection *ProtectionLedger

	// StepUpFreshness is how recently a successful step-up must have happened for
	// a protection-level /authorize request to pass through without re-challenging
	// (AUTHORIZE_STEPUP_FRESHNESS). 0 → defaultStepUpFreshness.
	StepUpFreshness time.Duration

	// Analyzer records the device fingerprint + runs CAEP drift analysis at the
	// /authorize step-up validation.
	Analyzer *DeviceAnalyzer

	// CAEP emits a Security Event Token to risk-service when an advice-tracked
	// transaction completes authentication (mintCodeAndRedirect). Optional.
	CAEP *CAEPTransmitter

	// FlowEngine routes /authorize through the configurable flow executor
	// (flowexec.go) instead of the legacy hardcoded branch. OFF by default; the
	// built-in default flow reproduces the legacy behavior exactly (FLOW_ENGINE).
	FlowEngine bool

	// Risk is the risk-service client the risk-evaluation stage uses to fetch a
	// live score/tier before policy-gated stages run. Optional — nil (or an
	// unreachable risk-service) degrades fail-open: risk inputs default to falsy
	// and policies referencing them evaluate as if risk were absent.
	Risk RiskEvaluator
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
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"acr_values_supported":                  supportedACRValues(),
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
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "email", "name"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"acr_values_supported":                  supportedACRValues(),
	})
}

// JWKS serves the RFC 7517 JSON Web Key Set containing this service's RS256
// public signing key. Routed at GET /v1/auth/jwks (ARCHITECTURE.md §4.3) and
// GET /.well-known/jwks.json (the `jwks_uri` advertised by the discovery
// documents). Any service can verify access tokens against this document.
func (h *OIDCHandlers) JWKS(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.Signer.JWKS())
}

// Authorize handles GET /authorize — the phase-1 stub consent endpoint.
//
// Phase-1 behaviour: accept query params, auto-approve, 302 the user back to
// redirect_uri with a freshly minted code + state. No real login screen, no
// consent UI.
//
// PKCE (ARCHITECTURE.md §10.4, RFC 7636) is MANDATORY: every request must
// carry code_challenge and code_challenge_method=S256. Anything else —
// missing challenge, missing method, or "plain" — is a structured 400
// invalid_request before a code is minted.
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
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	transactionID := q.Get("transaction_id") // advice-lifecycle id (optional); echoed full circle

	if clientID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	if redirectURI == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
		return
	}
	// PKCE is mandatory and S256-only (§10.4). RFC 7636 defaults an omitted
	// method to "plain", which we do not support — so the method must be
	// explicitly S256.
	if codeChallenge == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "code_challenge is required (PKCE, RFC 7636)")
		return
	}
	if codeChallengeMethod != "S256" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "code_challenge_method must be S256 (plain is not supported)")
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

	// Determine the authoritative tenant. A tenant-bound client (§ client↔tenant
	// binding) pins it and a contradicting tenant_id parameter is rejected — a
	// client cannot drive flows in tenants it was not registered for. An unbound
	// (legacy) client falls back to the request parameter.
	effectiveTenant := client.TenantID
	if effectiveTenant == "" {
		effectiveTenant = tenantID
	} else if tenantID != "" && tenantID != effectiveTenant {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "tenant_id does not match the client's registered tenant")
		return
	}
	if effectiveTenant == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "tenant_id is required (client is not tenant-bound)")
		return
	}

	// Resolve the end user. The secure path identifies the user from the
	// authz-session cookie set by an identity-proving leg (social login, the
	// dev console) — NOT from a client-supplied user_id, which a caller could
	// forge. With no valid session the request is unauthenticated: bounce back
	// to the client with the OAuth `login_required` error (RFC 6749 §4.1.2.1)
	// so it can start a login.
	//
	// DevAutologin re-enables the legacy phase-1 behaviour (trust a user_id
	// parameter, or auto-create a dev user) for local development and tests. It
	// is OFF in production.
	var user User
	var authzSessionID string // backs the protection-level assurance ledger
	if h.DevAutologin {
		if userID != "" {
			user, err = h.Store.GetUser(effectiveTenant, userID)
			if err != nil {
				httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "user_id not found in tenant")
				return
			}
		} else {
			user, err = h.devAutoUser(effectiveTenant)
			if err != nil {
				h.Logger.Error("authorize_auto_user_failed", "err", err, "tenant_id", effectiveTenant)
				httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to provision dev user")
				return
			}
		}
	} else {
		sess, ok := h.authzSession(r, effectiveTenant)
		if !ok {
			h.redirectAuthorizeError(w, r, redir, state, "login_required", "authentication required — sign in first")
			return
		}
		authzSessionID = sess.ID
		user, err = h.Store.GetUser(effectiveTenant, sess.UserID)
		if err != nil {
			h.redirectAuthorizeError(w, r, redir, state, "login_required", "session user no longer exists")
			return
		}
	}

	// Authentication-context interlude (otp.go / protection.go). acr_values is
	// client preference order (OIDC Core §3.1.2.1). Two shapes are accepted:
	//
	//   - a PROTECTION LEVEL (urn:xauth:protect:…) — the client states the bar the
	//     action needs; auth-service decides (mocked) whether to pass through or
	//     challenge, and with what. This is the preferred interface.
	//   - a specific METHOD (urn:xauth:otp:sms, urn:xauth:fido2) — the legacy
	//     explicit-method step-up, kept for back-compat.
	//
	// Either way /authorize/verify finishes the flow.
	pend := pendingAuthorize{
		ClientID:      clientID,
		TenantID:      effectiveTenant,
		UserID:        user.ID,
		RedirectURI:   redirectURI,
		Scope:         scope,
		State:         state,
		Nonce:         nonce,
		CodeChallenge: codeChallenge,
		TransactionID: transactionID,
	}

	lvl, lvlOK := matchProtection(q.Get("acr_values"))

	// Advice → /authorize binding. When a transaction_id is presented it must be a
	// known, not-yet-completed advice call for THIS tenant, issued for THIS user
	// (when the advice named one), and the requested protection level must
	// meet-or-exceed the advised rank. This stops a client-supplied transaction_id
	// from being a free-floating correlation token: it can't be forged, replayed,
	// bound to a different subject, or used to downgrade the required assurance.
	if transactionID != "" {
		advice, err := h.Store.GetAdviceCall(effectiveTenant, transactionID)
		switch {
		case errors.Is(err, ErrNotFound):
			h.Logger.Warn("authorize_transaction_unknown", "transaction_id", transactionID, "tenant_id", effectiveTenant, "user_id", user.ID)
			httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "unknown transaction_id")
			return
		case err != nil:
			h.Logger.Error("authorize_transaction_lookup_failed", "err", err, "tenant_id", effectiveTenant)
			httpx.WriteError(w, http.StatusBadGateway, "internal_error", "could not resolve transaction_id")
			return
		}
		if advice.CompletedAt != nil {
			h.Logger.Warn("authorize_transaction_replay", "transaction_id", transactionID, "tenant_id", effectiveTenant, "user_id", user.ID)
			httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "transaction_id has already been used")
			return
		}
		if advice.UserID != "" && advice.UserID != user.ID {
			h.Logger.Warn("authorize_transaction_subject_mismatch", "transaction_id", transactionID,
				"tenant_id", effectiveTenant, "advice_user", advice.UserID, "auth_user", user.ID)
			httpx.WriteError(w, http.StatusForbidden, "access_denied", "transaction_id was issued for a different user")
			return
		}
		reqRank := 0
		if lvlOK {
			reqRank = lvl.Rank
		}
		if advice.Rank > 0 && reqRank < advice.Rank {
			h.Logger.Warn("authorize_transaction_downgrade", "transaction_id", transactionID,
				"tenant_id", effectiveTenant, "advised_rank", advice.Rank, "requested_rank", reqRank)
			httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "acr_values must request at least the advised protection level")
			return
		}
	}

	// Flow engine: when enabled, drive the request through the configurable flow
	// executor. The built-in default flow reproduces the legacy branch below
	// exactly (validate → issue), so this is behavior-identical for an
	// un-customized tenant. The advice/transaction binding above stays a
	// precondition (not a stage). Flag OFF → the legacy branch runs unchanged.
	if h.FlowEngine {
		// Seed the policy facts the risk-evaluation stage and stage-bound policies
		// read: request.* (client, ip, device, ua) and protection.* (requested vs
		// already-achieved rank). risk.* is filled by the risk-evaluation stage.
		reqRank := 0
		if lvlOK {
			reqRank = lvl.Rank
		}
		achievedRank := 0
		if h.Protection != nil && authzSessionID != "" {
			achievedRank = h.Protection.Achieved(authzSessionID)
		}
		exec := &FlowExecution{
			ID: uuid.NewString(), TenantID: effectiveTenant, Designation: FlowAuthorizeStepUp,
			ClientID: clientID, UserID: user.ID, RedirectURI: redirectURI, Scope: scope,
			State: state, Nonce: nonce, CodeChallenge: codeChallenge, TransactionID: transactionID,
			AuthzSessionID: authzSessionID, ACRValues: q.Get("acr_values"),
			Context: map[string]any{
				"request": map[string]any{
					"client_id":  clientID,
					"ip":         clientIP(r),
					"device_fp":  q.Get("device_fp"),
					"user_agent": r.UserAgent(),
				},
				"protection": map[string]any{
					"requested_rank": reqRank,
					"achieved_rank":  achievedRank,
				},
			},
			CreatedAt: time.Now().UTC(),
		}
		flow := h.selectAuthorizeFlow(effectiveTenant)
		if _, err := runFlow(w, r, exec, flow.Stages); err != nil {
			// Stages write their own responses; just record the fault.
			h.Logger.Error("flow_run_failed", "err", err, "flow", flow.Slug, "tenant_id", effectiveTenant, "user_id", user.ID)
		}
		return
	}

	if lvlOK {
		h.handleProtection(w, r, lvl, authzSessionID, pend)
		return
	}
	if spec, ok := matchStepUp(q.Get("acr_values")); ok {
		h.startStepUpFlow(w, r, h.effectiveStepUpSpec(effectiveTenant, spec), pend)
		return
	}

	h.mintCodeAndRedirect(w, r, AuthCode{
		ClientID:      clientID,
		TenantID:      effectiveTenant,
		UserID:        user.ID,
		RedirectURI:   redirectURI,
		Scope:         scope,
		State:         state,
		Nonce:         nonce,
		CodeChallenge: codeChallenge,
		TransactionID: transactionID,
	})
}

// AuthzSessionCookie is the HttpOnly cookie that carries the browser's
// authenticated session id into /authorize. It is set by an identity-proving
// leg (the social-login callback, the dev console) and read by /authorize to
// resolve the end user without trusting a client-supplied user_id. Scoped to
// /authorize so it is not sent to the token, userinfo, or console surfaces.
const AuthzSessionCookie = "xauth_authz_session"

// SetAuthzSession writes the authz-session cookie for sessionID.
func SetAuthzSession(w http.ResponseWriter, sessionID string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     AuthzSessionCookie,
		Value:    sessionID,
		Path:     "/authorize",
		Expires:  expires,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// authzSession resolves the live session referenced by the authz-session
// cookie, scoped to the given tenant. Returns false when the cookie is absent,
// the session is unknown to this tenant, invalidated, or expired.
func (h *OIDCHandlers) authzSession(r *http.Request, tenantID string) (Session, bool) {
	c, err := r.Cookie(AuthzSessionCookie)
	if err != nil || c.Value == "" {
		return Session{}, false
	}
	sess, err := h.Store.GetSession(tenantID, c.Value)
	if err != nil || sess.InvalidatedAt != nil || time.Now().UTC().After(sess.ExpiresAt) {
		return Session{}, false
	}
	return sess, true
}

// redirectAuthorizeError bounces an OAuth error back to the client's
// (already-validated) redirect_uri per RFC 6749 §4.1.2.1.
func (h *OIDCHandlers) redirectAuthorizeError(w http.ResponseWriter, r *http.Request, redir *url.URL, state, code, desc string) {
	rq := redir.Query()
	rq.Set("error", code)
	if desc != "" {
		rq.Set("error_description", desc)
	}
	if state != "" {
		rq.Set("state", state)
	}
	redir.RawQuery = rq.Encode()
	http.Redirect(w, r, redir.String(), http.StatusFound)
}

// devAutoUser returns (creating if needed) the dev@example.com user for the
// DevAutologin path. Never used in production.
func (h *OIDCHandlers) devAutoUser(tenantID string) (User, error) {
	const devEmail = "dev@example.com"
	if u, err := h.Store.GetUserByEmail(tenantID, devEmail); err == nil {
		return u, nil
	}
	now := time.Now().UTC()
	return h.Store.CreateUser(User{
		ID:        "usr_" + uuid.NewString(),
		TenantID:  tenantID,
		Email:     devEmail,
		Name:      "Dev User",
		CreatedAt: now,
		UpdatedAt: now,
	})
}

// Token handles POST /token for both the `authorization_code` and
// `refresh_token` grant types. Accepts client credentials via HTTP Basic or
// form body — phase 1 validates credentials only if the client row has a
// non-empty secret hash, to allow the default public dev client without auth.
// The code grant additionally requires PKCE (code_verifier, S256 — §10.4).
// TODO(phase-2): enforce client authentication strictly.
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
//
// PKCE (§10.4) is enforced unconditionally: code_verifier is required and
// SHA-256(verifier), base64url-encoded, must equal the code_challenge stored
// on the auth code at /authorize time. There is no PKCE-optional path.
//
// The grant also starts a new refresh-token family (§10.1): all tokens minted
// here — and every rotation descending from them — share one family id, so a
// replayed (already-rotated) refresh token can revoke the whole lineage.
func (h *OIDCHandlers) handleCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.PostForm.Get("code")
	redirectURI := r.PostForm.Get("redirect_uri")
	codeVerifier := r.PostForm.Get("code_verifier")
	if code == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	if codeVerifier == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "code_verifier is required (PKCE, RFC 7636)")
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
	// PKCE verification: SHA-256(code_verifier) base64url == stored challenge.
	// ac.CodeChallenge can only be empty for codes minted before PKCE became
	// mandatory; those fail too — no PKCE-optional path remains.
	if !verifyPKCES256(ac.CodeChallenge, codeVerifier) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "code_verifier does not match code_challenge")
		return
	}

	// Mint a session for the authenticated user. A second factor verified at
	// /authorize (non-empty amr on the code) makes the session stepped-up
	// from birth.
	now := time.Now().UTC()
	sess := Session{
		ID:              "ses_" + uuid.NewString(),
		TenantID:        ac.TenantID,
		UserID:          ac.UserID,
		RiskLevel:       RiskLow, // TODO(phase-2): pull from risk-service context
		StepUpCompleted: len(ac.AMR) > 0,
		CreatedAt:       now,
		UpdatedAt:       now,
		ExpiresAt:       now.Add(time.Duration(SessionTTLSeconds) * time.Second),
	}
	if _, err := h.Store.CreateSession(sess); err != nil {
		h.Logger.Error("token_session_create_failed", "err", err, "tenant_id", ac.TenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue session")
		return
	}

	// Every code-grant login starts a fresh token family (§10.1). All future
	// rotations of this refresh token inherit the same family id.
	familyID := "fam_" + uuid.NewString()
	accessPlain, refreshPlain, err := h.issueTokenPair(sess, ac.Scope, ac.ClientID, familyID)
	if err != nil {
		h.Logger.Error("token_issue_failed", "err", err, "session_id", sess.ID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue tokens")
		return
	}

	resp := map[string]any{
		"access_token":  accessPlain,
		"refresh_token": refreshPlain,
		"token_type":    "Bearer",
		"expires_in":    AccessTokenTTLSeconds,
		"scope":         ac.Scope,
	}
	// Standard OIDC: the code grant returns an id_token whenever the original
	// /authorize request asked for the "openid" scope. The nonce travels from
	// /authorize through the auth-code record into the id_token to bind the
	// token to the client's original request (replay protection, §10.1).
	if scopeContains(ac.Scope, "openid") {
		idToken, err := h.issueIDToken(sess, ac.ClientID, ac.Nonce, ac.ACR, ac.AMR, ac.TransactionID)
		if err != nil {
			h.Logger.Error("id_token_issue_failed", "err", err, "session_id", sess.ID)
			httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue id_token")
			return
		}
		resp["id_token"] = idToken
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// handleRefreshGrant validates a presented refresh token and issues a brand-new
// access + refresh token pair, revoking the old refresh token (rotation, RFC
// 6749 §10.4 / ARCHITECTURE.md §10.1). The replacement tokens stay in the same
// token family as the presented token, and the issuing client_id persisted on
// the token record at login supplies the rotated access token's `aud` claim —
// the caller cannot change the audience at refresh time.
//
// Family-based revocation (§10.1): presenting a refresh token that has already
// been rotated out (revoked_at is stamped) is treated as a theft signal — a
// legitimate client never replays a spent token. The ENTIRE family (every
// refresh token and access-token record descending from the same login) is
// revoked and the request is rejected with a structured 401.
func (h *OIDCHandlers) handleRefreshGrant(w http.ResponseWriter, r *http.Request) {
	presented := r.PostForm.Get("refresh_token")
	if presented == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	// Optional client authentication, same rules as the code grant.
	clientID, _, ok := h.extractClientCreds(r)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	hash := HashToken(presented)
	tok, err := h.Store.GetTokenByHash(hash)
	if err != nil || tok.TokenType != TokenTypeRefresh {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "refresh token not recognised")
		return
	}
	if tok.RevokedAt != nil {
		// Replay of a rotated-out (or otherwise revoked) refresh token: theft
		// signal. Kill the whole family — all refresh AND access records — then
		// reject. RevokeTokenFamily is a no-op for the empty family id carried
		// by pre-migration legacy rows.
		revoked, ferr := h.Store.RevokeTokenFamily(tok.FamilyID)
		if ferr != nil {
			h.Logger.Error("refresh_family_revoke_failed", "err", ferr, "family_id", tok.FamilyID)
		} else if revoked > 0 {
			h.Logger.Warn("refresh_token_replay_family_revoked",
				"family_id", tok.FamilyID, "session_id", tok.SessionID,
				"tenant_id", tok.TenantID, "tokens_revoked", revoked)
		}
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_grant",
			"refresh token already used — token family revoked")
		return
	}
	if time.Now().UTC().After(tok.ExpiresAt) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}
	// If the caller authenticated as a client, it must be the client the token
	// was issued to. (tok.ClientID can be empty on pre-migration legacy rows.)
	if clientID != "" && tok.ClientID != "" && clientID != tok.ClientID {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "refresh token was issued to a different client")
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

	// aud comes from the persisted record, not the request; legacy rows without
	// a stored client_id fall back to whatever the caller authenticated as.
	audClientID := tok.ClientID
	if audClientID == "" {
		audClientID = clientID
	}
	accessPlain, refreshPlain, err := h.issueTokenPair(sess, tok.Scope, audClientID, tok.FamilyID)
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

// issueTokenPair creates an access + refresh token bound to sess and returns
// the plaintext values for the response body.
//
// The access token is an RS256 JWT (ARCHITECTURE.md §10.1) carrying
// sub/iss/aud/exp/iat plus the X-Auth claims tenant_id, scope, and session_id.
// The jti keeps two tokens minted in the same second textually distinct so
// their storage hashes never collide. The refresh token stays an opaque UUID.
// Both are persisted as SHA-256 hashes — the access-token record doubles as
// the revocation deny list (see UserInfo).
//
// clientID and familyID are persisted on BOTH records: clientID so the refresh
// grant can mint a stable `aud` without trusting the caller, familyID so a
// refresh-token replay can revoke the whole lineage (§10.1) including the
// access tokens it produced.
func (h *OIDCHandlers) issueTokenPair(sess Session, scope, clientID, familyID string) (string, string, error) {
	now := time.Now().UTC()
	accessExpiry := now.Add(time.Duration(AccessTokenTTLSeconds) * time.Second)
	accessPlain, err := h.Signer.Sign(jwtx.Claims{
		Sub:       sess.UserID,
		Iss:       h.JWTIssuer,
		Aud:       clientID,
		Exp:       accessExpiry.Unix(),
		Iat:       now.Unix(),
		JTI:       uuid.NewString(),
		TenantID:  sess.TenantID,
		Scope:     scope,
		SessionID: sess.ID,
	}, nil)
	if err != nil {
		return "", "", err
	}
	refreshPlain := uuid.NewString()

	accessRec := Token{
		TokenHash: HashToken(accessPlain),
		SessionID: sess.ID,
		UserID:    sess.UserID,
		TenantID:  sess.TenantID,
		ClientID:  clientID,
		FamilyID:  familyID,
		TokenType: TokenTypeAccess,
		Scope:     scope,
		IssuedAt:  now,
		ExpiresAt: accessExpiry,
	}
	refreshRec := Token{
		TokenHash: HashToken(refreshPlain),
		SessionID: sess.ID,
		UserID:    sess.UserID,
		TenantID:  sess.TenantID,
		ClientID:  clientID,
		FamilyID:  familyID,
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

// issueIDToken mints a standard OIDC ID token (RS256, same key as access
// tokens per §10.1): iss/sub/aud/exp/iat plus the nonce from the original
// /authorize request and the tenant_id for multi-tenant consumers. ID tokens
// are proof-of-authentication for the client, not API credentials — they are
// not persisted and cannot be revoked or presented to /userinfo's deny list.
func (h *OIDCHandlers) issueIDToken(sess Session, clientID, nonce, acr string, amr []string, transactionID string) (string, error) {
	now := time.Now().UTC()
	// The advice-lifecycle id rides along as an extra claim so the authenticated
	// proof itself carries the correlation, not just the redirect query.
	var extra map[string]any
	if transactionID != "" {
		extra = map[string]any{"transaction_id": transactionID}
	}
	return h.Signer.Sign(jwtx.Claims{
		Sub:      sess.UserID,
		Iss:      h.JWTIssuer,
		Aud:      clientID,
		Exp:      now.Add(time.Duration(AccessTokenTTLSeconds) * time.Second).Unix(),
		Iat:      now.Unix(),
		TenantID: sess.TenantID,
		Nonce:    nonce,
		ACR:      acr,
		AMR:      amr,
	}, extra)
}

// verifyPKCES256 reports whether the RFC 7636 S256 transformation of verifier
// — BASE64URL-ENCODE(SHA256(ASCII(code_verifier))), unpadded — equals the
// stored challenge. An empty challenge never matches (codes minted before
// PKCE became mandatory must not be exchangeable). Comparison is constant-time
// out of caution, though both inputs derive from attacker-visible material.
func verifyPKCES256(challenge, verifier string) bool {
	if challenge == "" || verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// scopeContains reports whether the space-delimited OAuth scope string
// includes want as a whole token.
func scopeContains(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
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

// UserInfo returns minimal OIDC user claims for the bearer. Response shape:
// {sub, email, name}. Returns 401 with RFC 6750 WWW-Authenticate whenever the
// bearer is missing, malformed, signed by an unknown key, expired, unknown to
// storage, or revoked.
//
// HYBRID validation — deliberately both, in this order:
//
//  1. Stateless RS256 verification (signature, exp/iat window, issuer) via
//     jwtx, exactly what any sister service does against our JWKS (§10.1).
//  2. Stored-record lookup: the hashed access-token row written at issue time
//     must still exist and not carry revoked_at.
//
// The spec makes access tokens stateless, but /revoke (RFC 7009) must keep
// taking effect immediately; until distributed revocation (shared deny cache /
// token-family invalidation) lands, the persisted record acts as a deny list.
func (h *OIDCHandlers) UserInfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "bearer token required")
		return
	}
	plain := strings.TrimPrefix(auth, prefix)
	if _, _, err := h.Verifier.Verify(plain, time.Now().UTC()); err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "token signature or claims invalid")
		return
	}
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
		// Public-client PKCE flows may omit client_id entirely. The auth code /
		// token record still carries the authoritative client_id.
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
