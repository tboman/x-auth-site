package internal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// SocialHandlers serves /v1/social/{provider}/authorize and /callback in one
// of two modes, decided per provider:
//
//   - **Real** (provider present in Providers): full OAuth2 authorization-code
//     handshake with PKCE (S256) against the provider — /authorize redirects
//     to the provider's consent page, /callback exchanges the returned code
//     and resolves the user's profile from the userinfo endpoint. Wired for
//     google via GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET.
//   - **Stub** (provider not configured): the phase-1 mock — /authorize
//     immediately redirects back to our own /callback with a mock code, and
//     /callback "exchanges" it for a canned profile. Keeps local dev and CI
//     working with zero provider configuration.
//
// Both modes converge in completeLogin: upsert the user by (tenant, email),
// mint a low-risk session, and redirect to the caller's redirect_uri.
//
// In-flight state (stub codes, real state nonces + PKCE verifiers) lives in
// process memory: entries expire after pendingTTL, and a callback must land
// on the instance that served /authorize. Run a single replica (or add sticky
// sessions / a shared store) before scaling out the real flow.
type SocialHandlers struct {
	Store  Storage
	Logger *slog.Logger
	Issuer string

	// Providers maps provider name → real OAuth2 wiring. Absent providers
	// (or an empty ClientID) fall back to the stub. See SocialProvidersFromEnv.
	Providers map[string]SocialProviderConfig

	// HTTP overrides the outbound client for token/userinfo calls (tests).
	// Nil means a default client with a 10s timeout.
	HTTP *http.Client

	// mu guards pending. Stub entries are keyed by the mock code; real entries
	// are keyed by the state nonce we hand the provider.
	mu          sync.Mutex
	pending     map[string]socialPending
	pendingOnce sync.Once
}

// pendingTTL bounds how long an in-flight login may sit at the provider's
// consent screen before we refuse the callback.
const pendingTTL = 10 * time.Minute

type socialPending struct {
	Provider     string
	TenantID     string
	RedirectURI  string
	State        string // the caller's state, echoed back on the final redirect
	CodeVerifier string // PKCE verifier (real mode only)
	CreatedAt    time.Time
}

// ensureMap lazily initialises the pending map. Router wiring constructs
// SocialHandlers as &SocialHandlers{...} so the map is nil until first use.
func (h *SocialHandlers) ensureMap() {
	h.pendingOnce.Do(func() {
		h.pending = make(map[string]socialPending)
	})
}

// providerConfig returns the real-mode config for provider, if configured.
func (h *SocialHandlers) providerConfig(provider string) (SocialProviderConfig, bool) {
	cfg, ok := h.Providers[provider]
	return cfg, ok && cfg.ClientID != ""
}

// callbackURL is our redirect_uri registered with the provider.
func (h *SocialHandlers) callbackURL(provider string) string {
	return strings.TrimRight(h.Issuer, "/") + "/v1/social/" + provider + "/callback"
}

// storePending records an in-flight login and opportunistically sweeps
// expired entries (abandoned consent screens would otherwise accumulate).
func (h *SocialHandlers) storePending(key string, p socialPending) {
	h.ensureMap()
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := time.Now().UTC().Add(-pendingTTL)
	for k, v := range h.pending {
		if v.CreatedAt.Before(cutoff) {
			delete(h.pending, k)
		}
	}
	h.pending[key] = p
}

// takePending consumes an in-flight login. Each key is single-use; expired
// entries are treated as absent.
func (h *SocialHandlers) takePending(key string) (socialPending, bool) {
	h.ensureMap()
	h.mu.Lock()
	defer h.mu.Unlock()
	p, ok := h.pending[key]
	if !ok {
		return socialPending{}, false
	}
	delete(h.pending, key)
	if time.Since(p.CreatedAt) > pendingTTL {
		return socialPending{}, false
	}
	return p, true
}

// randToken returns n crypto-random bytes as unpadded base64url — used for
// state nonces and PKCE verifiers.
func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing means the platform's entropy source is broken —
		// nothing sensible to do but crash loudly rather than mint guessable
		// state values.
		panic("social: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Authorize handles GET /v1/social/{provider}/authorize.
//
// Real mode redirects to the provider's authorization endpoint with PKCE;
// stub mode mints a mock code and 302s straight to our own /callback.
func (h *SocialHandlers) Authorize(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if !ValidSocialProvider(provider) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "unsupported provider")
		return
	}

	q := r.URL.Query()
	tenantID := q.Get("tenant_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	if tenantID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "tenant_id is required")
		return
	}
	if redirectURI == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
		return
	}
	if u, err := url.Parse(redirectURI); err != nil || !u.IsAbs() {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must be an absolute URL")
		return
	}
	// The final hop of this leg hands a freshly minted session_id + user_id to
	// redirect_uri, so an arbitrary redirect_uri would leak a logged-in session
	// to any host. Allow only same-origin (hosted console/login callbacks) or a
	// redirect URI registered for this tenant's client.
	if !redirectAllowedForTenant(h.Store, h.Issuer, tenantID, redirectURI) {
		h.Logger.Warn("social_redirect_rejected", "tenant_id", tenantID, "redirect_uri", redirectURI)
		httpx.WriteError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri is not registered for this tenant")
		return
	}

	if cfg, ok := h.providerConfig(provider); ok {
		h.authorizeReal(w, r, cfg, provider, tenantID, redirectURI, state)
		return
	}

	// ── Stub mode ──
	code := uuid.NewString()
	h.storePending(code, socialPending{
		Provider:    provider,
		TenantID:    tenantID,
		RedirectURI: redirectURI,
		State:       state,
		CreatedAt:   time.Now().UTC(),
	})

	// Simulate the user-agent round-trip delay seen in real provider flows.
	time.Sleep(100 * time.Millisecond)

	// Redirect back to our own callback with the mock code + state.
	cb, _ := url.Parse(h.callbackURL(provider))
	cbq := cb.Query()
	cbq.Set("code", code)
	if state != "" {
		cbq.Set("state", state)
	}
	cb.RawQuery = cbq.Encode()
	http.Redirect(w, r, cb.String(), http.StatusFound)
}

// redirectAllowedForTenant guards the social-login leg (and the /login chooser
// that feeds it) from being an open redirect. The leg's final hop carries a
// freshly minted session_id + user_id back to redirect_uri, so an arbitrary
// redirect_uri would hand a logged-in session to any host. A redirect_uri is
// allowed only when it is either:
//
//   - same-origin as the issuer — the hosted console/login callbacks
//     (/admin/…, /dev/…, /admin/signup/…), which can't leak to a third party
//     because they point back at X-Auth itself; or
//   - an exact match of a redirect URI registered for an OIDC client bound to
//     this tenant, or for an unbound (legacy/env) client.
//
// Registration is the trust boundary. A self-service client's redirect URIs are
// bound to the tenant that registered them, so an attacker's host only ever
// matches under their OWN tenant_id (where the session would be their own
// anyway). Unbound clients can only be created by an admin/env, never via
// self-service, so an attacker cannot slip their host onto the list either.
func redirectAllowedForTenant(store Storage, issuer, tenantID, redirectURI string) bool {
	if sameOrigin(issuer, redirectURI) {
		return true
	}
	clients, err := store.ListClients()
	if err != nil {
		return false
	}
	for _, c := range clients {
		// Unbound clients (TenantID == "") are admin/env-registered and trusted
		// across tenants; a bound client only counts for its own tenant.
		if c.TenantID != "" && c.TenantID != tenantID {
			continue
		}
		if redirectURIAllowed(redirectURI, c.RedirectURIs) {
			return true
		}
	}
	return false
}

// sameOrigin reports whether candidate shares scheme + host with base.
func sameOrigin(base, candidate string) bool {
	b, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || b.Host == "" {
		return false
	}
	c, err := url.Parse(candidate)
	if err != nil || c.Host == "" {
		return false
	}
	return b.Scheme == c.Scheme && b.Host == c.Host
}

// authorizeReal sends the browser to the provider's consent page. The state
// nonce is ours (single-use, unguessable) — the caller's state rides along in
// the pending entry and is echoed on the final redirect, never forwarded to
// the provider.
func (h *SocialHandlers) authorizeReal(w http.ResponseWriter, r *http.Request, cfg SocialProviderConfig, provider, tenantID, redirectURI, callerState string) {
	nonce := randToken(32)
	verifier := randToken(48) // 64 chars — within RFC 7636's 43..128 bounds
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	h.storePending(nonce, socialPending{
		Provider:     provider,
		TenantID:     tenantID,
		RedirectURI:  redirectURI,
		State:        callerState,
		CodeVerifier: verifier,
		CreatedAt:    time.Now().UTC(),
	})

	authz, err := url.Parse(cfg.AuthURL)
	if err != nil {
		h.Logger.Error("social_auth_url_invalid", "provider", provider, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "provider misconfigured")
		return
	}
	aq := authz.Query()
	aq.Set("client_id", cfg.ClientID)
	aq.Set("redirect_uri", h.callbackURL(provider))
	aq.Set("response_type", "code")
	aq.Set("scope", "openid email profile")
	aq.Set("state", nonce)
	aq.Set("code_challenge", challenge)
	aq.Set("code_challenge_method", "S256")
	// Force the account chooser (OIDC prompt=select_account) so a user with a
	// live provider session still picks which account to use, instead of being
	// silently signed in with their single/last one. Honoured by Google and any
	// OIDC-compliant provider.
	aq.Set("prompt", "select_account")
	authz.RawQuery = aq.Encode()
	http.Redirect(w, r, authz.String(), http.StatusFound)
}

// Callback handles GET /v1/social/{provider}/callback.
func (h *SocialHandlers) Callback(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if !ValidSocialProvider(provider) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "unsupported provider")
		return
	}

	if cfg, ok := h.providerConfig(provider); ok {
		h.callbackReal(w, r, cfg, provider)
		return
	}

	// ── Stub mode: "exchange" the mock code for a canned profile ──
	code := r.URL.Query().Get("code")
	if code == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	pending, ok := h.takePending(code)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "code is invalid or already used")
		return
	}
	if pending.Provider != provider {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "provider mismatch")
		return
	}

	h.completeLogin(w, r, pending, cannedProfile(provider))
}

// callbackReal finishes the provider handshake: validate state, exchange the
// code (PKCE), fetch the profile, and hand off to completeLogin.
func (h *SocialHandlers) callbackReal(w http.ResponseWriter, r *http.Request, cfg SocialProviderConfig, provider string) {
	q := r.URL.Query()
	state := q.Get("state")
	if state == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "state is required")
		return
	}
	pending, ok := h.takePending(state)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "state is invalid, expired, or already used")
		return
	}
	if pending.Provider != provider {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "provider mismatch")
		return
	}

	// Provider-reported errors (user clicked "cancel", consent denied, …) go
	// back to the caller's redirect_uri per the usual OAuth error contract.
	if errCode := q.Get("error"); errCode != "" {
		redir, err := url.Parse(pending.RedirectURI)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_redirect_uri", "stored redirect_uri is invalid")
			return
		}
		rq := redir.Query()
		rq.Set("error", errCode)
		if pending.State != "" {
			rq.Set("state", pending.State)
		}
		redir.RawQuery = rq.Encode()
		http.Redirect(w, r, redir.String(), http.StatusFound)
		return
	}

	code := q.Get("code")
	if code == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}

	profile, err := h.fetchProfile(r.Context(), cfg, provider, code, pending.CodeVerifier)
	if err != nil {
		h.Logger.Error("social_provider_exchange_failed", "provider", provider, "err", err)
		httpx.WriteError(w, http.StatusBadGateway, "provider_error", "could not complete sign-in with the provider")
		return
	}

	h.completeLogin(w, r, pending, profile)
}

// completeLogin is the provider-agnostic tail of both modes: upsert a user
// keyed by (tenant_id, email), mint a session with risk_level=low, and
// redirect to the original redirect_uri with `?session_id=...&state=...`. No
// access token is issued here — the caller is expected to follow up with a
// POST /v1/sessions or the OIDC token flow if it needs bearer tokens.
func (h *SocialHandlers) completeLogin(w http.ResponseWriter, r *http.Request, pending socialPending, profile SocialProfile) {
	// Upsert by (tenant, email). A repeat login for the same email returns the
	// existing user — we don't want every /callback to create a new row.
	user, err := h.Store.GetUserByEmail(pending.TenantID, profile.Email)
	if err != nil {
		now := time.Now().UTC()
		user, err = h.Store.CreateUser(User{
			ID:        "usr_" + uuid.NewString(),
			TenantID:  pending.TenantID,
			Email:     profile.Email,
			Name:      profile.Name,
			CreatedAt: now,
			UpdatedAt: now,
		})
		if err != nil {
			h.Logger.Error("social_user_create_failed", "err", err, "tenant_id", pending.TenantID)
			httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to create user")
			return
		}
	}

	now := time.Now().UTC()
	sess := Session{
		ID:              "ses_" + uuid.NewString(),
		TenantID:        pending.TenantID,
		UserID:          user.ID,
		RiskLevel:       RiskLow,
		StepUpCompleted: false,
		CreatedAt:       now,
		UpdatedAt:       now,
		ExpiresAt:       now.Add(time.Duration(SessionTTLSeconds) * time.Second),
	}
	if _, err := h.Store.CreateSession(sess); err != nil {
		h.Logger.Error("social_session_create_failed", "err", err, "tenant_id", pending.TenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to create session")
		return
	}

	// Set the authz-session cookie so the subsequent /authorize call can
	// identify this user server-side, without the SPA forwarding a (forgeable)
	// user_id. SameSite=Lax is sent on the SPA's top-level navigation to
	// /authorize.
	SetAuthzSession(w, sess.ID, sess.ExpiresAt)

	// Redirect back to the caller's redirect_uri with session metadata.
	// A richer implementation would hand back an ID token; phase 1 returns the
	// session id directly so local dev flows can keep working without JWT plumbing.
	redir, err := url.Parse(pending.RedirectURI)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_redirect_uri", "stored redirect_uri is invalid")
		return
	}
	rq := redir.Query()
	rq.Set("session_id", sess.ID)
	rq.Set("user_id", user.ID)
	if pending.State != "" {
		rq.Set("state", pending.State)
	}
	redir.RawQuery = rq.Encode()
	http.Redirect(w, r, redir.String(), http.StatusFound)
}

// cannedProfile returns the canned SocialProfile used by stub mode. Real mode
// normalises the provider's userinfo response instead (fetchProfile).
func cannedProfile(provider string) SocialProfile {
	name := provider
	if len(name) > 0 {
		name = strings.ToUpper(name[:1]) + name[1:]
	}
	return SocialProfile{
		Provider:   provider,
		ExternalID: provider + "|stub-user",
		Email:      "stub-" + provider + "@example.com",
		Name:       name + " Stub User",
	}
}
