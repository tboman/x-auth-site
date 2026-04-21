package internal

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// SocialHandlers implements the phase-1 social-login stubs for google, github,
// and microsoft. No real OAuth2 handshake happens — /authorize immediately
// redirects back to our own /callback with a mock `code`, and /callback
// "exchanges" that code for a canned profile.
//
// Purpose: give frontend and SDK developers a working provider button to click
// in local / staging environments without configuring real client IDs.
// TODO(phase-2): replace stubs with real per-provider OAuth2 code + PKCE.
type SocialHandlers struct {
	Store  Storage
	Logger *slog.Logger
	Issuer string

	// mu guards pendingCodes. Codes live only long enough for the browser to
	// follow the redirect from /authorize to /callback — ~seconds.
	mu            sync.Mutex
	pendingCodes  map[string]socialPending
	pendingOnceGC sync.Once
}

type socialPending struct {
	Provider    string
	TenantID    string
	RedirectURI string
	State       string
	CreatedAt   time.Time
}

// ensureMap lazily initialises the pendingCodes map. Router wiring constructs
// SocialHandlers as &SocialHandlers{...} so the map is nil until first use.
func (h *SocialHandlers) ensureMap() {
	h.pendingOnceGC.Do(func() {
		h.pendingCodes = make(map[string]socialPending)
	})
}

// Authorize handles GET /v1/social/{provider}/authorize.
//
// Phase-1 behaviour: validate the provider, mint a mock code, store it keyed to
// the state, and 302 to our own /v1/social/{provider}/callback. Real providers
// would redirect to their own authorization endpoint. The 100ms "feel" from
// the spec is simulated via a short sleep so tests that assert ordering pass.
func (h *SocialHandlers) Authorize(w http.ResponseWriter, r *http.Request) {
	h.ensureMap()

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
	if _, err := url.Parse(redirectURI); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must be a valid URL")
		return
	}

	code := uuid.NewString()
	h.mu.Lock()
	h.pendingCodes[code] = socialPending{
		Provider:    provider,
		TenantID:    tenantID,
		RedirectURI: redirectURI,
		State:       state,
		CreatedAt:   time.Now().UTC(),
	}
	h.mu.Unlock()

	// Simulate the user-agent round-trip delay seen in real provider flows.
	// TODO(phase-2): drop this sleep — real providers won't need it.
	time.Sleep(100 * time.Millisecond)

	// Redirect back to our own callback with the mock code + state.
	cb, _ := url.Parse(strings.TrimRight(h.Issuer, "/") + "/v1/social/" + provider + "/callback")
	cbq := cb.Query()
	cbq.Set("code", code)
	if state != "" {
		cbq.Set("state", state)
	}
	cb.RawQuery = cbq.Encode()
	http.Redirect(w, r, cb.String(), http.StatusFound)
}

// Callback handles GET /v1/social/{provider}/callback.
//
// Phase-1 behaviour: exchange the mock code for a canned profile, upsert a
// user keyed by (tenant_id, email), mint a session with risk_level=low, and
// redirect to the original redirect_uri with `?session_id=...&state=...`. No
// access token is issued here — the caller is expected to follow up with a
// POST /v1/sessions or the OIDC token flow if it needs bearer tokens.
func (h *SocialHandlers) Callback(w http.ResponseWriter, r *http.Request) {
	h.ensureMap()

	provider := r.PathValue("provider")
	if !ValidSocialProvider(provider) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "unsupported provider")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}

	h.mu.Lock()
	pending, ok := h.pendingCodes[code]
	if ok {
		delete(h.pendingCodes, code)
	}
	h.mu.Unlock()
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "code is invalid or already used")
		return
	}
	if pending.Provider != provider {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "provider mismatch")
		return
	}

	profile := cannedProfile(provider)

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

// cannedProfile returns the canned SocialProfile we use for every provider in
// phase 1. Real providers return per-provider JSON shapes; phase 1 normalises.
// TODO(phase-2): delete — real callbacks will exchange the code for a real
// OAuth2 access token, hit the provider's userinfo endpoint, and normalise
// the response into SocialProfile.
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
