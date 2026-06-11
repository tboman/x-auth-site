package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// SocialProviderConfig is the OAuth2 wiring for a real social-login provider.
// A provider present in SocialHandlers.Providers runs the real authorization-
// code + PKCE handshake; providers absent from the map keep the phase-1 stub
// behaviour. Endpoint URLs are fields (not constants) so tests can point them
// at an httptest server.
type SocialProviderConfig struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	UserinfoURL  string
}

// Google OAuth2 / OIDC endpoints (https://accounts.google.com/.well-known/openid-configuration).
const (
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserinfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
)

// SocialProvidersFromEnv assembles the real-provider map from environment
// variables. Only google is wired today: set GOOGLE_CLIENT_ID and
// GOOGLE_CLIENT_SECRET (an OAuth client of type "Web application" in the
// Google Cloud console, with <AUTH_ISSUER>/v1/social/google/callback as an
// authorized redirect URI). github and microsoft remain stubs.
func SocialProvidersFromEnv(logger *slog.Logger) map[string]SocialProviderConfig {
	providers := map[string]SocialProviderConfig{}

	id, secret := os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")
	switch {
	case id != "" && secret != "":
		providers["google"] = SocialProviderConfig{
			ClientID:     id,
			ClientSecret: secret,
			AuthURL:      googleAuthURL,
			TokenURL:     googleTokenURL,
			UserinfoURL:  googleUserinfoURL,
		}
		logger.Info("social_provider_configured", "provider", "google")
	case id != "" || secret != "":
		logger.Warn("social_provider_partial_config",
			"provider", "google",
			"hint", "set both GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET; falling back to stub")
	}

	return providers
}

// defaultSocialHTTP is the outbound client for provider token/userinfo calls.
// Provider endpoints are public, TLS-verified hosts — tlsx does not apply here.
var defaultSocialHTTP = &http.Client{Timeout: 10 * time.Second}

// fetchProfile runs the back-channel half of the real handshake: exchange the
// authorization code (+ PKCE verifier) at the provider's token endpoint, then
// resolve the user's profile from the userinfo endpoint. Errors are returned
// for logging; callers surface a generic 502 so provider internals never leak
// to the browser.
func (h *SocialHandlers) fetchProfile(ctx context.Context, cfg SocialProviderConfig, provider, code, verifier string) (SocialProfile, error) {
	client := h.HTTP
	if client == nil {
		client = defaultSocialHTTP
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"redirect_uri":  {h.callbackURL(provider)},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return SocialProfile{}, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return SocialProfile{}, fmt.Errorf("token exchange: %w", err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		return SocialProfile{}, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return SocialProfile{}, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, truncate(body, 256))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return SocialProfile{}, fmt.Errorf("decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return SocialProfile{}, fmt.Errorf("token response missing access_token")
	}

	uiReq, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.UserinfoURL, nil)
	if err != nil {
		return SocialProfile{}, fmt.Errorf("build userinfo request: %w", err)
	}
	uiReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	uiResp, err := client.Do(uiReq)
	if err != nil {
		return SocialProfile{}, fmt.Errorf("userinfo: %w", err)
	}
	uiBody, err := io.ReadAll(io.LimitReader(uiResp.Body, 1<<20))
	uiResp.Body.Close()
	if err != nil {
		return SocialProfile{}, fmt.Errorf("read userinfo response: %w", err)
	}
	if uiResp.StatusCode != http.StatusOK {
		return SocialProfile{}, fmt.Errorf("userinfo endpoint returned %d: %s", uiResp.StatusCode, truncate(uiBody, 256))
	}
	var ui struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := json.Unmarshal(uiBody, &ui); err != nil {
		return SocialProfile{}, fmt.Errorf("decode userinfo response: %w", err)
	}
	if ui.Email == "" {
		return SocialProfile{}, fmt.Errorf("userinfo response missing email")
	}
	// The user upsert is keyed by (tenant, email). Accepting an unverified
	// provider email would let an attacker claim someone else's address at a
	// provider and inherit their X-Auth account — reject outright.
	if ui.EmailVerified != nil && !*ui.EmailVerified {
		return SocialProfile{}, fmt.Errorf("provider email %q is not verified", ui.Email)
	}

	name := ui.Name
	if name == "" {
		name = ui.Email
	}
	return SocialProfile{
		Provider:   provider,
		ExternalID: ui.Sub,
		Email:      ui.Email,
		Name:       name,
	}, nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
