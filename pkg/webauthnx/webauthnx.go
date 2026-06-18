// Package webauthnx is the relying-party boundary for WebAuthn (passkey)
// ceremonies — the vendor seam around github.com/go-webauthn/webauthn, mirroring
// pkg/smsx. It builds a configured *webauthn.WebAuthn from the environment so the
// authenticator-service adapter stays thin and testable.
//
// Credentials are bound to the RP ID, so WAUTHN_RP_ID must be stable in
// production (auth.x-auth.com) — changing it invalidates every registered
// passkey. When unset (local dev / CI), New falls back to a localhost config so
// the service still boots; WebAuthn just won't work against a real origin.
package webauthnx

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Config holds the relying-party settings.
type Config struct {
	RPID             string   // WAUTHN_RP_ID — the registrable domain (no scheme/port), e.g. auth.x-auth.com
	RPDisplayName    string   // WAUTHN_RP_DISPLAY_NAME — human label, e.g. X-Auth
	RPOrigins        []string // WAUTHN_RP_ORIGINS — fully-qualified allowed origins, e.g. https://auth.x-auth.com
	UserVerification string   // WAUTHN_USER_VERIFICATION — preferred (default) | required | discouraged
}

// ConfigFromEnv reads the WAUTHN_* environment variables.
func ConfigFromEnv() Config {
	return Config{
		RPID:             strings.TrimSpace(os.Getenv("WAUTHN_RP_ID")),
		RPDisplayName:    strings.TrimSpace(os.Getenv("WAUTHN_RP_DISPLAY_NAME")),
		RPOrigins:        splitTrim(os.Getenv("WAUTHN_RP_ORIGINS")),
		UserVerification: strings.TrimSpace(os.Getenv("WAUTHN_USER_VERIFICATION")),
	}
}

// New builds the relying party. When RPID is unset it logs a warning and uses a
// localhost dev config so non-WebAuthn boots succeed. A malformed config (which
// webauthn.New rejects) is a fatal error for the caller.
func New(cfg Config, logger *slog.Logger) (*webauthn.WebAuthn, error) {
	rpID := cfg.RPID
	origins := cfg.RPOrigins
	display := cfg.RPDisplayName
	if rpID == "" {
		rpID = "localhost"
		if len(origins) == 0 {
			origins = []string{"http://localhost:8082", "http://localhost:8083"}
		}
		if logger != nil {
			logger.Warn("webauthn", "rp_id", rpID, "reason", "WAUTHN_RP_ID unset — using localhost dev config")
		}
	}
	if display == "" {
		display = "X-Auth"
	}
	uv := userVerification(cfg.UserVerification)

	w, err := webauthn.New(&webauthn.Config{
		RPID:                  rpID,
		RPDisplayName:         display,
		RPOrigins:             origins,
		AttestationPreference: protocol.PreferNoAttestation, // privacy: no AAGUID tracking
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: uv,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("webauthnx: %w", err)
	}
	if logger != nil {
		logger.Info("webauthn", "rp_id", rpID, "origins", strings.Join(origins, ","), "user_verification", string(uv))
	}
	return w, nil
}

func userVerification(s string) protocol.UserVerificationRequirement {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "required":
		return protocol.VerificationRequired
	case "discouraged":
		return protocol.VerificationDiscouraged
	default:
		return protocol.VerificationPreferred
	}
}

func splitTrim(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
