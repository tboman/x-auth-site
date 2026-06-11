package internal

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"
)

// SeedClientsFromEnv registers additional OIDC clients from the OIDC_CLIENTS
// environment variable, bridging the gap until dynamic client registration
// lands. Format (semicolon-separated entries, comma-separated URIs):
//
//	OIDC_CLIENTS="cryptofreight-web=https://cryptofreight.org/callback.html,http://localhost:3000/callback.html;other-app=https://other.example/cb"
//
// Seeded clients are public (no secret) — they are expected to use the
// authorization-code flow with PKCE, which /authorize mandates anyway.
// PutClient is an upsert in both storage backends, so re-seeding at every
// boot is idempotent and env changes take effect on restart.
func SeedClientsFromEnv(store Storage, logger *slog.Logger) error {
	raw := strings.TrimSpace(os.Getenv("OIDC_CLIENTS"))
	if raw == "" {
		return nil
	}

	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, uris, ok := strings.Cut(entry, "=")
		id = strings.TrimSpace(id)
		if !ok || id == "" {
			return fmt.Errorf("OIDC_CLIENTS: malformed entry %q (want client-id=uri[,uri...])", entry)
		}

		var list []string
		for _, u := range strings.Split(uris, ",") {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			parsed, err := url.Parse(u)
			if err != nil || !parsed.IsAbs() {
				return fmt.Errorf("OIDC_CLIENTS: client %q: redirect URI %q must be an absolute URL", id, u)
			}
			list = append(list, u)
		}
		if len(list) == 0 {
			return fmt.Errorf("OIDC_CLIENTS: client %q has no redirect URIs", id)
		}

		if err := store.PutClient(OIDCClient{
			ClientID:         id,
			ClientSecretHash: "", // public client — PKCE is the proof of possession
			RedirectURIs:     list,
			CreatedAt:        time.Now().UTC(),
		}); err != nil {
			return fmt.Errorf("OIDC_CLIENTS: seed client %q: %w", id, err)
		}
		logger.Info("oidc_client_seeded", "client_id", id, "redirect_uris", len(list))
	}
	return nil
}
