// broker-service is the public-facing entry point for X-Auth for Agents.
// It speaks MCP, OAuth 2.0, OIDC, RFC 7591 Dynamic Client Registration, and
// Client Identifier Metadata Document flows, and orchestrates install creation
// by calling persona-service, pool-service, and grant-service.
//
// See REQUIREMENTS.md §4 and services/broker-service/README.md for the full
// endpoint list and phase-1 scope.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xentranet/x-auth/pkg/config"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/jwtx"
	"github.com/xentranet/x-auth/pkg/logx"
	"github.com/xentranet/x-auth/pkg/pgxdb"
	"github.com/xentranet/x-auth/services/broker-service/internal"
)

func main() {
	logger := logx.New("broker-service")

	personaURL := config.Env("PERSONA_SERVICE_URL", "http://localhost:8180")
	poolURL := config.Env("POOL_SERVICE_URL", "http://localhost:8181")
	grantURL := config.Env("GRANT_SERVICE_URL", "http://localhost:8183")
	issuer := config.Env("BROKER_ISSUER", "http://localhost:8182")

	// Access-token signing key (RS256). Production sets JWT_SIGNING_KEY to a PEM
	// private key (in production this is https://mcp.x-auth.com's key from secret
	// storage); unset means an ephemeral per-process key with a logged warning.
	signingKey, err := jwtx.LoadOrGenerateKey("JWT_SIGNING_KEY", logger)
	if err != nil {
		logger.Error("jwt_key_load_failed", "err", err)
		os.Exit(1)
	}
	signer := jwtx.NewSigner(signingKey)

	// The `iss` claim defaults to the discovery-document issuer (BROKER_ISSUER,
	// canonically https://mcp.x-auth.com in production) so issued JWTs validate
	// against the metadata this service serves; JWT_ISSUER overrides it only for
	// split-horizon deployments.
	jwtIssuer := config.Env("JWT_ISSUER", issuer)
	verifier := jwtx.NewVerifier(jwtIssuer, &signingKey.PublicKey)

	clients := internal.NewHTTPClients(personaURL, poolURL, grantURL)

	// Resolve storage. Postgres is the phase-2 default; the in-memory fallback is
	// preserved so the service still boots during local dev or CI without a DB —
	// same pattern as transaction-service (see docs/postgres.md).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var store internal.Storage
	pool, err := pgxdb.Open(ctx, pgxdb.Config{
		ServiceName: "broker-service",
	}, logger)
	switch {
	case err == nil:
		defer pool.Close()
		store = internal.NewPGStorage(pool)
	case errors.Is(err, pgxdb.ErrMissingDSN):
		logger.Warn("db_fallback_memory", "reason", "PG_DSN unset")
		store = internal.NewMemStorage()
	default:
		logger.Error("db_connect_failed", "err", err)
		os.Exit(1)
	}

	// Background sweeper: tokens and auth codes only have their TTLs enforced at
	// read time, so without this they grow unbounded. Runs against whichever
	// storage backend was resolved above and stops with the signal-aware ctx.
	go runPurgeSweeper(ctx, logger, store)

	handler := internal.Router(internal.Deps{
		Store:      store,
		Logger:     logger,
		Clients:    clients,
		Issuer:     issuer,
		Signer:     signer,
		Verifier:   verifier,
		JWTIssuer:  jwtIssuer,
		DefaultTTL: internal.DefaultTokenTTLSeconds,
	})

	addr := config.Addr(8182)
	if err := httpx.Run(ctx, logger, addr, handler); err != nil {
		logger.Error("server_exited_with_error", "err", err)
		os.Exit(1)
	}
}

// runPurgeSweeper periodically deletes expired tokens and auth codes via
// Storage.PurgeExpired. The interval comes from PURGE_INTERVAL (a Go duration,
// default 5m — see the README env table); an unparsable or non-positive value
// falls back to the default rather than aborting startup. The loop exits cleanly
// when ctx is cancelled (SIGINT/SIGTERM).
func runPurgeSweeper(ctx context.Context, logger *slog.Logger, store internal.Storage) {
	const defaultInterval = 5 * time.Minute
	raw := config.Env("PURGE_INTERVAL", defaultInterval.String())
	interval, err := time.ParseDuration(raw)
	if err != nil || interval <= 0 {
		logger.Warn("purge_interval_invalid", "value", raw, "fallback", defaultInterval.String())
		interval = defaultInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	logger.Info("purge_sweeper_started", "interval", interval.String())
	for {
		select {
		case <-ctx.Done():
			logger.Info("purge_sweeper_stopped")
			return
		case <-ticker.C:
			n, err := store.PurgeExpired(time.Now().UTC())
			if err != nil {
				logger.Error("purge_expired_failed", "err", err)
				continue
			}
			logger.Info("purge_expired", "removed", n)
		}
	}
}
