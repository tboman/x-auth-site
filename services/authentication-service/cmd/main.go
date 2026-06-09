// authentication-service is the public OIDC provider for X-Auth for Apps.
// It owns users, sessions, tokens, and OIDC endpoints (discovery, authorize,
// token, userinfo, revoke), plus phase-1 social-login stubs for google,
// github, and microsoft.
//
// See ARCHITECTURE.md §4.3 for the source-of-truth contract and
// services/authentication-service/README.md for the full endpoint list.
package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xentranet/x-auth/pkg/config"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/jwtx"
	"github.com/xentranet/x-auth/pkg/logx"
	"github.com/xentranet/x-auth/pkg/pgxdb"
	"github.com/xentranet/x-auth/services/authentication-service/internal"
)

func main() {
	logger := logx.New("authentication-service")

	authenticatorURL := config.Env("AUTHENTICATOR_SERVICE_URL", "http://localhost:8083")
	issuer := config.Env("AUTH_ISSUER", "http://localhost:8082")
	// The `iss` claim minted into access/ID tokens. Defaults to the discovery
	// issuer so tokens match the published OIDC configuration; override with
	// JWT_ISSUER only when the signing identity must differ from the base URL.
	jwtIssuer := config.Env("JWT_ISSUER", issuer)

	// RS256 signing key (ARCHITECTURE.md §10.1). Production injects a PEM via
	// JWT_SIGNING_KEY (from KMS/secret storage); local dev falls back to an
	// ephemeral per-process key (jwtx logs a warning — tokens won't survive a
	// restart or verify across replicas).
	key, err := jwtx.LoadOrGenerateKey("JWT_SIGNING_KEY", logger)
	if err != nil {
		logger.Error("jwt_signing_key_load_failed", "err", err)
		os.Exit(1)
	}
	signer := jwtx.NewSigner(key)

	// Resolve storage. Postgres is the phase-2 default; the in-memory fallback is
	// preserved so the service still boots during local dev or CI without a DB
	// (same switch as transaction-service — see docs/postgres.md).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var store internal.Storage
	pool, err := pgxdb.Open(ctx, pgxdb.Config{
		ServiceName: "authentication-service",
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

	// Background sweeper: tokens and auth codes are TTL-checked only at read
	// time, so without a sweep the stores grow unbounded. PurgeExpired removes
	// expired tokens, stale auth codes, and long-expired sessions on every tick
	// (interval from PURGE_INTERVAL, default 5m) until the signal-aware ctx is
	// cancelled. Works identically against MemStorage and PGStorage.
	purgeInterval := 5 * time.Minute
	if v := config.Env("PURGE_INTERVAL", ""); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			logger.Warn("purge_interval_invalid", "value", v, "fallback", purgeInterval.String())
		} else {
			purgeInterval = d
		}
	}
	go func() {
		ticker := time.NewTicker(purgeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				removed, err := store.PurgeExpired(time.Now().UTC())
				if err != nil {
					logger.Error("purge_expired_failed", "err", err)
					continue
				}
				logger.Info("purge_expired", "removed", removed, "interval", purgeInterval.String())
			}
		}
	}()

	authenticator := internal.NewHTTPAuthenticatorClient(authenticatorURL)

	handler := internal.Router(internal.Deps{
		Store:         store,
		Logger:        logger,
		Authenticator: authenticator,
		Issuer:        issuer,
		Signer:        signer,
		JWTIssuer:     jwtIssuer,
	})

	addr := config.Addr(8082)
	if err := httpx.Run(ctx, logger, addr, handler); err != nil {
		logger.Error("server_exited_with_error", "err", err)
		os.Exit(1)
	}
}
