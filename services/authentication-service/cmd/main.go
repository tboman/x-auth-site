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

	"github.com/xentranet/x-auth/pkg/config"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/logx"
	"github.com/xentranet/x-auth/pkg/pgxdb"
	"github.com/xentranet/x-auth/services/authentication-service/internal"
)

func main() {
	logger := logx.New("authentication-service")

	authenticatorURL := config.Env("AUTHENTICATOR_SERVICE_URL", "http://localhost:8083")
	issuer := config.Env("AUTH_ISSUER", "http://localhost:8082")

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

	authenticator := internal.NewHTTPAuthenticatorClient(authenticatorURL)

	handler := internal.Router(internal.Deps{
		Store:         store,
		Logger:        logger,
		Authenticator: authenticator,
		Issuer:        issuer,
	})

	addr := config.Addr(8082)
	if err := httpx.Run(ctx, logger, addr, handler); err != nil {
		logger.Error("server_exited_with_error", "err", err)
		os.Exit(1)
	}
}
