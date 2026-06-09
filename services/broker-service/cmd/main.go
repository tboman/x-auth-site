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
	"os"
	"os/signal"
	"syscall"

	"github.com/xentranet/x-auth/pkg/config"
	"github.com/xentranet/x-auth/pkg/httpx"
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

	handler := internal.Router(internal.Deps{
		Store:      store,
		Logger:     logger,
		Clients:    clients,
		Issuer:     issuer,
		DefaultTTL: internal.DefaultTokenTTLSeconds,
	})

	addr := config.Addr(8182)
	if err := httpx.Run(ctx, logger, addr, handler); err != nil {
		logger.Error("server_exited_with_error", "err", err)
		os.Exit(1)
	}
}
