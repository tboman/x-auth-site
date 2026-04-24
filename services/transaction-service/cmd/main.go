// Command transaction-service runs the orchestrator HTTP server for X-Auth for Apps.
// See services/transaction-service/README.md for endpoints and local run instructions.
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
	"github.com/xentranet/x-auth/services/transaction-service/internal"
)

func main() {
	logger := logx.New("transaction-service")

	clients := internal.NewHTTPClients(
		config.Env("RISK_SERVICE_URL", "http://localhost:8081"),
		config.Env("AUTHENTICATION_SERVICE_URL", "http://localhost:8082"),
		config.Env("AUTHENTICATOR_SERVICE_URL", "http://localhost:8083"),
	)

	// Resolve storage. Postgres is the phase-2 default; the in-memory fallback is
	// preserved so the service still boots during local dev or CI without a DB,
	// matching the pattern we'll apply to the remaining 7 services.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var store internal.Storage
	pool, err := pgxdb.Open(ctx, pgxdb.Config{
		ServiceName: "transaction-service",
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

	handlers := internal.NewHandlers(store, logger, clients, clients, clients)

	addr := config.Addr(8080)
	if err := httpx.Run(ctx, logger, addr, handlers.Router()); err != nil {
		logger.Error("server_exit", "err", err)
		os.Exit(1)
	}
}
