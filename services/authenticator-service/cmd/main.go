// Command authenticator-service is the internal authenticator CRUD + challenge
// dispatch/verify service for X-Auth for Apps.
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
	"github.com/xentranet/x-auth/services/authenticator-service/internal"
)

func main() {
	log := logx.New("authenticator-service")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Resolve storage. Postgres is the phase-2 default; the in-memory fallback is
	// preserved so the service still boots during local dev or CI without a DB,
	// matching the pattern established by transaction-service (docs/postgres.md).
	var store internal.Storage
	pool, err := pgxdb.Open(ctx, pgxdb.Config{
		ServiceName: "authenticator-service",
	}, log)
	switch {
	case err == nil:
		defer pool.Close()
		store = internal.NewPGStorage(pool, log)
	case errors.Is(err, pgxdb.ErrMissingDSN):
		log.Warn("db_fallback_memory", "reason", "PG_DSN unset")
		store = internal.NewStore(nil)
	default:
		log.Error("db_connect_failed", "err", err)
		os.Exit(1)
	}

	registry := internal.NewRegistry(log)
	handler := internal.Router(log, store, registry)

	if err := httpx.Run(ctx, log, config.Addr(8083), handler); err != nil {
		log.Error("server_exit", "err", err)
		os.Exit(1)
	}
}
