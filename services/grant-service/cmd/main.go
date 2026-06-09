// Command grant-service runs the grant + audit log HTTP server.
// See services/grant-service/README.md for endpoints and local run instructions.
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
	"github.com/xentranet/x-auth/services/grant-service/internal"
)

func main() {
	logger := logx.New("grant-service")

	// Resolve storage. Postgres is the phase-2 default; the in-memory fallback is
	// preserved so the service still boots during local dev or CI without a DB,
	// matching the pattern established by transaction-service (docs/postgres.md).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var (
		grants internal.GrantStore
		audit  internal.AuditStore
	)
	pool, err := pgxdb.Open(ctx, pgxdb.Config{
		ServiceName: "grant-service",
	}, logger)
	switch {
	case err == nil:
		defer pool.Close()
		pg := internal.NewPGStorage(pool)
		grants, audit = pg, pg
	case errors.Is(err, pgxdb.ErrMissingDSN):
		logger.Warn("db_fallback_memory", "reason", "PG_DSN unset")
		grants, audit = internal.NewMemGrantStore(), internal.NewMemAuditStore()
	default:
		logger.Error("db_connect_failed", "err", err)
		os.Exit(1)
	}

	handlers := internal.NewHandlers(grants, audit, logger)

	addr := config.Addr(8183)
	if err := httpx.Run(ctx, logger, addr, handlers.Router()); err != nil {
		logger.Error("server_exit", "err", err)
		os.Exit(1)
	}
}
