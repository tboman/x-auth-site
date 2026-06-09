// Command pool-service runs the X-Auth for Agents pool-service HTTP server.
// See REQUIREMENTS.md §3 & §4 for scope.
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
	"github.com/xentranet/x-auth/pkg/tlsx"
	"github.com/xentranet/x-auth/services/pool-service/internal"
)

func main() {
	logger := logx.New("pool-service")

	// Resolve storage. Postgres is the phase-2 default; the in-memory fallback is
	// preserved so the service still boots during local dev or CI without a DB,
	// matching the transaction-service pattern (see docs/postgres.md).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var storage internal.Storage
	pool, err := pgxdb.Open(ctx, pgxdb.Config{
		ServiceName: "pool-service",
	}, logger)
	switch {
	case err == nil:
		defer pool.Close()
		storage = internal.NewPGStorage(pool)
	case errors.Is(err, pgxdb.ErrMissingDSN):
		logger.Warn("db_fallback_memory", "reason", "PG_DSN unset")
		storage = internal.NewMemStorage()
	default:
		logger.Error("db_connect_failed", "err", err)
		os.Exit(1)
	}

	srv := internal.NewServer(storage, logger)

	// Wrap the service handler with shared middleware (recover + structured logging).
	handler := httpx.Recover(logger)(httpx.Logging(logger)(srv.Handler()))

	// Transport security (ARCHITECTURE.md §10.3): TLS/mTLS from the
	// TLS_CERT_FILE / TLS_KEY_FILE / TLS_CLIENT_CA_FILE env vars. A nil config
	// means plaintext local dev; a partial config is fatal.
	tlsConf, err := tlsx.ServerConfig(logger)
	if err != nil {
		logger.Error("tls_config_failed", "err", err)
		os.Exit(1)
	}

	addr := config.Addr(8181)
	if err := httpx.RunTLS(ctx, logger, addr, handler, tlsConf); err != nil {
		logger.Error("server_failed", "err", err)
		os.Exit(1)
	}
}
