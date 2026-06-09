// Command authenticator-service is the internal authenticator CRUD + challenge
// dispatch/verify service for X-Auth for Apps.
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
	"github.com/xentranet/x-auth/pkg/logx"
	"github.com/xentranet/x-auth/pkg/pgxdb"
	"github.com/xentranet/x-auth/services/authenticator-service/internal"
)

// defaultPurgeInterval is how often the expired-challenge sweeper runs when
// PURGE_INTERVAL is unset.
const defaultPurgeInterval = 5 * time.Minute

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

	// Background sweeper: expired challenges accumulate (lazy expiry only flips
	// status on a verify touch), so purge them on a ticker. Works against both
	// backends via Storage.PurgeExpired. Stops with the signal-aware ctx.
	interval := defaultPurgeInterval
	if v := os.Getenv("PURGE_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			log.Error("invalid_purge_interval", "value", v, "err", err)
			os.Exit(1)
		}
		interval = d
	}
	go runPurgeSweeper(ctx, log, store, interval)

	registry := internal.NewRegistry(log)
	handler := internal.Router(log, store, registry)

	if err := httpx.Run(ctx, log, config.Addr(8083), handler); err != nil {
		log.Error("server_exit", "err", err)
		os.Exit(1)
	}
}

// runPurgeSweeper deletes expired challenges every interval until ctx is
// cancelled. Each successful sweep logs `purge_expired` with the row count;
// failures are logged and retried on the next tick.
func runPurgeSweeper(ctx context.Context, log *slog.Logger, store internal.Storage, interval time.Duration) {
	log.Info("purge_sweeper_started", "interval", interval.String())
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("purge_sweeper_stopped")
			return
		case <-ticker.C:
			n, err := store.PurgeExpired(store.Now())
			if err != nil {
				log.Error("purge_expired_failed", "err", err)
				continue
			}
			log.Info("purge_expired", "count", n)
		}
	}
}
