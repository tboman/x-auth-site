// Command fido-service serves the FIDO2 Authenticator Risk & Metadata (MDS) API
// at fido.x-auth.com. See services/fido-service/README.md for the contract.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/xentranet/x-auth/pkg/config"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/logx"
	"github.com/xentranet/x-auth/pkg/pgxdb"
	"github.com/xentranet/x-auth/pkg/ratex"
	"github.com/xentranet/x-auth/pkg/redisx"
	"github.com/xentranet/x-auth/pkg/tlsx"
	"github.com/xentranet/x-auth/services/fido-service/internal"
)

// defaultRefreshInterval is how often the MDS blob is re-fetched when
// MDS_REFRESH_INTERVAL is unset.
const defaultRefreshInterval = 24 * time.Hour

func main() {
	logger := logx.New("fido-service")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Snapshot store: Postgres (fido_db) is the durable default; the in-memory
	// fallback keeps the service bootable in local dev / CI without a DB,
	// matching the pattern across the other services. The MDS index lives in
	// memory regardless — the store only provides warm restarts + audit.
	var store internal.SnapshotStore
	pool, err := pgxdb.Open(ctx, pgxdb.Config{ServiceName: "fido-service"}, logger)
	switch {
	case err == nil:
		defer pool.Close()
		store = internal.NewPGSnapshotStore(pool)
	case errors.Is(err, pgxdb.ErrMissingDSN):
		logger.Warn("db_fallback_memory", "reason", "PG_DSN unset")
		store = internal.NewMemSnapshotStore()
	default:
		logger.Error("db_connect_failed", "err", err)
		os.Exit(1)
	}

	// Shared Redis backs both the cross-replica blob cache and the rate limiter.
	// Absent Redis (ErrMissingAddr) the cache is skipped and the limiter is
	// per-replica; a configured-but-unreachable Redis is fatal.
	rdb := openRedis(ctx, logger)
	if rdb != nil {
		defer rdb.Close()
	}
	cache := internal.NewBlobCache(rdb, 48*time.Hour)

	// §10.5 layer-2 rate limiting, per tenant + endpoint. RATE_LIMIT is
	// "N/window" (default 600/1m); "off" disables. limiter stays an untyped nil
	// when disabled so ratex.Middleware bypasses cleanly.
	var limiter ratex.Allower
	if l := buildLimiter(rdb, logger); l != nil {
		limiter = l
	}

	fetcher, err := internal.NewFetcher(
		config.Env("MDS_URL", internal.DefaultMDSURL),
		os.Getenv("MDS_ROOT_CERT_FILE"),
	)
	if err != nil {
		logger.Error("mds_fetcher_init_failed", "err", err)
		os.Exit(1)
	}

	mgr := internal.NewManager(logger, fetcher, store, cache)

	// Load asynchronously so /healthz comes up immediately (Cloud Run startup
	// probe). Risk endpoints answer 503 until the first snapshot loads.
	go func() {
		mgr.Bootstrap(ctx)
		mgr.RunRefresher(ctx, refreshInterval(logger))
	}()

	handlers := internal.NewHandlers(mgr, logger)

	tlsConf, err := tlsx.ServerConfig(logger)
	if err != nil {
		logger.Error("tls_config_failed", "err", err)
		os.Exit(1)
	}

	if err := httpx.RunTLS(ctx, logger, config.Addr(8184), handlers.Router(limiter), tlsConf); err != nil {
		logger.Error("server_exit", "err", err)
		os.Exit(1)
	}
}

// openRedis returns a connected client, or nil when no Redis is configured. A
// configured-but-unreachable Redis is fatal.
func openRedis(ctx context.Context, logger *slog.Logger) *redis.Client {
	rdb, err := redisx.Open(ctx, redisx.Config{ServiceName: "fido-service"}, logger)
	switch {
	case err == nil:
		return rdb
	case errors.Is(err, redisx.ErrMissingAddr):
		logger.Warn("redis_unset", "reason", "REDIS_URL/REDIS_ADDR unset; cache disabled, limits per replica")
		return nil
	default:
		logger.Error("redis_connect_failed", "err", err)
		os.Exit(1)
		return nil
	}
}

// buildLimiter parses RATE_LIMIT and returns the configured Allower, or nil when
// disabled. An invalid spec is fatal — never boot with a silently-missing limit.
func buildLimiter(rdb *redis.Client, logger *slog.Logger) ratex.Allower {
	spec := config.Env("RATE_LIMIT", "600/1m")
	if spec == "off" {
		logger.Warn("rate_limit_disabled")
		return nil
	}
	limit, window, err := ratex.ParseRate(spec)
	if err != nil {
		logger.Error("rate_limit_config_invalid", "value", spec, "err", err)
		os.Exit(1)
	}
	if rdb != nil {
		logger.Info("rate_limit_redis", "spec", spec, "prefix", "rate:fido")
		return ratex.NewRedis(rdb, limit, window, "rate:fido", logger)
	}
	logger.Warn("rate_limit_local", "spec", spec, "reason", "no Redis; limits per replica")
	return ratex.New(limit, window)
}

// refreshInterval reads MDS_REFRESH_INTERVAL (Go duration); an invalid value is
// fatal.
func refreshInterval(logger *slog.Logger) time.Duration {
	v := os.Getenv("MDS_REFRESH_INTERVAL")
	if v == "" {
		return defaultRefreshInterval
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		logger.Error("invalid_refresh_interval", "value", v, "err", err)
		os.Exit(1)
	}
	return d
}
