// Command id-service serves the remote identity-verification API + UIs at
// id.x-auth.com: a decoupled "verify with wallet" flow that presents an ISO
// 18013-5 mobile driver's licence over the W3C Digital Credentials API /
// OpenID4VP and verifies it end-to-end. See services/id-service/README.md.
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
	"github.com/xentranet/x-auth/pkg/jwtx"
	"github.com/xentranet/x-auth/pkg/logx"
	"github.com/xentranet/x-auth/pkg/pgxdb"
	"github.com/xentranet/x-auth/pkg/ratex"
	"github.com/xentranet/x-auth/pkg/redisx"
	"github.com/xentranet/x-auth/pkg/tlsx"
	"github.com/xentranet/x-auth/services/id-service/internal"
)

const defaultPurgeInterval = 5 * time.Minute

func main() {
	logger := logx.New("id-service")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	issuer := config.Env("ID_ISSUER", "http://localhost:8185")

	// Proof-token signing key (RS256). Production sets JWT_SIGNING_KEY from secret
	// storage; unset means an ephemeral per-process key with a logged warning.
	signingKey, err := jwtx.LoadOrGenerateKey("JWT_SIGNING_KEY", logger)
	if err != nil {
		logger.Error("jwt_key_load_failed", "err", err)
		os.Exit(1)
	}
	signer := jwtx.NewSigner(signingKey)

	// Verification store: Postgres (id_db) is the durable default; the in-memory
	// fallback keeps the service bootable in local dev / CI without a DB.
	var store internal.Storage
	pool, err := pgxdb.Open(ctx, pgxdb.Config{ServiceName: "id-service"}, logger)
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

	// Shared Redis backs the token cache and the rate limiter. Absent Redis the
	// cache is skipped and limits are per-replica; a configured-but-unreachable
	// Redis is fatal.
	rdb := openRedis(ctx, logger)
	if rdb != nil {
		defer rdb.Close()
	}
	cache := internal.NewVerificationCache(rdb, time.Hour)

	var limiter ratex.Allower
	if l := buildLimiter(rdb, logger); l != nil {
		limiter = l
	}

	trust, err := internal.NewTrustStore(
		os.Getenv("TRUST_MODE"),
		os.Getenv("IACA_ROOT_CERT_FILE"),
		os.Getenv("IACA_ROOTS_DIR"),
		logger,
	)
	if err != nil {
		logger.Error("trust_store_init_failed", "err", err)
		os.Exit(1)
	}

	mgr := internal.NewManager(store, trust, signer, cache, issuer, verificationTTL(logger), logger)

	console, err := internal.NewConsole(mgr, logger)
	if err != nil {
		logger.Error("console_init_failed", "err", err)
		os.Exit(1)
	}

	go runPurgeSweeper(ctx, logger, mgr)

	handlers := internal.NewHandlers(mgr, console, logger)

	tlsConf, err := tlsx.ServerConfig(logger)
	if err != nil {
		logger.Error("tls_config_failed", "err", err)
		os.Exit(1)
	}

	if err := httpx.RunTLS(ctx, logger, config.Addr(8185), handlers.Router(limiter), tlsConf); err != nil {
		logger.Error("server_exit", "err", err)
		os.Exit(1)
	}
}

// openRedis returns a connected client, or nil when no Redis is configured. A
// configured-but-unreachable Redis is fatal.
func openRedis(ctx context.Context, logger *slog.Logger) *redis.Client {
	rdb, err := redisx.Open(ctx, redisx.Config{ServiceName: "id-service"}, logger)
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
// disabled. An invalid spec is fatal.
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
		logger.Info("rate_limit_redis", "spec", spec, "prefix", "rate:id")
		return ratex.NewRedis(rdb, limit, window, "rate:id", logger)
	}
	logger.Warn("rate_limit_local", "spec", spec, "reason", "no Redis; limits per replica")
	return ratex.New(limit, window)
}

// verificationTTL reads VERIFICATION_TTL (Go duration); an invalid value is fatal.
func verificationTTL(logger *slog.Logger) time.Duration {
	v := os.Getenv("VERIFICATION_TTL")
	if v == "" {
		return 10 * time.Minute
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		logger.Error("invalid_verification_ttl", "value", v, "err", err)
		os.Exit(1)
	}
	return d
}

// runPurgeSweeper periodically deletes expired pending verifications.
func runPurgeSweeper(ctx context.Context, logger *slog.Logger, mgr *internal.Manager) {
	raw := config.Env("PURGE_INTERVAL", defaultPurgeInterval.String())
	interval, err := time.ParseDuration(raw)
	if err != nil || interval <= 0 {
		logger.Warn("purge_interval_invalid", "value", raw, "fallback", defaultPurgeInterval.String())
		interval = defaultPurgeInterval
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
			n, err := mgr.PurgeExpired(ctx)
			if err != nil {
				logger.Error("purge_expired_failed", "err", err)
				continue
			}
			if n > 0 {
				logger.Info("purge_expired", "removed", n)
			}
		}
	}
}
