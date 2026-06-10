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

	"github.com/redis/go-redis/v9"

	"github.com/xentranet/x-auth/pkg/config"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/logx"
	"github.com/xentranet/x-auth/pkg/pgxdb"
	"github.com/xentranet/x-auth/pkg/ratex"
	"github.com/xentranet/x-auth/pkg/redisx"
	"github.com/xentranet/x-auth/pkg/tlsx"
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

	// §10.5 layer-3 abuse controls, both ratex counters keyed tenant|user.
	// With shared Redis configured (REDIS_URL/REDIS_ADDR) the counters are
	// Redis fixed windows shared across replicas (§6.3 `rate:` keys); the
	// redisx.ErrMissingAddr fallback keeps the per-replica in-memory limiters
	// so local dev and CI boot without Redis, mirroring the PG_DSN fallback
	// above. The per-challenge exponential backoff needs no config (derived
	// from persisted challenge state). "off" disables a control; an
	// unparseable value is fatal — never boot with a silently-missing abuse
	// control.
	chalLimit, chalWindow, chalOn, err := rateFromEnv("CHALLENGE_RATE_LIMIT", "10/1m")
	if err != nil {
		log.Error("invalid_challenge_rate_limit", "err", err)
		os.Exit(1)
	}
	lockThreshold, lockWindow, lockOn, err := rateFromEnv("LOCKOUT_THRESHOLD", "5/15m")
	if err != nil {
		log.Error("invalid_lockout_threshold", "err", err)
		os.Exit(1)
	}

	// One shared client for both controls; opened only if some control needs it.
	var rdb *redis.Client
	limitBackend := "memory"
	if chalOn || lockOn {
		switch client, err := redisx.Open(ctx, redisx.Config{ServiceName: "authenticator-service"}, log); {
		case err == nil:
			defer client.Close()
			rdb = client
			limitBackend = "redis"
		case errors.Is(err, redisx.ErrMissingAddr):
			log.Warn("rate_limit_fallback_memory", "reason", "REDIS_URL/REDIS_ADDR unset")
		default:
			log.Error("redis_connect_failed", "err", err)
			os.Exit(1)
		}
	}

	var limits internal.Limits
	if chalOn {
		if rdb != nil {
			limits.ChallengeCreate = ratex.NewRedis(rdb, chalLimit, chalWindow, "rate:authr:challenge", log)
		} else {
			limits.ChallengeCreate = ratex.New(chalLimit, chalWindow)
		}
		log.Info("challenge_rate_limit_enabled",
			"limit", chalLimit, "window", chalWindow.String(), "backend", limitBackend)
	} else {
		log.Warn("challenge_rate_limit_disabled")
	}
	if lockOn {
		if rdb != nil {
			// Failure COUNTING is shared across replicas; the lockedUntil map
			// stays per-replica — see the internal.Lockout doc for why every
			// replica converges on its own next counted failure.
			limits.Lockout = internal.NewRedisLockout(lockThreshold, lockWindow, rdb, "rate:authr:lockout", log, store.Now)
		} else {
			limits.Lockout = internal.NewLockout(lockThreshold, lockWindow, store.Now)
		}
		log.Info("account_lockout_enabled",
			"threshold", lockThreshold, "window", lockWindow.String(), "backend", limitBackend)
	} else {
		log.Warn("account_lockout_disabled")
	}

	registry := internal.NewRegistry(log)
	handler := internal.Router(log, store, registry, limits)

	// Transport security (ARCHITECTURE.md §10.3): TLS_CERT_FILE/TLS_KEY_FILE
	// enable TLS, TLS_CLIENT_CA_FILE additionally enforces mTLS. With none set
	// the service serves plaintext (local dev). Partial config is fatal — never
	// silently fall back to plaintext because one path was mistyped.
	tlsConf, err := tlsx.ServerConfig(log)
	if err != nil {
		log.Error("tls_config_failed", "err", err)
		os.Exit(1)
	}

	if err := httpx.RunTLS(ctx, log, config.Addr(8083), handler, tlsConf); err != nil {
		log.Error("server_exit", "err", err)
		os.Exit(1)
	}
}

// rateFromEnv reads an "N/window" rate (ratex.ParseRate syntax, e.g. "10/1m")
// from the named env var, falling back to def when unset. The literal "off"
// disables the control (enabled=false, nil error); anything else that fails
// to parse is returned as an error for the caller to treat as fatal.
func rateFromEnv(name, def string) (limit int, window time.Duration, enabled bool, err error) {
	v := os.Getenv(name)
	if v == "" {
		v = def
	}
	if v == "off" {
		return 0, 0, false, nil
	}
	n, d, err := ratex.ParseRate(v)
	if err != nil {
		return 0, 0, false, err
	}
	return n, d, true, nil
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
