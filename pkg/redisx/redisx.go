// Package redisx is the shared Redis connection helper for X-Auth services
// (ARCHITECTURE.md §6.3: one shared Redis for session cache, rate-limit
// counters, risk-score cache, and OIDC nonces).
//
// It mirrors pkg/pgxdb's shape: env-driven resolution, a startup ping so a
// misconfigured service fails fast, one structured "redis_connect" log line,
// and a sentinel error (ErrMissingAddr) so callers can fall back to their
// in-memory implementations in local dev — the same pattern as PG_DSN and
// JWT_SIGNING_KEY.
//
// Env contract:
//
//	REDIS_URL   full URL, e.g. redis://:pass@host:6379/0 — rediss:// enables
//	            TLS (§10.3: Service → Redis runs over TLS in production)
//	REDIS_ADDR  host:port shorthand when REDIS_URL is unset; combined with
//	            optional REDIS_PASSWORD and REDIS_DB
package redisx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Env var names, exported for tests and deploy tooling.
const (
	EnvURL      = "REDIS_URL"
	EnvAddr     = "REDIS_ADDR"
	EnvPassword = "REDIS_PASSWORD"
	EnvDB       = "REDIS_DB"
)

// ErrMissingAddr is returned by Open when neither REDIS_URL nor REDIS_ADDR is
// set; callers treat it like pgxdb.ErrMissingDSN and fall back to in-memory.
var ErrMissingAddr = errors.New("no Redis configured (set REDIS_URL or REDIS_ADDR)")

// Config controls client construction. Zero values use env + defaults.
type Config struct {
	// URL takes precedence; empty falls back to REDIS_URL then REDIS_ADDR.
	URL string
	// ServiceName tags the connect log line (e.g. "transaction-service").
	ServiceName string
	// PingTimeout bounds the startup ping. 0 -> 5 seconds.
	PingTimeout time.Duration
}

// Open builds a *redis.Client, verifies connectivity with a ping, and returns
// it. Callers own the client and should defer client.Close().
func Open(ctx context.Context, cfg Config, logger *slog.Logger) (*redis.Client, error) {
	opts, err := resolveOptions(cfg)
	if err != nil {
		return nil, err
	}

	client := redis.NewClient(opts)

	pingTimeout := cfg.PingTimeout
	if pingTimeout == 0 {
		pingTimeout = 5 * time.Second
	}
	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redisx: ping %s: %w", opts.Addr, err)
	}

	logger.Info("redis_connect",
		"service", cfg.ServiceName,
		"addr", opts.Addr,
		"db", opts.DB,
		"tls", opts.TLSConfig != nil,
	)
	return client, nil
}

func resolveOptions(cfg Config) (*redis.Options, error) {
	url := cfg.URL
	if url == "" {
		url = os.Getenv(EnvURL)
	}
	if url != "" {
		opts, err := redis.ParseURL(url)
		if err != nil {
			return nil, fmt.Errorf("redisx: parse %s: %w", EnvURL, err)
		}
		return opts, nil
	}

	addr := os.Getenv(EnvAddr)
	if addr == "" {
		return nil, ErrMissingAddr
	}
	opts := &redis.Options{
		Addr:     addr,
		Password: os.Getenv(EnvPassword),
	}
	if dbStr := os.Getenv(EnvDB); dbStr != "" {
		db, err := strconv.Atoi(dbStr)
		if err != nil {
			return nil, fmt.Errorf("redisx: %s=%q is not an integer: %w", EnvDB, dbStr, err)
		}
		opts.DB = db
	}
	return opts, nil
}
