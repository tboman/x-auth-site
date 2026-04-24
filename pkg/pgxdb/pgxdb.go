// Package pgxdb is the shared PostgreSQL connection helper for every X-Auth service.
//
// It wraps jackc/pgx/v5/pgxpool so every service gets:
//   - env-driven DSN resolution (PG_DSN, or a per-service PG_DSN_<SERVICE>),
//   - a ping on startup so misconfigured services fail fast rather than at first query,
//   - graceful shutdown (close the pool when the caller-owned context is cancelled),
//   - a single structured "db_connect" log line so Cloud Logging / local journals can
//     surface connection problems without having to grep pgx's own internals.
//
// Phase 1 used in-memory maps. Phase 2 moves each service onto its own Postgres
// database (per §6 of ARCHITECTURE.md). This package is deliberately small — services
// own their own queries and migrations; this is just the shared bootstrap.
package pgxdb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultMaxConns is the pool ceiling applied when PG_MAX_CONNS is unset.
// Each service runs its own pool; 10 is a safe default for phase-2 rollout and can
// be tuned per-service via the PG_MAX_CONNS env var.
const DefaultMaxConns = 10

// ErrMissingDSN is returned by Open when no DSN can be resolved from the environment.
var ErrMissingDSN = errors.New("no Postgres DSN configured (set PG_DSN)")

// Config controls pool construction. Zero values fall back to sensible defaults.
type Config struct {
	// DSN is the Postgres connection string (e.g. "postgres://user:pass@host:5432/db").
	// When empty, Open falls back to os.Getenv("PG_DSN").
	DSN string

	// ServiceName (e.g. "transaction-service") is used for an optional
	// PG_DSN_<SERVICE> lookup (uppercased, dashes to underscores) — lets operators
	// point a single process at a different DB without colliding with PG_DSN.
	ServiceName string

	// MaxConns caps pool size. 0 -> DefaultMaxConns, overridable via PG_MAX_CONNS.
	MaxConns int32

	// PingTimeout is the upper bound on the startup ping. 0 -> 5 seconds.
	PingTimeout time.Duration
}

// Open builds a pgxpool.Pool, verifies connectivity, and returns it. Callers own the
// pool and should defer pool.Close() before the process exits. The returned pool is
// safe for concurrent use.
func Open(ctx context.Context, cfg Config, logger *slog.Logger) (*pgxpool.Pool, error) {
	dsn := resolveDSN(cfg)
	if dsn == "" {
		return nil, ErrMissingDSN
	}

	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxdb: parse dsn: %w", err)
	}

	if mc := resolveMaxConns(cfg); mc > 0 {
		poolCfg.MaxConns = mc
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("pgxdb: new pool: %w", err)
	}

	pingTimeout := cfg.PingTimeout
	if pingTimeout == 0 {
		pingTimeout = 5 * time.Second
	}
	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgxdb: ping: %w", err)
	}

	if logger != nil {
		logger.Info("db_connect",
			"host", poolCfg.ConnConfig.Host,
			"database", poolCfg.ConnConfig.Database,
			"max_conns", poolCfg.MaxConns,
		)
	}
	return pool, nil
}

// CloseOnContext closes the pool when ctx is cancelled. Intended to be launched as a
// goroutine alongside httpx.Run so the pool is released during graceful shutdown
// without each service duplicating the boilerplate.
func CloseOnContext(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	<-ctx.Done()
	if logger != nil {
		logger.Info("db_close")
	}
	pool.Close()
}

// resolveDSN mirrors pkg/config.Env's explicit-over-env precedence:
//  1. cfg.DSN wins if set.
//  2. PG_DSN_<SERVICE> (uppercased, '-' -> '_') wins if set — lets per-service overrides
//     coexist with a repo-wide PG_DSN for docker-compose style setups.
//  3. PG_DSN.
//  4. "" -> ErrMissingDSN from the caller.
func resolveDSN(cfg Config) string {
	if cfg.DSN != "" {
		return cfg.DSN
	}
	if cfg.ServiceName != "" {
		key := "PG_DSN_" + envSanitize(cfg.ServiceName)
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return os.Getenv("PG_DSN")
}

func resolveMaxConns(cfg Config) int32 {
	if cfg.MaxConns > 0 {
		return cfg.MaxConns
	}
	if v := os.Getenv("PG_MAX_CONNS"); v != "" {
		// Hand-parsed so we don't pull in strconv just for this — invalid values
		// silently fall back to DefaultMaxConns rather than crashing startup.
		var n int32
		for _, c := range v {
			if c < '0' || c > '9' {
				return DefaultMaxConns
			}
			n = n*10 + int32(c-'0')
		}
		if n > 0 {
			return n
		}
	}
	return DefaultMaxConns
}

func envSanitize(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			out = append(out, c-('a'-'A'))
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		case c == '-', c == '.', c == ' ':
			out = append(out, '_')
		}
	}
	return string(out)
}
