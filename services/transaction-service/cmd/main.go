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
	"github.com/xentranet/x-auth/pkg/ratex"
	"github.com/xentranet/x-auth/pkg/redisx"
	"github.com/xentranet/x-auth/pkg/tlsx"
	"github.com/xentranet/x-auth/services/transaction-service/internal"
)

func main() {
	logger := logx.New("transaction-service")

	// Downstream calls target the sister services' /internal/v1 trees over
	// (m)TLS when TLS_CA_FILE / TLS_CERT_FILE / TLS_KEY_FILE are configured
	// (ARCHITECTURE.md §10.3). A partial TLS configuration is fatal.
	clients, err := internal.NewHTTPClients(
		logger,
		config.Env("RISK_SERVICE_URL", "http://localhost:8081"),
		config.Env("AUTHENTICATION_SERVICE_URL", "http://localhost:8082"),
		config.Env("AUTHENTICATOR_SERVICE_URL", "http://localhost:8083"),
	)
	if err != nil {
		logger.Error("tls_transport_failed", "err", err)
		os.Exit(1)
	}

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

	// §10.5 layer-2 rate limiting: per-tenant, per-endpoint limits. RATE_LIMIT
	// is "N/window" (e.g. "600/1m"); the literal "off" disables it. Backend
	// selection mirrors storage: shared Redis when configured (limits hold
	// across replicas, rate:txn:* counters per §6.3), in-memory when no Redis
	// is set (per-replica), fatal when Redis is configured but unreachable —
	// a misconfigured limiter must not silently degrade to per-replica.
	//
	// limiter stays an UNTYPED nil when RATE_LIMIT=off so the Allower
	// interface itself is nil and ratex.Middleware bypasses; assigning a nil
	// *ratex.Limiter here would make the interface non-nil (typed-nil trap),
	// which only works because of the limiter's nil-receiver guard.
	rateSpec := config.Env("RATE_LIMIT", "600/1m")
	var limiter ratex.Allower
	limit, window, rateEnabled, err := internal.ParseRateLimit(rateSpec)
	if err != nil {
		logger.Error("rate_limit_config_invalid", "value", rateSpec, "err", err)
		os.Exit(1)
	}
	if rateEnabled {
		rdb, err := redisx.Open(ctx, redisx.Config{ServiceName: "transaction-service"}, logger)
		switch {
		case err == nil:
			defer rdb.Close()
			limiter = ratex.NewRedis(rdb, limit, window, "rate:txn", logger)
			logger.Info("rate_limit_redis", "spec", rateSpec, "prefix", "rate:txn")
		case errors.Is(err, redisx.ErrMissingAddr):
			logger.Warn("rate_limit_local", "reason", "no Redis configured (REDIS_URL/REDIS_ADDR unset); limits are per replica", "spec", rateSpec)
			limiter = ratex.New(limit, window)
		default:
			logger.Error("redis_connect_failed", "err", err)
			os.Exit(1)
		}
	}

	// Transport security (ARCHITECTURE.md §10.3): TLS/mTLS from the
	// TLS_CERT_FILE / TLS_KEY_FILE / TLS_CLIENT_CA_FILE env vars. A nil config
	// means plaintext local dev; a partial config is fatal.
	tlsConf, err := tlsx.ServerConfig(logger)
	if err != nil {
		logger.Error("tls_config_failed", "err", err)
		os.Exit(1)
	}

	addr := config.Addr(8080)
	if err := httpx.RunTLS(ctx, logger, addr, handlers.Router(limiter), tlsConf); err != nil {
		logger.Error("server_exit", "err", err)
		os.Exit(1)
	}
}
