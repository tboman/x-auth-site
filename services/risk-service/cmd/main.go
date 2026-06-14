// risk-service is the internal risk scoring and policy engine for X-Auth for Apps.
// It ingests identity signals (device, behavior, network, user) plus resource
// sensitivity, aggregates a weighted risk score, evaluates tenant policies, and
// returns a risk tier (low / medium / high) with a policy decision.
//
// See ARCHITECTURE.md §4.2 and §7 for the source-of-truth request/response
// shapes, scorers, weights, and tier thresholds. See services/risk-service/README.md
// for local-run and cURL examples.
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
	"github.com/xentranet/x-auth/services/risk-service/internal"
)

func main() {
	logger := logx.New("risk-service")

	// Resolve storage. Postgres is the phase-2 default; the in-memory fallback is
	// preserved so the service still boots during local dev or CI without a DB,
	// matching the pattern established by transaction-service.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var store internal.Storage
	pool, err := pgxdb.Open(ctx, pgxdb.Config{
		ServiceName: "risk-service",
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

	handlers := internal.NewHandlers(store, logger)

	// CAEP SET receiver: trust authentication-service's signing key by fetching
	// its JWKS. Both AUTHN_JWKS_URL and AUTHN_ISSUER must be set to enable the
	// receiver; otherwise POST /internal/v1/ssf/events returns 503.
	if jwksURL, issuer := os.Getenv("AUTHN_JWKS_URL"), os.Getenv("AUTHN_ISSUER"); jwksURL != "" && issuer != "" {
		v, err := internal.VerifierFromJWKS(jwksURL, issuer)
		if err != nil {
			logger.Error("caep_verifier_init_failed", "err", err, "jwks_url", jwksURL)
		} else {
			handlers.CAEPVerifier = v
			logger.Info("caep_receiver_enabled", "issuer", issuer)
		}
	} else {
		logger.Warn("caep_receiver_disabled", "reason", "AUTHN_JWKS_URL / AUTHN_ISSUER unset")
	}

	// Transport security (ARCHITECTURE.md §10.3): TLS/mTLS from the
	// TLS_CERT_FILE / TLS_KEY_FILE / TLS_CLIENT_CA_FILE env vars. A nil config
	// means plaintext local dev; a partial config is fatal.
	tlsConf, err := tlsx.ServerConfig(logger)
	if err != nil {
		logger.Error("tls_config_failed", "err", err)
		os.Exit(1)
	}

	addr := config.Addr(8081)
	if err := httpx.RunTLS(ctx, logger, addr, handlers.Router(), tlsConf); err != nil {
		logger.Error("server_exited_with_error", "err", err)
		os.Exit(1)
	}
}
