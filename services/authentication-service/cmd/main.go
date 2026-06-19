// authentication-service is the public OIDC provider for X-Auth for Apps.
// It owns users, sessions, tokens, and OIDC endpoints (discovery, authorize,
// token, userinfo, revoke), plus social login for google (real OAuth2 + PKCE
// when GOOGLE_CLIENT_ID/SECRET are set, stub otherwise) and phase-1 stubs
// for github and microsoft.
//
// See ARCHITECTURE.md §4.3 for the source-of-truth contract and
// services/authentication-service/README.md for the full endpoint list.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xentranet/x-auth/pkg/config"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/jwtx"
	"github.com/xentranet/x-auth/pkg/logx"
	"github.com/xentranet/x-auth/pkg/pgxdb"
	"github.com/xentranet/x-auth/pkg/tlsx"
	"github.com/xentranet/x-auth/services/authentication-service/internal"
)

func main() {
	// Capture recent log events into an in-process ring buffer for the operator
	// Monitoring console, while keeping the normal JSON-to-stdout logging.
	events := internal.NewEventBuffer(200)
	logger := slog.New(internal.NewBufferHandler(logx.New("authentication-service").Handler(), events))

	authenticatorURL := config.Env("AUTHENTICATOR_SERVICE_URL", "http://localhost:8083")
	issuer := config.Env("AUTH_ISSUER", "http://localhost:8082")
	// The `iss` claim minted into access/ID tokens. Defaults to the discovery
	// issuer so tokens match the published OIDC configuration; override with
	// JWT_ISSUER only when the signing identity must differ from the base URL.
	jwtIssuer := config.Env("JWT_ISSUER", issuer)

	// RS256 signing key (ARCHITECTURE.md §10.1). Production injects a PEM via
	// JWT_SIGNING_KEY (from KMS/secret storage); local dev falls back to an
	// ephemeral per-process key (jwtx logs a warning — tokens won't survive a
	// restart or verify across replicas).
	key, err := jwtx.LoadOrGenerateKey("JWT_SIGNING_KEY", logger)
	if err != nil {
		logger.Error("jwt_signing_key_load_failed", "err", err)
		os.Exit(1)
	}
	signer := jwtx.NewSigner(key)

	// Resolve storage. Postgres is the phase-2 default; the in-memory fallback is
	// preserved so the service still boots during local dev or CI without a DB
	// (same switch as transaction-service — see docs/postgres.md).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var store internal.Storage
	pool, err := pgxdb.Open(ctx, pgxdb.Config{
		ServiceName: "authentication-service",
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

	// Background sweeper: tokens and auth codes are TTL-checked only at read
	// time, so without a sweep the stores grow unbounded. PurgeExpired removes
	// expired tokens, stale auth codes, and long-expired sessions on every tick
	// (interval from PURGE_INTERVAL, default 5m) until the signal-aware ctx is
	// cancelled. Works identically against MemStorage and PGStorage.
	purgeInterval := 5 * time.Minute
	if v := config.Env("PURGE_INTERVAL", ""); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			logger.Warn("purge_interval_invalid", "value", v, "fallback", purgeInterval.String())
		} else {
			purgeInterval = d
		}
	}
	go func() {
		ticker := time.NewTicker(purgeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				removed, err := store.PurgeExpired(time.Now().UTC())
				if err != nil {
					logger.Error("purge_expired_failed", "err", err)
					continue
				}
				logger.Info("purge_expired", "removed", removed, "interval", purgeInterval.String())
			}
		}
	}()

	// Extra OIDC clients from the environment (OIDC_CLIENTS) — lets relying
	// apps register without dynamic client registration. Fatal on a malformed
	// value: silently dropping a client would surface as baffling
	// invalid_client errors at /authorize.
	if err := internal.SeedClientsFromEnv(store, logger); err != nil {
		logger.Error("oidc_clients_seed_failed", "err", err)
		os.Exit(1)
	}

	// Outbound (m)TLS to authenticator-service comes from the same TLS env
	// vars (tlsx.Transport inside the constructor). A partial TLS
	// configuration is fatal — never silently fall back to plaintext.
	authenticator, err := internal.NewHTTPAuthenticatorClient(logger, authenticatorURL)
	if err != nil {
		logger.Error("client_tls_config_failed", "err", err)
		os.Exit(1)
	}

	handler := internal.Router(internal.Deps{
		Store:         store,
		Logger:        logger,
		Authenticator: authenticator,
		Issuer:        issuer,
		Signer:        signer,
		JWTIssuer:     jwtIssuer,
		// Real social login per provider when its OAuth client credentials are
		// present in the environment (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET);
		// unconfigured providers keep the phase-1 stub.
		SocialProviders: internal.SocialProvidersFromEnv(logger),
		// Browser origins allowed to fetch the public OIDC endpoints
		// (comma-separated; empty disables CORS).
		CORSOrigins: splitNonEmpty(config.Env("CORS_ALLOWED_ORIGINS", "")),
		// Google-account allowlist for the /admin console (comma-separated;
		// empty denies all admin sign-ins).
		AdminEmails: splitNonEmpty(config.Env("ADMIN_EMAILS", "")),
		// Break-glass root accounts (comma-separated): always allowed into the
		// console and re-granted every staff role + reactivated on each boot.
		RootEmails: splitNonEmpty(config.Env("ROOT_EMAILS", "")),
		// Operator Monitoring console: recent-activity feed + a health probe of
		// the platform services (authn itself, risk-service, authenticator-service).
		Events: events,
		Health: internal.NewHealthChecker([]internal.ServiceTarget{
			{Name: "authentication-service", URL: issuer, Path: "/.well-known/openid-configuration"},
			{Name: "risk-service", URL: internal.RiskBaseURL(config.Env("RISK_EVENTS_URL", "")), Path: "/"},
			{Name: "authenticator-service", URL: authenticatorURL, Path: "/"},
		}),
		// Local-dev escape hatch: trust user_id / auto-create a dev user at
		// /authorize. MUST be unset in production (where a real authz-session
		// cookie is required).
		DevAutologin: config.Env("AUTHORIZE_DEV_AUTOLOGIN", "") == "true",
		// A protection-level /authorize request passes through (no re-challenge)
		// when the user stepped up at >= that level within this window. Default 5m.
		StepUpFreshness: parseDurationEnv(logger, "AUTHORIZE_STEPUP_FRESHNESS"),
		// Route /authorize through the configurable flow executor. OFF by default;
		// the built-in default flow reproduces the legacy behavior exactly.
		FlowEngine: config.Env("FLOW_ENGINE", "") == "true",
	})

	// Transport security (ARCHITECTURE.md §10.3): TLS/mTLS from the
	// TLS_CERT_FILE / TLS_KEY_FILE / TLS_CLIENT_CA_FILE env vars. A nil config
	// means plaintext local dev; a partial config is fatal.
	tlsConf, err := tlsx.ServerConfig(logger)
	if err != nil {
		logger.Error("tls_config_failed", "err", err)
		os.Exit(1)
	}

	addr := config.Addr(8082)
	if err := httpx.RunTLS(ctx, logger, addr, handler, tlsConf); err != nil {
		logger.Error("server_exited_with_error", "err", err)
		os.Exit(1)
	}
}

// parseDurationEnv reads key as a Go duration (e.g. "5m"); empty or invalid
// returns 0, letting the consumer fall back to its default.
func parseDurationEnv(logger *slog.Logger, key string) time.Duration {
	v := config.Env(key, "")
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		logger.Warn("invalid_duration_env", "key", key, "value", v, "err", err)
		return 0
	}
	return d
}

// splitNonEmpty splits a comma-separated env value, dropping empty segments.
func splitNonEmpty(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
