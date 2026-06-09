package internal

import (
	"log/slog"
	"net/http"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// Router builds the authenticator-service HTTP handler. /healthz is mounted
// without tenant middleware so infra probes don't need to know about tenants;
// every other route goes through tenantx.Middleware.
//
// The /v1 tree is mounted twice (ARCHITECTURE.md §10.3):
//
//   - /v1/* — the original phase-1 prefix, kept open for back-compat.
//   - /internal/v1/* — the same handlers aliased for service-to-service
//     callers (transaction-service challenges, authentication-service
//     authenticator listing), gated by httpx.InternalAuth: a verified mTLS
//     peer certificate or the X-Internal-Auth shared secret
//     (INTERNAL_AUTH_SECRET); with neither configured the gate is open (dev).
func Router(log *slog.Logger, store Storage, registry *Registry) http.Handler {
	auth := NewAuthenticatorHandlers(log, store)
	chal := NewChallengeHandlers(log, store, registry)

	// tenanted is the router that requires X-Tenant-Id. All /v1/* routes go here.
	tenanted := http.NewServeMux()
	tenanted.HandleFunc("POST /v1/authenticators", auth.Enroll)
	tenanted.HandleFunc("GET /v1/authenticators", auth.List)
	tenanted.HandleFunc("GET /v1/authenticators/{id}", auth.Get)
	tenanted.HandleFunc("DELETE /v1/authenticators/{id}", auth.Delete)

	tenanted.HandleFunc("POST /v1/challenges", chal.Create)
	tenanted.HandleFunc("GET /v1/challenges/{id}", chal.Get)
	tenanted.HandleFunc("POST /v1/challenges/{id}/verify", chal.Verify)

	// top is the outer mux. /healthz skips the tenant gate; /v1/* goes through it.
	top := http.NewServeMux()
	top.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	top.Handle("/v1/", tenantx.Middleware(tenanted))

	// /internal/v1/* aliases the ENTIRE /v1 route tree onto the same handlers:
	// StripPrefix removes "/internal" so the tenanted mux patterns match
	// unchanged. InternalAuth runs before the tenant gate, so an
	// unauthenticated internal call gets 401 rather than leaking which
	// tenant-validation error it would have hit.
	top.Handle("/internal/v1/", httpx.InternalAuth(log)(
		http.StripPrefix("/internal", tenantx.Middleware(tenanted))))

	// Wrap the top mux in the shared logging + panic-recovery middleware.
	return httpx.Logging(log)(httpx.Recover(log)(top))
}
