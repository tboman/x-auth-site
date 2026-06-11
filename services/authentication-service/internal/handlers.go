package internal

import (
	"log/slog"
	"net/http"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/jwtx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// Deps bundles every collaborator authentication-service needs. Passing this to
// the router keeps cmd/main.go's constructor small and the test wiring obvious.
type Deps struct {
	Store         Storage
	Logger        *slog.Logger
	Authenticator AuthenticatorClient
	Issuer        string

	// Signer holds the RS256 key that signs access + ID tokens and backs the
	// JWKS endpoints. Required. JWTIssuer is the `iss` claim minted into
	// tokens; empty means "same as Issuer" (the normal case — tokens should
	// match the discovery document).
	Signer    *jwtx.Signer
	JWTIssuer string

	// SocialProviders enables the real OAuth2 handshake per provider (see
	// SocialHandlers). Nil/empty means every provider runs the phase-1 stub.
	SocialProviders map[string]SocialProviderConfig

	// CORSOrigins lists web origins allowed to call the public OIDC surface
	// (/token, /userinfo, /revoke, discovery, JWKS) from a browser. Empty
	// means no CORS headers are emitted (server-to-server callers only).
	CORSOrigins []string
}

// Router builds the complete http.Handler for authentication-service.
//
// Routing tiers:
//
//   - /healthz — unauthenticated, always served
//   - /.well-known/*, /authorize, /token, /revoke, /userinfo, /v1/auth/jwks —
//     public OIDC surface, no tenant header (tenant is carried by the
//     authorization code or the bearer token's claims)
//   - /v1/social/{provider}/authorize|/callback — public social-login stub
//   - /v1/users/*, /v1/sessions/* — tenant-scoped, behind tenantx.Middleware
//   - /internal/v1/sessions/* — service-to-service alias of the session
//     endpoints (same handlers), additionally wrapped in httpx.InternalAuth
//     (ARCHITECTURE.md §10.3). transaction-service calls GET
//     /internal/v1/sessions/{id} and POST /internal/v1/sessions/{id}/upgrade
//     here. Verified mTLS peers or the X-Internal-Auth shared secret are
//     accepted; with neither configured the tree is open (local dev). Only the
//     session subtree is aliased — the OIDC/user surface stays public-only.
//
// The whole tree is wrapped in Recover + Logging so every request logs and
// handler panics turn into 500 instead of crashing the process.
func Router(d Deps) http.Handler {
	jwtIssuer := d.JWTIssuer
	if jwtIssuer == "" {
		jwtIssuer = d.Issuer
	}
	// Build the bearer verifier from the signer's own published key set — the
	// same document /v1/auth/jwks serves — so /userinfo validates tokens the
	// exact way an external consumer would. A Signer's JWKS always contains
	// one usable RSA key, so a construction error is a programming bug.
	verifier, err := jwtx.NewVerifierFromJWKS(jwtIssuer, d.Signer.JWKS())
	if err != nil {
		panic("authentication-service: verifier from signer JWKS: " + err.Error())
	}
	oidc := &OIDCHandlers{
		Store:     d.Store,
		Logger:    d.Logger,
		Issuer:    d.Issuer,
		Signer:    d.Signer,
		Verifier:  verifier,
		JWTIssuer: jwtIssuer,
	}
	social := &SocialHandlers{Store: d.Store, Logger: d.Logger, Issuer: d.Issuer, Providers: d.SocialProviders}
	users := &UserHandlers{Store: d.Store, Logger: d.Logger}
	sessions := &SessionHandlers{Store: d.Store, Logger: d.Logger}

	mux := http.NewServeMux()

	// Liveness probe. No tenant header required.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// The public OIDC surface is CORS-enabled for configured SPA origins;
	// fetch-able routes additionally answer OPTIONS preflights (the /userinfo
	// Authorization header triggers one). /authorize is top-level navigation
	// and needs no CORS.
	withCORS := func(h http.HandlerFunc) http.Handler { return corsHandler(d.CORSOrigins, h) }

	// OIDC discovery — static JSON.
	mux.Handle("GET /.well-known/oauth-authorization-server", withCORS(oidc.OAuthMetadata))
	mux.Handle("GET /.well-known/openid-configuration", withCORS(oidc.OIDCMetadata))

	// JWKS — canonical route per ARCHITECTURE.md §4.3, plus the conventional
	// well-known alias the discovery documents advertise as jwks_uri.
	mux.Handle("GET /v1/auth/jwks", withCORS(oidc.JWKS))
	mux.Handle("GET /.well-known/jwks.json", withCORS(oidc.JWKS))

	// OIDC / OAuth2 flows — public, no tenant header.
	mux.HandleFunc("GET /authorize", oidc.Authorize)
	mux.Handle("POST /token", withCORS(oidc.Token))
	mux.Handle("OPTIONS /token", withCORS(oidc.Token))
	mux.Handle("POST /revoke", withCORS(oidc.Revoke))
	mux.Handle("OPTIONS /revoke", withCORS(oidc.Revoke))
	mux.Handle("GET /userinfo", withCORS(oidc.UserInfo))
	mux.Handle("OPTIONS /userinfo", withCORS(oidc.UserInfo))

	// Social login stubs — public, no tenant header (tenant_id is a query param).
	mux.HandleFunc("GET /v1/social/{provider}/authorize", social.Authorize)
	mux.HandleFunc("GET /v1/social/{provider}/callback", social.Callback)

	// Tenant-scoped admin endpoints. A dedicated mux under /v1/ lets us wrap only
	// these routes with tenantx.Middleware without firing it for OIDC traffic.
	v1 := http.NewServeMux()
	v1.HandleFunc("POST /v1/users", users.Create)
	v1.HandleFunc("GET /v1/users", users.List)
	v1.HandleFunc("GET /v1/users/{id}", users.Get)
	v1.HandleFunc("PATCH /v1/users/{id}", users.Patch)
	v1.HandleFunc("DELETE /v1/users/{id}", users.Delete)

	v1.HandleFunc("POST /v1/sessions", sessions.Create)
	v1.HandleFunc("GET /v1/sessions/{id}", sessions.Get)
	v1.HandleFunc("POST /v1/sessions/{id}/refresh", sessions.Refresh)
	v1.HandleFunc("POST /v1/sessions/{id}/invalidate", sessions.Invalidate)
	v1.HandleFunc("POST /v1/sessions/{id}/upgrade", sessions.Upgrade)

	// Social routes collide with the /v1/ prefix, so they are registered on the
	// root mux *before* this point. tenantx.Middleware only applies to the
	// tenant-scoped subtree.
	mux.Handle("/v1/users", tenantx.Middleware(v1))
	mux.Handle("/v1/users/", tenantx.Middleware(v1))
	mux.Handle("/v1/sessions", tenantx.Middleware(v1))
	mux.Handle("/v1/sessions/", tenantx.Middleware(v1))

	// Internal alias: /internal/v1/sessions... → InternalAuth → strip
	// "/internal" → the same tenant-scoped v1 mux. One registration, zero
	// handler duplication. Mounted only on the session subtree so the user
	// CRUD endpoints don't grow an internal alias they have no caller for.
	internalSessions := httpx.InternalAuth(d.Logger)(
		http.StripPrefix("/internal", tenantx.Middleware(v1)))
	mux.Handle("/internal/v1/sessions", internalSessions)
	mux.Handle("/internal/v1/sessions/", internalSessions)

	return httpx.Recover(d.Logger)(httpx.Logging(d.Logger)(mux))
}
