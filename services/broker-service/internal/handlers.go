package internal

import (
	"log/slog"
	"net/http"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// Deps bundles every collaborator broker-service needs. Passing this to the
// router keeps the constructor in cmd/main.go small and the test wiring obvious.
type Deps struct {
	Store  Storage
	Logger *slog.Logger
	// Clients is the combined persona + pool + grant client surface.
	// In production this is *HTTPClients; tests swap in a mock.
	Clients interface {
		PersonaClient
		PoolClient
		GrantClient
	}
	Issuer     string
	DefaultTTL int
}

// Router builds the complete http.Handler for broker-service.
//
// Routing tiers:
//
//   - /healthz — unauthenticated, always served
//   - /.well-known/*, /register, /metadata.json, /authorize, /token, /revoke,
//     /userinfo, /mcp/* — public OAuth/OIDC/MCP surface, no tenant header
//     (tenant is embedded in the auth code or derived from the bearer)
//   - /v1/installs/* — tenant-scoped admin, behind tenantx.Middleware
//
// The whole tree is wrapped in Recover + Logging so every request is logged and
// handler panics turn into 500 instead of crashing the process.
func Router(d Deps) http.Handler {
	oidc := &OIDCHandlers{
		Store:      d.Store,
		Clients:    d.Clients,
		Logger:     d.Logger,
		Issuer:     d.Issuer,
		DefaultTTL: d.DefaultTTL,
	}
	dcr := &DCRHandlers{Store: d.Store, Logger: d.Logger}
	cimd := &CIMDHandler{Issuer: d.Issuer}
	mcp := &MCPHandlers{Logger: d.Logger}
	installs := &InstallHandlers{Store: d.Store, Clients: d.Clients, Logger: d.Logger}

	mux := http.NewServeMux()

	// Health.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Discovery.
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", oidc.OAuthMetadata)
	mux.HandleFunc("GET /.well-known/openid-configuration", oidc.OIDCMetadata)

	// DCR + CIMD.
	mux.HandleFunc("POST /register", dcr.Register)
	mux.Handle("GET /metadata.json", cimd)

	// OAuth / OIDC.
	mux.HandleFunc("GET /authorize", oidc.Authorize)
	mux.HandleFunc("POST /token", oidc.Token)
	mux.HandleFunc("POST /revoke", oidc.Revoke)
	mux.HandleFunc("GET /userinfo", oidc.UserInfo)

	// MCP stubs.
	mux.HandleFunc("GET /mcp/sse", mcp.SSE)
	mux.HandleFunc("POST /mcp/rpc", mcp.RPC)

	// Install admin — tenant-scoped. A dedicated mux under /v1/ lets us put
	// tenantx.Middleware on only these routes without firing it for OIDC traffic.
	v1 := http.NewServeMux()
	v1.HandleFunc("POST /v1/installs", installs.Create)
	v1.HandleFunc("GET /v1/installs", installs.List)
	v1.HandleFunc("GET /v1/installs/{id}", installs.Get)
	v1.HandleFunc("POST /v1/installs/{id}/revoke", installs.Revoke)
	mux.Handle("/v1/", tenantx.Middleware(v1))

	return httpx.Recover(d.Logger)(httpx.Logging(d.Logger)(mux))
}
