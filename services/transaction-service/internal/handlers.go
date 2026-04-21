package internal

import (
	"log/slog"
	"net/http"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// Handlers groups the transaction-service HTTP handlers and their dependencies.
// Three client interfaces are injected so tests can swap in in-process fakes without
// touching the network.
type Handlers struct {
	Store          Storage
	Logger         *slog.Logger
	Risk           RiskClient
	Authentication AuthenticationClient
	Authenticator  AuthenticatorClient
}

// NewHandlers constructs a Handlers value. Any of the client arguments may be nil in
// tests that don't exercise the affected endpoint.
func NewHandlers(store Storage, logger *slog.Logger, risk RiskClient, auth AuthenticationClient, authr AuthenticatorClient) *Handlers {
	return &Handlers{
		Store:          store,
		Logger:         logger,
		Risk:           risk,
		Authentication: auth,
		Authenticator:  authr,
	}
}

// Router builds the http.Handler wiring every route. /healthz is served without tenant
// enforcement; every /v1/* route sits behind tenantx.Middleware. The whole tree is
// wrapped in Recover + Logging so every request (including /healthz) is logged and any
// panic returns 500 instead of crashing the process.
//
// /v1/advice is the canonical endpoint. /v1/evaluate is an alias that points at the
// same handler — keeping ARCHITECTURE.md §4.1's original contract callable while we
// migrate clients to the new name.
func (h *Handlers) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.Health)

	v1 := http.NewServeMux()
	v1.HandleFunc("POST /v1/advice", h.Advice)
	v1.HandleFunc("POST /v1/evaluate", h.Advice) // alias
	v1.HandleFunc("POST /v1/step-up/verify", h.StepUpVerify)
	v1.HandleFunc("POST /v1/authorize", h.Authorize)
	v1.HandleFunc("GET /v1/transactions", h.ListTransactions)
	v1.HandleFunc("GET /v1/transactions/{id}", h.GetTransaction)

	mux.Handle("/v1/", tenantx.Middleware(v1))

	return httpx.Recover(h.Logger)(httpx.Logging(h.Logger)(mux))
}

// Health is an unauthenticated liveness probe.
func (h *Handlers) Health(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
