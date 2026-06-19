package internal

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/ratex"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// defaultListLimit / maxListLimit bound GET /v1/authenticators pages.
const (
	defaultListLimit = 50
	maxListLimit     = 500
)

// Handlers serves the fido-service HTTP API over the MDS Manager.
type Handlers struct {
	Manager *Manager
	Logger  *slog.Logger
}

// NewHandlers constructs the handler bundle.
func NewHandlers(mgr *Manager, logger *slog.Logger) *Handlers {
	return &Handlers{Manager: mgr, Logger: logger}
}

// Router wires every route. /healthz is unauthenticated; the /v1/* tree sits
// behind the per-tenant rate limiter (a nil Allower disables) and then
// tenantx.Middleware. The whole tree is wrapped in Recover + Logging.
//
// The MDS dataset is global, not tenant-scoped — the X-Tenant-Id header is
// required by convention and used only as the rate-limit key, not for data
// isolation.
func (h *Handlers) Router(limiter ratex.Allower) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.Health)

	v1 := http.NewServeMux()
	v1.HandleFunc("GET /v1/authenticators", h.ListAuthenticators)
	v1.HandleFunc("GET /v1/authenticators/{aaguid}", h.GetAuthenticator)
	v1.HandleFunc("POST /v1/attestation", h.PostAttestation)
	v1.HandleFunc("GET /v1/mds/status", h.MDSStatus)

	mux.Handle("/v1/", ratex.Middleware(limiter, rateLimitKey)(tenantx.Middleware(v1)))

	return httpx.Recover(h.Logger)(httpx.Logging(h.Logger)(mux))
}

// Health is an unauthenticated liveness probe.
func (h *Handlers) Health(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// GetAuthenticator returns the risk profile for an AAGUID.
func (h *Handlers) GetAuthenticator(w http.ResponseWriter, r *http.Request) {
	aaguid := r.PathValue("aaguid")
	profile, found, loaded := h.Manager.Profile(aaguid)
	if !loaded {
		writeUnavailable(w)
		return
	}
	if !found {
		httpx.WriteError(w, http.StatusNotFound, "aaguid_not_found",
			"no FIDO MDS entry for that AAGUID")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, profile)
}

// PostAttestation parses an attestation (or full credential), extracts the
// AAGUID + authenticator-data flags, and returns the enriched profile.
func (h *Handlers) PostAttestation(w http.ResponseWriter, r *http.Request) {
	var req AttestationRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "malformed json body")
		return
	}
	if req.AttestationObject == "" && len(req.Credential) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request",
			"provide attestationObject or credential")
		return
	}

	aaguid, flags, err := parseAttestation(req)
	if err != nil {
		h.Logger.Info("attestation_parse_failed", "err", err)
		httpx.WriteError(w, http.StatusBadRequest, "invalid_attestation",
			"could not parse attestation")
		return
	}

	profile, loaded := h.Manager.ProfileForAttestation(aaguid, flags)
	if !loaded {
		writeUnavailable(w)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, profile)
}

// ListAuthenticators returns a page of all known profiles.
func (h *Handlers) ListAuthenticators(w http.ResponseWriter, r *http.Request) {
	offset := parseIntDefault(r.URL.Query().Get("offset"), 0)
	limit := parseIntDefault(r.URL.Query().Get("limit"), defaultListLimit)
	if limit > maxListLimit {
		limit = maxListLimit
	}
	if limit < 0 {
		limit = 0
	}
	resp, loaded := h.Manager.List(offset, limit)
	if !loaded {
		writeUnavailable(w)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// MDSStatus reports snapshot freshness and the last refresh outcome.
func (h *Handlers) MDSStatus(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.Manager.Status())
}

func writeUnavailable(w http.ResponseWriter) {
	httpx.WriteError(w, http.StatusServiceUnavailable, "mds_unavailable",
		"FIDO metadata not yet loaded; retry shortly")
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// rateLimitKey keys the limiter by tenant + method + endpoint class, mirroring
// transaction-service. The endpoint class is the first two path segments. A
// missing tenant returns "" (bypasses the limiter); tenantx rejects it with 400.
func rateLimitKey(r *http.Request) string {
	tenant := r.Header.Get(tenantx.Header)
	if tenant == "" {
		return ""
	}
	return tenant + "|" + r.Method + "|" + endpointClass(r.URL.Path)
}

func endpointClass(path string) string {
	segs := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
	if len(segs) > 2 {
		segs = segs[:2]
	}
	return "/" + strings.Join(segs, "/")
}
