package internal

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// Server wires the pool-service Storage into an HTTP handler.
type Server struct {
	Storage Storage
	Logger  *slog.Logger
	// Now is overridable for testing.
	Now func() time.Time
	// NewID is overridable for testing.
	NewID func() string
}

// NewServer returns a Server with production defaults (UTC wall clock, random UUIDs).
func NewServer(storage Storage, logger *slog.Logger) *Server {
	return &Server{
		Storage: storage,
		Logger:  logger,
		Now:     func() time.Time { return time.Now().UTC() },
		NewID:   uuid.NewString,
	}
}

// Handler returns the top-level http.Handler for this service, with middleware wired.
// /healthz is public; everything under /v1/ is behind tenantx.Middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Tenant-scoped: attach per-route and then wrap once for middleware order clarity.
	authed := http.NewServeMux()
	authed.HandleFunc("POST /v1/pools", s.handleCreatePool)
	authed.HandleFunc("GET /v1/pools", s.handleListPools)
	authed.HandleFunc("GET /v1/pools/{id}", s.handleGetPool)
	authed.HandleFunc("DELETE /v1/pools/{id}", s.handleDeletePool)
	authed.HandleFunc("POST /v1/pools/{id}/identities", s.handleAddIdentity)
	authed.HandleFunc("GET /v1/pools/{id}/identities", s.handleListIdentities)
	authed.HandleFunc("POST /v1/pools/{id}/claim", s.handleClaim)
	authed.HandleFunc("POST /v1/identities/{id}/release", s.handleRelease)
	authed.HandleFunc("POST /v1/identities/{id}/revoke", s.handleRevoke)

	mux.Handle("/v1/", tenantx.Middleware(authed))

	return mux
}

// ---------- handlers ----------

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleCreatePool(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromRequest(w, r)
	if !ok {
		return
	}
	var req CreatePoolRequest
	if err := decodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > MaxNameLen {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_name",
			fmt.Sprintf("name required, 1-%d chars", MaxNameLen))
		return
	}
	if req.Size < MinSize || req.Size > MaxSize {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_size",
			fmt.Sprintf("size must be between %d and %d", MinSize, MaxSize))
		return
	}
	// persona_ids may be empty at creation time; we store as given.
	personaIDs := req.PersonaIDs
	if personaIDs == nil {
		personaIDs = []string{}
	}
	now := s.Now()
	pool := Pool{
		ID:         s.NewID(),
		TenantID:   tenant,
		Name:       name,
		Size:       req.Size,
		PersonaIDs: personaIDs,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	created, err := s.Storage.CreatePool(pool)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "create_failed", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, created)
}

// handleListPools handles GET /v1/pools. Supports:
//   - limit (int, default 100, max 500)
//   - cursor (RFC3339 timestamp; results are strictly older than this)
func (s *Server) handleListPools(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromRequest(w, r)
	if !ok {
		return
	}
	limit, cursor, ok := paginationFromRequest(w, r)
	if !ok {
		return
	}
	pools, err := s.Storage.ListPools(tenant, limit, cursor)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	resp := PoolListResponse{Items: pools}
	// If we returned a full page, provide a cursor for the next page. Callers that
	// do not need pagination can ignore next_cursor.
	if len(pools) == limit && limit > 0 {
		resp.NextCursor = pools[len(pools)-1].CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetPool(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromRequest(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_id", "pool id required")
		return
	}
	pool, err := s.Storage.GetPool(tenant, id)
	if err != nil {
		if errors.Is(err, ErrPoolNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "pool_not_found", "pool not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "get_failed", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pool)
}

func (s *Server) handleDeletePool(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromRequest(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_id", "pool id required")
		return
	}
	if err := s.Storage.DeletePool(tenant, id); err != nil {
		if errors.Is(err, ErrPoolNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "pool_not_found", "pool not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAddIdentity(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromRequest(w, r)
	if !ok {
		return
	}
	poolID := r.PathValue("id")
	if poolID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_id", "pool id required")
		return
	}
	var req AddIdentityRequest
	if err := decodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	subject := strings.TrimSpace(req.SubjectID)
	if subject == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_subject_id", "subject_id required")
		return
	}
	now := s.Now()
	ident := Identity{
		ID:        s.NewID(),
		PoolID:    poolID,
		SubjectID: subject,
		Status:    StatusAvailable,
		CreatedAt: now,
		UpdatedAt: now,
	}
	created, err := s.Storage.AddIdentity(tenant, poolID, ident)
	if err != nil {
		switch {
		case errors.Is(err, ErrPoolNotFound):
			httpx.WriteError(w, http.StatusNotFound, "pool_not_found", "pool not found")
		case errors.Is(err, ErrPoolFull):
			httpx.WriteError(w, http.StatusConflict, "pool_full", "pool is at capacity")
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "add_identity_failed", err.Error())
		}
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, created)
}

// handleListIdentities handles GET /v1/pools/{id}/identities. Supports:
//   - limit (int, default 100, max 500)
//   - cursor (RFC3339 timestamp; results are strictly older than this)
func (s *Server) handleListIdentities(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromRequest(w, r)
	if !ok {
		return
	}
	poolID := r.PathValue("id")
	if poolID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_id", "pool id required")
		return
	}
	limit, cursor, ok := paginationFromRequest(w, r)
	if !ok {
		return
	}
	idents, err := s.Storage.ListIdentities(tenant, poolID, limit, cursor)
	if err != nil {
		if errors.Is(err, ErrPoolNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "pool_not_found", "pool not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	resp := IdentityListResponse{Items: idents}
	// If we returned a full page, provide a cursor for the next page. Callers that
	// do not need pagination can ignore next_cursor.
	if len(idents) == limit && limit > 0 {
		resp.NextCursor = idents[len(idents)-1].CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromRequest(w, r)
	if !ok {
		return
	}
	poolID := r.PathValue("id")
	if poolID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_id", "pool id required")
		return
	}
	var req ClaimRequest
	if err := decodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if strings.TrimSpace(req.PersonaID) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_persona_id", "persona_id required")
		return
	}
	if strings.TrimSpace(req.InstallID) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_install_id", "install_id required")
		return
	}
	claimed, err := s.Storage.ClaimIdentity(tenant, poolID, req.PersonaID, req.InstallID)
	if err != nil {
		switch {
		case errors.Is(err, ErrPoolNotFound), errors.Is(err, ErrPersonaNotEligible):
			// Per spec, both map to 404.
			httpx.WriteError(w, http.StatusNotFound, "pool_not_found", "pool not found or persona not eligible")
		case errors.Is(err, ErrNoAvailableIdentity):
			httpx.WriteError(w, http.StatusConflict, "no_available_identity", "no available identity in pool")
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "claim_failed", err.Error())
		}
		return
	}
	httpx.WriteJSON(w, http.StatusOK, claimed)
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromRequest(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_id", "identity id required")
		return
	}
	ident, err := s.Storage.ReleaseIdentity(tenant, id)
	if err != nil {
		switch {
		case errors.Is(err, ErrIdentityNotFound):
			httpx.WriteError(w, http.StatusNotFound, "identity_not_found", "identity not found")
		case errors.Is(err, ErrIdentityRevoked):
			httpx.WriteError(w, http.StatusConflict, "identity_revoked", "cannot release revoked identity")
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "release_failed", err.Error())
		}
		return
	}
	httpx.WriteJSON(w, http.StatusOK, ident)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromRequest(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_id", "identity id required")
		return
	}
	if err := s.Storage.RevokeIdentity(tenant, id); err != nil {
		if errors.Is(err, ErrIdentityNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "identity_not_found", "identity not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "revoke_failed", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- helpers ----------

// tenantFromRequest extracts the tenant id from the request context. If it is missing
// (tenantx.Middleware bypassed or misconfigured) it writes the structured missing_tenant
// error shared by every X-Auth service and returns ok=false, so no storage query ever
// runs with an empty — and therefore unscoped — tenant id.
func tenantFromRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenant, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
	}
	return tenant, ok
}

// paginationFromRequest parses the shared `limit` / `cursor` query params used by the
// list endpoints, mirroring the transaction-service contract: limit defaults to
// DefaultListLimit, is capped at MaxListLimit, and must be a positive integer; cursor
// must be an RFC3339 timestamp. On a bad param it writes the structured 400
// (invalid_limit / invalid_cursor) and returns ok=false.
func paginationFromRequest(w http.ResponseWriter, r *http.Request) (int, time.Time, bool) {
	q := r.URL.Query()

	limit := DefaultListLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_limit",
				"limit must be a positive integer")
			return 0, time.Time{}, false
		}
		if n > MaxListLimit {
			n = MaxListLimit
		}
		limit = n
	}

	var cursor time.Time
	if v := q.Get("cursor"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_cursor",
				"cursor must be an RFC3339 timestamp")
			return 0, time.Time{}, false
		}
		cursor = t
	}
	return limit, cursor, true
}

// decodeJSON decodes a request body using httpx.ReadJSON and normalises empty-body errors.
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return errors.New("missing request body")
	}
	if err := httpx.ReadJSON(r, v); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("missing request body")
		}
		return err
	}
	return nil
}
