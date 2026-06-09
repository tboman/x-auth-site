package internal

import (
	"errors"
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

// Handlers groups the persona-service HTTP handlers and their dependencies.
type Handlers struct {
	Store  Storage
	Logger *slog.Logger
}

// NewHandlers constructs a Handlers value with the given storage and logger.
func NewHandlers(store Storage, logger *slog.Logger) *Handlers {
	return &Handlers{Store: store, Logger: logger}
}

// Router builds an http.Handler wiring every route for the persona-service.
// /healthz is served without tenant enforcement; /v1/* sits behind tenantx.Middleware.
// The whole tree is wrapped in Recover + Logging so every request (including /healthz)
// is logged and any panic returns 500 instead of crashing the process.
func (h *Handlers) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.Health)

	v1 := http.NewServeMux()
	v1.HandleFunc("POST /v1/personas", h.Create)
	v1.HandleFunc("GET /v1/personas", h.List)
	v1.HandleFunc("GET /v1/personas/{id}", h.Get)
	v1.HandleFunc("PATCH /v1/personas/{id}", h.Update)
	v1.HandleFunc("DELETE /v1/personas/{id}", h.Delete)

	mux.Handle("/v1/", tenantx.Middleware(v1))

	return httpx.Recover(h.Logger)(httpx.Logging(h.Logger)(mux))
}

// Health is an unauthenticated liveness probe.
func (h *Handlers) Health(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Create handles POST /v1/personas.
func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	var req CreateRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		if errors.Is(err, io.EOF) {
			httpx.WriteError(w, http.StatusBadRequest, "empty_body", "request body required")
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_name", "name is required")
		return
	}
	if len(name) > MaxNameLen {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_name", "name must be 1-100 characters")
		return
	}

	ttl := DefaultTokenTTLSeconds
	if req.TokenTTLSeconds != nil {
		ttl = *req.TokenTTLSeconds
	}
	if ttl <= 0 || ttl > MaxTokenTTLSeconds {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_token_ttl_seconds",
			"token_ttl_seconds must be between 1 and 86400")
		return
	}

	scopes := req.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	now := time.Now().UTC()
	p := Persona{
		ID:              uuid.NewString(),
		TenantID:        tenantID,
		Name:            name,
		Scopes:          scopes,
		Claims:          req.Claims,
		TokenTTLSeconds: ttl,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	saved, err := h.Store.Create(p)
	if err != nil {
		h.Logger.Error("persona_create_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to create persona")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, saved)
}

// List handles GET /v1/personas. Supports:
//   - limit (int, default 100, max 500)
//   - cursor (RFC3339 timestamp; results are strictly older than this)
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	q := r.URL.Query()

	limit := DefaultListLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_limit",
				"limit must be a positive integer")
			return
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
			return
		}
		cursor = t
	}

	items, err := h.Store.List(tenantID, limit, cursor)
	if err != nil {
		h.Logger.Error("persona_list_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to list personas")
		return
	}

	resp := ListResponse{Items: items}
	// If we returned a full page, provide a cursor for the next page. Callers that
	// do not need pagination can ignore next_cursor.
	if len(items) == limit && limit > 0 {
		resp.NextCursor = items[len(items)-1].CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// Get handles GET /v1/personas/{id}.
func (h *Handlers) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_id", "id is required")
		return
	}
	p, err := h.Store.Get(tenantID, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "persona not found")
			return
		}
		h.Logger.Error("persona_get_failed", "err", err, "tenant_id", tenantID, "id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to read persona")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

// Update handles PATCH /v1/personas/{id}.
func (h *Handlers) Update(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_id", "id is required")
		return
	}

	var req UpdateRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		if errors.Is(err, io.EOF) {
			httpx.WriteError(w, http.StatusBadRequest, "empty_body", "request body required")
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	existing, err := h.Store.Get(tenantID, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "persona not found")
			return
		}
		h.Logger.Error("persona_update_read_failed", "err", err, "tenant_id", tenantID, "id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to read persona")
		return
	}

	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" || len(name) > MaxNameLen {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_name", "name must be 1-100 characters")
			return
		}
		existing.Name = name
	}
	if req.Scopes != nil {
		existing.Scopes = *req.Scopes
		if existing.Scopes == nil {
			existing.Scopes = []string{}
		}
	}
	// Claims: a present (non-nil) map replaces the stored value. A nil claims field in the
	// PATCH body leaves claims untouched — this is consistent with omitempty semantics and
	// matches how callers typically distinguish "not set" from "set to empty".
	if req.Claims != nil {
		existing.Claims = req.Claims
	}
	if req.TokenTTLSeconds != nil {
		ttl := *req.TokenTTLSeconds
		if ttl <= 0 || ttl > MaxTokenTTLSeconds {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_token_ttl_seconds",
				"token_ttl_seconds must be between 1 and 86400")
			return
		}
		existing.TokenTTLSeconds = ttl
	}

	saved, err := h.Store.Update(existing)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "persona not found")
			return
		}
		h.Logger.Error("persona_update_failed", "err", err, "tenant_id", tenantID, "id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to update persona")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, saved)
}

// Delete handles DELETE /v1/personas/{id}.
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_id", "id is required")
		return
	}
	if err := h.Store.Delete(tenantID, id); err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "persona not found")
			return
		}
		h.Logger.Error("persona_delete_failed", "err", err, "tenant_id", tenantID, "id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to delete persona")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
