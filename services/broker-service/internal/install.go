package internal

import (
	"context"
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

// InstallHandlers groups the install-admin endpoints (create/read/revoke).
// OIDC-driven creation lives in oidc.go; these handlers cover the manual /v1/installs
// surface used by admin tools and the /revoke cascade.
type InstallHandlers struct {
	Store   Storage
	Clients interface {
		PersonaClient
		PoolClient
		GrantClient
	}
	Logger *slog.Logger
}

// Create handles POST /v1/installs — the "manual" path that bypasses OIDC.
// The install is created in status=pending; OIDC binding (or a future admin
// action) is what moves it to active.
func (h *InstallHandlers) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	var req CreateInstallRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		if errors.Is(err, io.EOF) {
			httpx.WriteError(w, http.StatusBadRequest, "empty_body", "request body required")
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	runtime := strings.TrimSpace(req.Runtime)
	if !ValidRuntime(runtime) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_runtime",
			"runtime must be one of claude|chatgpt|cursor|custom")
		return
	}
	if strings.TrimSpace(req.PersonaID) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_persona_id", "persona_id is required")
		return
	}
	if strings.TrimSpace(req.ClientID) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_client_id", "client_id is required")
		return
	}

	now := time.Now().UTC()
	i := Install{
		ID:        uuid.NewString(),
		TenantID:  tenantID,
		Runtime:   runtime,
		PersonaID: req.PersonaID,
		ClientID:  req.ClientID,
		Status:    InstallStatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	saved, err := h.Store.CreateInstall(i)
	if err != nil {
		h.Logger.Error("install_create_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to create install")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, saved)
}

// List handles GET /v1/installs — tenant-scoped keyset pagination, same contract
// as transaction-service's GET /v1/transactions:
//   - limit (int, default 100, max 500)
//   - cursor (RFC3339 timestamp; results are strictly older than this)
//
// The response envelope is {"installs": [...], "next_cursor": "..."}; next_cursor
// is only present when a full page was returned.
func (h *InstallHandlers) List(w http.ResponseWriter, r *http.Request) {
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

	items, err := h.Store.ListInstalls(tenantID, limit, cursor)
	if err != nil {
		h.Logger.Error("install_list_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to list installs")
		return
	}

	resp := InstallListResponse{Installs: items}
	// If we returned a full page, provide a cursor for the next page. Callers that
	// do not need pagination can ignore next_cursor.
	if len(items) == limit && limit > 0 {
		resp.NextCursor = items[len(items)-1].CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// Get handles GET /v1/installs/{id}.
func (h *InstallHandlers) Get(w http.ResponseWriter, r *http.Request) {
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
	i, err := h.Store.GetInstall(tenantID, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "install not found")
			return
		}
		h.Logger.Error("install_get_failed", "err", err, "tenant_id", tenantID, "id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to read install")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, i)
}

// Revoke handles POST /v1/installs/{id}/revoke. Cascade:
//  1. mark install revoked in local store
//  2. ask grant-service to revoke every grant bound to this install
//  3. release the claimed identity back to its pool (if one was bound)
//
// Steps 2 and 3 are best-effort: if either downstream call fails we log but still
// return 204 because the install itself is already marked revoked locally and the
// cascade can be retried by an operator. This keeps revocation idempotent from the
// caller's perspective while avoiding a partially-revoked state visible to agents.
func (h *InstallHandlers) Revoke(w http.ResponseWriter, r *http.Request) {
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

	existing, err := h.Store.GetInstall(tenantID, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "install not found")
			return
		}
		h.Logger.Error("install_revoke_read_failed", "err", err, "tenant_id", tenantID, "id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to read install")
		return
	}

	if existing.Status == InstallStatusRevoked {
		// Idempotent — already revoked.
		w.WriteHeader(http.StatusNoContent)
		return
	}

	existing.Status = InstallStatusRevoked
	if _, err := h.Store.UpdateInstall(existing); err != nil {
		h.Logger.Error("install_revoke_update_failed", "err", err, "tenant_id", tenantID, "id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to revoke install")
		return
	}

	// Non-cancellable context for the cascade: the install is already marked revoked
	// locally, so if the caller disconnects now we must still revoke the grants and
	// release the identity — otherwise a dropped connection leaves live grants behind
	// a revoked install. The HTTP client's own timeout still bounds each call.
	cascadeCtx := context.WithoutCancel(r.Context())
	if err := h.Clients.RevokeGrantsForInstall(cascadeCtx, tenantID, id); err != nil {
		h.Logger.Warn("install_revoke_grants_failed",
			downstreamLogAttrs(err, "tenant_id", tenantID, "install_id", id)...)
	}
	if existing.IdentityID != "" {
		if err := h.Clients.ReleaseIdentity(cascadeCtx, tenantID, existing.IdentityID); err != nil {
			h.Logger.Warn("install_revoke_release_failed",
				downstreamLogAttrs(err, "tenant_id", tenantID, "install_id", id, "identity_id", existing.IdentityID)...)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
