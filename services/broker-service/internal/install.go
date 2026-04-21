package internal

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
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

	if err := h.Clients.RevokeGrantsForInstall(tenantID, id); err != nil {
		h.Logger.Warn("install_revoke_grants_failed", "err", err, "tenant_id", tenantID, "install_id", id)
	}
	if existing.IdentityID != "" {
		if err := h.Clients.ReleaseIdentity(tenantID, existing.IdentityID); err != nil {
			h.Logger.Warn("install_revoke_release_failed", "err", err,
				"tenant_id", tenantID, "install_id", id, "identity_id", existing.IdentityID)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
