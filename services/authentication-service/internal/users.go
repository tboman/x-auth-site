package internal

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// UserHandlers implements the tenant-scoped user CRUD endpoints under /v1/users.
// Every call derives tenant id from the X-Tenant-Id header (populated by
// tenantx.Middleware) — nothing in the JSON body can override it.
type UserHandlers struct {
	Store  Storage
	Logger *slog.Logger
}

// Create handles POST /v1/users. Body: {email, name}. Email is required.
// 409 on (tenant_id, email) collision. User ids are prefixed `usr_`.
func (h *UserHandlers) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	var req CreateUserRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if email == "" || !strings.Contains(email, "@") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "email is required and must be a valid address")
		return
	}

	now := time.Now().UTC()
	u := User{
		ID:        "usr_" + uuid.NewString(),
		TenantID:  tenantID,
		Email:     email,
		Name:      strings.TrimSpace(req.Name),
		CreatedAt: now,
		UpdatedAt: now,
	}
	created, err := h.Store.CreateUser(u)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			httpx.WriteError(w, http.StatusConflict, "user_exists", "a user with that email already exists")
			return
		}
		h.Logger.Error("user_create_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to create user")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, created)
}

// List handles GET /v1/users. Returns every user belonging to the header tenant.
// Response shape: {"users": [...]} — wrapping in an object leaves room to add
// pagination metadata without a breaking change.
func (h *UserHandlers) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}
	users, err := h.Store.ListUsers(tenantID)
	if err != nil {
		h.Logger.Error("user_list_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to list users")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"users": users})
}

// Get handles GET /v1/users/{id}. 404 if the user does not exist or belongs to
// a different tenant.
func (h *UserHandlers) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}
	id := r.PathValue("id")
	u, err := h.Store.GetUser(tenantID, id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

// Patch handles PATCH /v1/users/{id}. Only non-empty fields in the request body
// are applied — omitted fields keep their prior value.
func (h *UserHandlers) Patch(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}
	id := r.PathValue("id")

	var req UpdateUserRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	existing, err := h.Store.GetUser(tenantID, id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	if req.Email != "" {
		email := strings.TrimSpace(strings.ToLower(req.Email))
		if !strings.Contains(email, "@") {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "email must be a valid address")
			return
		}
		existing.Email = email
	}
	if req.Name != "" {
		existing.Name = strings.TrimSpace(req.Name)
	}

	updated, err := h.Store.UpdateUser(existing)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			httpx.WriteError(w, http.StatusConflict, "user_exists", "a user with that email already exists")
			return
		}
		h.Logger.Error("user_update_failed", "err", err, "tenant_id", tenantID, "user_id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to update user")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, updated)
}

// Delete handles DELETE /v1/users/{id}. Returns 204 on success, 404 if not found.
// Phase 1 does a hard delete — TODO(phase-2): soft-delete + GDPR-safe
// pseudonymisation per ARCHITECTURE.md §11.
func (h *UserHandlers) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}
	id := r.PathValue("id")
	if err := h.Store.DeleteUser(tenantID, id); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
