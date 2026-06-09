package internal

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// AuthenticatorHandlers wires authenticator-CRUD endpoints onto a Storage.
type AuthenticatorHandlers struct {
	log   *slog.Logger
	store Storage
}

// NewAuthenticatorHandlers constructs a handler bundle.
func NewAuthenticatorHandlers(log *slog.Logger, store Storage) *AuthenticatorHandlers {
	return &AuthenticatorHandlers{log: log, store: store}
}

// Enroll handles POST /v1/authenticators — register a new authenticator for a user.
func (h *AuthenticatorHandlers) Enroll(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	var req EnrollRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "malformed json body")
		return
	}
	if strings.TrimSpace(req.UserID) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "user_id is required")
		return
	}
	if !IsValidMethod(req.Method) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "method must be one of fido2, totp, push, sms, magic_link")
		return
	}

	now := h.store.Now()
	a := Authenticator{
		ID:        "authr_" + uuid.NewString(),
		TenantID:  tenantID,
		UserID:    req.UserID,
		Method:    req.Method,
		Metadata:  req.Metadata,
		Status:    AuthenticatorStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := h.store.PutAuthenticator(a); err != nil {
		h.log.Error("authenticator_put_failed", "err", err, "id", a.ID, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to store authenticator")
		return
	}
	h.log.Info("authenticator_enrolled", "id", a.ID, "user_id", a.UserID, "method", a.Method, "tenant_id", tenantID)
	httpx.WriteJSON(w, http.StatusCreated, a)
}

// List handles GET /v1/authenticators?user_id=... — list authenticators for a user,
// scoped to the request's tenant.
func (h *AuthenticatorHandlers) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
	if userID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "user_id query param is required")
		return
	}
	// The service-to-service contract (ARCHITECTURE.md §4.4) carries tenant_id
	// in the query string as well as the X-Tenant-Id header (which
	// authentication-service's client always forwards). The header — already
	// validated by tenantx.Middleware — stays authoritative; the query param is
	// accepted and cross-checked so a caller can't read tenant A's rows while
	// claiming tenant B in the URL.
	if qt := strings.TrimSpace(r.URL.Query().Get("tenant_id")); qt != "" && qt != tenantID {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "tenant_id query param does not match X-Tenant-Id header")
		return
	}
	items, err := h.store.ListAuthenticators(tenantID, userID)
	if err != nil {
		h.log.Error("authenticator_list_failed", "err", err, "user_id", userID, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to list authenticators")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, ListResponse{Authenticators: items})
}

// Get handles GET /v1/authenticators/{id}.
func (h *AuthenticatorHandlers) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	a, err := h.store.GetAuthenticator(tenantID, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "authenticator not found")
			return
		}
		h.log.Error("authenticator_get_failed", "err", err, "id", id, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to read authenticator")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, a)
}

// Delete handles DELETE /v1/authenticators/{id} as a soft-delete
// (status → `disabled`). Idempotent.
func (h *AuthenticatorHandlers) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	if err := h.store.DisableAuthenticator(tenantID, id); err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "authenticator not found")
			return
		}
		h.log.Error("authenticator_disable_failed", "err", err, "id", id, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to disable authenticator")
		return
	}
	h.log.Info("authenticator_disabled", "id", id, "tenant_id", tenantID)
	w.WriteHeader(http.StatusNoContent)
}
