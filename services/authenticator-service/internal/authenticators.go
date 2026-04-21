package internal

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// AuthenticatorHandlers wires authenticator-CRUD endpoints onto a Store.
type AuthenticatorHandlers struct {
	log   *slog.Logger
	store *Store
}

// NewAuthenticatorHandlers constructs a handler bundle.
func NewAuthenticatorHandlers(log *slog.Logger, store *Store) *AuthenticatorHandlers {
	return &AuthenticatorHandlers{log: log, store: store}
}

// Enroll handles POST /v1/authenticators — register a new authenticator for a user.
func (h *AuthenticatorHandlers) Enroll(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := tenantx.FromContext(r.Context())

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
	h.store.PutAuthenticator(a)
	h.log.Info("authenticator_enrolled", "id", a.ID, "user_id", a.UserID, "method", a.Method, "tenant_id", tenantID)
	httpx.WriteJSON(w, http.StatusCreated, a)
}

// List handles GET /v1/authenticators?user_id=... — list authenticators for a user,
// scoped to the request's tenant.
func (h *AuthenticatorHandlers) List(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := tenantx.FromContext(r.Context())

	userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
	if userID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "user_id query param is required")
		return
	}
	items := h.store.ListAuthenticators(tenantID, userID)
	httpx.WriteJSON(w, http.StatusOK, ListResponse{Items: items})
}

// Get handles GET /v1/authenticators/{id}.
func (h *AuthenticatorHandlers) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := tenantx.FromContext(r.Context())

	id := r.PathValue("id")
	if id == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	a, err := h.store.GetAuthenticator(tenantID, id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "authenticator not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, a)
}

// Delete handles DELETE /v1/authenticators/{id} as a soft-delete
// (status → `disabled`). Idempotent.
func (h *AuthenticatorHandlers) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := tenantx.FromContext(r.Context())

	id := r.PathValue("id")
	if id == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	if err := h.store.DisableAuthenticator(tenantID, id); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "authenticator not found")
		return
	}
	h.log.Info("authenticator_disabled", "id", id, "tenant_id", tenantID)
	w.WriteHeader(http.StatusNoContent)
}
