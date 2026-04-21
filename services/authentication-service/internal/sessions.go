package internal

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// SessionHandlers implements the tenant-scoped session endpoints under /v1/sessions.
// sessions are created by transaction-service after a successful first-factor
// check; the session id + session TTL is what downstream callers present on every
// subsequent request.
type SessionHandlers struct {
	Store  Storage
	Logger *slog.Logger
}

// Create handles POST /v1/sessions. Body: {user_id, risk_level, step_up_completed}.
//
// transaction-service calls this after it has already verified the user's
// primary credentials with authenticator-service. authentication-service does
// NOT re-verify — we trust the internal caller and mint a fresh session.
// TODO(phase-2): require a service-to-service signed token so a rogue internal
// caller cannot fabricate sessions for arbitrary users.
func (h *SessionHandlers) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	var req CreateSessionRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.UserID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "user_id is required")
		return
	}
	if req.RiskLevel == "" {
		req.RiskLevel = RiskLow
	}
	if !ValidRiskLevel(req.RiskLevel) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "risk_level must be one of low|medium|high")
		return
	}

	// Verify the user exists in this tenant before minting a session — catches
	// typos and stops a rogue caller from creating sessions for users that don't
	// belong to their tenant.
	if _, err := h.Store.GetUser(tenantID, req.UserID); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "user_id not found in tenant")
		return
	}

	now := time.Now().UTC()
	sess := Session{
		ID:              "ses_" + uuid.NewString(),
		TenantID:        tenantID,
		UserID:          req.UserID,
		RiskLevel:       req.RiskLevel,
		StepUpCompleted: req.StepUpCompleted,
		CreatedAt:       now,
		UpdatedAt:       now,
		ExpiresAt:       now.Add(time.Duration(SessionTTLSeconds) * time.Second),
	}
	created, err := h.Store.CreateSession(sess)
	if err != nil {
		h.Logger.Error("session_create_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to create session")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, created)
}

// Get handles GET /v1/sessions/{id}. 404 if missing / wrong tenant.
func (h *SessionHandlers) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}
	id := r.PathValue("id")
	sess, err := h.Store.GetSession(tenantID, id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sess)
}

// Refresh handles POST /v1/sessions/{id}/refresh. Extends expires_at by one TTL
// from *now* (not from the previous expiry) and bumps updated_at. Refusing to
// refresh an already-invalidated session avoids resurrecting revoked sessions.
func (h *SessionHandlers) Refresh(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}
	id := r.PathValue("id")

	sess, err := h.Store.GetSession(tenantID, id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	if sess.InvalidatedAt != nil {
		httpx.WriteError(w, http.StatusConflict, "session_invalidated", "session has been invalidated")
		return
	}

	sess.ExpiresAt = time.Now().UTC().Add(time.Duration(SessionTTLSeconds) * time.Second)
	updated, err := h.Store.UpdateSession(sess)
	if err != nil {
		h.Logger.Error("session_refresh_failed", "err", err, "tenant_id", tenantID, "session_id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to refresh session")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, updated)
}

// Invalidate handles POST /v1/sessions/{id}/invalidate. Idempotent: calling it
// twice is a no-op (still 204).
func (h *SessionHandlers) Invalidate(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}
	id := r.PathValue("id")

	sess, err := h.Store.GetSession(tenantID, id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	if sess.InvalidatedAt != nil {
		// Already invalidated — treat as success.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	now := time.Now().UTC()
	sess.InvalidatedAt = &now
	if _, err := h.Store.UpdateSession(sess); err != nil {
		h.Logger.Error("session_invalidate_failed", "err", err, "tenant_id", tenantID, "session_id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to invalidate session")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Upgrade handles POST /v1/sessions/{id}/upgrade. Called after
// authenticator-service verifies a step-up challenge to flip step_up_completed
// to true and (optionally) lower the risk level. If risk_level is omitted we
// leave whatever the risk-service last classified.
func (h *SessionHandlers) Upgrade(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}
	id := r.PathValue("id")

	var req UpgradeSessionRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	sess, err := h.Store.GetSession(tenantID, id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	if sess.InvalidatedAt != nil {
		httpx.WriteError(w, http.StatusConflict, "session_invalidated", "session has been invalidated")
		return
	}
	if req.RiskLevel != "" {
		if !ValidRiskLevel(req.RiskLevel) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "risk_level must be one of low|medium|high")
			return
		}
		sess.RiskLevel = req.RiskLevel
	}
	sess.StepUpCompleted = req.StepUpCompleted

	updated, err := h.Store.UpdateSession(sess)
	if err != nil {
		h.Logger.Error("session_upgrade_failed", "err", err, "tenant_id", tenantID, "session_id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to upgrade session")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, updated)
}
