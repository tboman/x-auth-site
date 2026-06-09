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

// Handlers groups the grant-service HTTP handlers and their dependencies.
type Handlers struct {
	Grants GrantStore
	Audit  AuditStore
	Logger *slog.Logger
	// Now returns the current time; overridable from tests. Defaults to time.Now in UTC.
	Now func() time.Time
}

// NewHandlers constructs a Handlers with the given stores and logger. Now defaults to
// time.Now().UTC.
func NewHandlers(grants GrantStore, audit AuditStore, logger *slog.Logger) *Handlers {
	return &Handlers{
		Grants: grants,
		Audit:  audit,
		Logger: logger,
		Now:    func() time.Time { return time.Now().UTC() },
	}
}

// Router builds an http.Handler wiring every route for the grant-service.
// /healthz is served without tenant enforcement; /v1/* sits behind tenantx.Middleware.
// The whole tree is wrapped in Recover + Logging.
func (h *Handlers) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.Health)

	v1 := http.NewServeMux()
	v1.HandleFunc("POST /v1/grants", h.CreateGrant)
	v1.HandleFunc("GET /v1/grants/{id}", h.GetGrant)
	v1.HandleFunc("POST /v1/grants/{id}/revoke", h.RevokeGrant)
	v1.HandleFunc("POST /v1/installs/{install_id}/revoke-grants", h.RevokeGrantsForInstall)
	v1.HandleFunc("POST /v1/introspect", h.Introspect)
	v1.HandleFunc("POST /v1/audit", h.AppendAudit)
	v1.HandleFunc("GET /v1/audit", h.QueryAudit)

	mux.Handle("/v1/", tenantx.Middleware(v1))

	return httpx.Recover(h.Logger)(httpx.Logging(h.Logger)(mux))
}

// Health is an unauthenticated liveness probe.
func (h *Handlers) Health(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// CreateGrant handles POST /v1/grants. Token hashes arrive pre-computed (SHA-256 hex,
// matching HashToken's format) per REQUIREMENTS.md §4, so plaintext bearer tokens never
// reach this service on the create path. Also emits a `grant_issued` audit event so the
// install lifecycle has a record even if the caller forgets to post its own.
func (h *Handlers) CreateGrant(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	var req CreateGrantRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		if errors.Is(err, io.EOF) {
			httpx.WriteError(w, http.StatusBadRequest, "empty_body", "request body required")
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	installID := strings.TrimSpace(req.InstallID)
	identityID := strings.TrimSpace(req.IdentityID)
	personaID := strings.TrimSpace(req.PersonaID)
	if installID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_install_id", "install_id is required")
		return
	}
	if identityID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_identity_id", "identity_id is required")
		return
	}
	if personaID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_persona_id", "persona_id is required")
		return
	}
	accessHash := strings.TrimSpace(req.AccessTokenHash)
	refreshHash := strings.TrimSpace(req.RefreshTokenHash)
	if !isTokenHash(accessHash) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_access_token_hash",
			"access_token_hash must be a 64-char SHA-256 hex digest")
		return
	}
	if refreshHash != "" && !isTokenHash(refreshHash) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_refresh_token_hash",
			"refresh_token_hash must be empty or a 64-char SHA-256 hex digest")
		return
	}

	ttl := req.TTLSeconds
	if ttl == 0 {
		ttl = DefaultTTLSeconds
	}
	if ttl <= 0 || ttl > MaxTTLSeconds {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_ttl_seconds",
			"ttl_seconds must be between 1 and 86400")
		return
	}

	now := h.Now()
	g := Grant{
		ID:               uuid.NewString(),
		TenantID:         tenantID,
		InstallID:        installID,
		IdentityID:       identityID,
		PersonaID:        personaID,
		AccessTokenHash:  accessHash,
		RefreshTokenHash: refreshHash,
		IssuedAt:         now,
		ExpiresAt:        now.Add(time.Duration(ttl) * time.Second),
	}

	saved, err := h.Grants.Create(g)
	if err != nil {
		h.Logger.Error("grant_create_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to create grant")
		return
	}
	saved.Status = DeriveStatus(saved, now)

	// Emit grant_issued audit entry. Failure here is logged but does not fail the grant
	// creation — the grant is already persisted, and phase 2 will put this behind a
	// transaction with the same storage backend.
	if _, auditErr := h.Audit.Append(AuditEvent{
		ID:        uuid.NewString(),
		TenantID:  tenantID,
		Type:      "grant_issued",
		Actor:     "system",
		InstallID: installID,
		GrantID:   saved.ID,
		Payload: map[string]any{
			"persona_id":  personaID,
			"identity_id": identityID,
			"expires_at":  saved.ExpiresAt,
		},
		CreatedAt: now,
	}); auditErr != nil {
		h.Logger.Error("grant_issued_audit_failed", "err", auditErr, "grant_id", saved.ID)
	}

	httpx.WriteJSON(w, http.StatusCreated, saved)
}

// GetGrant handles GET /v1/grants/{id}.
func (h *Handlers) GetGrant(w http.ResponseWriter, r *http.Request) {
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
	g, err := h.Grants.Get(tenantID, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "grant not found")
			return
		}
		h.Logger.Error("grant_get_failed", "err", err, "tenant_id", tenantID, "id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to read grant")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, g)
}

// RevokeGrant handles POST /v1/grants/{id}/revoke. Idempotent: a second revoke on an
// already-revoked grant is a successful no-op. Emits `grant_revoked` on the *first*
// revoke only to keep the log free of dup entries for retries.
func (h *Handlers) RevokeGrant(w http.ResponseWriter, r *http.Request) {
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

	now := h.Now()
	g, alreadyRevoked, err := h.Grants.Revoke(tenantID, id, now)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "grant not found")
			return
		}
		h.Logger.Error("grant_revoke_failed", "err", err, "tenant_id", tenantID, "id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to revoke grant")
		return
	}

	if !alreadyRevoked {
		if _, auditErr := h.Audit.Append(AuditEvent{
			ID:        uuid.NewString(),
			TenantID:  tenantID,
			Type:      "grant_revoked",
			Actor:     "system",
			InstallID: g.InstallID,
			GrantID:   g.ID,
			CreatedAt: now,
		}); auditErr != nil {
			h.Logger.Error("grant_revoked_audit_failed", "err", auditErr, "grant_id", g.ID)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// RevokeGrantsForInstall handles POST /v1/installs/{install_id}/revoke-grants.
// Cascades install revocation: finds every grant bound to the install in this tenant
// and revokes each one. Idempotent — already-revoked grants are counted but don't
// re-emit `grant_revoked` audit events. Returns 200 with a summary body so broker-service
// (the typical caller) can log what actually happened.
func (h *Handlers) RevokeGrantsForInstall(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}
	installID := r.PathValue("install_id")
	if installID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_install_id", "install_id is required")
		return
	}

	now := h.Now()
	grants, err := h.Grants.ListByInstall(tenantID, installID)
	if err != nil {
		h.Logger.Error("list_by_install_failed", "err", err, "tenant_id", tenantID, "install_id", installID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to list grants")
		return
	}

	revoked := 0
	alreadyRevokedCount := 0
	for _, g := range grants {
		updated, alreadyRevoked, err := h.Grants.Revoke(tenantID, g.ID, now)
		if err != nil {
			// Only ErrNotFound is plausible (race with a concurrent revoke); skip and keep going.
			h.Logger.Warn("cascade_revoke_skipped", "grant_id", g.ID, "err", err)
			continue
		}
		if alreadyRevoked {
			alreadyRevokedCount++
			continue
		}
		revoked++
		if _, auditErr := h.Audit.Append(AuditEvent{
			ID:        uuid.NewString(),
			TenantID:  tenantID,
			Type:      "grant_revoked",
			Actor:     "system",
			InstallID: updated.InstallID,
			GrantID:   updated.ID,
			Payload:   map[string]any{"cause": "install_revoked"},
			CreatedAt: now,
		}); auditErr != nil {
			h.Logger.Error("cascade_revoke_audit_failed", "err", auditErr, "grant_id", updated.ID)
		}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"install_id":      installID,
		"total":           len(grants),
		"revoked":         revoked,
		"already_revoked": alreadyRevokedCount,
	})
}

// Introspect handles POST /v1/introspect (RFC 7662).
//
// Tenancy note: RFC 7662 does not require the caller to know the tenant that issued
// the token — the whole point of introspection is to resolve an opaque token. We still
// require X-Tenant-Id so the endpoint sits behind the same middleware as the rest of
// the API, but we only return `active: true` if the resolved grant belongs to that
// tenant. A token belonging to tenant B presented with tenant A's header answers
// `active: false` — leaking no details of the other tenant's grant.
func (h *Handlers) Introspect(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	var req IntrospectRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		if errors.Is(err, io.EOF) {
			httpx.WriteError(w, http.StatusBadRequest, "empty_body", "request body required")
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	token := strings.TrimSpace(req.Token)
	if token == "" {
		// RFC 7662 §2.2: introspection endpoint MUST NOT disclose information about
		// tokens. An empty token is always inactive.
		httpx.WriteJSON(w, http.StatusOK, IntrospectResponse{Active: false})
		return
	}

	hash := HashToken(token)
	g, err := h.Grants.FindByAccessTokenHash(hash)
	if err != nil {
		// Unknown token — always "inactive", never 404.
		httpx.WriteJSON(w, http.StatusOK, IntrospectResponse{Active: false})
		return
	}

	if g.TenantID != tenantID {
		httpx.WriteJSON(w, http.StatusOK, IntrospectResponse{Active: false})
		return
	}

	status := DeriveStatus(g, h.Now())
	if status != StatusActive {
		httpx.WriteJSON(w, http.StatusOK, IntrospectResponse{Active: false})
		return
	}

	httpx.WriteJSON(w, http.StatusOK, IntrospectResponse{
		Active:     true,
		InstallID:  g.InstallID,
		IdentityID: g.IdentityID,
		PersonaID:  g.PersonaID,
		TenantID:   g.TenantID,
		IssuedAt:   g.IssuedAt.Unix(),
		ExpiresAt:  g.ExpiresAt.Unix(),
	})
}

// AppendAudit handles POST /v1/audit. Accepts arbitrary event types from callers;
// the schema is intentionally open so sister services can emit their own lifecycle
// events (install_created, persona_bound, identity_released, …) without this service
// needing to know the full enum.
func (h *Handlers) AppendAudit(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	var req AppendAuditRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		if errors.Is(err, io.EOF) {
			httpx.WriteError(w, http.StatusBadRequest, "empty_body", "request body required")
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	typ := strings.TrimSpace(req.Type)
	actor := strings.TrimSpace(req.Actor)
	if typ == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_type", "type is required")
		return
	}
	if actor == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_actor", "actor is required")
		return
	}

	e := AuditEvent{
		ID:        uuid.NewString(),
		TenantID:  tenantID,
		Type:      typ,
		Actor:     actor,
		InstallID: strings.TrimSpace(req.InstallID),
		GrantID:   strings.TrimSpace(req.GrantID),
		Payload:   req.Payload,
		CreatedAt: h.Now(),
	}
	saved, err := h.Audit.Append(e)
	if err != nil {
		h.Logger.Error("audit_append_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to append audit event")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, saved)
}

// QueryAudit handles GET /v1/audit. Tenant-scoped; supports install/grant/type/since/until/limit.
func (h *Handlers) QueryAudit(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	f, errCode := parseAuditFilter(r.URL.Query())
	if errCode != "" {
		httpx.WriteError(w, http.StatusBadRequest, errCode, "invalid query parameter")
		return
	}

	items, err := h.Audit.Query(tenantID, f)
	if err != nil {
		h.Logger.Error("audit_query_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to query audit log")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, AuditListResponse{Items: items})
}
