package internal

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/jwtx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// EvaluationIDPrefix is the standard prefix for newly-minted evaluation ids.
// Keeping the prefix in one place makes it easy to grep server logs and lets
// callers sanity-check ids they receive.
const EvaluationIDPrefix = "rev_"

// PolicyIDPrefix is the equivalent for policy ids.
const PolicyIDPrefix = "pol_"

// Handlers bundles every collaborator a request handler needs. Clock is
// injected so tests can pin "now" — production wiring passes SystemClock{}.
type Handlers struct {
	Store  Storage
	Logger *slog.Logger
	Clock  Clock

	// CAEPVerifier verifies incoming Security Event Tokens against authn's JWKS
	// (caep.go). Nil → the SET receiver returns 503 (not configured).
	CAEPVerifier *jwtx.Verifier
}

// NewHandlers constructs a Handlers value with the given storage and logger,
// using the real clock.
func NewHandlers(store Storage, logger *slog.Logger) *Handlers {
	return &Handlers{Store: store, Logger: logger, Clock: SystemClock{}}
}

// Router builds the complete http.Handler for risk-service.
//
//   - /healthz is unauthenticated.
//   - /v1/* sits behind tenantx.Middleware so every evaluation / policy
//     operation is tenant-scoped.
//   - /internal/v1/* is the same route tree (same handlers) additionally
//     wrapped in httpx.InternalAuth — the service-to-service entry point
//     (ARCHITECTURE.md §10.3). It accepts verified mTLS peers or the
//     X-Internal-Auth shared secret; with neither configured it is open
//     (local dev). /v1/* stays as-is for back-compat with phase-1 callers.
//
// The whole tree is wrapped in Recover + Logging so every request is logged
// and handler panics turn into 500 instead of crashing the process.
func (h *Handlers) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.Health)

	v1 := http.NewServeMux()
	v1.HandleFunc("POST /v1/evaluations", h.CreateEvaluation)
	v1.HandleFunc("GET /v1/evaluations/{id}", h.GetEvaluation)

	v1.HandleFunc("POST /v1/policies", h.CreatePolicy)
	v1.HandleFunc("GET /v1/policies", h.ListPolicies)
	v1.HandleFunc("GET /v1/policies/{id}", h.GetPolicy)
	v1.HandleFunc("PATCH /v1/policies/{id}", h.UpdatePolicy)
	v1.HandleFunc("DELETE /v1/policies/{id}", h.DeletePolicy)

	// /v1/* is tenant-scoped. risk-service is an INTERNAL service: when
	// V1_INTERNAL_ONLY=true (the deployed posture, since Cloud Run ingress is
	// public and gating happens at the app layer) the whole /v1 tree additionally
	// requires the InternalAuth secret — otherwise the evaluate/policy write API
	// would be open to the internet. Mirrors authenticator-service.
	v1Handler := http.Handler(tenantx.Middleware(v1))
	if strings.EqualFold(os.Getenv("V1_INTERNAL_ONLY"), "true") {
		v1Handler = httpx.InternalAuth(h.Logger)(v1Handler)
	}
	mux.Handle("/v1/", v1Handler)

	// Alias: /internal/v1/... → InternalAuth → strip "/internal" → the same
	// tenant-scoped v1 mux. One registration, zero handler duplication.
	mux.Handle("/internal/v1/",
		httpx.InternalAuth(h.Logger)(http.StripPrefix("/internal", tenantx.Middleware(v1))))

	// CAEP SET receiver — internal (service-to-service from authn), NOT tenant-
	// scoped: the tenant + subject come from the verified SET claims. A more
	// specific pattern than /internal/v1/ so it wins the route match.
	mux.Handle("POST /internal/v1/ssf/events",
		httpx.InternalAuth(h.Logger)(http.HandlerFunc(h.ReceiveSET)))

	return httpx.Recover(h.Logger)(httpx.Logging(h.Logger)(mux))
}

// Health is an unauthenticated liveness probe.
func (h *Handlers) Health(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// CreateEvaluation handles POST /v1/evaluations. It runs the four scorers,
// aggregates, derives a tier, applies tenant policies, stores the result
// (even on deny — audit trail), and returns the persisted record.
func (h *Handlers) CreateEvaluation(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	var req EvaluateRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		if errors.Is(err, io.EOF) {
			httpx.WriteError(w, http.StatusBadRequest, "empty_body", "request body required")
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	if strings.TrimSpace(req.UserID) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_user_id", "user_id is required")
		return
	}
	if strings.TrimSpace(req.Action) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_action", "action is required")
		return
	}
	if !ValidSensitivity(req.ResourceSensitivity) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_resource_sensitivity",
			"resource_sensitivity must be one of: low, medium, high")
		return
	}

	// Pipeline: scorers → weighted aggregation → sensitivity overlay → tier.
	// The user scorer reads storage to detect a first high-value action, so
	// this must run *before* we Put the new evaluation.
	signals, score := Aggregate(r.Context(), req, tenantID, h.Store, h.Clock)
	derivedTier := DeriveTier(score)

	// Policy overlay. Matching rules can only raise the tier or deny outright.
	// limit 0 = unbounded: the overlay must see every tenant policy.
	policies, err := h.Store.ListPolicies(tenantID, 0, time.Time{})
	if err != nil {
		h.Logger.Error("risk_policy_list_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to load policies")
		return
	}
	policyResult := EvaluatePolicies(req, derivedTier, policies)

	eval := RiskEvaluation{
		ID:                  EvaluationIDPrefix + uuid.NewString(),
		TenantID:            tenantID,
		UserID:              req.UserID,
		SessionID:           req.SessionID,
		Action:              req.Action,
		Resource:            req.Resource,
		ResourceSensitivity: req.ResourceSensitivity,
		Tier:                policyResult.EffectiveTier,
		Score:               score,
		Signals:             signals,
		Flags:               collectFlags(signals),
		PolicyDecision:      policyResult.Decision,
		MatchedPolicies:     policyResult.MatchedPolicies,
		CreatedAt:           h.Clock.Now(),
	}

	if err := h.Store.PutEvaluation(eval); err != nil {
		h.Logger.Error("risk_evaluation_put_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to persist evaluation")
		return
	}

	httpx.WriteJSON(w, http.StatusCreated, eval)
}

// GetEvaluation handles GET /v1/evaluations/{id}.
func (h *Handlers) GetEvaluation(w http.ResponseWriter, r *http.Request) {
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
	e, err := h.Store.GetEvaluation(tenantID, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "evaluation not found")
			return
		}
		h.Logger.Error("risk_evaluation_get_failed", "err", err, "tenant_id", tenantID, "id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to read evaluation")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, e)
}

// CreatePolicy handles POST /v1/policies.
func (h *Handlers) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	var req CreatePolicyRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		if errors.Is(err, io.EOF) {
			httpx.WriteError(w, http.StatusBadRequest, "empty_body", "request body required")
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > MaxNameLen {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_name", "name must be 1-100 characters")
		return
	}
	if err := ValidateRules(req.Rules); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_rules", err.Error())
		return
	}

	now := h.Clock.Now()
	p := Policy{
		ID:        PolicyIDPrefix + uuid.NewString(),
		TenantID:  tenantID,
		Name:      name,
		Rules:     req.Rules,
		CreatedAt: now,
		UpdatedAt: now,
	}
	saved, err := h.Store.CreatePolicy(p)
	if err != nil {
		h.Logger.Error("risk_policy_create_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to create policy")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, saved)
}

// ListPolicies handles GET /v1/policies. Supports:
//   - limit (int, default 100, max 500)
//   - cursor (RFC3339 timestamp; results are strictly older than this)
func (h *Handlers) ListPolicies(w http.ResponseWriter, r *http.Request) {
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

	items, err := h.Store.ListPolicies(tenantID, limit, cursor)
	if err != nil {
		h.Logger.Error("risk_policy_list_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to list policies")
		return
	}

	resp := ListPoliciesResponse{Items: items}
	// If we returned a full page, provide a cursor for the next page. Callers
	// that do not need pagination can ignore next_cursor.
	if len(items) == limit && limit > 0 {
		resp.NextCursor = items[len(items)-1].CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// GetPolicy handles GET /v1/policies/{id}.
func (h *Handlers) GetPolicy(w http.ResponseWriter, r *http.Request) {
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
	p, err := h.Store.GetPolicy(tenantID, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "policy not found")
			return
		}
		h.Logger.Error("risk_policy_get_failed", "err", err, "tenant_id", tenantID, "id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to read policy")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

// UpdatePolicy handles PATCH /v1/policies/{id}. Only `name` and `rules` are
// mutable; tenant_id and timestamps are handled server-side.
func (h *Handlers) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
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

	var req UpdatePolicyRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		if errors.Is(err, io.EOF) {
			httpx.WriteError(w, http.StatusBadRequest, "empty_body", "request body required")
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	existing, err := h.Store.GetPolicy(tenantID, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "policy not found")
			return
		}
		h.Logger.Error("risk_policy_update_read_failed", "err", err, "tenant_id", tenantID, "id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to read policy")
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
	if req.Rules != nil {
		if err := ValidateRules(*req.Rules); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_rules", err.Error())
			return
		}
		existing.Rules = *req.Rules
	}

	saved, err := h.Store.UpdatePolicy(existing)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "policy not found")
			return
		}
		h.Logger.Error("risk_policy_update_failed", "err", err, "tenant_id", tenantID, "id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to update policy")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, saved)
}

// DeletePolicy handles DELETE /v1/policies/{id}.
func (h *Handlers) DeletePolicy(w http.ResponseWriter, r *http.Request) {
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
	if err := h.Store.DeletePolicy(tenantID, id); err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "policy not found")
			return
		}
		h.Logger.Error("risk_policy_delete_failed", "err", err, "tenant_id", tenantID, "id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to delete policy")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
