package internal

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// ChallengeHandlers wires the challenge dispatch/verify endpoints.
type ChallengeHandlers struct {
	log      *slog.Logger
	store    Storage
	registry *Registry
	limits   Limits
}

// NewChallengeHandlers constructs a handler bundle. registry provides the
// per-method adapters; tests can inject a custom one. limits carries the
// §10.5 layer-3 abuse controls (zero value = disabled).
func NewChallengeHandlers(log *slog.Logger, store Storage, registry *Registry, limits Limits) *ChallengeHandlers {
	return &ChallengeHandlers{log: log, store: store, registry: registry, limits: limits}
}

// Create handles POST /v1/challenges. It picks the caller's most-preferred
// method that the user has an active authenticator for, dispatches via the
// vendor adapter, persists a `pending` challenge, and returns the prompt.
//
// Method selection rules (phase 1):
//  1. Walk req.Methods in the order supplied — caller preference wins.
//  2. For each method, pick the user's oldest `active` authenticator of that
//     method (stable ordering by CreatedAt, then by ID as a tiebreaker).
//  3. The first hit is chosen. If no method in the request list matches any
//     active authenticator, return 409 `no_authenticator_available`.
//
// Rationale: callers that care about a specific method supply only that one;
// risk tiering that accepts any strong factor can pass `["fido2","push","totp"]`
// and let us fall through. Oldest-first prevents surprise on a newly-added
// authenticator while the user is mid-session.
func (h *ChallengeHandlers) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	var req ChallengeRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "malformed json body")
		return
	}
	if strings.TrimSpace(req.UserID) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "user_id is required")
		return
	}
	if len(req.Methods) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "methods must be a non-empty list")
		return
	}
	for _, m := range req.Methods {
		if !IsValidMethod(m) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "unsupported method: "+m)
			return
		}
	}

	// §10.5 layer 3, enforced here in the handler so both the /v1 and
	// /internal/v1 mounts (same handler instances) are covered:
	//  1. account lockout — a locked-out user may not create challenges, and
	//     the check is first so locked traffic doesn't consume limiter slots;
	//  2. per-user challenge-creation rate limit (CHALLENGE_RATE_LIMIT).
	key := abuseKey(tenantID, req.UserID)
	if locked, retryAfter := h.limits.Lockout.Locked(key); locked {
		h.log.Warn("challenge_create_locked_out", "user_id", req.UserID, "tenant_id", tenantID)
		writeAccountLocked(w, retryAfter)
		return
	}
	if ok, retryAfter := allow(h.limits.ChallengeCreate, key); !ok {
		h.log.Warn("challenge_create_rate_limited", "user_id", req.UserID, "tenant_id", tenantID)
		writeRetryAfterError(w, http.StatusTooManyRequests, "rate_limited",
			"challenge creation rate limit exceeded for user", retryAfter)
		return
	}

	active, err := h.store.ListActiveAuthenticators(tenantID, req.UserID)
	if err != nil {
		h.log.Error("challenge_list_authenticators_failed", "err", err, "user_id", req.UserID, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to list authenticators")
		return
	}
	method, authr, ok := selectAuthenticator(req.Methods, active)
	if !ok {
		httpx.WriteError(w, http.StatusConflict, "no_authenticator_available",
			"user has no active authenticator for the requested methods")
		return
	}

	adapter, ok := h.registry.Lookup(method)
	if !ok {
		// IsValidMethod and the registry are populated from the same constant set,
		// so this branch is a programmer error rather than user input.
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "no adapter for method")
		return
	}

	now := h.store.Now()
	chal := Challenge{
		ID:              "ch_" + uuid.NewString(),
		TenantID:        tenantID,
		UserID:          req.UserID,
		Method:          method,
		AuthenticatorID: authr.ID,
		Status:          ChallengeStatusPending,
		CreatedAt:       now,
		ExpiresAt:       now.Add(ChallengeTTL),
	}

	res, err := adapter.Dispatch(r.Context(), chal)
	if err != nil {
		// A user with no enrolled passkey can't be challenged for fido2 — surface
		// it distinctly so the caller runs registration first.
		if errors.Is(err, errNoCredential) {
			httpx.WriteError(w, http.StatusConflict, "no_credential", "user has no credential for this method")
			return
		}
		h.log.Error("adapter_dispatch_failed", "challenge_id", chal.ID, "method", method, "err", err)
		httpx.WriteError(w, http.StatusBadGateway, "dispatch_failed", "adapter failed to dispatch challenge")
		return
	}
	chal.Prompt = res.Prompt
	chal.OptionsJSON = res.Options
	chal.SessionData = res.SessionData
	if err := h.store.PutChallenge(chal); err != nil {
		h.log.Error("challenge_put_failed", "err", err, "challenge_id", chal.ID, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to store challenge")
		return
	}
	h.log.Info("challenge_dispatched",
		"challenge_id", chal.ID,
		"method", method,
		"authenticator_id", authr.ID,
		"user_id", req.UserID,
		"tenant_id", tenantID,
	)

	httpx.WriteJSON(w, http.StatusCreated, ChallengeDispatched{
		ChallengeID: chal.ID,
		Method:      chal.Method,
		Prompt:      chal.Prompt,
		ExpiresAt:   chal.ExpiresAt,
		Options:     json.RawMessage(chal.OptionsJSON),
	})
}

// Get handles GET /v1/challenges/{id}. Returns the current state (including
// attempt counter and lifecycle status) without advancing it. Note that a
// challenge whose expires_at has passed is reported with its stored status
// (often `pending`) — status is only flipped to `expired` on a verify call.
// This is intentional for phase 1; a real deployment would run a sweeper.
func (h *ChallengeHandlers) Get(w http.ResponseWriter, r *http.Request) {
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
	c, err := h.store.GetChallenge(tenantID, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "challenge not found")
			return
		}
		h.log.Error("challenge_get_failed", "err", err, "challenge_id", id, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to read challenge")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

// Verify handles POST /v1/challenges/{id}/verify.
//
// Lifecycle:
//   - `pending` + not expired → call adapter.Verify. On success mark
//     `completed`. On failure increment `attempts`; if that lands ≥
//     MaxChallengeAttempts mark `failed`.
//   - `pending` + expired → mark `expired`, return 410.
//   - Terminal states (`completed`, `failed`, `expired`) → 410 immediately.
func (h *ChallengeHandlers) Verify(w http.ResponseWriter, r *http.Request) {
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
	var req VerifyRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "malformed json body")
		return
	}

	c, err := h.store.GetChallenge(tenantID, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "challenge not found")
			return
		}
		h.log.Error("challenge_get_failed", "err", err, "challenge_id", id, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to read challenge")
		return
	}

	// §10.5 layer 3: account lockout trumps every other state — a locked-out
	// user can neither probe nor verify any challenge until the failure
	// window slides.
	lockKey := abuseKey(tenantID, c.UserID)
	if locked, retryAfter := h.limits.Lockout.Locked(lockKey); locked {
		h.log.Warn("challenge_verify_locked_out", "challenge_id", id, "user_id", c.UserID, "tenant_id", tenantID)
		writeAccountLocked(w, retryAfter)
		return
	}

	// Terminal states short-circuit before any adapter work. A previously
	// expired challenge is still reported as `gone`.
	if c.Status != ChallengeStatusPending {
		httpx.WriteError(w, http.StatusGone, "challenge_closed",
			"challenge is "+c.Status+" and cannot be verified")
		return
	}

	// Lazy expiry: we flip `pending` → `expired` the first time a stale
	// challenge is touched (the background sweeper purges stale rows too, but
	// the lazy flip keeps a verify between sweeps correct). If persisting the
	// flip fails we still answer 410 — the challenge IS expired regardless, the
	// flip is idempotent bookkeeping a later verify or sweep will redo.
	if !h.store.Now().Before(c.ExpiresAt) {
		if _, err := h.store.UpdateChallenge(tenantID, id, func(ch *Challenge) {
			ch.Status = ChallengeStatusExpired
		}); err != nil {
			h.log.Error("challenge_expire_flip_failed", "err", err, "challenge_id", id, "tenant_id", tenantID)
		}
		httpx.WriteError(w, http.StatusGone, "challenge_expired", "challenge has expired")
		return
	}

	// §10.5 layer 3: exponential backoff after failed verifications — the
	// challenge may not be retried until 2^attempts seconds after the last
	// failed attempt. A premature retry is rejected BEFORE the adapter runs,
	// so it does not consume an attempt.
	if wait := backoffRemaining(c, h.store.Now()); wait > 0 {
		h.log.Warn("challenge_verify_backoff", "challenge_id", id, "attempts", c.Attempts, "tenant_id", tenantID)
		writeRetryAfterError(w, http.StatusTooManyRequests, "retry_backoff",
			"verification retried too soon after a failed attempt", wait)
		return
	}

	adapter, ok := h.registry.Lookup(c.Method)
	if !ok {
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "no adapter for method")
		return
	}

	res, err := adapter.Verify(r.Context(), c, req.Response)
	if err != nil {
		h.log.Error("adapter_verify_failed", "challenge_id", c.ID, "method", c.Method, "err", err)
		httpx.WriteError(w, http.StatusBadGateway, "verify_failed", "adapter failed to verify")
		return
	}
	verified := res.OK

	updated, err := h.store.UpdateChallenge(tenantID, id, func(ch *Challenge) {
		if verified {
			ch.Status = ChallengeStatusCompleted
			t := h.store.Now()
			ch.CompletedAt = &t
			return
		}
		ch.Attempts++
		// Stamp the failure time for the exponential-backoff window
		// (§10.5 layer 3 — see backoffRemaining).
		t := h.store.Now()
		ch.LastAttemptAt = &t
		if ch.Attempts >= MaxChallengeAttempts {
			ch.Status = ChallengeStatusFailed
		}
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Extremely unlikely — challenge was in the store a moment ago.
			httpx.WriteError(w, http.StatusNotFound, "not_found", "challenge not found")
			return
		}
		// The attempt counter / terminal status failed to persist — we must not
		// report a verification result that isn't on record.
		h.log.Error("challenge_update_failed", "err", err, "challenge_id", id, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to update challenge")
		return
	}

	// Count the failure toward the cross-challenge account lockout (§10.5
	// layer 3) only after it is on record.
	if !verified {
		h.limits.Lockout.RecordFailure(lockKey)
	}

	h.log.Info("challenge_verified",
		"challenge_id", updated.ID,
		"method", updated.Method,
		"verified", verified,
		"attempts", updated.Attempts,
		"status", updated.Status,
	)

	resp := VerifyResponse{Verified: verified}
	if verified {
		resp.AuthenticatorID = updated.AuthenticatorID
		resp.AMR = res.AMR
	} else {
		if updated.Status == ChallengeStatusFailed {
			resp.Reason = "max_attempts_exceeded"
		} else {
			resp.Reason = "invalid_response"
		}
	}
	status := http.StatusOK
	if !verified {
		status = http.StatusUnauthorized
	}
	httpx.WriteJSON(w, status, resp)
}

// selectAuthenticator implements the method-selection rule described on Create.
// Exposed to the package (not exported) so handlers_test.go can exercise it
// directly without going through HTTP.
func selectAuthenticator(preferred []string, active []Authenticator) (string, Authenticator, bool) {
	// Bucket active authenticators by method for O(1) lookup.
	byMethod := make(map[string][]Authenticator, len(active))
	for _, a := range active {
		byMethod[a.Method] = append(byMethod[a.Method], a)
	}
	for _, m := range preferred {
		candidates := byMethod[m]
		if len(candidates) == 0 {
			continue
		}
		// Deterministic "oldest first" ordering so the same inputs always
		// select the same authenticator.
		best := candidates[0]
		for _, c := range candidates[1:] {
			if c.CreatedAt.Before(best.CreatedAt) ||
				(c.CreatedAt.Equal(best.CreatedAt) && c.ID < best.ID) {
				best = c
			}
		}
		return m, best, true
	}
	return "", Authenticator{}, false
}
