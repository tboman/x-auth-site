package internal

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/ratex"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// Handlers serves the id-service HTTP API and the two server-rendered UIs.
type Handlers struct {
	Manager *Manager
	Console *Console
	Logger  *slog.Logger
}

func NewHandlers(mgr *Manager, console *Console, logger *slog.Logger) *Handlers {
	return &Handlers{Manager: mgr, Console: console, Logger: logger}
}

// Router wires every route.
//
//   - /healthz, /v1/jwks, /.well-known/jwks.json — unauthenticated.
//   - /v/{token}, /dashboard — server-rendered UIs (token / OIDC gated).
//   - POST /v1/verifications/{id}/response — consumer/wallet, no tenant header;
//     rate-limited by verification id.
//   - POST /v1/verifications, GET /v1/verifications/{id} — agent API behind the
//     per-tenant rate limiter + tenantx.Middleware.
//
// The whole tree is wrapped in Recover + Logging.
func (h *Handlers) Router(limiter ratex.Allower) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", h.Health)
	mux.HandleFunc("GET /v1/jwks", h.JWKS)
	mux.HandleFunc("GET /.well-known/jwks.json", h.JWKS)

	if h.Console != nil {
		mux.HandleFunc("GET /v/{token}", h.Console.VerifyPage)
		mux.HandleFunc("GET /dashboard", h.Console.Dashboard)
		mux.HandleFunc("GET /", h.Console.Root)
	}

	// Consumer/wallet response: token-bound (no tenant), limited by id.
	mux.Handle("POST /v1/verifications/{id}/response",
		ratex.Middleware(limiter, consumerKey)(http.HandlerFunc(h.PostResponse)))

	// Agent API: per-tenant rate limit + tenant enforcement.
	tenantScoped := func(fn http.HandlerFunc) http.Handler {
		return ratex.Middleware(limiter, rateLimitKey)(tenantx.Middleware(fn))
	}
	mux.Handle("POST /v1/verifications", tenantScoped(h.CreateVerification))
	mux.Handle("GET /v1/verifications/{id}", tenantScoped(h.GetVerification))

	return httpx.Recover(h.Logger)(httpx.Logging(h.Logger)(mux))
}

// Health is an unauthenticated liveness probe that also reports trust posture.
func (h *Handlers) Health(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"trustMode":  h.Manager.TrustMode(),
		"trustRoots": h.Manager.RootCount(),
	})
}

// JWKS publishes the Verified Identity Token signing key.
func (h *Handlers) JWKS(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.Manager.JWKS())
}

// CreateVerification mints a pending verification for the tenant. An empty body
// is allowed and yields mDL defaults.
func (h *Handlers) CreateVerification(w http.ResponseWriter, r *http.Request) {
	tenant, _ := tenantx.FromContext(r.Context())
	var spec VerifyRequestSpec
	if err := httpx.ReadJSON(r, &spec); err != nil && !errors.Is(err, io.EOF) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "malformed json body")
		return
	}
	v, err := h.Manager.CreateVerification(r.Context(), tenant, spec)
	if err != nil {
		h.Logger.Error("create_verification_failed", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "could not create verification")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, CreateResponse{
		ID:        v.ID,
		Status:    v.Status,
		VerifyURL: v.VerifyURL,
		ExpiresAt: v.ExpiresAt,
	})
}

// GetVerification returns the agent-facing view of a verification.
func (h *Handlers) GetVerification(w http.ResponseWriter, r *http.Request) {
	tenant, _ := tenantx.FromContext(r.Context())
	v, err := h.Manager.Get(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "no such verification")
			return
		}
		h.Logger.Error("get_verification_failed", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "lookup failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

// PostResponse accepts a wallet's vp_token (JSON body or OID4VP direct_post form)
// and verifies it. A cryptographic failure returns 200 with status=failed; only
// lookup/state errors map to 4xx.
func (h *Handlers) PostResponse(w http.ResponseWriter, r *http.Request) {
	sub, err := parseSubmission(r)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "could not read vp_token")
		return
	}
	v, err := h.Manager.SubmitResponse(r.Context(), r.PathValue("id"), sub)
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "no such verification")
		return
	case errors.Is(err, errConflict):
		httpx.WriteError(w, http.StatusConflict, "not_pending", "verification is not pending")
		return
	case errors.Is(err, errExpired):
		httpx.WriteError(w, http.StatusGone, "expired", "verification expired")
		return
	case err != nil:
		h.Logger.Error("submit_response_failed", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "could not process response")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, consumerView(v))
}

// consumerView is the trimmed result returned to the user's verify page: enough
// to show success/failure, never the agent's proof token.
func consumerView(v *Verification) map[string]any {
	out := map[string]any{"id": v.ID, "status": v.Status}
	if v.Result != nil {
		res := map[string]any{
			"assurance":     v.Result.Assurance,
			"deviceBound":   v.Result.DeviceBound,
			"issuerTrusted": v.Result.IssuerTrusted,
		}
		if v.Result.FailReason != "" {
			res["failReason"] = v.Result.FailReason
		}
		out["result"] = res
	}
	return out
}

// parseSubmission reads the vp_token from a JSON body or an OID4VP direct_post
// (application/x-www-form-urlencoded) body.
func parseSubmission(r *http.Request) (ResponseSubmission, error) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			return ResponseSubmission{}, err
		}
		vt := r.PostForm.Get("vp_token")
		if vt == "" {
			return ResponseSubmission{}, errors.New("missing vp_token")
		}
		// Form vp_token is either raw JSON or a bare base64 string; normalize to
		// a JSON value for extractDeviceResponse.
		var raw json.RawMessage
		if json.Valid([]byte(vt)) {
			raw = json.RawMessage(vt)
		} else {
			b, _ := json.Marshal(vt)
			raw = b
		}
		return ResponseSubmission{
			VPToken:            raw,
			MDocGeneratedNonce: r.PostForm.Get("mdoc_generated_nonce"),
		}, nil
	}

	var sub ResponseSubmission
	if err := httpx.ReadJSON(r, &sub); err != nil {
		return ResponseSubmission{}, err
	}
	return sub, nil
}

// rateLimitKey keys the agent limiter by tenant + method + endpoint class. A
// missing tenant returns "" (bypass; tenantx then rejects with 400).
func rateLimitKey(r *http.Request) string {
	tenant := r.Header.Get(tenantx.Header)
	if tenant == "" {
		return ""
	}
	return tenant + "|" + r.Method + "|" + endpointClass(r.URL.Path)
}

// consumerKey keys the consumer response limiter by verification id (no tenant
// header is present on these requests).
func consumerKey(r *http.Request) string {
	id := r.PathValue("id")
	if id == "" {
		return ""
	}
	return "consumer|" + id
}

func endpointClass(path string) string {
	segs := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
	if len(segs) > 2 {
		segs = segs[:2]
	}
	return "/" + strings.Join(segs, "/")
}
