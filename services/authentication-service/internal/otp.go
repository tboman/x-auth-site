package internal

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// Step-up interludes for /authorize (ARCHITECTURE.md §4.4 challenge flow).
//
// A client opts in with the standard OIDC `acr_values` parameter:
//
//	GET /authorize?...&acr_values=urn:xauth:otp:sms
//	GET /authorize?...&acr_values=urn:xauth:fido2
//
// Instead of minting a code immediately, /authorize creates a challenge on
// authenticator-service (stub adapters today — SMS accepts the hard-coded
// 123456; FIDO2 accepts the stub assertion signature), parks the authorize
// request under a one-time flow id, and serves a minimal hosted verification
// page. POST /authorize/verify proxies the response to authenticator-service
// (which enforces attempts, backoff, and lockout) and, on success, mints the
// authorization code with `acr` + `amr` recorded — the token mint stamps them
// into the ID token and marks the session step_up_completed.
//
// Parked flows live in process memory with a TTL, like the social-login
// handshake state: single replica, or a shared store before scaling out.

// Authentication context class references clients put in acr_values and
// relying apps check in the ID token's acr claim.
const (
	// ACRSMSOTP — SMS one-time code interlude.
	ACRSMSOTP = "urn:xauth:otp:sms"
	// ACRFIDO2 — FIDO2/WebAuthn assertion interlude. The stub ceremony proves
	// possession of a software key without user verification, so the amr is
	// ["user","swk"]; UV-required and device-bound tiers (urn:xauth:fido2:uv,
	// :uv:hw) arrive with the real webauthn adapter.
	ACRFIDO2 = "urn:xauth:fido2"
)

// stepUpSpec ties one advertised acr value to the authenticator-service
// method that satisfies it and the RFC 8176 amr values stamped on success.
type stepUpSpec struct {
	ACR    string
	Method string   // authenticator-service method name
	AMR    []string // RFC 8176 values for the ID token's amr claim
	// AutoEnrollMetadata seeds the stub authenticator created for users with
	// nothing enrolled (mock-stage convenience; real deployments enroll
	// through a proper registration journey).
	AutoEnrollMetadata map[string]any
	// ResponseField names the key authenticator-service's adapter expects the
	// submitted form value under ("code" for OTP digits, "signature" for the
	// stub WebAuthn assertion).
	ResponseField string
	// RetryError is the message shown on the re-rendered page after a wrong
	// response that has not gone terminal.
	RetryError string
}

var stepUpSpecs = []stepUpSpec{
	{
		ACR:                ACRSMSOTP,
		Method:             "sms",
		AMR:                []string{"otp", "sms"},
		AutoEnrollMetadata: map[string]any{"phone_number": "+15551234", "enrolled_by": "authorize-otp-stub"},
		ResponseField:      "code",
		RetryError:         "Incorrect code — try again.",
	},
	{
		ACR:                ACRFIDO2,
		Method:             "fido2",
		AMR:                []string{"user", "swk"},
		AutoEnrollMetadata: map[string]any{"credential_id": "stub-credential", "enrolled_by": "authorize-fido2-stub"},
		ResponseField:      "signature",
		RetryError:         "Assertion rejected — try again.",
	},
}

// matchStepUp returns the first requested acr value this server supports.
// acr_values is space-delimited and ordered by client preference (OIDC Core
// §3.1.2.1), so iteration order follows the request, not stepUpSpecs.
func matchStepUp(acrValues string) (stepUpSpec, bool) {
	for _, want := range strings.Fields(acrValues) {
		for _, spec := range stepUpSpecs {
			if spec.ACR == want {
				return spec, true
			}
		}
	}
	return stepUpSpec{}, false
}

// specForMethod resolves a parked flow's method back to its spec.
func specForMethod(method string) (stepUpSpec, bool) {
	for _, spec := range stepUpSpecs {
		if spec.Method == method {
			return spec, true
		}
	}
	return stepUpSpec{}, false
}

// supportedACRValues feeds discovery's acr_values_supported: the method-specific
// step-up ACRs plus the protection-level ACRs (protection.go).
func supportedACRValues() []string {
	out := make([]string, 0, len(stepUpSpecs)+len(protectionLevels))
	for _, spec := range stepUpSpecs {
		out = append(out, spec.ACR)
	}
	out = append(out, protectionACRs()...)
	return out
}

const otpFlowTTL = 10 * time.Minute

// pendingAuthorize parks a validated /authorize request while the user
// completes the step-up challenge.
type pendingAuthorize struct {
	ClientID      string
	TenantID      string
	UserID        string
	RedirectURI   string
	Scope         string
	State         string
	Nonce         string
	CodeChallenge string
	ChallengeID   string
	Prompt        string
	Method        string // authenticator-service method; resolves the stepUpSpec on verify
	CreatedAt     time.Time

	// Protection-level fields (protection.go). When the flow was triggered by a
	// protection-level request, TargetACR overrides the method spec's ACR on the
	// minted token, and a successful verify records TargetRank against
	// AuthzSessionID in the assurance ledger. Empty/zero for plain method
	// (acr_values=urn:xauth:otp:sms) step-ups.
	TargetACR      string
	TargetRank     int
	AuthzSessionID string
}

func (h *OIDCHandlers) storeFlow(id string, p pendingAuthorize) {
	h.flowOnce.Do(func() { h.flows = make(map[string]pendingAuthorize) })
	h.flowMu.Lock()
	defer h.flowMu.Unlock()
	cutoff := time.Now().UTC().Add(-otpFlowTTL)
	for k, v := range h.flows {
		if v.CreatedAt.Before(cutoff) {
			delete(h.flows, k)
		}
	}
	h.flows[id] = p
}

// peekFlow returns a live flow without consuming it — wrong-code retries
// re-use the same flow until the challenge goes terminal.
func (h *OIDCHandlers) peekFlow(id string) (pendingAuthorize, bool) {
	h.flowOnce.Do(func() { h.flows = make(map[string]pendingAuthorize) })
	h.flowMu.Lock()
	defer h.flowMu.Unlock()
	p, ok := h.flows[id]
	if !ok || time.Since(p.CreatedAt) > otpFlowTTL {
		delete(h.flows, id)
		return pendingAuthorize{}, false
	}
	return p, true
}

func (h *OIDCHandlers) dropFlow(id string) {
	h.flowMu.Lock()
	delete(h.flows, id)
	h.flowMu.Unlock()
	// Also clear the live-step-up mirror so the consoles stop showing it.
	h.StepUps.Done(id)
}

// startStepUpFlow runs the interlude setup for the matched spec: make sure
// the user has a usable authenticator for the method (auto-enrolling a stub
// one if not), dispatch a challenge, park the authorize request, and serve
// the hosted verification page.
func (h *OIDCHandlers) startStepUpFlow(w http.ResponseWriter, r *http.Request, spec stepUpSpec, p pendingAuthorize) {
	ctx := r.Context()

	// Ensure an enrolled, usable authenticator. Mock-stage convenience:
	// auto-enroll a stub one so any user can exercise the flow; a real
	// deployment replaces this with a proper enrollment journey.
	auths, err := h.Authenticator.ListAuthenticators(ctx, p.TenantID, p.UserID)
	if err != nil {
		h.Logger.Error("stepup_list_authenticators_failed", "err", err, "user_id", p.UserID, "method", spec.Method)
		httpx.WriteError(w, http.StatusBadGateway, "authenticator_unavailable", "could not reach authenticator service")
		return
	}
	enrolled := false
	for _, a := range auths {
		if a.Method == spec.Method && a.Status != "disabled" {
			enrolled = true
			break
		}
	}
	if !enrolled {
		if _, err := h.Authenticator.EnrollAuthenticator(ctx, p.TenantID, p.UserID, spec.Method, spec.AutoEnrollMetadata); err != nil {
			h.Logger.Error("stepup_auto_enroll_failed", "err", err, "user_id", p.UserID, "method", spec.Method)
			httpx.WriteError(w, http.StatusBadGateway, "authenticator_unavailable", "could not enroll "+spec.Method+" authenticator")
			return
		}
	}

	chal, err := h.Authenticator.CreateChallenge(ctx, p.TenantID, p.UserID, []string{spec.Method})
	if err != nil {
		h.Logger.Error("stepup_challenge_create_failed", "err", err, "user_id", p.UserID, "method", spec.Method)
		httpx.WriteError(w, http.StatusBadGateway, "authenticator_unavailable", "could not create "+spec.Method+" challenge")
		return
	}

	p.ChallengeID = chal.ChallengeID
	p.Prompt = chal.Prompt
	p.Method = spec.Method
	p.CreatedAt = time.Now().UTC()
	flowID := uuid.NewString()
	h.storeFlow(flowID, p)
	h.StepUps.Start(StepUpAttempt{
		FlowID: flowID, TenantID: p.TenantID, UserID: p.UserID, Method: spec.Method, StartedAt: p.CreatedAt,
	})

	h.Logger.Info("stepup_flow_started", "flow_id", flowID, "challenge_id", chal.ChallengeID,
		"user_id", p.UserID, "tenant_id", p.TenantID, "method", spec.Method)
	h.renderOTPForm(w, http.StatusOK, otpFormData{FlowID: flowID, Prompt: chal.Prompt, Method: spec.Method})
}

// AuthorizeVerify handles POST /authorize/verify — the hosted verification
// page's submission for any step-up method.
func (h *OIDCHandlers) AuthorizeVerify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "could not parse form body")
		return
	}
	flowID := r.PostForm.Get("flow")
	code := r.PostForm.Get("code")
	if flowID == "" || code == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "flow and code are required")
		return
	}
	flow, ok := h.peekFlow(flowID)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "flow is invalid or expired — restart the login")
		return
	}
	spec, ok := specForMethod(flow.Method)
	if !ok {
		// Unreachable unless a flow was parked by a spec that no longer
		// exists (binary downgrade mid-flow). Treat as an expired flow.
		h.dropFlow(flowID)
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "flow is invalid or expired — restart the login")
		return
	}

	outcome, err := h.Authenticator.VerifyChallenge(r.Context(), flow.TenantID, flow.ChallengeID,
		map[string]any{spec.ResponseField: code})
	if err != nil {
		var de *DownstreamError
		switch {
		case errors.As(err, &de) && de.Status == http.StatusGone:
			// Challenge terminal (expired / max attempts) — the flow is dead.
			h.dropFlow(flowID)
			httpx.WriteError(w, http.StatusBadRequest, "challenge_closed",
				"the verification challenge has expired or failed — restart the login")
		case errors.As(err, &de) && de.Status == http.StatusTooManyRequests:
			h.renderOTPForm(w, http.StatusTooManyRequests, otpFormData{
				FlowID: flowID, Prompt: flow.Prompt, Method: flow.Method,
				Error: "Too many attempts — wait a moment and try again.",
			})
		default:
			h.Logger.Error("otp_verify_failed", "err", err, "flow_id", flowID)
			httpx.WriteError(w, http.StatusBadGateway, "authenticator_unavailable", "could not verify the code")
		}
		return
	}

	if !outcome.Verified {
		if outcome.Reason == "max_attempts_exceeded" {
			h.dropFlow(flowID)
			httpx.WriteError(w, http.StatusBadRequest, "challenge_closed",
				"too many incorrect codes — restart the login")
			return
		}
		h.renderOTPForm(w, http.StatusUnauthorized, otpFormData{
			FlowID: flowID, Prompt: flow.Prompt, Method: flow.Method,
			Error: spec.RetryError,
		})
		return
	}

	h.dropFlow(flowID)
	h.Logger.Info("stepup_flow_completed", "flow_id", flowID, "challenge_id", flow.ChallengeID,
		"user_id", flow.UserID, "tenant_id", flow.TenantID, "method", flow.Method)

	// A protection-level flow stamps the requested level as the token's acr (the
	// method's own ACR is the fallback for plain method step-ups) and records the
	// satisfied rank so later equal-or-lower requests pass through.
	acr := spec.ACR
	if flow.TargetACR != "" {
		acr = flow.TargetACR
	}
	if flow.TargetRank > 0 {
		h.Protection.Record(flow.AuthzSessionID, flow.TargetRank)
	}
	h.mintCodeAndRedirect(w, r, AuthCode{
		ClientID:      flow.ClientID,
		TenantID:      flow.TenantID,
		UserID:        flow.UserID,
		RedirectURI:   flow.RedirectURI,
		Scope:         flow.Scope,
		State:         flow.State,
		Nonce:         flow.Nonce,
		CodeChallenge: flow.CodeChallenge,
		ACR:           acr,
		AMR:           spec.AMR,
	})
}

// otpFormData feeds the verification page template. Method selects the
// ceremony block: "fido2" renders the stub-assertion button, anything else
// renders the code input.
type otpFormData struct {
	FlowID string
	Prompt string
	Error  string
	Method string
}

// otpFormTmpl is the minimal hosted verification page. Brand-consistent with
// the marketing site's dark theme; no JavaScript required.
var otpFormTmpl = template.Must(template.New("otp").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verify your identity — X-Auth</title>
<style>
  body { background:#09090b; color:#dddde4; font-family:system-ui,sans-serif;
         display:grid; place-items:center; min-height:100vh; margin:0 }
  .card { background:rgba(18,18,22,.85); border:1px solid rgba(255,255,255,.07);
          border-radius:12px; padding:2.5rem; max-width:24rem; text-align:center }
  h1 { font-size:1.1rem; margin:0 0 .75rem }
  p  { color:#7c7c8a; font-size:.9rem; margin:0 0 1.5rem }
  .err { color:#f04040; font-size:.85rem; margin:0 0 1rem }
  input[type=text] { width:100%; box-sizing:border-box; background:#0c0c10; color:#dddde4;
          border:1px solid rgba(255,255,255,.12); border-radius:6px; padding:.7rem 1rem;
          font-size:1.2rem; text-align:center; letter-spacing:.5em; font-family:monospace }
  button { width:100%; margin-top:1rem; background:#00e096; color:#000; font-weight:700;
           border:0; border-radius:6px; padding:.8rem; font-size:1rem; cursor:pointer }
</style>
</head>
<body>
<div class="card">
  {{if eq .Method "fido2"}}<h1>Confirm with your passkey</h1>{{else}}<h1>Enter verification code</h1>{{end}}
  <p>{{.Prompt}}</p>
  {{if .Error}}<p class="err">{{.Error}}</p>{{end}}
  <form method="POST" action="/authorize/verify">
    <input type="hidden" name="flow" value="{{.FlowID}}">
    {{if eq .Method "fido2"}}
    <!-- Stub ceremony: the real WebAuthn adapter replaces this with a
         navigator.credentials.get() call and posts the signed assertion. -->
    <input type="hidden" name="code" value="stub_valid_signature">
    <button type="submit">Touch your authenticator (stub)</button>
    {{else}}
    <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code"
           maxlength="6" autofocus required>
    <button type="submit">Verify</button>
    {{end}}
  </form>
</div>
</body>
</html>
`))

func (h *OIDCHandlers) renderOTPForm(w http.ResponseWriter, status int, data otpFormData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := otpFormTmpl.Execute(w, data); err != nil {
		h.Logger.Error("otp_form_render_failed", "err", err)
	}
}

// mintCodeAndRedirect is the shared tail of /authorize and /authorize/verify:
// persist the one-shot authorization code and bounce the browser back to the
// client's redirect_uri. The redirect URI was validated against the client's
// registration before the flow was parked.
func (h *OIDCHandlers) mintCodeAndRedirect(w http.ResponseWriter, r *http.Request, ac AuthCode) {
	redir, err := url.Parse(ac.RedirectURI)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_redirect_uri", "stored redirect_uri is invalid")
		return
	}

	ac.Code = uuid.NewString()
	ac.CreatedAt = time.Now().UTC()
	if err := h.Store.PutAuthCode(ac); err != nil {
		h.Logger.Error("authorize_store_failed", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue code")
		return
	}

	rq := redir.Query()
	rq.Set("code", ac.Code)
	if ac.State != "" {
		rq.Set("state", ac.State)
	}
	redir.RawQuery = rq.Encode()
	http.Redirect(w, r, redir.String(), http.StatusFound)
}
