package internal

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// SMS-OTP interlude for /authorize (ARCHITECTURE.md §4.4 challenge flow).
//
// A client opts in with the standard OIDC `acr_values` parameter:
//
//	GET /authorize?...&acr_values=urn:xauth:otp:sms
//
// Instead of minting a code immediately, /authorize creates an SMS challenge
// on authenticator-service (stub adapter today — the accepted code is the
// adapter's hard-coded 123456), parks the authorize request under a one-time
// flow id, and serves a minimal OTP form. POST /authorize/verify proxies the
// submitted code to authenticator-service (which enforces attempts, backoff,
// and lockout) and, on success, mints the authorization code with `acr` +
// `amr` recorded — the token mint stamps them into the ID token and marks the
// session step_up_completed.
//
// Parked flows live in process memory with a TTL, like the social-login
// handshake state: single replica, or a shared store before scaling out.

// ACRSMSOTP is the authentication context class reference for the SMS-OTP
// interlude — the value clients put in acr_values and relying apps check in
// the ID token's acr claim.
const ACRSMSOTP = "urn:xauth:otp:sms"

// amrSMSOTP is the RFC 8176 method list stamped into the amr claim when the
// interlude succeeds.
var amrSMSOTP = []string{"otp", "sms"}

const otpFlowTTL = 10 * time.Minute

// pendingAuthorize parks a validated /authorize request while the user
// completes the OTP challenge.
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
	CreatedAt     time.Time
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
	defer h.flowMu.Unlock()
	delete(h.flows, id)
}

// acrRequested reports whether the space-delimited acr_values parameter asks
// for the given context class.
func acrRequested(acrValues, want string) bool {
	return scopeContains(acrValues, want)
}

// startOTPFlow runs the interlude setup: make sure the user has an SMS
// authenticator (auto-enrolling a stub one if not), dispatch a challenge, park
// the authorize request, and serve the OTP form.
func (h *OIDCHandlers) startOTPFlow(w http.ResponseWriter, r *http.Request, p pendingAuthorize) {
	ctx := r.Context()

	// Ensure an enrolled, usable SMS authenticator. Mock-stage convenience:
	// auto-enroll a stub one so any user can exercise the flow; a real
	// deployment replaces this with a proper enrollment journey.
	auths, err := h.Authenticator.ListAuthenticators(ctx, p.TenantID, p.UserID)
	if err != nil {
		h.Logger.Error("otp_list_authenticators_failed", "err", err, "user_id", p.UserID)
		httpx.WriteError(w, http.StatusBadGateway, "authenticator_unavailable", "could not reach authenticator service")
		return
	}
	hasSMS := false
	for _, a := range auths {
		if a.Method == "sms" && a.Status != "disabled" {
			hasSMS = true
			break
		}
	}
	if !hasSMS {
		if _, err := h.Authenticator.EnrollAuthenticator(ctx, p.TenantID, p.UserID, "sms",
			map[string]any{"phone_number": "+15551234", "enrolled_by": "authorize-otp-stub"}); err != nil {
			h.Logger.Error("otp_auto_enroll_failed", "err", err, "user_id", p.UserID)
			httpx.WriteError(w, http.StatusBadGateway, "authenticator_unavailable", "could not enroll sms authenticator")
			return
		}
	}

	chal, err := h.Authenticator.CreateChallenge(ctx, p.TenantID, p.UserID, []string{"sms"})
	if err != nil {
		h.Logger.Error("otp_challenge_create_failed", "err", err, "user_id", p.UserID)
		httpx.WriteError(w, http.StatusBadGateway, "authenticator_unavailable", "could not create sms challenge")
		return
	}

	p.ChallengeID = chal.ChallengeID
	p.Prompt = chal.Prompt
	p.CreatedAt = time.Now().UTC()
	flowID := uuid.NewString()
	h.storeFlow(flowID, p)

	h.Logger.Info("otp_flow_started", "flow_id", flowID, "challenge_id", chal.ChallengeID,
		"user_id", p.UserID, "tenant_id", p.TenantID)
	h.renderOTPForm(w, http.StatusOK, otpFormData{FlowID: flowID, Prompt: chal.Prompt})
}

// AuthorizeVerify handles POST /authorize/verify — the OTP form submission.
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

	outcome, err := h.Authenticator.VerifyChallenge(r.Context(), flow.TenantID, flow.ChallengeID,
		map[string]any{"code": code})
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
				FlowID: flowID, Prompt: flow.Prompt,
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
			FlowID: flowID, Prompt: flow.Prompt,
			Error: "Incorrect code — try again.",
		})
		return
	}

	h.dropFlow(flowID)
	h.Logger.Info("otp_flow_completed", "flow_id", flowID, "challenge_id", flow.ChallengeID,
		"user_id", flow.UserID, "tenant_id", flow.TenantID)
	h.mintCodeAndRedirect(w, r, AuthCode{
		ClientID:      flow.ClientID,
		TenantID:      flow.TenantID,
		UserID:        flow.UserID,
		RedirectURI:   flow.RedirectURI,
		Scope:         flow.Scope,
		State:         flow.State,
		Nonce:         flow.Nonce,
		CodeChallenge: flow.CodeChallenge,
		ACR:           ACRSMSOTP,
		AMR:           amrSMSOTP,
	})
}

// otpFormData feeds the verification page template.
type otpFormData struct {
	FlowID string
	Prompt string
	Error  string
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
  <h1>Enter verification code</h1>
  <p>{{.Prompt}}</p>
  {{if .Error}}<p class="err">{{.Error}}</p>{{end}}
  <form method="POST" action="/authorize/verify">
    <input type="hidden" name="flow" value="{{.FlowID}}">
    <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code"
           maxlength="6" autofocus required>
    <button type="submit">Verify</button>
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
