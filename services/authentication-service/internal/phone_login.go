package internal

import (
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// phone_login.go implements primary login by phone number — the "Continue with
// phone" path of the hosted /login chooser, separate from Google.
//
// Flow:
//
//	GET  /login/phone            → enter your phone number
//	POST /login/phone            → "send" an SMS OTP, show the code form
//	POST /login/phone/verify     → check the code, then:
//	     known number  → log in as that user
//	     new number    → create an account (phone anchor, verified) and offer to
//	                     link a Google login before continuing
//	POST /login/phone/link       → start the Google leg to link an email
//	POST /login/phone/skip       → continue without linking
//	GET  /login/phone/link/callback → attach the Google email, then continue
//
// On success it mirrors the social leg's finalize exactly: mint a low-risk
// session, set the authz-session cookie, and redirect to the app's redirect_uri
// with ?session_id=…&user_id=…&state=… — so the tenant app's auth.js continues
// into the OIDC code flow unchanged.
//
// ⚠️ SMS is a STUB. No provider is wired (authenticator-service's SMS adapter is
// likewise a stub), so sendOTP "sends" the fixed code 123456 — the same
// convention the step-up SMS stub uses. Swapping in Twilio/MessageBird is a
// one-function change (sendOTP) that generates a random code and texts it.
type PhoneLoginHandlers struct {
	Store  Storage
	Logger *slog.Logger
	Issuer string

	// Analyzer records the device fingerprint + runs CAEP drift analysis at the
	// phone-OTP validation.
	Analyzer *DeviceAnalyzer

	mu    sync.Mutex
	otps  map[string]pendingPhoneOTP  // keyed by otp flow id (carried in the form)
	links map[string]pendingPhoneLink // keyed by link id (carried in a cookie)
}

// NewPhoneLoginHandlers builds the handler set with initialised flow maps.
func NewPhoneLoginHandlers(store Storage, logger *slog.Logger, issuer string) *PhoneLoginHandlers {
	return &PhoneLoginHandlers{
		Store:  store,
		Logger: logger,
		Issuer: issuer,
		otps:   make(map[string]pendingPhoneOTP),
		links:  make(map[string]pendingPhoneLink),
	}
}

const (
	phoneFlowTTL    = 10 * time.Minute
	phoneMaxOTP     = 5        // wrong-code attempts before the flow is killed
	stubOTPCode     = "123456" // STUB delivery — see the sendOTP note above
	phoneLinkCookie = "xauth_phone_link"
	phoneLinkState  = "xauth_phone_link_state"
)

// pendingPhoneOTP parks a phone across the "code sent → code entered" round-trip.
type pendingPhoneOTP struct {
	TenantID    string
	Phone       string
	RedirectURI string
	State       string
	IsNew       bool // number unknown → create the account + offer to link Google
	Code        string
	Attempts    int
	CreatedAt   time.Time
}

// pendingPhoneLink parks an already-logged-in new account across the optional
// Google-link round-trip, so the leg can attach the verified email and then
// finalise the original app login.
type pendingPhoneLink struct {
	ID          string // the link id (also the cookie value / map key)
	TenantID    string
	UserID      string
	SessionID   string
	RedirectURI string
	State       string
	CSRF        string
	CreatedAt   time.Time
}

// ---- flow map helpers (in-process, single replica — same model as otp.go) ----

func (h *PhoneLoginHandlers) putOTP(id string, p pendingPhoneOTP) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.gcLocked()
	h.otps[id] = p
}

func (h *PhoneLoginHandlers) getOTP(id string) (pendingPhoneOTP, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, ok := h.otps[id]
	if !ok || time.Since(p.CreatedAt) > phoneFlowTTL {
		delete(h.otps, id)
		return pendingPhoneOTP{}, false
	}
	return p, true
}

func (h *PhoneLoginHandlers) dropOTP(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.otps, id)
}

func (h *PhoneLoginHandlers) putLink(id string, p pendingPhoneLink) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.gcLocked()
	h.links[id] = p
}

func (h *PhoneLoginHandlers) getLink(id string) (pendingPhoneLink, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, ok := h.links[id]
	if !ok || time.Since(p.CreatedAt) > phoneFlowTTL {
		delete(h.links, id)
		return pendingPhoneLink{}, false
	}
	return p, true
}

func (h *PhoneLoginHandlers) dropLink(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.links, id)
}

// gcLocked drops expired flows. Caller holds h.mu.
func (h *PhoneLoginHandlers) gcLocked() {
	cutoff := time.Now().UTC().Add(-phoneFlowTTL)
	for k, v := range h.otps {
		if v.CreatedAt.Before(cutoff) {
			delete(h.otps, k)
		}
	}
	for k, v := range h.links {
		if v.CreatedAt.Before(cutoff) {
			delete(h.links, k)
		}
	}
}

// sendOTP "sends" a one-time code to phone and returns the code the verify step
// will accept. STUB: no SMS provider is wired, so it returns the fixed 123456
// (matching authenticator-service's SMS stub). Replace with a Twilio/MessageBird
// call that generates a random code, texts it, and returns it for storage.
func (h *PhoneLoginHandlers) sendOTP(phone string) string {
	h.Logger.Info("phone_otp_sent_stub", "phone", phone)
	return stubOTPCode
}

// ---- handlers ----

// Start renders the phone-entry form. Required query params (tenant_id,
// redirect_uri, state) are validated the same way /login is and threaded
// through hidden fields.
func (h *PhoneLoginHandlers) Start(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tenantID := strings.TrimSpace(q.Get("tenant_id"))
	redirectURI := strings.TrimSpace(q.Get("redirect_uri"))
	state := q.Get("state")
	if !h.validEntry(w, tenantID, redirectURI) {
		return
	}

	heading := "Sign in with your phone"
	if t, err := h.Store.GetTenant(tenantID); err == nil && t.CompanyName != "" {
		heading = "Sign in to " + t.CompanyName
	}
	h.page(w, http.StatusOK, "Phone sign-in", `<h1>`+html.EscapeString(heading)+`</h1>
<p class="muted">Enter your mobile number — we'll text you a verification code.</p>
<form class="panel" method="post" action="/login/phone">
`+hidden("tenant_id", tenantID)+hidden("redirect_uri", redirectURI)+hidden("state", state)+`
<label for="phone">Mobile number</label>
<input id="phone" name="phone" type="tel" inputmode="tel" placeholder="+15551234567" autocomplete="tel" autofocus required>
<button class="btn" type="submit" style="margin-top:14px">Send code</button>
</form>`)
}

// Submit validates the number, "sends" the OTP, parks the flow, and shows the
// code form. Known vs new is resolved here (and remembered in the flow) but not
// revealed to the user — both paths text a code, so there's no enumeration leak.
func (h *PhoneLoginHandlers) Submit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.errorPage(w, "Could not read the form.")
		return
	}
	tenantID := strings.TrimSpace(r.PostForm.Get("tenant_id"))
	redirectURI := strings.TrimSpace(r.PostForm.Get("redirect_uri"))
	state := r.PostForm.Get("state")
	if !h.validEntry(w, tenantID, redirectURI) {
		return
	}
	phone, ok := normalizePhone(r.PostForm.Get("phone"))
	if !ok {
		h.page(w, http.StatusBadRequest, "Phone sign-in", `<h1 class="err">Check the number</h1>
<p class="muted">Enter a valid mobile number in international format, e.g. <code>+15551234567</code>.</p>
<div class="actions"><a class="btn secondary" href="`+html.EscapeString(h.entryHref(tenantID, redirectURI, state))+`">Back</a></div>`)
		return
	}

	_, err := h.Store.GetIdentityAnchorByValue(tenantID, AnchorPhone, phone)
	isNew := err == ErrNotFound
	if err != nil && err != ErrNotFound {
		h.Logger.Error("phone_anchor_lookup_failed", "err", err, "tenant_id", tenantID)
		h.errorPage(w, "Could not start sign-in. Try again.")
		return
	}

	code := h.sendOTP(phone)
	flowID := uuid.NewString()
	h.putOTP(flowID, pendingPhoneOTP{
		TenantID: tenantID, Phone: phone, RedirectURI: redirectURI, State: state,
		IsNew: isNew, Code: code, CreatedAt: time.Now().UTC(),
	})
	h.renderCodeForm(w, flowID, phone, "")
}

// Verify checks the code and, on success, logs the user in (creating the account
// for a new number) and either finalises or offers the Google link.
func (h *PhoneLoginHandlers) Verify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.errorPage(w, "Could not read the form.")
		return
	}
	flowID := r.PostForm.Get("flow")
	code := strings.TrimSpace(r.PostForm.Get("code"))
	flow, ok := h.getOTP(flowID)
	if !ok {
		h.errorPage(w, "Your code expired. Start again.")
		return
	}
	if code != flow.Code {
		flow.Attempts++
		if flow.Attempts >= phoneMaxOTP {
			h.dropOTP(flowID)
			h.errorPage(w, "Too many incorrect codes. Start again.")
			return
		}
		h.putOTP(flowID, flow)
		h.renderCodeForm(w, flowID, flow.Phone, "Incorrect code — try again.")
		return
	}
	h.dropOTP(flowID)

	user, isNew, ok := h.resolveUser(w, flow)
	if !ok {
		return
	}
	sess, ok := h.mintSession(w, flow.TenantID, user.ID)
	if !ok {
		return
	}
	h.Logger.Info("phone_login", "tenant_id", flow.TenantID, "user_id", user.ID, "new", isNew)
	h.Analyzer.Observe(r, flow.TenantID, user.ID, sess.ID, DeviceStageOTP, r.PostForm.Get("device_fp"))

	if isNew {
		h.offerLink(w, flow, user, sess)
		return
	}
	h.finalize(w, r, flow.RedirectURI, sess.ID, user.ID, flow.State)
}

// resolveUser returns the user for the verified phone — the existing one for a
// known number, or a freshly created phone-anchored account for a new number.
func (h *PhoneLoginHandlers) resolveUser(w http.ResponseWriter, flow pendingPhoneOTP) (User, bool, bool) {
	if !flow.IsNew {
		anchor, err := h.Store.GetIdentityAnchorByValue(flow.TenantID, AnchorPhone, flow.Phone)
		if err != nil {
			h.errorPage(w, "Could not find your account. Start again.")
			return User{}, false, false
		}
		user, err := h.Store.GetUser(flow.TenantID, anchor.UserID)
		if err != nil {
			h.errorPage(w, "Could not load your account. Start again.")
			return User{}, false, false
		}
		return user, false, true
	}

	now := time.Now().UTC()
	// A phone-first signup has no email/name. Seed the display name with the
	// verified number so /userinfo (sub/email/name) still carries a human
	// identity — relying apps can show the phone instead of a blank "signed in".
	user, err := h.Store.CreateUser(User{
		ID: "usr_" + uuid.NewString(), TenantID: flow.TenantID, Name: flow.Phone, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		h.Logger.Error("phone_user_create_failed", "err", err, "tenant_id", flow.TenantID)
		h.errorPage(w, "Could not create your account. Try again.")
		return User{}, false, false
	}
	if _, err := h.Store.CreateIdentityAnchor(IdentityAnchor{
		ID: "ian_" + uuid.NewString(), UserID: user.ID, TenantID: flow.TenantID,
		Type: AnchorPhone, Value: flow.Phone, VerifiedAt: &now, CreatedAt: now,
	}); err != nil {
		// Roll back the orphan user so the number stays claimable on retry.
		_ = h.Store.DeleteUser(flow.TenantID, user.ID)
		h.Logger.Error("phone_anchor_create_failed", "err", err, "tenant_id", flow.TenantID)
		h.errorPage(w, "Could not register your number. Try again.")
		return User{}, false, false
	}
	return user, true, true
}

// offerLink mints the link flow, sets the link cookie, and renders the
// "link a Google account?" interlude shown to a brand-new phone account.
func (h *PhoneLoginHandlers) offerLink(w http.ResponseWriter, flow pendingPhoneOTP, user User, sess Session) {
	linkID := uuid.NewString()
	h.putLink(linkID, pendingPhoneLink{
		ID: linkID, TenantID: flow.TenantID, UserID: user.ID, SessionID: sess.ID,
		RedirectURI: flow.RedirectURI, State: flow.State, CreatedAt: time.Now().UTC(),
	})
	http.SetCookie(w, &http.Cookie{
		Name: phoneLinkCookie, Value: linkID, Path: "/login/phone",
		MaxAge: int(phoneFlowTTL.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	h.page(w, http.StatusOK, "Account created", `<h1 class="ok">Account created</h1>
<p class="muted">You're signed in with your phone number. Want to also be able to sign in with Google? You can link it now.</p>
<div class="panel">
<form method="post" action="/login/phone/link" style="margin:0 0 10px">
<button class="btn" type="submit">Link my Google account</button>
</form>
<form method="post" action="/login/phone/skip" style="margin:0">
<button class="btn secondary" type="submit">Skip for now</button>
</form>
</div>`)
}

// LinkStart begins the Google leg in the staging tenant (ten_signup) purely to
// obtain a verified email, which LinkCallback then attaches to the phone account.
func (h *PhoneLoginHandlers) LinkStart(w http.ResponseWriter, r *http.Request) {
	link, ok := h.currentLink(r)
	if !ok {
		h.errorPage(w, "Your session expired. Start again.")
		return
	}
	csrf := randToken(32)
	link.CSRF = csrf
	h.putLink(cookieValue(r, phoneLinkCookie), link)
	http.SetCookie(w, &http.Cookie{
		Name: phoneLinkState, Value: csrf, Path: "/login/phone",
		MaxAge: int(phoneFlowTTL.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})

	u, _ := url.Parse(strings.TrimRight(h.Issuer, "/") + "/v1/social/google/authorize")
	q := u.Query()
	q.Set("tenant_id", signupTenantID)
	q.Set("redirect_uri", strings.TrimRight(h.Issuer, "/")+"/login/phone/link/callback")
	q.Set("state", csrf)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// LinkCallback consumes the Google email and attaches it to the phone account,
// then finalises the original app login. A collision (the email already belongs
// to another account in the tenant) is non-fatal: the user stays logged in via
// phone, just unlinked.
func (h *PhoneLoginHandlers) LinkCallback(w http.ResponseWriter, r *http.Request) {
	link, ok := h.currentLink(r)
	if !ok {
		h.errorPage(w, "Your session expired. Start again.")
		return
	}
	stateCookie := cookieValue(r, phoneLinkState)
	if stateCookie == "" || stateCookie != r.URL.Query().Get("state") || stateCookie != link.CSRF {
		h.errorPage(w, "State mismatch. Start again.")
		return
	}
	h.clearLinkCookies(w)

	email, ok := h.googleEmail(r)
	if !ok {
		// Couldn't read the Google identity — finish logged in, unlinked.
		h.Logger.Warn("phone_link_email_unresolved", "tenant_id", link.TenantID, "user_id", link.UserID)
		h.finishLink(w, r, link, "We couldn't read your Google account, so it wasn't linked. You're still signed in.")
		return
	}

	user, err := h.Store.GetUser(link.TenantID, link.UserID)
	if err != nil {
		h.errorPage(w, "Could not load your account.")
		return
	}
	user.Email = email
	if _, err := h.Store.UpdateUser(user); err != nil {
		if err == ErrConflict {
			h.finishLink(w, r, link, "That Google account is already linked to a different account here, so it wasn't linked. You're still signed in with your phone.")
			return
		}
		h.Logger.Error("phone_link_update_failed", "err", err, "tenant_id", link.TenantID)
		h.finishLink(w, r, link, "We couldn't link your Google account, so you're signed in with your phone for now.")
		return
	}
	h.Logger.Info("phone_link_completed", "tenant_id", link.TenantID, "user_id", link.UserID)
	h.dropLink(link.ID)
	h.finalize(w, r, link.RedirectURI, link.SessionID, link.UserID, link.State)
}

// Skip continues to the app without linking a social login.
func (h *PhoneLoginHandlers) Skip(w http.ResponseWriter, r *http.Request) {
	link, ok := h.currentLink(r)
	if !ok {
		h.errorPage(w, "Your session expired. Start again.")
		return
	}
	h.clearLinkCookies(w)
	h.dropLink(link.ID)
	h.finalize(w, r, link.RedirectURI, link.SessionID, link.UserID, link.State)
}

// ---- shared bits ----

// finishLink shows a brief notice (link skipped/failed) with a Continue button
// that finalises the app login. Used when linking didn't complete but the user
// is logged in regardless.
func (h *PhoneLoginHandlers) finishLink(w http.ResponseWriter, r *http.Request, link pendingPhoneLink, note string) {
	h.dropLink(link.ID)
	redir, err := url.Parse(link.RedirectURI)
	if err != nil {
		h.errorPage(w, "Invalid redirect.")
		return
	}
	rq := redir.Query()
	rq.Set("session_id", link.SessionID)
	rq.Set("user_id", link.UserID)
	if link.State != "" {
		rq.Set("state", link.State)
	}
	redir.RawQuery = rq.Encode()
	h.page(w, http.StatusOK, "Signed in", `<h1 class="ok">Signed in</h1>
<p class="muted">`+html.EscapeString(note)+`</p>
<div class="actions"><a class="btn" href="`+html.EscapeString(redir.String())+`">Continue</a></div>`)
}

// finalize mirrors the social leg's tail: redirect to the app's redirect_uri
// with the session id + user id (+ state). The authz cookie was set at session
// mint, so the app's follow-up /authorize identifies the user server-side.
func (h *PhoneLoginHandlers) finalize(w http.ResponseWriter, r *http.Request, redirectURI, sessionID, userID, state string) {
	redir, err := url.Parse(redirectURI)
	if err != nil {
		h.errorPage(w, "Invalid redirect.")
		return
	}
	rq := redir.Query()
	rq.Set("session_id", sessionID)
	rq.Set("user_id", userID)
	if state != "" {
		rq.Set("state", state)
	}
	redir.RawQuery = rq.Encode()
	http.Redirect(w, r, redir.String(), http.StatusFound)
}

// mintSession creates the low-risk login session and sets the authz cookie.
func (h *PhoneLoginHandlers) mintSession(w http.ResponseWriter, tenantID, userID string) (Session, bool) {
	now := time.Now().UTC()
	sess, err := h.Store.CreateSession(Session{
		ID: "ses_" + uuid.NewString(), TenantID: tenantID, UserID: userID, RiskLevel: RiskLow,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Duration(SessionTTLSeconds) * time.Second),
	})
	if err != nil {
		h.Logger.Error("phone_session_create_failed", "err", err, "tenant_id", tenantID)
		h.errorPage(w, "Could not start your session. Try again.")
		return Session{}, false
	}
	SetAuthzSession(w, sess.ID, sess.ExpiresAt)
	return sess, true
}

// googleEmail reads the provider-verified email from the staging (ten_signup)
// session the Google leg returned. Mirrors the console consoles' pattern.
func (h *PhoneLoginHandlers) googleEmail(r *http.Request) (string, bool) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		return "", false
	}
	sess, err := h.Store.GetSession(signupTenantID, sessionID)
	if err != nil || sess.InvalidatedAt != nil || time.Now().UTC().After(sess.ExpiresAt) {
		return "", false
	}
	user, err := h.Store.GetUser(signupTenantID, sess.UserID)
	if err != nil || user.Email == "" {
		return "", false
	}
	return user.Email, true
}

// currentLink resolves the pending link flow from the cookie.
func (h *PhoneLoginHandlers) currentLink(r *http.Request) (pendingPhoneLink, bool) {
	id := cookieValue(r, phoneLinkCookie)
	if id == "" {
		return pendingPhoneLink{}, false
	}
	return h.getLink(id)
}

func (h *PhoneLoginHandlers) clearLinkCookies(w http.ResponseWriter) {
	for _, n := range []string{phoneLinkCookie, phoneLinkState} {
		http.SetCookie(w, &http.Cookie{Name: n, Path: "/login/phone", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
}

// validEntry enforces the same tenant_id + registered-redirect contract as
// /login, rendering an error page and returning false on failure.
func (h *PhoneLoginHandlers) validEntry(w http.ResponseWriter, tenantID, redirectURI string) bool {
	if tenantID == "" {
		h.errorPage(w, "tenant_id is required.")
		return false
	}
	if u, err := url.Parse(redirectURI); redirectURI == "" || err != nil || !u.IsAbs() {
		h.errorPage(w, "A valid redirect_uri is required.")
		return false
	}
	if !redirectAllowedForTenant(h.Store, h.Issuer, tenantID, redirectURI) {
		h.errorPage(w, "This redirect URL isn't registered for this workspace.")
		return false
	}
	return true
}

func (h *PhoneLoginHandlers) entryHref(tenantID, redirectURI, state string) string {
	q := url.Values{}
	q.Set("tenant_id", tenantID)
	q.Set("redirect_uri", redirectURI)
	if state != "" {
		q.Set("state", state)
	}
	return "/login/phone?" + q.Encode()
}

func (h *PhoneLoginHandlers) renderCodeForm(w http.ResponseWriter, flowID, phone, errMsg string) {
	errBlock := ""
	if errMsg != "" {
		errBlock = `<p class="err">` + html.EscapeString(errMsg) + `</p>`
	}
	h.page(w, http.StatusOK, "Enter code", `<h1>Enter your code</h1>
<p class="muted">We texted a 6-digit code to <strong>`+html.EscapeString(phone)+`</strong>.</p>`+errBlock+`
<form class="panel" method="post" action="/login/phone/verify">
`+hidden("flow", flowID)+`
<input type="hidden" name="device_fp" data-device-fp>
<label for="code">Verification code</label>
<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" autofocus required>
<button class="btn" type="submit" style="margin-top:14px">Verify</button>
</form>`+deviceFPScript)
}

// ---- page shell ----

func (h *PhoneLoginHandlers) page(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>`+html.EscapeString(title)+`</title>
<style>
:root{color-scheme:dark;--bg:#09090b;--panel:#121217;--text:#dddde4;--muted:#8a8a96;--line:rgba(255,255,255,.11);--accent:#00e096;--warn:#f0b429;--danger:#f04040}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;line-height:1.55;display:grid;place-items:center;min-height:100vh}
main{width:min(420px,calc(100% - 32px))}
h1{font-size:1.6rem;line-height:1.1;margin:0 0 6px;letter-spacing:-.02em}
.muted{color:var(--muted)}.err{color:#ff8e8e}.ok{color:var(--accent)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:22px;margin-top:18px}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
label{display:block;color:var(--muted);font-size:.83rem;margin:2px 0 5px}
input{width:100%;background:#0d0d12;border:1px solid var(--line);color:var(--text);border-radius:6px;padding:11px 12px;font:inherit}
.btn{appearance:none;width:100%;border:0;border-radius:8px;background:var(--accent);color:#00150e;font-weight:800;padding:12px 14px;text-decoration:none;cursor:pointer;display:flex;align-items:center;justify-content:center;font:inherit;font-weight:800}
.btn.secondary{background:#22232b;color:var(--text);border:1px solid var(--line)}
code{font-family:"JetBrains Mono",ui-monospace,Menlo,Consolas,monospace}
</style>
</head><body><main>`+body+`</main></body></html>`)
}

func (h *PhoneLoginHandlers) errorPage(w http.ResponseWriter, msg string) {
	h.page(w, http.StatusBadRequest, "Phone sign-in", `<h1 class="err">Can't sign in</h1>
<p class="muted">`+html.EscapeString(msg)+`</p>`)
}

// ---- small helpers ----

// hidden renders a hidden form input with an escaped value.
func hidden(name, value string) string {
	return `<input type="hidden" name="` + html.EscapeString(name) + `" value="` + html.EscapeString(value) + `">`
}

// cookieValue returns the named cookie's value, or "".
func cookieValue(r *http.Request, name string) string {
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}

// normalizePhone trims formatting and accepts an E.164-ish number: an optional
// leading '+' and 8–15 digits. Returns the normalised "+digits" form.
func normalizePhone(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	var b strings.Builder
	for i, r := range raw {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && i == 0:
			// allowed leading plus, dropped from the digit count
		case r == ' ' || r == '-' || r == '(' || r == ')' || r == '.':
			// formatting — ignore
		default:
			return "", false
		}
	}
	digits := b.String()
	if len(digits) < 8 || len(digits) > 15 {
		return "", false
	}
	return "+" + digits, true
}
