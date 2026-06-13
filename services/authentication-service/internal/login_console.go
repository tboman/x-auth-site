package internal

import (
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// login_console.go implements the hosted, standalone end-user login chooser at
// GET /login — the page a tenant's app sends users to so they can pick a
// sign-in method. It is public: the user is not authenticated yet.
//
// Today the only working method is Google. Phone (SMS OTP) is shown but
// disabled — the primary-login OTP flow is not built yet (identity_anchors is
// in place for it; see migration 000007). When phone login lands it slots in
// here next to Google with no change to integrators.
//
// For Google the page simply forwards to the existing social-login leg
// (/v1/social/{provider}/authorize), passing the caller's tenant_id,
// redirect_uri and state through unchanged. The rest of the flow (provider
// callback → OIDC /authorize → token exchange) is exactly what the generated
// auth.js already drives — the only change for integrators is that login() now
// points the browser at /login instead of hard-coding the Google leg.
type LoginHandlers struct {
	Store  Storage
	Logger *slog.Logger
	Issuer string
}

// loginGoogleProvider is the social provider the "Continue with Google" button
// drives. Kept as a constant so the page and any future provider list stay in
// sync with ValidSocialProvider.
const loginGoogleProvider = "google"

func (h *LoginHandlers) page(w http.ResponseWriter, status int, title, body string) {
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
.muted{color:var(--muted)}.err{color:#ff8e8e}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:22px;margin-top:18px}
.btn{appearance:none;width:100%;border:0;border-radius:8px;background:var(--accent);color:#00150e;font-weight:800;padding:12px 14px;text-decoration:none;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px;font:inherit;font-weight:800}
.btn.secondary{background:#22232b;color:var(--text);border:1px solid var(--line)}
.btn[disabled]{opacity:.45;cursor:not-allowed}
.sep{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:.8rem;margin:14px 0}
.sep::before,.sep::after{content:"";height:1px;background:var(--line);flex:1}
.soon{font-size:.72rem;color:var(--warn);border:1px solid var(--line);border-radius:999px;padding:1px 7px;margin-left:6px}
</style>
</head><body><main>`+body+`</main></body></html>`)
}

// Login renders the sign-in chooser. Required query params mirror the social
// leg the Google button forwards to: tenant_id and redirect_uri (state is
// optional but passed through). redirect_uri is validated as an absolute URL —
// the same contract the social authorize endpoint enforces.
func (h *LoginHandlers) Login(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tenantID := strings.TrimSpace(q.Get("tenant_id"))
	redirectURI := strings.TrimSpace(q.Get("redirect_uri"))
	state := q.Get("state")

	if tenantID == "" {
		h.errorPage(w, "tenant_id is required.")
		return
	}
	if redirectURI == "" {
		h.errorPage(w, "redirect_uri is required.")
		return
	}
	if u, err := url.Parse(redirectURI); err != nil || !u.IsAbs() {
		h.errorPage(w, "redirect_uri must be an absolute URL.")
		return
	}

	// Best-effort workspace name for the heading. Derived/console tenants (no
	// registry row) just get the generic title.
	heading := "Sign in"
	if t, err := h.Store.GetTenant(tenantID); err == nil && t.CompanyName != "" {
		heading = "Sign in to " + t.CompanyName
	}

	// Google button → the existing social leg with the caller's params passed
	// through unchanged. Relative URL: /login and the social leg share an origin.
	gv := url.Values{}
	gv.Set("tenant_id", tenantID)
	gv.Set("redirect_uri", redirectURI)
	if state != "" {
		gv.Set("state", state)
	}
	googleHref := "/v1/social/" + loginGoogleProvider + "/authorize?" + gv.Encode()

	h.page(w, http.StatusOK, "Sign in", `<h1>`+html.EscapeString(heading)+`</h1>
<p class="muted">Choose how you'd like to continue.</p>
<div class="panel">
<a class="btn" href="`+html.EscapeString(googleHref)+`">Continue with Google</a>
<div class="sep">or</div>
<button class="btn secondary" type="button" disabled aria-disabled="true">Continue with phone<span class="soon">coming soon</span></button>
<p class="muted" style="margin:12px 0 0;font-size:.8rem">Phone sign-in is on the way.</p>
</div>`)
}

// errorPage renders a minimal sign-in error. No back link — the user arrived
// here from their app, which owns the retry.
func (h *LoginHandlers) errorPage(w http.ResponseWriter, msg string) {
	h.page(w, http.StatusBadRequest, "Sign in", `<h1 class="err">Can't sign in</h1>
<p class="muted">`+html.EscapeString(msg)+`</p>`)
}
