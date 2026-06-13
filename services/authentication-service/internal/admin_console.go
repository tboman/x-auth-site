package internal

import (
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	adminTenantID      = "ten_admin"
	adminSessionCookie = "xauth_admin_session"
	adminStateCookie   = "xauth_admin_state"
)

// AdminConsoleHandlers is a small hosted administration surface. A
// Google-authenticated user whose email is on the allowlist can view the
// platform's tenants (derived listing — phase 1 has no tenant registry).
//
// Authentication reuses the same real Google social-login leg as the developer
// console, but in a dedicated tenant (ten_admin) and gated by an email
// allowlist (ADMIN_EMAILS). The allowlist is enforced both at the login
// callback AND on every request, so removing an email from the list revokes
// access immediately, even for an already-issued cookie.
//
// This is a stub admin surface, not a full admin product: it is read-only and
// its protection is only as strong as the email allowlist plus Google's
// account security. See the README for the (still-open) public /v1 admin API
// caveat.
type AdminConsoleHandlers struct {
	Store  Storage
	Logger *slog.Logger
	Issuer string

	// AllowedEmails is the case-insensitive set of Google account emails
	// permitted to administer. Empty means no one can sign in (deny by
	// default) — a deployment must set ADMIN_EMAILS explicitly.
	AllowedEmails map[string]bool

	// EnvOrigins is the CORS_ALLOWED_ORIGINS env baseline, shown read-only on
	// the client-management page so the operator can see the global origins
	// that apply regardless of per-client web origins.
	EnvOrigins []string
}

// NewAdminConsoleHandlers builds the handler set, normalising the allowlist to
// lower-case for case-insensitive comparison.
func NewAdminConsoleHandlers(store Storage, logger *slog.Logger, issuer string, emails, envOrigins []string) *AdminConsoleHandlers {
	allow := make(map[string]bool, len(emails))
	for _, e := range emails {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			allow[e] = true
		}
	}
	return &AdminConsoleHandlers{Store: store, Logger: logger, Issuer: issuer, AllowedEmails: allow, EnvOrigins: envOrigins}
}

func (h *AdminConsoleHandlers) isAllowed(email string) bool {
	return h.AllowedEmails[strings.ToLower(strings.TrimSpace(email))]
}

func (h *AdminConsoleHandlers) page(w http.ResponseWriter, status int, title, body string) {
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
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;line-height:1.55}
main{width:min(980px,calc(100% - 32px));margin:44px auto 80px}
h1{font-size:clamp(2rem,5vw,3.2rem);line-height:1.02;margin:0 0 12px;letter-spacing:-.03em}
.muted{color:var(--muted)}.err{color:#ff8e8e}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:18px;margin-top:18px}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
button,.btn{appearance:none;border:0;border-radius:6px;background:var(--accent);color:#00150e;font-weight:800;padding:10px 14px;text-decoration:none;cursor:pointer;display:inline-flex;align-items:center;gap:8px}
.btn.secondary,button.secondary{background:#22232b;color:var(--text);border:1px solid var(--line)}
button.danger{background:var(--danger);color:#1a0000}
label{display:block;color:var(--muted);font-size:.83rem;margin:12px 0 5px}
input,textarea{width:100%;background:#0d0d12;border:1px solid var(--line);color:var(--text);border-radius:6px;padding:10px 12px;font:inherit}
textarea{resize:vertical}h2{font-size:1.2rem}h3{font-size:1rem}
code{font-family:"JetBrains Mono",ui-monospace,Menlo,Consolas,monospace}
table{width:100%;border-collapse:collapse;margin-top:8px}th,td{border-top:1px solid var(--line);padding:10px 8px;text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:.82rem;text-transform:uppercase;letter-spacing:.04em}
td.num{text-align:right;font-variant-numeric:tabular-nums}
</style>
</head><body><main>`+body+`</main></body></html>`)
}

// Home renders the admin console. Signed-out (or non-allowlisted) users see the
// Google sign-in button; an allowlisted admin sees the tenant listing.
func (h *AdminConsoleHandlers) Home(w http.ResponseWriter, r *http.Request) {
	admin, ok := h.currentAdmin(w, r)
	if !ok {
		h.page(w, http.StatusOK, "X-Auth admin", `<h1>X-Auth administration</h1>
<p class="muted">Sign in with Google. Access is restricted to authorised administrators.</p>
<div class="actions"><a class="btn" href="/admin/login/google">Sign in with Google</a></div>`)
		return
	}

	tenants, err := h.Store.ListTenants()
	if err != nil {
		h.Logger.Error("admin_list_tenants_failed", "err", err)
		h.page(w, http.StatusBadGateway, "X-Auth admin", `<h1 class="err">Could not load tenants</h1>
<p class="muted">The tenant listing is temporarily unavailable.</p>`)
		return
	}

	var rows strings.Builder
	if len(tenants) == 0 {
		rows.WriteString(`<tr><td colspan="4" class="muted">No tenants yet.</td></tr>`)
	} else {
		for _, t := range tenants {
			last := "—"
			if !t.LastActivity.IsZero() {
				last = t.LastActivity.UTC().Format(time.RFC3339)
			}
			rows.WriteString(`<tr><td><code>` + html.EscapeString(t.TenantID) + `</code></td>`)
			rows.WriteString(`<td class="num">` + itoa(t.Users) + `</td>`)
			rows.WriteString(`<td class="num">` + itoa(t.Sessions) + `</td>`)
			rows.WriteString(`<td class="muted">` + html.EscapeString(last) + `</td></tr>`)
		}
	}

	h.page(w, http.StatusOK, "X-Auth admin", `<h1>Administration</h1>
<p class="muted">Signed in as <strong>`+html.EscapeString(admin.User.Email)+`</strong>.</p>
<form method="post" action="/admin/logout"><button class="secondary" type="submit">Sign out</button></form>
<h2 style="margin-top:28px">Tenants</h2>
<p class="muted">`+itoa(len(tenants))+` tenant(s). Derived from existing users and sessions — phase 1 has no tenant registry.</p>
<div class="panel"><table>
<thead><tr><th>Tenant</th><th>Users</th><th>Sessions</th><th>Last activity (UTC)</th></tr></thead>
<tbody>`+rows.String()+`</tbody></table></div>`+
		h.clientsSection())
}

// clientsSection renders the OIDC client-management block: the env CORS
// baseline (read-only), the list of registered clients with delete buttons,
// and the registration form.
func (h *AdminConsoleHandlers) clientsSection() string {
	clients, err := h.Store.ListClients()
	if err != nil {
		h.Logger.Error("admin_list_clients_failed", "err", err)
		return `<h2 style="margin-top:32px">OIDC clients</h2><p class="err">Could not load clients.</p>`
	}

	var rows strings.Builder
	if len(clients) == 0 {
		rows.WriteString(`<tr><td colspan="4" class="muted">No clients registered.</td></tr>`)
	} else {
		for _, c := range clients {
			tenant := `<span class="muted">unbound</span>`
			if c.TenantID != "" {
				tenant = `<code>` + html.EscapeString(c.TenantID) + `</code>`
			}
			rows.WriteString(`<tr><td><code>` + html.EscapeString(c.ClientID) + `</code></td>`)
			rows.WriteString(`<td>` + tenant + `</td>`)
			rows.WriteString(`<td>` + originList(c.RedirectURIs) + `</td>`)
			rows.WriteString(`<td>` + originList(c.WebOrigins) + `</td>`)
			rows.WriteString(`<td><form method="post" action="/admin/clients/delete" ` +
				`onsubmit="return confirm('Delete client ` + html.EscapeString(c.ClientID) + `?')">` +
				`<input type="hidden" name="client_id" value="` + html.EscapeString(c.ClientID) + `">` +
				`<button class="danger" type="submit">Delete</button></form></td></tr>`)
		}
	}

	envOrigins := `<span class="muted">none</span>`
	if len(h.EnvOrigins) > 0 {
		envOrigins = originList(h.EnvOrigins)
	}

	return `<h2 style="margin-top:32px">OIDC clients</h2>
<p class="muted">Public PKCE clients. An origin is allowed for browser calls (/token, /userinfo, /revoke)
if it is a global env origin <em>or</em> a registered client's web origin.</p>
<div class="panel">
<p class="muted">Global origins (from <code>CORS_ALLOWED_ORIGINS</code> env): ` + envOrigins + `</p>
<table>
<thead><tr><th>Client ID</th><th>Tenant</th><th>Redirect URIs</th><th>Web origins</th><th></th></tr></thead>
<tbody>` + rows.String() + `</tbody></table>
</div>
<div class="panel">
<h3 style="margin:0 0 8px">Register a client</h3>
<form method="post" action="/admin/clients">
<label>Client ID</label>
<input name="client_id" placeholder="unlimitedfreight-web" required>
<label>Tenant ID (binds the client to one tenant; recommended)</label>
<input name="tenant_id" placeholder="ten_unlimitedfreight">
<label>Redirect URIs (one per line)</label>
<textarea name="redirect_uris" rows="3" placeholder="https://unlimitedfreight.com/callback.html"></textarea>
<label>Web origins (one per line, for CORS)</label>
<textarea name="web_origins" rows="2" placeholder="https://unlimitedfreight.com"></textarea>
<div class="actions"><button type="submit">Register client</button></div>
</form>
<p class="muted" style="margin-top:10px">⚠️ Clients registered here live in memory and are lost on redeploy.
To make one permanent, add it to the <code>OIDC_CLIENTS</code> env var (and origins to
<code>CORS_ALLOWED_ORIGINS</code>) on the Cloud Run service.</p>
</div>`
}

// RegisterClient handles POST /admin/clients.
func (h *AdminConsoleHandlers) RegisterClient(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.currentAdmin(w, r); !ok {
		h.loginErrorStatus(w, http.StatusForbidden, "Sign in as an administrator first.")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.loginError(w, "Could not parse the form.")
		return
	}
	clientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	tenantID := strings.TrimSpace(r.PostForm.Get("tenant_id"))
	redirects := splitLines(r.PostForm.Get("redirect_uris"))
	origins := splitLines(r.PostForm.Get("web_origins"))

	if clientID == "" {
		h.loginError(w, "client_id is required.")
		return
	}
	if len(redirects) == 0 {
		h.loginError(w, "At least one redirect URI is required.")
		return
	}
	for _, u := range redirects {
		parsed, err := url.Parse(u)
		if err != nil || !parsed.IsAbs() {
			h.loginError(w, "Redirect URI must be an absolute URL: "+u)
			return
		}
	}
	for i, o := range origins {
		origins[i] = strings.TrimRight(o, "/")
	}

	if err := h.Store.PutClient(OIDCClient{
		ClientID:     clientID,
		TenantID:     tenantID,
		RedirectURIs: redirects,
		WebOrigins:   origins,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		h.Logger.Error("admin_register_client_failed", "err", err, "client_id", clientID)
		h.loginErrorStatus(w, http.StatusBadGateway, "Could not register the client.")
		return
	}
	h.Logger.Info("admin_client_registered", "client_id", clientID, "by", "admin")
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// DeleteClient handles POST /admin/clients/delete.
func (h *AdminConsoleHandlers) DeleteClient(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.currentAdmin(w, r); !ok {
		h.loginErrorStatus(w, http.StatusForbidden, "Sign in as an administrator first.")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.loginError(w, "Could not parse the form.")
		return
	}
	clientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	if clientID == "" {
		h.loginError(w, "client_id is required.")
		return
	}
	if err := h.Store.DeleteClient(clientID); err != nil && err != ErrNotFound {
		h.Logger.Error("admin_delete_client_failed", "err", err, "client_id", clientID)
		h.loginErrorStatus(w, http.StatusBadGateway, "Could not delete the client.")
		return
	}
	h.Logger.Info("admin_client_deleted", "client_id", clientID)
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// splitLines splits a textarea value into trimmed, non-empty, de-duplicated
// lines (also tolerating comma separation).
func splitLines(raw string) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';'
	}) {
		if f = strings.TrimSpace(f); f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// originList renders a slice as escaped <code> chips, or an em dash if empty.
func originList(items []string) string {
	if len(items) == 0 {
		return `<span class="muted">—</span>`
	}
	var b strings.Builder
	for i, it := range items {
		if i > 0 {
			b.WriteString("<br>")
		}
		b.WriteString(`<code>` + html.EscapeString(it) + `</code>`)
	}
	return b.String()
}

// LoginGoogle starts the real Google social login, returning to the admin
// callback.
func (h *AdminConsoleHandlers) LoginGoogle(w http.ResponseWriter, r *http.Request) {
	state := randToken(32)
	http.SetCookie(w, &http.Cookie{
		Name:     adminStateCookie,
		Value:    state,
		Path:     "/admin",
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	u, _ := url.Parse(strings.TrimRight(h.Issuer, "/") + "/v1/social/google/authorize")
	q := u.Query()
	q.Set("tenant_id", adminTenantID)
	q.Set("redirect_uri", strings.TrimRight(h.Issuer, "/")+"/admin/social/callback")
	q.Set("state", state)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// SocialCallback consumes the social-login redirect, enforces the email
// allowlist, and (only then) issues an admin session cookie.
func (h *AdminConsoleHandlers) SocialCallback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(adminStateCookie)
	if err != nil || c.Value == "" || c.Value != r.URL.Query().Get("state") {
		h.loginError(w, "State mismatch. Start again from the admin console.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: adminStateCookie, Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		h.loginError(w, "The social callback did not include a session_id.")
		return
	}
	sess, err := h.Store.GetSession(adminTenantID, sessionID)
	if err != nil || sess.InvalidatedAt != nil || time.Now().UTC().After(sess.ExpiresAt) {
		h.loginError(w, "The returned session is not valid.")
		return
	}
	user, err := h.Store.GetUser(adminTenantID, sess.UserID)
	if err != nil {
		h.loginError(w, "Could not resolve the signed-in user.")
		return
	}
	if !h.isAllowed(user.Email) {
		// Refuse: invalidate the freshly minted session so it cannot be reused,
		// and never set the admin cookie.
		now := time.Now().UTC()
		sess.InvalidatedAt = &now
		_, _ = h.Store.UpdateSession(sess)
		h.Logger.Warn("admin_login_denied", "email", user.Email, "tenant_id", adminTenantID)
		h.loginErrorStatus(w, http.StatusForbidden,
			"This account ("+user.Email+") is not authorised for administration.")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookie,
		Value:    sess.ID,
		Path:     "/admin",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	h.Logger.Info("admin_login", "email", user.Email)
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// Logout invalidates the admin session and clears the cookie.
func (h *AdminConsoleHandlers) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(adminSessionCookie); err == nil && c.Value != "" {
		if sess, err := h.Store.GetSession(adminTenantID, c.Value); err == nil && sess.InvalidatedAt == nil {
			now := time.Now().UTC()
			sess.InvalidatedAt = &now
			_, _ = h.Store.UpdateSession(sess)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: adminSessionCookie, Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// adminSession is the resolved admin browser session.
type adminSession struct {
	Session Session
	User    User
}

// currentAdmin returns the signed-in admin iff the cookie maps to a live
// ten_admin session whose user is STILL on the allowlist. Re-checking the
// allowlist on every request means de-authorising an email takes effect at
// once, without waiting for the cookie to expire.
func (h *AdminConsoleHandlers) currentAdmin(w http.ResponseWriter, r *http.Request) (adminSession, bool) {
	c, err := r.Cookie(adminSessionCookie)
	if err != nil || c.Value == "" {
		return adminSession{}, false
	}
	sess, err := h.Store.GetSession(adminTenantID, c.Value)
	if err != nil || sess.InvalidatedAt != nil || time.Now().UTC().After(sess.ExpiresAt) {
		h.clearCookie(w)
		return adminSession{}, false
	}
	user, err := h.Store.GetUser(adminTenantID, sess.UserID)
	if err != nil || !h.isAllowed(user.Email) {
		h.clearCookie(w)
		return adminSession{}, false
	}
	return adminSession{Session: sess, User: user}, true
}

func (h *AdminConsoleHandlers) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: adminSessionCookie, Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func (h *AdminConsoleHandlers) loginError(w http.ResponseWriter, msg string) {
	h.loginErrorStatus(w, http.StatusBadRequest, msg)
}

func (h *AdminConsoleHandlers) loginErrorStatus(w http.ResponseWriter, status int, msg string) {
	h.page(w, status, "Admin sign-in failed", `<h1 class="err">Sign-in failed</h1>
<p class="muted">`+html.EscapeString(msg)+`</p>
<div class="actions"><a class="btn" href="/admin">Back</a></div>`)
}

// itoa is a tiny non-allocating-ish int formatter to keep the render code
// free of fmt imports for hot string building.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
