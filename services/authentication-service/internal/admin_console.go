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

	// StepUps surfaces live in-progress step-up attempts in the per-tenant
	// session view. Optional (nil renders an empty list).
	StepUps *StepUpTracker

	// Events is the in-process recent-activity feed; Health probes platform
	// services. Both power the operator Monitoring domain. Optional (nil → the
	// panel renders an empty/placeholder state).
	Events *EventBuffer
	Health *HealthChecker
}

func NewAdminConsoleHandlers(store Storage, logger *slog.Logger, issuer string, emails, rootEmails, envOrigins []string) *AdminConsoleHandlers {
	allow := make(map[string]bool, len(emails)+len(rootEmails))
	for _, e := range emails {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			allow[e] = true
			// ADMIN_EMAILS members get the administrator role; an existing
			// disabled account is left disabled (deactivation must stick).
			ensureStaff(store, e, []string{"administrator"}, false)
		}
	}
	// ROOT_EMAILS are break-glass root accounts: always allowed to sign in and
	// re-granted EVERY staff role + reactivated on every boot, so the emergency
	// account can't be locked out by a DB edit, a missing grant, or an accidental
	// deactivation (ARCHITECTURE.md break-glass requirement, §A.8.2 / HIPAA).
	for _, e := range rootEmails {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			allow[e] = true
			ensureStaff(store, e, allStaffRoles, true)
		}
	}
	return &AdminConsoleHandlers{Store: store, Logger: logger, Issuer: issuer, AllowedEmails: allow, EnvOrigins: envOrigins}
}

// ensureStaff idempotently makes email an active staff_user carrying every role
// in roles. forceActive reactivates a disabled row (break-glass root must not be
// lockable); without it, a disabled account is left untouched so a deliberate
// deactivation of a normal admin sticks. Best-effort: store errors are ignored
// (this runs at construction, mirroring the original seed).
func ensureStaff(store Storage, email string, roles []string, forceActive bool) {
	staff, err := store.GetStaffUserByEmail(email)
	if err == ErrNotFound {
		id := "stf_" + randToken(16)
		now := time.Now().UTC()
		store.PutStaffUser(StaffUser{ID: id, Email: email, Active: true, CreatedAt: now, UpdatedAt: now})
		for _, r := range roles {
			store.AddStaffUserRole(id, r)
		}
		return
	}
	if err != nil {
		return
	}
	if forceActive && !staff.Active {
		staff.Active = true
		staff.UpdatedAt = time.Now().UTC()
		store.PutStaffUser(staff)
	} else if !staff.Active {
		return
	}
	have := map[string]bool{}
	if existing, err := store.GetStaffUserRoles(staff.ID); err == nil {
		for _, r := range existing {
			have[r] = true
		}
	}
	for _, r := range roles {
		if !have[r] {
			store.AddStaffUserRole(staff.ID, r)
		}
	}
}

func (h *AdminConsoleHandlers) isAllowed(email string) bool {
	return h.AllowedEmails[strings.ToLower(strings.TrimSpace(email))]
}

// render writes the full HTML shell with the standard admin chrome: a sticky top
// header carrying the X-Auth wordmark (left) and headerRight (right — e.g. the
// signed-in email + a Sign out button) above the page <main>. page() and
// pageSignedIn() are the two entry points.
func (h *AdminConsoleHandlers) render(w http.ResponseWriter, status int, title, headerRight, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `<!doctype html>
<html lang="en">
<head>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>`+html.EscapeString(title)+`</title>
<style>
:root{color-scheme:dark;--bg:#09090b;--panel:#121217;--text:#dddde4;--muted:#8a8a96;--line:rgba(255,255,255,.11);--accent:#00e096;--warn:#f0b429;--danger:#f04040}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;line-height:1.55}
header.topbar{position:sticky;top:0;z-index:10;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:11px 20px;background:rgba(9,9,11,.82);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.brand{display:inline-flex;align-items:center;gap:10px;text-decoration:none;color:var(--text);font-weight:800;letter-spacing:-.02em;font-size:1.02rem;min-width:0}
.brand svg{width:24px;height:24px;display:block;flex:none}
.brand .slash{color:var(--accent)}
.brand .sub{color:var(--muted);font-weight:500;font-size:.78rem;letter-spacing:.02em}
.topbar .right{display:flex;align-items:center;gap:12px;min-width:0}
.topbar .who{color:var(--muted);font-size:.85rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.topbar form{margin:0}
.topbar button{padding:7px 13px;font-size:.85rem}
main{width:min(980px,calc(100% - 32px));margin:36px auto 80px}
h1{font-size:clamp(1.8rem,5vw,3rem);line-height:1.02;margin:0 0 12px;letter-spacing:-.03em}
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
</head><body>
<header class="topbar"><a class="brand" href="/admin">`+xAuthFaviconSVG+`<span>X-AUTH<span class="slash">//</span></span><span class="sub">admin</span></a><div class="right">`+headerRight+`</div></header>
<main>`+body+`</main></body></html>`)
}

// page renders a chromed page with no signed-in controls — the sign-in screen
// and error pages.
func (h *AdminConsoleHandlers) page(w http.ResponseWriter, status int, title, body string) {
	h.render(w, status, title, "", body)
}

// pageSignedIn renders a chromed page whose header carries the signed-in email
// and a Sign out button in the top-right corner.
func (h *AdminConsoleHandlers) pageSignedIn(w http.ResponseWriter, status int, title, email, body string) {
	right := `<span class="who">` + html.EscapeString(email) + `</span>` +
		`<form method="post" action="/admin/logout"><button class="secondary" type="submit">Sign out</button></form>`
	h.render(w, status, title, right, body)
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

	domains := allowedDomains(admin.Roles)
	if len(domains) == 0 {
		h.pageSignedIn(w, http.StatusForbidden, "Access Denied", admin.User.Email, `<h1>Access Denied</h1><p class="err">No active roles.</p>`)
		return
	}

	currentDomain := r.URL.Query().Get("domain")
	if currentDomain == "" {
		currentDomain = domains[0]
	}

	allowed := false
	for _, d := range domains {
		if d == currentDomain {
			allowed = true
		}
	}
	if !allowed {
		h.pageSignedIn(w, http.StatusForbidden, "Access Denied", admin.User.Email, `<h1>Access Denied</h1><p class="err">You do not have access to this domain.</p><div class="actions"><a class="btn" href="/admin">Back</a></div>`)
		return
	}

	var nav strings.Builder
	nav.WriteString(`<div class="actions" style="margin-bottom: 24px;">`)
	for _, d := range domains {
		class := "btn secondary"
		if d == currentDomain {
			class = "btn"
		}
		title := d
		if len(title) > 0 {
			title = strings.ToUpper(title[:1]) + title[1:]
		}
		nav.WriteString(`<a class="` + class + `" href="/admin?domain=` + url.QueryEscape(d) + `">` + html.EscapeString(title) + `</a>`)
	}
	nav.WriteString(`</div>`)

	var content string
	switch currentDomain {
	case "tenants":
		content = h.renderTenantsDomain(w, r)
	case "documents":
		content = h.renderDocumentsDomain()
	case "marketing":
		content = h.renderMarketingDomain()
	case "monitoring":
		content = h.renderMonitoringDomain(r)
	}

	h.pageSignedIn(w, http.StatusOK, "X-Auth admin", admin.User.Email, `<h1>Administration</h1>
<p class="muted">Roles: `+html.EscapeString(strings.Join(admin.Roles, ", "))+`</p>
`+nav.String()+content)
}

func (h *AdminConsoleHandlers) renderTenantsDomain(w http.ResponseWriter, r *http.Request) string {
	tenants, err := h.Store.ListTenants()
	if err != nil {
		h.Logger.Error("admin_list_tenants_failed", "err", err)
		return `<h1 class="err">Could not load tenants</h1><p class="muted">The tenant listing is temporarily unavailable.</p>`
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
			rows.WriteString(`<tr><td><a href="/admin/tenants/` + url.PathEscape(t.TenantID) + `"><code>` + html.EscapeString(t.TenantID) + `</code></a></td>`)
			rows.WriteString(`<td class="num">` + itoa(t.Users) + `</td>`)
			rows.WriteString(`<td class="num">` + itoa(t.Sessions) + `</td>`)
			rows.WriteString(`<td class="muted">` + html.EscapeString(last) + `</td></tr>`)
		}
	}

	return `<h2 style="margin-top:28px">Tenants</h2>
<p class="muted">` + itoa(len(tenants)) + ` tenant(s). Derived from existing users and sessions — phase 1 has no tenant registry.</p>
<div class="panel"><table>
<thead><tr><th>Tenant</th><th>Users</th><th>Sessions</th><th>Last activity (UTC)</th></tr></thead>
<tbody>` + rows.String() + `</tbody></table></div>` +
		h.clientsSection()
}

func (h *AdminConsoleHandlers) renderDocumentsDomain() string {
	return `<h2>Documents</h2>
<p class="muted">Architecture and deployment documents. Editing requires the <code>documents:write</code> permission.</p>
<div class="panel">
	<ul>
		<li>Architecture (Readiness: In Progress)</li>
		<li>Service topology</li>
		<li>Deployment plans</li>
		<li>Design decisions</li>
		<li>Compliance mappings</li>
	</ul>
</div>`
}

func (h *AdminConsoleHandlers) renderMarketingDomain() string {
	return `<h2>Marketing</h2>
<p class="muted">Sales collateral, pitch decks, and business metrics.</p>
<div class="panel">
	<ul>
		<li>Slides</li>
		<li>Sales pipeline</li>
		<li>Customer overview</li>
		<li>Product positioning</li>
		<li>Growth metrics</li>
	</ul>
</div>`
}

// renderMonitoringDomain is the operator Monitoring surface (operator role,
// monitoring:read / monitoring:view_logs): a live health probe of the platform
// services and an in-process feed of recent activity. Both data sources are
// self-contained (see monitoring.go).
func (h *AdminConsoleHandlers) renderMonitoringDomain(r *http.Request) string {
	var b strings.Builder
	b.WriteString(`<h2>Monitoring</h2>
<p class="muted">Operator view — live service health and recent activity (<code>monitoring:read</code>).</p>`)

	// Services panel — live probe.
	b.WriteString(`<div class="panel"><h3>Services</h3>`)
	var health []ServiceHealth
	if h.Health != nil {
		health = h.Health.Snapshot(r.Context())
	}
	if len(health) == 0 {
		b.WriteString(`<p class="muted">No service targets configured.</p>`)
	} else {
		b.WriteString(`<p class="muted">Live probe of each service (cached ~15s). The internal services are scale-to-zero, so the first probe after idle shows cold-start latency.</p>
<table><thead><tr><th>Service</th><th>Status</th><th class="num">Latency</th></tr></thead><tbody>`)
		for _, s := range health {
			b.WriteString(`<tr><td><code>` + html.EscapeString(s.Name) + `</code></td><td>` + healthBadge(s) + `</td><td class="num">` + latencyText(s) + `</td></tr>`)
		}
		b.WriteString(`</tbody></table>`)
	}
	b.WriteString(`</div>`)

	// Recent activity panel — in-process log ring buffer.
	b.WriteString(`<div class="panel"><h3>Recent activity</h3>`)
	var events []LogEvent
	if h.Events != nil {
		events = h.Events.Recent(60)
	}
	if len(events) == 0 {
		b.WriteString(`<p class="muted">No events captured yet on this instance. Activity — sign-ins, step-ups, CAEP deliveries, errors — appears here as it happens.</p>`)
	} else {
		b.WriteString(`<p class="muted">Newest first — this instance's in-memory feed (resets on restart; single replica).</p>
<table><thead><tr><th>Time (UTC)</th><th>Level</th><th>Event</th><th>Details</th></tr></thead><tbody>`)
		for _, e := range events {
			b.WriteString(`<tr><td><code>` + e.Time.UTC().Format("15:04:05") + `</code></td><td>` + levelBadge(e.Level) +
				`</td><td><code>` + html.EscapeString(e.Msg) + `</code></td><td class="muted">` + html.EscapeString(e.Attrs) + `</td></tr>`)
		}
		b.WriteString(`</tbody></table>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// healthBadge renders a coloured status dot + label for a service probe result.
func healthBadge(s ServiceHealth) string {
	color, label := "var(--muted)", "Unknown"
	switch s.Status {
	case "up":
		color, label = "var(--accent)", "Healthy"
	case "errors":
		color, label = "var(--warn)", "Errors"
	case "down":
		color, label = "var(--danger)", "Unreachable"
	}
	return `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:` + color +
		`;margin-right:7px;vertical-align:middle"></span><span style="color:` + color + `">` + label + `</span>`
}

// latencyText renders the probe round-trip, or a dash when there was no response.
func latencyText(s ServiceHealth) string {
	if s.Status == "down" || s.Status == "unknown" {
		return `<span class="muted">—</span>`
	}
	return itoa(int(s.Latency.Milliseconds())) + ` ms`
}

// levelBadge colours a log level for the recent-activity feed.
func levelBadge(l slog.Level) string {
	color := "var(--muted)"
	switch {
	case l >= slog.LevelError:
		color = "var(--danger)"
	case l >= slog.LevelWarn:
		color = "var(--warn)"
	case l >= slog.LevelInfo:
		color = "var(--accent)"
	}
	return `<span style="color:` + color + `;font-weight:600">` + html.EscapeString(l.String()) + `</span>`
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

// TenantDetail renders the identities for a single tenant — the master-admin
// drill-down from the tenant listing. Staff-only (currentAdmin). Works for both
// registry tenants (shows the company name) and derived/console tenants
// (ten_admin, …, which have no registry row — the id is shown instead).
func (h *AdminConsoleHandlers) TenantDetail(w http.ResponseWriter, r *http.Request) {
	admin, ok := h.currentAdmin(w, r)
	if !ok || !hasPermission(admin.Roles, "tenants:read") {
		h.loginErrorStatus(w, http.StatusForbidden, "Sign in as an administrator first.")
		return
	}
	tenantID := r.PathValue("id")
	if tenantID == "" {
		h.pageSignedIn(w, http.StatusBadRequest, "X-Auth admin", admin.User.Email, `<h1 class="err">Missing tenant</h1>
<div class="actions"><a class="btn" href="/admin">Back</a></div>`)
		return
	}

	// Registry name when this is a self-service tenant; the raw id otherwise.
	name := tenantID
	if t, err := h.Store.GetTenant(tenantID); err == nil {
		name = t.CompanyName
	}

	users, err := h.Store.ListUsers(tenantID, 0, time.Time{})
	if err != nil {
		h.Logger.Error("admin_tenant_users_failed", "err", err, "tenant_id", tenantID)
		h.pageSignedIn(w, http.StatusBadGateway, "X-Auth admin", admin.User.Email, `<h1 class="err">Could not load identities</h1>
<div class="actions"><a class="btn" href="/admin">Back</a></div>`)
		return
	}
	anchors, err := h.Store.ListIdentityAnchors(tenantID)
	if err != nil {
		h.Logger.Error("admin_tenant_anchors_failed", "err", err, "tenant_id", tenantID)
		h.pageSignedIn(w, http.StatusBadGateway, "X-Auth admin", admin.User.Email, `<h1 class="err">Could not load identities</h1>
<div class="actions"><a class="btn" href="/admin">Back</a></div>`)
		return
	}

	// Session management: active sessions + live in-progress step-ups, with a
	// staff revoke action.
	now := time.Now().UTC()
	sessions, err := h.Store.ListSessions(tenantID, 0)
	if err != nil {
		h.Logger.Error("admin_tenant_sessions_failed", "err", err, "tenant_id", tenantID)
		sessions = nil
	}
	emailByUser := emailIndex(users)
	revoke := func(sess Session) string {
		if sess.InvalidatedAt != nil || now.After(sess.ExpiresAt) {
			return ""
		}
		return `<form method="post" action="/admin/sessions/revoke" onsubmit="return confirm('Revoke this session?')">` +
			`<input type="hidden" name="session_id" value="` + html.EscapeString(sess.ID) + `">` +
			`<input type="hidden" name="tenant_id" value="` + html.EscapeString(tenantID) + `">` +
			`<button class="danger" type="submit">Revoke</button></form>`
	}

	h.pageSignedIn(w, http.StatusOK, "Tenant identities", admin.User.Email, `<h1>`+html.EscapeString(name)+`</h1>
<p class="muted">Tenant <code>`+html.EscapeString(tenantID)+`</code> — `+itoa(len(users))+` identit`+plural(len(users), "y", "ies")+`.</p>
<div class="actions"><a class="btn secondary" href="/admin">← All tenants</a></div>
<h2 style="margin-top:24px">Identities</h2>
<p class="muted">Every identity is anchored by its Google-verified email. Phone and passkey are additional
anchor types: the store is ready for them, and they will appear here once the validation flows are built.</p>`+
		identityTable(users, anchors)+
		sessionsPanel(sessions, emailByUser, now, revoke)+
		stepUpsPanel(h.StepUps.ListByTenant(tenantID), emailByUser, now)+
		deviceSignalsPanel(h.deviceSignals(tenantID), emailByUser))
}

// deviceSignals fetches the tenant's recent device observations, swallowing
// errors (the panel renders "none" rather than failing the whole page).
func (h *AdminConsoleHandlers) deviceSignals(tenantID string) []DeviceSignal {
	sigs, err := h.Store.ListDeviceSignals(tenantID, 50)
	if err != nil {
		h.Logger.Error("admin_device_signals_failed", "err", err, "tenant_id", tenantID)
		return nil
	}
	return sigs
}

// RevokeSession handles POST /admin/sessions/revoke — staff invalidates any
// tenant's session (sets invalidated_at).
func (h *AdminConsoleHandlers) RevokeSession(w http.ResponseWriter, r *http.Request) {
	admin, ok := h.currentAdmin(w, r)
	if !ok || !hasPermission(admin.Roles, "tenants:manage_sessions") {
		h.loginErrorStatus(w, http.StatusForbidden, "Sign in as an administrator first.")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.loginError(w, "Could not parse the form.")
		return
	}
	tenantID := strings.TrimSpace(r.PostForm.Get("tenant_id"))
	sessionID := strings.TrimSpace(r.PostForm.Get("session_id"))
	if tenantID == "" || sessionID == "" {
		h.loginError(w, "tenant_id and session_id are required.")
		return
	}
	if err := revokeSession(h.Store, tenantID, sessionID); err != nil && err != ErrNotFound {
		h.Logger.Error("admin_revoke_session_failed", "err", err, "tenant_id", tenantID, "session_id", sessionID)
		h.loginErrorStatus(w, http.StatusBadGateway, "Could not revoke the session.")
		return
	}
	h.Logger.Info("admin_session_revoked", "tenant_id", tenantID, "session_id", sessionID)
	http.Redirect(w, r, "/admin/tenants/"+url.PathEscape(tenantID), http.StatusFound)
}

// plural picks the singular or plural suffix for n.
func plural(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

// RegisterClient handles POST /admin/clients.
func (h *AdminConsoleHandlers) RegisterClient(w http.ResponseWriter, r *http.Request) {
	admin, ok := h.currentAdmin(w, r)
	if !ok || !hasPermission(admin.Roles, "tenants:manage_settings") {
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
	admin, ok := h.currentAdmin(w, r)
	if !ok || !hasPermission(admin.Roles, "tenants:manage_settings") {
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
	Session   Session
	User      User
	StaffUser StaffUser
	Roles     []string
}

// currentAdmin returns the signed-in admin iff the cookie maps to a live
// ten_admin session whose user is STILL on the allowlist, and they have an active
// staff account with roles.
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
	staff, err := h.Store.GetStaffUserByEmail(user.Email)
	if err != nil || !staff.Active {
		h.clearCookie(w)
		return adminSession{}, false
	}
	roles, err := h.Store.GetStaffUserRoles(staff.ID)
	if err != nil || len(roles) == 0 {
		h.clearCookie(w)
		return adminSession{}, false
	}
	return adminSession{Session: sess, User: user, StaffUser: staff, Roles: roles}, true
}

// allStaffRoles is the canonical set of staff roles a break-glass root account
// receives. Keep it in sync with rolePermissions/allowedDomains below — every
// role handled there must appear here so "all roles" really means all of them.
var allStaffRoles = []string{"administrator", "architect", "executive", "operator"}

func rolePermissions(role string) []string {
	switch role {
	case "administrator":
		return []string{"tenants:read", "tenants:manage_sessions", "tenants:manage_settings"}
	case "architect":
		return []string{"documents:read", "documents:write"}
	case "executive":
		return []string{"marketing:read", "marketing:view_pipeline"}
	case "operator":
		return []string{"monitoring:read", "monitoring:view_logs"}
	}
	return nil
}

func hasPermission(roles []string, perm string) bool {
	for _, r := range roles {
		for _, p := range rolePermissions(r) {
			if p == perm {
				return true
			}
		}
	}
	return false
}

func allowedDomains(roles []string) []string {
	hasDomain := map[string]bool{}
	for _, r := range roles {
		switch r {
		case "administrator":
			hasDomain["tenants"] = true
		case "architect":
			hasDomain["documents"] = true
		case "executive":
			hasDomain["marketing"] = true
		case "operator":
			hasDomain["monitoring"] = true
		}
	}
	var out []string
	if hasDomain["tenants"] {
		out = append(out, "tenants")
	}
	if hasDomain["documents"] {
		out = append(out, "documents")
	}
	if hasDomain["marketing"] {
		out = append(out, "marketing")
	}
	if hasDomain["monitoring"] {
		out = append(out, "monitoring")
	}
	return out
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
