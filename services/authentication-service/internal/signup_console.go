package internal

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// signup_console.go implements the self-service onboarding funnel reached from
// the marketing site's "Get Started Free" CTA, plus the tenant-owner dashboard
// it drops the new customer on.
//
// Flow:
//
//	x-auth.com  ──"Get Started Free" + company name──▶  GET /admin/signup?company=…
//	GET  /admin/signup          → confirm form (company + optional app URL)
//	GET  /admin/signup/start    → Google login leg (rate-limited), into ten_signup
//	GET  /admin/signup/callback → read the verified email, PROVISION:
//	                                tenant (named after company, if free)
//	                                + owner user + session
//	                                + a random CONFIDENTIAL OIDC client (id+secret)
//	                              → one-time "here is your secret" screen
//
// Returning owners sign back in via GET /admin/owner/login (same Google leg),
// resolved to their workspace by owner email. The dashboard lives at /admin
// (role-aware — see Router): a signed-in owner sees ONLY their own tenant and
// client; a XentraNET staff member on ADMIN_EMAILS still gets the full
// all-tenants console.
//
// The signup leg reuses the exact pattern the /admin and /dev consoles use:
// run the social-login leg into a fixed staging tenant (ten_signup, like
// ten_admin / ten_developer), then read the provider-verified email from the
// returned session. The customer's real tenant is created separately, keyed by
// the company-derived slug.
type SignupConsoleHandlers struct {
	Store  Storage
	Logger *slog.Logger
	Issuer string
}

const (
	// signupTenantID is the staging tenant the Google login runs in, purely to
	// obtain a provider-verified email (mirrors ten_admin / ten_developer). The
	// customer's real workspace tenant is ten_<slug>, created at provisioning.
	signupTenantID = "ten_signup"

	// ownerSessionCookie carries "<tenantID>|<sessionID>" for the signed-in
	// tenant owner. The tenant id is part of the value because an owner's
	// session lives in their own ten_<slug>, not a fixed tenant, so currentOwner
	// needs it to scope the GetSession lookup. Scoped to /admin.
	ownerSessionCookie = "xauth_owner_session"
	signupStateCookie  = "xauth_signup_state"  // CSRF nonce for the signup leg
	signupIntentCookie = "xauth_signup_intent" // base64 JSON {company, redirect}
	ownerStateCookie   = "xauth_owner_state"   // CSRF nonce for owner re-login

	// maxSlugLen caps the slug (and thus the tenant id) length.
	maxSlugLen = 40
)

// signupIntent is the company name (and optional app redirect URI) carried
// across the Google round trip in a short-lived cookie.
type signupIntent struct {
	Company  string `json:"company"`
	Redirect string `json:"redirect,omitempty"`
}

// ownerSession is the resolved tenant-owner browser session: the workspace
// tenant, the owning user, and their single OIDC client (if found).
type ownerSession struct {
	Session   Session
	User      User
	Tenant    Tenant
	Client    OIDCClient
	HasClient bool
}

// ---- shared HTML shell ----

func (h *SignupConsoleHandlers) page(w http.ResponseWriter, status int, title, body string) {
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
main{width:min(820px,calc(100% - 32px));margin:44px auto 80px}
h1{font-size:clamp(2rem,5vw,3.2rem);line-height:1.04;margin:0 0 12px;letter-spacing:-.03em}
.muted{color:var(--muted)}.err{color:#ff8e8e}.ok{color:var(--accent)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:18px;margin-top:18px}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
button,.btn{appearance:none;border:0;border-radius:6px;background:var(--accent);color:#00150e;font-weight:800;padding:10px 14px;text-decoration:none;cursor:pointer;display:inline-flex;align-items:center;gap:8px}
.btn.secondary,button.secondary{background:#22232b;color:var(--text);border:1px solid var(--line)}
button.danger{background:var(--danger);color:#1a0000}
label{display:block;color:var(--muted);font-size:.83rem;margin:12px 0 5px}
input,textarea{width:100%;background:#0d0d12;border:1px solid var(--line);color:var(--text);border-radius:6px;padding:10px 12px;font:inherit}
textarea{resize:vertical}h2{font-size:1.2rem}h3{font-size:1rem}
code{font-family:"JetBrains Mono",ui-monospace,Menlo,Consolas,monospace}
.secret{font-family:"JetBrains Mono",ui-monospace,monospace;background:#0b0b10;border:1px solid var(--line);border-radius:8px;padding:14px;word-break:break-all}
table{width:100%;border-collapse:collapse;margin-top:8px}td{border-top:1px solid var(--line);padding:10px 8px;vertical-align:top}td:first-child{color:var(--muted);width:150px}
.warn{color:var(--warn)}
</style>
</head><body><main>`+body+`</main></body></html>`)
}

// ---- signup ----

// SignupLanding renders the confirm form. The company name arrives as ?company=
// from the marketing site; the visitor can correct it and optionally supply
// their application's redirect URI before signing in with Google.
func (h *SignupConsoleHandlers) SignupLanding(w http.ResponseWriter, r *http.Request) {
	company := strings.TrimSpace(r.URL.Query().Get("company"))
	h.page(w, http.StatusOK, "Create your X-Auth workspace", `<h1>Create your workspace</h1>
<p class="muted">Sign in with Google to provision a tenant and an OIDC client. Your company name becomes your workspace identity.</p>
<form class="panel" method="get" action="/admin/signup/start">
<label for="company">Company name</label>
<input id="company" name="company" value="`+html.EscapeString(company)+`" placeholder="Acme Inc" required autofocus>
<label for="redirect">Application redirect URI (optional — you can add this later)</label>
<input id="redirect" name="redirect" placeholder="https://app.acme.com/callback">
<div class="actions"><button type="submit">Continue with Google</button></div>
</form>
<p class="muted" style="margin-top:14px">Already have a workspace? <a href="/admin/owner/login">Sign in</a>.</p>`)
}

// SignupStart stashes the intent (company + optional redirect) and a CSRF nonce
// in short-lived cookies, then hands off to the Google login leg in ten_signup.
// Rate-limited per IP by the Router wrapper — this is the action that ends in a
// provisioned tenant.
func (h *SignupConsoleHandlers) SignupStart(w http.ResponseWriter, r *http.Request) {
	company := strings.TrimSpace(r.URL.Query().Get("company"))
	if company == "" {
		h.errorPage(w, http.StatusBadRequest, "A company name is required.", "/admin/signup")
		return
	}
	// Validate the slug up front so we fail before the Google round trip rather
	// than after it.
	if slugify(company) == "" {
		h.errorPage(w, http.StatusBadRequest,
			"That company name has no letters or digits to build a workspace id from. Try another.", "/admin/signup")
		return
	}
	intent := signupIntent{Company: company, Redirect: strings.TrimSpace(r.URL.Query().Get("redirect"))}
	raw, _ := json.Marshal(intent)

	state := randToken(32)
	h.setShortCookie(w, signupStateCookie, state, "/admin/signup")
	h.setShortCookie(w, signupIntentCookie, base64.RawURLEncoding.EncodeToString(raw), "/admin/signup")
	h.startGoogle(w, r, state, h.issuerURL("/admin/signup/callback"))
}

// SignupCallback finishes the Google leg, reads the verified email, and
// provisions the workspace.
func (h *SignupConsoleHandlers) SignupCallback(w http.ResponseWriter, r *http.Request) {
	email, ok := h.consumeGoogleEmail(w, r, signupStateCookie, "/admin/signup")
	if !ok {
		return
	}
	intentCookie, err := r.Cookie(signupIntentCookie)
	if err != nil || intentCookie.Value == "" {
		h.errorPage(w, http.StatusBadRequest, "Your signup session expired. Start again.", "/admin/signup")
		return
	}
	h.clearCookie(w, signupIntentCookie, "/admin/signup")
	var intent signupIntent
	if raw, err := base64.RawURLEncoding.DecodeString(intentCookie.Value); err == nil {
		_ = json.Unmarshal(raw, &intent)
	}

	// A returning owner who lands back in signup (e.g. used the marketing CTA
	// again) is sent to their existing workspace rather than told their email is
	// "taken" — owner_email is unique, so they can only have one.
	if existing, err := h.Store.GetTenantByOwnerEmail(email); err == nil {
		if sess, ok := h.mintOwnerSession(existing.ID, email); ok {
			h.setOwnerCookie(w, existing.ID, sess.ID, sess.ExpiresAt)
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
	}

	slug := slugify(intent.Company)
	if slug == "" {
		h.errorPage(w, http.StatusBadRequest, "That company name can't be turned into a workspace id. Try another.", "/admin/signup")
		return
	}
	if _, err := h.Store.GetTenantBySlug(slug); err == nil {
		h.errorPage(w, http.StatusConflict,
			`The name "`+intent.Company+`" is already taken. Please choose another.`, "/admin/signup")
		return
	} else if !errors.Is(err, ErrNotFound) {
		h.Logger.Error("signup_slug_lookup_failed", "err", err, "slug", slug)
		h.errorPage(w, http.StatusBadGateway, "Could not check name availability. Try again.", "/admin/signup")
		return
	}

	now := time.Now().UTC()
	tenantID := "ten_" + slug
	if _, err := h.Store.CreateTenant(Tenant{
		ID: tenantID, CompanyName: intent.Company, Slug: slug, OwnerEmail: email, CreatedAt: now,
	}); err != nil {
		if errors.Is(err, ErrConflict) {
			h.errorPage(w, http.StatusConflict,
				`The name "`+intent.Company+`" is already taken. Please choose another.`, "/admin/signup")
			return
		}
		h.Logger.Error("signup_create_tenant_failed", "err", err, "tenant_id", tenantID)
		h.errorPage(w, http.StatusBadGateway, "Could not create your workspace. Try again.", "/admin/signup")
		return
	}

	// Owner user + session in the new tenant.
	owner, err := h.Store.CreateUser(User{
		ID: "usr_" + uuid.NewString(), TenantID: tenantID, Email: email, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		h.Logger.Error("signup_create_owner_failed", "err", err, "tenant_id", tenantID)
		h.errorPage(w, http.StatusBadGateway, "Could not create your owner account.", "/admin/signup")
		return
	}
	sess, ok := h.mintOwnerSession(tenantID, email)
	if !ok {
		h.errorPage(w, http.StatusBadGateway, "Could not start your session.", "/admin/signup")
		return
	}
	_ = owner

	// Confidential OIDC client: random id + random secret. Only the SHA-256
	// hash is stored; the plaintext is shown to the owner exactly once below.
	clientID := "cli_" + randToken(8)
	secret := randToken(32)
	redirects, origins := redirectAndOrigin(intent.Redirect)
	if err := h.Store.PutClient(OIDCClient{
		ClientID:         clientID,
		ClientSecretHash: HashToken(secret),
		TenantID:         tenantID,
		RedirectURIs:     redirects,
		WebOrigins:       origins,
		CreatedAt:        now,
	}); err != nil {
		h.Logger.Error("signup_create_client_failed", "err", err, "tenant_id", tenantID)
		h.errorPage(w, http.StatusBadGateway, "Could not create your OIDC client.", "/admin/signup")
		return
	}

	h.setOwnerCookie(w, tenantID, sess.ID, sess.ExpiresAt)
	h.Logger.Info("signup_provisioned", "tenant_id", tenantID, "client_id", clientID, "owner", email)
	h.renderSecret(w, intent.Company, tenantID, clientID, secret, true)
}

// renderSecret shows the one-time client secret. firstTime distinguishes the
// post-signup screen from a later regeneration for copy.
func (h *SignupConsoleHandlers) renderSecret(w http.ResponseWriter, company, tenantID, clientID, secret string, firstTime bool) {
	lead := "Your OIDC client secret is shown below. This is the only time it will be displayed — copy it now and store it securely."
	title := "Workspace created"
	if !firstTime {
		title = "New client secret"
		lead = "Your client secret has been regenerated. The previous secret no longer works. This is the only time the new secret will be displayed — copy it now."
	}
	h.page(w, http.StatusOK, title, `<h1 class="ok">`+html.EscapeString(title)+`</h1>
<p class="muted">`+html.EscapeString(lead)+`</p>
<div class="panel"><table>
<tr><td>Workspace</td><td><strong>`+html.EscapeString(company)+`</strong></td></tr>
<tr><td>Tenant ID</td><td><code>`+html.EscapeString(tenantID)+`</code></td></tr>
<tr><td>Client ID</td><td><code>`+html.EscapeString(clientID)+`</code></td></tr>
</table>
<label style="margin-top:14px">Client secret (shown once)</label>
<div class="secret">`+html.EscapeString(secret)+`</div>
</div>
<div class="panel">
<h3 style="margin:0 0 8px">Starter kit</h3>
<p class="muted">A ready-to-run sign-in page wired to this client. Download both into one folder
and paste the secret above into <code>auth.js</code>.</p>
<div class="actions">
<a class="btn" href="/admin/owner/download/landing.html">Download landing.html</a>
<a class="btn secondary" href="/admin/owner/download/auth.js">Download auth.js</a>
</div>
</div>
<div class="actions"><a class="btn" href="/admin">Continue to dashboard</a></div>`)
}

// ---- owner re-login ----

// OwnerLogin starts the Google leg for a returning owner.
func (h *SignupConsoleHandlers) OwnerLogin(w http.ResponseWriter, r *http.Request) {
	state := randToken(32)
	h.setShortCookie(w, ownerStateCookie, state, "/admin")
	h.startGoogle(w, r, state, h.issuerURL("/admin/owner/callback"))
}

// OwnerCallback resolves the verified email to a workspace and sets the owner
// cookie. Unknown emails are nudged to sign up.
func (h *SignupConsoleHandlers) OwnerCallback(w http.ResponseWriter, r *http.Request) {
	email, ok := h.consumeGoogleEmail(w, r, ownerStateCookie, "/admin")
	if !ok {
		return
	}
	tenant, err := h.Store.GetTenantByOwnerEmail(email)
	if err != nil {
		h.page(w, http.StatusOK, "No workspace yet", `<h1>No workspace yet</h1>
<p class="muted">The account <strong>`+html.EscapeString(email)+`</strong> doesn't own a workspace.</p>
<div class="actions"><a class="btn" href="/admin/signup">Create one</a></div>`)
		return
	}
	sess, ok := h.mintOwnerSession(tenant.ID, email)
	if !ok {
		h.errorPage(w, http.StatusBadGateway, "Could not start your session.", "/admin/owner/login")
		return
	}
	h.setOwnerCookie(w, tenant.ID, sess.ID, sess.ExpiresAt)
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// OwnerLogout invalidates the owner session and clears the cookie.
func (h *SignupConsoleHandlers) OwnerLogout(w http.ResponseWriter, r *http.Request) {
	if owner, ok := h.currentOwner(w, r); ok {
		now := time.Now().UTC()
		owner.Session.InvalidatedAt = &now
		_, _ = h.Store.UpdateSession(owner.Session)
	}
	h.clearCookie(w, ownerSessionCookie, "/admin")
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// ---- owner dashboard ----

// Home renders the tenant-owner view of /admin: signed in → the single-tenant
// dashboard; signed out → the customer landing (owner sign-in + staff link).
// Router calls this only after confirming the visitor is NOT a staff admin.
func (h *SignupConsoleHandlers) Home(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		h.page(w, http.StatusOK, "X-Auth", `<h1>X-Auth</h1>
<p class="muted">Sign in to your workspace, or create one from the marketing site's "Get Started Free".</p>
<div class="actions"><a class="btn" href="/admin/owner/login">Sign in with Google</a><a class="btn secondary" href="/admin/signup">Create a workspace</a></div>
<p class="muted" style="margin-top:18px">XentraNET staff? <a href="/admin/login/google">Staff sign-in</a>.</p>`)
		return
	}
	h.renderDashboard(w, owner)
}

func (h *SignupConsoleHandlers) renderDashboard(w http.ResponseWriter, owner ownerSession) {
	var client string
	if !owner.HasClient {
		client = `<p class="err">No OIDC client found for this workspace.</p>`
	} else {
		c := owner.Client
		redirects := originList(c.RedirectURIs)
		origins := originList(c.WebOrigins)
		notice := ""
		if len(c.RedirectURIs) == 0 {
			notice = `<p class="warn">⚠️ No redirect URI set yet — add your application's callback URL below before starting an OIDC flow.</p>`
		}
		client = `<h2 style="margin-top:28px">OIDC client</h2>
<div class="panel"><table>
<tr><td>Client ID</td><td><code>` + html.EscapeString(c.ClientID) + `</code></td></tr>
<tr><td>Type</td><td>Confidential (client secret required)</td></tr>
<tr><td>Redirect URIs</td><td>` + redirects + `</td></tr>
<tr><td>Web origins</td><td>` + origins + `</td></tr>
</table>` + notice + `
<form method="post" action="/admin/owner/regenerate-secret" onsubmit="return confirm('Regenerate the client secret? The current secret stops working immediately.')" style="margin-top:14px">
<button class="danger" type="submit">Regenerate secret</button>
</form>
</div>
<div class="panel">
<h3 style="margin:0 0 8px">Update redirect URIs &amp; web origins</h3>
<form method="post" action="/admin/owner/client">
<label>Redirect URIs (one per line)</label>
<textarea name="redirect_uris" rows="3" placeholder="https://app.` + html.EscapeString(owner.Tenant.Slug) + `.com/callback">` + html.EscapeString(strings.Join(c.RedirectURIs, "\n")) + `</textarea>
<label>Web origins (one per line, for browser CORS)</label>
<textarea name="web_origins" rows="2" placeholder="https://app.` + html.EscapeString(owner.Tenant.Slug) + `.com">` + html.EscapeString(strings.Join(c.WebOrigins, "\n")) + `</textarea>
<div class="actions"><button type="submit">Save</button></div>
</form></div>
<h2 style="margin-top:28px">Starter kit</h2>
<div class="panel">
<p class="muted">A ready-to-run sign-in page wired to your client. Download both files into the
same folder, paste your client secret into <code>auth.js</code>, and serve them from an
origin listed under your client's web origins above.</p>
<div class="actions">
<a class="btn" href="/admin/owner/download/landing.html">Download landing.html</a>
<a class="btn secondary" href="/admin/owner/download/auth.js">Download auth.js</a>
</div>
</div>`
	}

	users, _ := h.Store.ListUsers(owner.Tenant.ID, 0, time.Time{})
	h.page(w, http.StatusOK, "Your X-Auth workspace", `<h1>`+html.EscapeString(owner.Tenant.CompanyName)+`</h1>
<p class="muted">Signed in as <strong>`+html.EscapeString(owner.User.Email)+`</strong> (workspace owner).</p>
<form method="post" action="/admin/owner/logout"><button class="secondary" type="submit">Sign out</button></form>
<h2 style="margin-top:28px">Workspace</h2>
<div class="panel"><table>
<tr><td>Company</td><td><strong>`+html.EscapeString(owner.Tenant.CompanyName)+`</strong></td></tr>
<tr><td>Tenant ID</td><td><code>`+html.EscapeString(owner.Tenant.ID)+`</code></td></tr>
<tr><td>Owner</td><td>`+html.EscapeString(owner.Tenant.OwnerEmail)+`</td></tr>
<tr><td>Users</td><td>`+itoa(len(users))+`</td></tr>
</table></div>`+client)
}

// RegenerateSecret issues a fresh client secret for the owner's client and
// shows it once.
func (h *SignupConsoleHandlers) RegenerateSecret(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		h.errorPage(w, http.StatusForbidden, "Sign in to your workspace first.", "/admin")
		return
	}
	if !owner.HasClient {
		h.errorPage(w, http.StatusBadRequest, "No client to regenerate.", "/admin")
		return
	}
	secret := randToken(32)
	c := owner.Client
	c.ClientSecretHash = HashToken(secret)
	if err := h.Store.PutClient(c); err != nil {
		h.Logger.Error("owner_regenerate_secret_failed", "err", err, "client_id", c.ClientID)
		h.errorPage(w, http.StatusBadGateway, "Could not regenerate the secret.", "/admin")
		return
	}
	h.Logger.Info("owner_secret_regenerated", "tenant_id", owner.Tenant.ID, "client_id", c.ClientID)
	h.renderSecret(w, owner.Tenant.CompanyName, owner.Tenant.ID, c.ClientID, secret, false)
}

// UpdateClient edits the owner client's redirect URIs and web origins.
func (h *SignupConsoleHandlers) UpdateClient(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		h.errorPage(w, http.StatusForbidden, "Sign in to your workspace first.", "/admin")
		return
	}
	if !owner.HasClient {
		h.errorPage(w, http.StatusBadRequest, "No client to update.", "/admin")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorPage(w, http.StatusBadRequest, "Could not parse the form.", "/admin")
		return
	}
	redirects := splitLines(r.PostForm.Get("redirect_uris"))
	origins := splitLines(r.PostForm.Get("web_origins"))
	for _, u := range redirects {
		parsed, err := url.Parse(u)
		if err != nil || !parsed.IsAbs() {
			h.errorPage(w, http.StatusBadRequest, "Redirect URI must be an absolute URL: "+u, "/admin")
			return
		}
	}
	for i, o := range origins {
		origins[i] = strings.TrimRight(o, "/")
	}
	c := owner.Client
	c.RedirectURIs = redirects
	c.WebOrigins = origins
	if err := h.Store.PutClient(c); err != nil {
		h.Logger.Error("owner_update_client_failed", "err", err, "client_id", c.ClientID)
		h.errorPage(w, http.StatusBadGateway, "Could not save the client.", "/admin")
		return
	}
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// ---- starter kit (downloadable integration files) ----

// DownloadAuthJS serves a tenant-specific auth.js — a dependency-free
// Authorization-Code + PKCE OIDC client pre-filled with the owner's issuer,
// client id, redirect URI, and tenant. Owner-only.
func (h *SignupConsoleHandlers) DownloadAuthJS(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		h.errorPage(w, http.StatusForbidden, "Sign in to your workspace first.", "/admin")
		return
	}
	if !owner.HasClient {
		h.errorPage(w, http.StatusBadRequest, "No client to generate a kit for.", "/admin")
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="auth.js"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, h.starterAuthJS(owner.Tenant, owner.Client))
}

// DownloadLanding serves a tenant-specific landing.html — a styled sign-in page
// that drives auth.js and renders the signed-in profile. Owner-only.
func (h *SignupConsoleHandlers) DownloadLanding(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		h.errorPage(w, http.StatusForbidden, "Sign in to your workspace first.", "/admin")
		return
	}
	if !owner.HasClient {
		h.errorPage(w, http.StatusBadRequest, "No client to generate a kit for.", "/admin")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="landing.html"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, h.starterLandingHTML(owner.Tenant, owner.Client))
}

// starterRedirectURI returns the client's first registered redirect URI, or a
// localhost default when none is set yet (the dashboard prompts the owner to
// register one).
func starterRedirectURI(c OIDCClient) string {
	if len(c.RedirectURIs) > 0 {
		return c.RedirectURIs[0]
	}
	return "http://localhost:8000/landing.html"
}

// starterAuthJS builds auth.js with a config header injected from the tenant's
// client. %q produces valid JS double-quoted string literals for these ASCII
// values, and the value itself can safely contain '%'.
func (h *SignupConsoleHandlers) starterAuthJS(t Tenant, c OIDCClient) string {
	issuer := strings.TrimRight(h.Issuer, "/")
	header := fmt.Sprintf(`// X-Auth starter client — tenant %q (%s)
// Authorization Code + PKCE against %s
//
// SECURITY NOTE: for a runnable quick-start this demo performs the /token
// exchange in the browser using the client secret. A CONFIDENTIAL client's
// secret must NOT ship in production browser code — move the /token call to
// your backend and keep the secret server-side. Also ensure the origin serving
// these files is listed as a Web origin on your client (X-Auth console →
// "Update web origins") so the browser /token + /userinfo calls pass CORS.
const XAUTH = {
  issuer: %q,
  clientId: %q,
  clientSecret: "PASTE_YOUR_CLIENT_SECRET_HERE",
  redirectUri: %q,
  scope: "openid profile email",
  tenantId: %q
};
`, t.CompanyName, t.ID, issuer, issuer, c.ClientID, starterRedirectURI(c), t.ID)
	return header + starterAuthJSBody
}

// starterLandingHTML builds landing.html. The template carries literal '%'
// (CSS), so company-name injection uses ReplaceAll rather than a format string.
func (h *SignupConsoleHandlers) starterLandingHTML(t Tenant, c OIDCClient) string {
	out := strings.ReplaceAll(starterLandingTemplate, "__COMPANY__", html.EscapeString(t.CompanyName))
	return out
}

// starterAuthJSBody is the static (config-independent) half of auth.js.
const starterAuthJSBody = `
// ---- PKCE OIDC client (no dependencies) ----
window.XAuth = (function () {
  const cfg = XAUTH;
  function b64url(buf) { return btoa(String.fromCharCode.apply(null, new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function rand(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return b64url(a.buffer); }
  async function sha256(s) { return crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)); }

  async function login() {
    const verifier = rand(32), state = rand(16);
    sessionStorage.setItem('xauth_verifier', verifier);
    sessionStorage.setItem('xauth_state', state);
    const challenge = b64url(await sha256(verifier));
    const u = new URL(cfg.issuer + '/authorize');
    u.search = new URLSearchParams({
      response_type: 'code', client_id: cfg.clientId, redirect_uri: cfg.redirectUri,
      scope: cfg.scope, state: state, code_challenge: challenge,
      code_challenge_method: 'S256', tenant_id: cfg.tenantId
    }).toString();
    location.href = u.toString();
  }

  async function handleRedirect() {
    const p = new URLSearchParams(location.search);
    const code = p.get('code');
    if (!code) return getSession();
    if (p.get('state') !== sessionStorage.getItem('xauth_state')) throw new Error('state mismatch');
    const body = new URLSearchParams({
      grant_type: 'authorization_code', code: code, redirect_uri: cfg.redirectUri,
      client_id: cfg.clientId, client_secret: cfg.clientSecret,
      code_verifier: sessionStorage.getItem('xauth_verifier')
    });
    const res = await fetch(cfg.issuer + '/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body });
    if (!res.ok) throw new Error('token exchange failed: ' + res.status + ' ' + (await res.text()));
    const tokens = await res.json();
    let user = null;
    try { const ui = await fetch(cfg.issuer + '/userinfo', { headers: { Authorization: 'Bearer ' + tokens.access_token } }); if (ui.ok) user = await ui.json(); } catch (e) {}
    const session = { tokens: tokens, user: user };
    sessionStorage.setItem('xauth_session', JSON.stringify(session));
    history.replaceState({}, '', cfg.redirectUri.split('?')[0]);
    return session;
  }

  function getSession() { try { return JSON.parse(sessionStorage.getItem('xauth_session') || 'null'); } catch (e) { return null; } }
  function logout() { sessionStorage.removeItem('xauth_session'); location.href = cfg.redirectUri.split('?')[0]; }
  return { login: login, handleRedirect: handleRedirect, getSession: getSession, logout: logout, config: cfg };
})();
`

// starterLandingTemplate is landing.html with __COMPANY__ placeholders.
const starterLandingTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__COMPANY__ — Sign in</title>
<style>
:root{color-scheme:dark;--bg:#09090b;--panel:#121217;--text:#dddde4;--muted:#8a8a96;--line:rgba(255,255,255,.11);--accent:#00e096}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(1200px 600px at 50% -10%,rgba(0,224,150,.08),transparent),var(--bg);color:var(--text);font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif}
.card{width:min(420px,calc(100% - 32px));background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:32px}
.brand{font-weight:800;letter-spacing:-.02em;color:var(--accent);margin-bottom:18px}
h1{margin:0 0 6px;font-size:1.7rem;letter-spacing:-.02em}.muted{color:var(--muted);margin:0 0 22px;font-size:.92rem}
button{appearance:none;border:0;border-radius:9px;background:var(--accent);color:#00150e;font-weight:800;padding:12px 16px;width:100%;cursor:pointer;font:inherit}
button.sec{background:#22232b;color:var(--text);border:1px solid var(--line);margin-top:10px}
pre{white-space:pre-wrap;word-break:break-word;background:#0b0b10;border:1px solid var(--line);border-radius:8px;padding:12px;font-family:"JetBrains Mono",ui-monospace,monospace;font-size:.82rem}
.err{color:#ff8e8e}
</style>
</head>
<body>
<main class="card">
  <div class="brand">__COMPANY__</div>
  <h1>Sign in</h1>
  <p class="muted">Secured by X-Auth</p>
  <button id="login">Sign in with X-Auth</button>
  <div id="profile" hidden></div>
  <pre id="error" class="err" hidden></pre>
</main>
<script src="auth.js"></script>
<script>
(async function () {
  const $ = function (id) { return document.getElementById(id); };
  $('login').addEventListener('click', function () { XAuth.login(); });
  try {
    const s = await XAuth.handleRedirect();
    if (s) {
      $('login').hidden = true;
      const u = (s && s.user) || {};
      const p = $('profile'); p.hidden = false;
      p.innerHTML = '<h1>Signed in</h1><p class="muted">' + (u.email || u.sub || '(no email claim)') + '</p>'
        + '<pre>' + JSON.stringify(s.user, null, 2) + '</pre>'
        + '<button class="sec" id="logout">Sign out</button>';
      $('logout').addEventListener('click', function () { XAuth.logout(); });
    }
  } catch (e) { const er = $('error'); er.hidden = false; er.textContent = String(e); }
})();
</script>
</body>
</html>
`

// ---- session helpers ----

// currentOwner resolves the signed-in owner from the ownerSessionCookie. The
// cookie value is "<tenantID>|<sessionID>": the session must be live in that
// tenant AND belong to the tenant's registered owner email (so an ordinary
// end-user with a session in the tenant cannot reach the owner dashboard).
func (h *SignupConsoleHandlers) currentOwner(w http.ResponseWriter, r *http.Request) (ownerSession, bool) {
	c, err := r.Cookie(ownerSessionCookie)
	if err != nil || c.Value == "" {
		return ownerSession{}, false
	}
	tenantID, sessionID, found := strings.Cut(c.Value, "|")
	if !found || tenantID == "" || sessionID == "" {
		h.clearCookie(w, ownerSessionCookie, "/admin")
		return ownerSession{}, false
	}
	sess, err := h.Store.GetSession(tenantID, sessionID)
	if err != nil || sess.InvalidatedAt != nil || time.Now().UTC().After(sess.ExpiresAt) {
		h.clearCookie(w, ownerSessionCookie, "/admin")
		return ownerSession{}, false
	}
	tenant, err := h.Store.GetTenant(tenantID)
	if err != nil {
		h.clearCookie(w, ownerSessionCookie, "/admin")
		return ownerSession{}, false
	}
	user, err := h.Store.GetUser(tenantID, sess.UserID)
	if err != nil || user.Email != tenant.OwnerEmail {
		h.clearCookie(w, ownerSessionCookie, "/admin")
		return ownerSession{}, false
	}
	client, hasClient := h.tenantClient(tenantID)
	return ownerSession{Session: sess, User: user, Tenant: tenant, Client: client, HasClient: hasClient}, true
}

// mintOwnerSession creates a fresh login session for email in tenantID,
// upserting the owner user by email so a re-login reuses the same user row.
func (h *SignupConsoleHandlers) mintOwnerSession(tenantID, email string) (Session, bool) {
	user, err := h.Store.GetUserByEmail(tenantID, email)
	if err != nil {
		now := time.Now().UTC()
		user, err = h.Store.CreateUser(User{
			ID: "usr_" + uuid.NewString(), TenantID: tenantID, Email: email, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			h.Logger.Error("owner_session_user_failed", "err", err, "tenant_id", tenantID)
			return Session{}, false
		}
	}
	now := time.Now().UTC()
	sess, err := h.Store.CreateSession(Session{
		ID: "ses_" + uuid.NewString(), TenantID: tenantID, UserID: user.ID, RiskLevel: RiskLow,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Duration(SessionTTLSeconds) * time.Second),
	})
	if err != nil {
		h.Logger.Error("owner_session_create_failed", "err", err, "tenant_id", tenantID)
		return Session{}, false
	}
	return sess, true
}

// tenantClient returns the OIDC client bound to tenantID (a self-service tenant
// has exactly one). Filtering ListClients keeps the storage interface small;
// the dashboard is low-traffic and only ever renders the matching client.
func (h *SignupConsoleHandlers) tenantClient(tenantID string) (OIDCClient, bool) {
	clients, err := h.Store.ListClients()
	if err != nil {
		return OIDCClient{}, false
	}
	for _, c := range clients {
		if c.TenantID == tenantID {
			return c, true
		}
	}
	return OIDCClient{}, false
}

// ---- Google leg helpers (shared by signup + owner re-login) ----

// startGoogle redirects to the social-login leg in ten_signup with the given
// CSRF state and our callback as redirect_uri.
func (h *SignupConsoleHandlers) startGoogle(w http.ResponseWriter, r *http.Request, state, callback string) {
	u, _ := url.Parse(h.issuerURL("/v1/social/google/authorize"))
	q := u.Query()
	q.Set("tenant_id", signupTenantID)
	q.Set("redirect_uri", callback)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// consumeGoogleEmail validates the CSRF state, reads the returned ten_signup
// session, and returns the provider-verified email. On any failure it renders
// an error page and returns ok=false.
func (h *SignupConsoleHandlers) consumeGoogleEmail(w http.ResponseWriter, r *http.Request, stateCookie, cookiePath string) (string, bool) {
	c, err := r.Cookie(stateCookie)
	if err != nil || c.Value == "" || c.Value != r.URL.Query().Get("state") {
		h.errorPage(w, http.StatusBadRequest, "State mismatch. Start again.", "/admin")
		return "", false
	}
	h.clearCookie(w, stateCookie, cookiePath)

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		h.errorPage(w, http.StatusBadRequest, "The Google callback did not include a session.", "/admin")
		return "", false
	}
	sess, err := h.Store.GetSession(signupTenantID, sessionID)
	if err != nil || sess.InvalidatedAt != nil || time.Now().UTC().After(sess.ExpiresAt) {
		h.errorPage(w, http.StatusBadRequest, "The returned session is not valid.", "/admin")
		return "", false
	}
	user, err := h.Store.GetUser(signupTenantID, sess.UserID)
	if err != nil || user.Email == "" {
		h.errorPage(w, http.StatusBadRequest, "Could not resolve your Google account.", "/admin")
		return "", false
	}
	return user.Email, true
}

// ---- cookie + misc helpers ----

func (h *SignupConsoleHandlers) setShortCookie(w http.ResponseWriter, name, value, path string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: path,
		MaxAge: int((10 * time.Minute).Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

func (h *SignupConsoleHandlers) setOwnerCookie(w http.ResponseWriter, tenantID, sessionID string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: ownerSessionCookie, Value: tenantID + "|" + sessionID, Path: "/admin",
		Expires: expires, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

func (h *SignupConsoleHandlers) clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: path, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func (h *SignupConsoleHandlers) errorPage(w http.ResponseWriter, status int, msg, backHref string) {
	h.page(w, status, "Signup", `<h1 class="err">Something went wrong</h1>
<p class="muted">`+html.EscapeString(msg)+`</p>
<div class="actions"><a class="btn" href="`+html.EscapeString(backHref)+`">Back</a></div>`)
}

func (h *SignupConsoleHandlers) issuerURL(path string) string {
	return strings.TrimRight(h.Issuer, "/") + path
}

// slugify lowercases s and collapses every run of non-[a-z0-9] into a single
// hyphen, trimming leading/trailing hyphens and capping the length. An empty
// result (e.g. a name with no ASCII letters/digits) signals "unusable".
func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	hyphen := false
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			hyphen = false
		default:
			if !hyphen && b.Len() > 0 {
				b.WriteByte('-')
				hyphen = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > maxSlugLen {
		out = strings.Trim(out[:maxSlugLen], "-")
	}
	return out
}

// redirectAndOrigin turns an optional app redirect URI into the client's
// redirect_uris and web_origins slices. An absent or invalid URI yields empty
// slices (the owner adds them later on the dashboard).
func redirectAndOrigin(raw string) (redirects, origins []string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return nil, nil
	}
	return []string{raw}, []string{u.Scheme + "://" + u.Host}
}

// clientIP extracts the caller's IP for rate-limit keying, honouring the first
// hop in X-Forwarded-For (Cloud Run sets it) and falling back to RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
