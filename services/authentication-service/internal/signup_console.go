package internal

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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
//	GET  /admin/signup/callback → read the verified email, PROVISION (atomically):
//	                                tenant (named after company, if free)
//	                                + owner user + session
//	                                + a PUBLIC OIDC client (PKCE, no secret)
//	                              → "workspace ready" screen with a downloadable,
//	                                pre-filled browser starter kit (see quickstart.go).
//	                                Owners can mint a secret later for a server-side
//	                                (confidential) client.
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

	// StepUps surfaces live in-progress step-up attempts in the owner's session
	// view. Optional (nil renders an empty list).
	StepUps *StepUpTracker
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
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
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

	// Build the whole workspace up front, then commit it in one atomic unit:
	// tenant registry row, owner user, owner session, and the confidential OIDC
	// client. Provisioning these separately could orphan a tenant (and burn the
	// owner's email, which is UNIQUE) if a later step failed — see the
	// redirect_uris regression that motivated ProvisionTenant.
	owner := User{
		ID: "usr_" + uuid.NewString(), TenantID: tenantID, Email: email, CreatedAt: now, UpdatedAt: now,
	}
	sess := Session{
		ID: "ses_" + uuid.NewString(), TenantID: tenantID, UserID: owner.ID, RiskLevel: RiskLow,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Duration(SessionTTLSeconds) * time.Second),
	}
	// Public OIDC client: a browser SPA can't safely hold a secret, so the
	// workspace's default client authenticates with PKCE and NO secret
	// (ClientSecretHash empty marks it public — see extractClientCreds). The
	// owner downloads a pre-filled starter kit for it from the dashboard; if
	// they later need a server-side/confidential client they can mint a secret
	// there, which the quickstart screen and dashboard explain.
	clientID := "cli_" + randToken(8)
	redirects, origins := redirectAndOrigin(intent.Redirect)
	client := OIDCClient{
		ClientID:         clientID,
		ClientSecretHash: "",
		TenantID:         tenantID,
		RedirectURIs:     redirects,
		WebOrigins:       origins,
		CreatedAt:        now,
	}
	tenant := Tenant{
		ID: tenantID, CompanyName: intent.Company, Slug: slug, OwnerEmail: email, CreatedAt: now,
	}

	if err := h.Store.ProvisionTenant(tenant, owner, sess, client); err != nil {
		if errors.Is(err, ErrConflict) {
			h.errorPage(w, http.StatusConflict,
				`The name "`+intent.Company+`" is already taken. Please choose another.`, "/admin/signup")
			return
		}
		h.Logger.Error("signup_provision_failed", "err", err, "tenant_id", tenantID)
		h.errorPage(w, http.StatusBadGateway, "Could not create your workspace. Try again.", "/admin/signup")
		return
	}

	h.setOwnerCookie(w, tenantID, sess.ID, sess.ExpiresAt)
	h.Logger.Info("signup_provisioned", "tenant_id", tenantID, "client_id", clientID, "owner", email)
	h.renderWorkspaceReady(w, tenant, client)
}

// renderWorkspaceReady is the post-signup screen for a public-client workspace:
// the workspace identifiers plus the downloadable starter kit. There is no
// secret to show (public/PKCE client).
func (h *SignupConsoleHandlers) renderWorkspaceReady(w http.ResponseWriter, t Tenant, c OIDCClient) {
	h.page(w, http.StatusOK, "Workspace created", `<h1 class="ok">Workspace created</h1>
<p class="muted">Your X-Auth workspace is ready. It uses a public (PKCE) OIDC client — there's no secret to manage.</p>
<div class="panel"><table>
<tr><td>Workspace</td><td><strong>`+html.EscapeString(t.CompanyName)+`</strong></td></tr>
<tr><td>Tenant ID</td><td><code>`+html.EscapeString(t.ID)+`</code></td></tr>
<tr><td>Client ID</td><td><code>`+html.EscapeString(c.ClientID)+`</code></td></tr>
<tr><td>Type</td><td>Public — PKCE, no client secret</td></tr>
</table></div>`+
		h.quickstartPanel(c.ClientID)+
		`<div class="actions"><a class="btn" href="/admin">Continue to dashboard</a></div>`)
}

// quickstartPanel renders the "download your starter kit" block shared by the
// post-signup screen and the owner dashboard. The links hit DownloadQuickstart,
// which serves each file pre-filled for this workspace's public client.
func (h *SignupConsoleHandlers) quickstartPanel(clientID string) string {
	var links strings.Builder
	for _, a := range quickstartAssets {
		links.WriteString(`<a class="btn secondary" href="/admin/owner/download/` + a.Download + `" download>` + a.Download + `</a>`)
	}
	issuer := html.EscapeString(strings.TrimRight(h.Issuer, "/"))
	return `<h2 style="margin-top:28px">Quickstart — browser app</h2>
<div class="panel">
<p class="muted">A dependency-free OIDC client, pre-filled for this workspace
(<code>` + html.EscapeString(clientID) + `</code>). Download all three files into one folder on any static host:</p>
<div class="actions">` + links.String() + `</div>
<ol class="muted" style="margin:14px 0 0;padding-left:20px;line-height:1.7">
<li>Host <code>landing.html</code>, <code>callback.html</code> and <code>auth.js</code> together (e.g. <code>https://yourapp.com/</code>).</li>
<li>Add <code>https://yourapp.com/callback.html</code> as a redirect URI below.</li>
<li>Open <code>landing.html</code> and click <strong>Sign in</strong>. Discovery: <code>` + issuer + `/.well-known/openid-configuration</code>.</li>
</ol>
</div>`
}

// DownloadQuickstart serves one starter file, filled in for the signed-in
// owner's workspace, as an attachment. Public clients only — the files ship to
// the browser and must never carry a secret.
func (h *SignupConsoleHandlers) DownloadQuickstart(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		h.errorPage(w, http.StatusForbidden, "Sign in to your workspace first.", "/admin")
		return
	}
	if !owner.HasClient {
		h.errorPage(w, http.StatusBadRequest, "This workspace has no OIDC client yet.", "/admin")
		return
	}
	if owner.Client.ClientSecretHash != "" {
		h.errorPage(w, http.StatusBadRequest,
			"The browser starter kit is only available for a public (PKCE) client. Your client is confidential.", "/admin")
		return
	}
	asset, ok := quickstartAssetByName(r.PathValue("asset"))
	if !ok {
		h.errorPage(w, http.StatusNotFound, "Unknown starter file.", "/admin")
		return
	}
	body, err := renderQuickstart(asset, quickstartParamsFor(h.Issuer, owner.Tenant, owner.Client))
	if err != nil {
		h.Logger.Error("quickstart_render_failed", "err", err, "asset", asset.Download)
		h.errorPage(w, http.StatusInternalServerError, "Could not generate the file.", "/admin")
		return
	}
	w.Header().Set("Content-Type", asset.ContentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+asset.Download+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
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
		public := c.ClientSecretHash == ""
		redirects := originList(c.RedirectURIs)
		origins := originList(c.WebOrigins)
		notice := ""
		if len(c.RedirectURIs) == 0 {
			notice = `<p class="warn">⚠️ No redirect URI set yet — add your application's callback URL below before starting an OIDC flow.</p>`
		}
		typeLabel := "Confidential — client secret required"
		if public {
			typeLabel = "Public — PKCE, no client secret"
		}

		// Public client → offer the browser starter kit; let the owner mint a
		// secret to switch to a confidential/server-side client. Confidential
		// client → the regenerate-secret action (the starter kit is hidden,
		// since a browser can't hold the secret).
		quickstart := ""
		var secretPanel string
		if public {
			quickstart = h.quickstartPanel(c.ClientID)
			secretPanel = `<div class="panel">
<h3 style="margin:0 0 8px">Server-side app?</h3>
<p class="muted">This client is public (PKCE). If you integrate from a backend that can keep a secret, generate one — this converts the client to confidential and the browser quickstart no longer applies.</p>
<form method="post" action="/admin/owner/regenerate-secret" onsubmit="return confirm('Generate a client secret? The client becomes confidential.')">
<button class="secondary" type="submit">Generate client secret</button>
</form></div>`
		} else {
			secretPanel = `<div class="panel">
<form method="post" action="/admin/owner/regenerate-secret" onsubmit="return confirm('Regenerate the client secret? The current secret stops working immediately.')">
<button class="danger" type="submit">Regenerate secret</button>
</form></div>`
		}

		client = `<h2 style="margin-top:28px">OIDC client</h2>
<div class="panel"><table>
<tr><td>Client ID</td><td><code>` + html.EscapeString(c.ClientID) + `</code></td></tr>
<tr><td>Type</td><td>` + typeLabel + `</td></tr>
<tr><td>Redirect URIs</td><td>` + redirects + `</td></tr>
<tr><td>Web origins</td><td>` + origins + `</td></tr>
</table>` + notice + `</div>` + quickstart + `
<div class="panel">
<h3 style="margin:0 0 8px">Update redirect URIs &amp; web origins</h3>
<form method="post" action="/admin/owner/client">
<label>Redirect URIs (one per line)</label>
<textarea name="redirect_uris" rows="3" placeholder="https://app.` + html.EscapeString(owner.Tenant.Slug) + `.com/callback.html">` + html.EscapeString(strings.Join(c.RedirectURIs, "\n")) + `</textarea>
<label>Web origins (one per line, for browser CORS)</label>
<textarea name="web_origins" rows="2" placeholder="https://app.` + html.EscapeString(owner.Tenant.Slug) + `.com">` + html.EscapeString(strings.Join(c.WebOrigins, "\n")) + `</textarea>
<div class="actions"><button type="submit">Save</button></div>
</form></div>` + secretPanel
	}

	users, _ := h.Store.ListUsers(owner.Tenant.ID, 0, time.Time{})
	anchors, _ := h.Store.ListIdentityAnchors(owner.Tenant.ID)
	usersSection := `<h2 style="margin-top:28px">Users</h2>
<p class="muted">Everyone who has signed in to your application. Each is anchored by their Google-verified
email; phone and passkey anchors will appear here once those sign-in methods are available.</p>` +
		identityTable(users, anchors)

	// Session management: the owner's own workspace sessions + live step-ups,
	// with a revoke action.
	now := time.Now().UTC()
	sessions, _ := h.Store.ListSessions(owner.Tenant.ID, 0)
	emailByUser := emailIndex(users)
	revoke := func(sess Session) string {
		if sess.InvalidatedAt != nil || now.After(sess.ExpiresAt) {
			return ""
		}
		return `<form method="post" action="/admin/owner/sessions/revoke" onsubmit="return confirm('Revoke this session?')">` +
			`<input type="hidden" name="session_id" value="` + html.EscapeString(sess.ID) + `">` +
			`<button class="danger" type="submit">Revoke</button></form>`
	}
	sessionsSection := sessionsPanel(sessions, emailByUser, now, revoke) +
		stepUpsPanel(h.StepUps.ListByTenant(owner.Tenant.ID), emailByUser, now)

	h.page(w, http.StatusOK, "Your X-Auth workspace", `<h1>`+html.EscapeString(owner.Tenant.CompanyName)+`</h1>
<p class="muted">Signed in as <strong>`+html.EscapeString(owner.User.Email)+`</strong> (workspace owner).</p>
<form method="post" action="/admin/owner/logout"><button class="secondary" type="submit">Sign out</button></form>
<h2 style="margin-top:28px">Workspace</h2>
<div class="panel"><table>
<tr><td>Company</td><td><strong>`+html.EscapeString(owner.Tenant.CompanyName)+`</strong></td></tr>
<tr><td>Tenant ID</td><td><code>`+html.EscapeString(owner.Tenant.ID)+`</code></td></tr>
<tr><td>Owner</td><td>`+html.EscapeString(owner.Tenant.OwnerEmail)+`</td></tr>
<tr><td>Users</td><td>`+itoa(len(users))+`</td></tr>
</table></div>`+usersSection+sessionsSection+client)
}

// RevokeSession handles POST /admin/owner/sessions/revoke — the owner
// invalidates a session belonging to their own workspace.
func (h *SignupConsoleHandlers) RevokeSession(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		h.errorPage(w, http.StatusForbidden, "Sign in to your workspace first.", "/admin")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorPage(w, http.StatusBadRequest, "Could not parse the form.", "/admin")
		return
	}
	sessionID := strings.TrimSpace(r.PostForm.Get("session_id"))
	if sessionID == "" {
		h.errorPage(w, http.StatusBadRequest, "session_id is required.", "/admin")
		return
	}
	// Scoped to the owner's tenant — revokeSession's GetSession is tenant-scoped,
	// so an owner can only ever invalidate their own workspace's sessions.
	if err := revokeSession(h.Store, owner.Tenant.ID, sessionID); err != nil && err != ErrNotFound {
		h.Logger.Error("owner_revoke_session_failed", "err", err, "tenant_id", owner.Tenant.ID, "session_id", sessionID)
		h.errorPage(w, http.StatusBadGateway, "Could not revoke the session.", "/admin")
		return
	}
	h.Logger.Info("owner_session_revoked", "tenant_id", owner.Tenant.ID, "session_id", sessionID)
	http.Redirect(w, r, "/admin", http.StatusFound)
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
