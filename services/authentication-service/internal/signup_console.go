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
	"github.com/xentranet/x-auth/pkg/smsx"
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

	// Verifier validates a phone number (Twilio Lookup) before the owner stores it
	// for a user. Optional/nil → no lookup validation (dev/stub).
	Verifier smsx.Verifier
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
	// ownerPickCookie holds the verified ten_signup session id between the login
	// callback and the workspace-picker selection (when an account manages more
	// than one tenant). Scoped to /admin/owner; re-validated server-side.
	ownerPickCookie = "xauth_owner_pick"

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

	slug := slugify(intent.Company)
	if slug == "" {
		h.errorPage(w, http.StatusBadRequest, "That company name can't be turned into a workspace id. Try another.", "/admin/signup")
		return
	}

	// A returning owner who re-runs signup for a workspace they already own is sent
	// straight there rather than hitting a slug conflict. Owners may now hold more
	// than one workspace, so we match on the requested slug — not just "any owned".
	for _, t := range h.ownedTenants(email) {
		if t.Slug == slug {
			if sess, ok := h.mintOwnerSession(t.ID, email); ok {
				h.setOwnerCookie(w, t.ID, sess.ID, sess.ExpiresAt)
				http.Redirect(w, r, "/admin", http.StatusFound)
				return
			}
		}
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
	// client. Provisioning these separately could orphan a tenant if a later step
	// failed — see the redirect_uris regression that motivated ProvisionTenant.
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
	tenants := h.ownedTenants(email)
	switch len(tenants) {
	case 0:
		h.page(w, http.StatusOK, "No workspace yet", `<h1>No workspace yet</h1>
<p class="muted">The account <strong>`+html.EscapeString(email)+`</strong> doesn't manage any workspace.</p>
<div class="actions"><a class="btn" href="/admin/signup">Create one</a></div>`)
	case 1:
		h.finishOwnerLogin(w, r, tenants[0].ID, email)
	default:
		// Multiple workspaces — keep the verified Google session and let them pick.
		h.setShortCookie(w, ownerPickCookie, r.URL.Query().Get("session_id"), "/admin/owner")
		h.renderTenantPicker(w, tenants)
	}
}

// OwnerSelect handles POST /admin/owner/select — the workspace the user picked
// when their account manages more than one. The verified Google email comes from
// the ten_signup session referenced by the pick cookie (re-validated here), and
// access to the chosen tenant is re-checked.
func (h *SignupConsoleHandlers) OwnerSelect(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(ownerPickCookie)
	if err != nil || c.Value == "" {
		h.errorPage(w, http.StatusBadRequest, "Your selection expired. Sign in again.", "/admin/owner/login")
		return
	}
	sess, err := h.Store.GetSession(signupTenantID, c.Value)
	if err != nil || sess.InvalidatedAt != nil || time.Now().UTC().After(sess.ExpiresAt) {
		h.clearCookie(w, ownerPickCookie, "/admin/owner")
		h.errorPage(w, http.StatusBadRequest, "Your selection expired. Sign in again.", "/admin/owner/login")
		return
	}
	user, err := h.Store.GetUser(signupTenantID, sess.UserID)
	if err != nil || user.Email == "" {
		h.errorPage(w, http.StatusBadRequest, "Could not resolve your account.", "/admin/owner/login")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorPage(w, http.StatusBadRequest, "Could not parse the form.", "/admin")
		return
	}
	tenantID := strings.TrimSpace(r.PostForm.Get("tenant_id"))
	if tenantID == "" || !h.isWorkspaceOwner(tenantID, user.Email) {
		h.errorPage(w, http.StatusForbidden, "You can't manage that workspace.", "/admin/owner/login")
		return
	}
	h.clearCookie(w, ownerPickCookie, "/admin/owner")
	// Invalidate the staging session so the pick can't be replayed.
	now := time.Now().UTC()
	sess.InvalidatedAt = &now
	_, _ = h.Store.UpdateSession(sess)
	h.finishOwnerLogin(w, r, tenantID, user.Email)
}

// OwnerSwitch handles POST /admin/owner/switch — a signed-in owner who manages
// more than one workspace switches the active one without signing in again. The
// target must be owned by the same verified account; the current owner session
// is invalidated and a fresh one minted for the target so the old workspace's
// cookie can't be reused.
func (h *SignupConsoleHandlers) OwnerSwitch(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		http.Redirect(w, r, "/admin/owner/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorPage(w, http.StatusBadRequest, "Could not parse the form.", "/admin")
		return
	}
	tenantID := strings.TrimSpace(r.PostForm.Get("tenant_id"))
	if tenantID == "" || tenantID == owner.Tenant.ID {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	if !h.isWorkspaceOwner(tenantID, owner.User.Email) {
		h.errorPage(w, http.StatusForbidden, "You can't manage that workspace.", "/admin")
		return
	}
	now := time.Now().UTC()
	owner.Session.InvalidatedAt = &now
	_, _ = h.Store.UpdateSession(owner.Session)
	h.finishOwnerLogin(w, r, tenantID, owner.User.Email)
}

// SetPhoneLogin handles POST /admin/owner/phone-login — the owner toggles the
// per-tenant SMS-OTP option shown on their hosted /login chooser.
func (h *SignupConsoleHandlers) SetPhoneLogin(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		http.Redirect(w, r, "/admin/owner/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorPage(w, http.StatusBadRequest, "Could not parse the form.", "/admin?tab=integration")
		return
	}
	enabled := r.PostForm.Get("enabled") == "true"
	if err := h.Store.SetTenantPhoneLogin(owner.Tenant.ID, enabled); err != nil {
		h.Logger.Error("owner_set_phone_login_failed", "err", err, "tenant_id", owner.Tenant.ID)
		h.errorPage(w, http.StatusBadGateway, "Could not update sign-in methods.", "/admin?tab=integration")
		return
	}
	h.Logger.Info("phone_login_toggled", "tenant_id", owner.Tenant.ID, "enabled", enabled, "by", owner.User.Email)
	http.Redirect(w, r, "/admin?tab=integration", http.StatusFound)
}

// SetUserPhone handles POST /admin/owner/identities/phone — the owner sets (or
// replaces) a verified phone number for one of their users. The number becomes
// a verified phone identity anchor, enabling SMS step-up and phone sign-in.
func (h *SignupConsoleHandlers) SetUserPhone(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		http.Redirect(w, r, "/admin/owner/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorPage(w, http.StatusBadRequest, "Could not parse the form.", "/admin?tab=users")
		return
	}
	userID := strings.TrimSpace(r.PostForm.Get("user_id"))
	phone, valid := normalizePhone(r.PostForm.Get("phone"))
	if userID == "" || !valid {
		h.errorPage(w, http.StatusBadRequest, "Enter a valid mobile number in international format, e.g. +15551234567.", "/admin?tab=users")
		return
	}
	// Confirm it's a real, sendable number (catches a missing country code, e.g.
	// a US number entered without the leading 1) before it's stored — otherwise
	// SMS step-up only fails later at send time.
	if !phoneLookupValid(r.Context(), h.Verifier, h.Logger, phone) {
		h.errorPage(w, http.StatusBadRequest,
			"That doesn't look like a valid phone number. Use the full international format, e.g. +14155551234.", "/admin?tab=users")
		return
	}
	if _, err := h.Store.GetUser(owner.Tenant.ID, userID); err != nil {
		h.errorPage(w, http.StatusBadRequest, "That user isn't in your workspace.", "/admin?tab=users")
		return
	}
	// The number can't already belong to a different user in this workspace.
	if existing, err := h.Store.GetIdentityAnchorByValue(owner.Tenant.ID, AnchorPhone, phone); err == nil && existing.UserID != userID {
		h.errorPage(w, http.StatusConflict, "That phone number is already assigned to another user.", "/admin?tab=users")
		return
	}
	// Replace any existing phone anchors for this user so "set" means "set".
	if anchors, err := h.Store.ListIdentityAnchors(owner.Tenant.ID); err == nil {
		for _, a := range anchors {
			if a.UserID == userID && a.Type == AnchorPhone {
				_ = h.Store.DeleteIdentityAnchor(owner.Tenant.ID, a.ID)
			}
		}
	}
	now := time.Now().UTC()
	if _, err := h.Store.CreateIdentityAnchor(IdentityAnchor{
		ID: "ian_" + uuid.NewString(), UserID: userID, TenantID: owner.Tenant.ID,
		Type: AnchorPhone, Value: phone, VerifiedAt: &now, CreatedAt: now,
	}); err != nil {
		h.Logger.Error("owner_set_phone_failed", "err", err, "tenant_id", owner.Tenant.ID, "user_id", userID)
		h.errorPage(w, http.StatusBadGateway, "Could not set the phone number.", "/admin?tab=users")
		return
	}
	h.Logger.Info("owner_user_phone_set", "tenant_id", owner.Tenant.ID, "user_id", userID, "by", owner.User.Email)
	http.Redirect(w, r, "/admin?tab=users", http.StatusFound)
}

// RemoveIdentity handles POST /admin/owner/identities/remove — the owner removes
// one of their users' non-primary anchors (e.g. a phone number). Tenant-scoped:
// an owner can only remove anchors in their own workspace.
func (h *SignupConsoleHandlers) RemoveIdentity(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		http.Redirect(w, r, "/admin/owner/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorPage(w, http.StatusBadRequest, "Could not parse the form.", "/admin?tab=users")
		return
	}
	anchorID := strings.TrimSpace(r.PostForm.Get("anchor_id"))
	if anchorID == "" {
		h.errorPage(w, http.StatusBadRequest, "anchor_id is required.", "/admin?tab=users")
		return
	}
	if err := h.Store.DeleteIdentityAnchor(owner.Tenant.ID, anchorID); err != nil && err != ErrNotFound {
		h.Logger.Error("owner_remove_identity_failed", "err", err, "tenant_id", owner.Tenant.ID)
		h.errorPage(w, http.StatusBadGateway, "Could not remove the identity.", "/admin?tab=users")
		return
	}
	h.Logger.Info("owner_identity_removed", "tenant_id", owner.Tenant.ID, "anchor_id", anchorID, "by", owner.User.Email)
	http.Redirect(w, r, "/admin?tab=users", http.StatusFound)
}

// finishOwnerLogin mints an owner session for email in tenantID, sets the owner
// cookie, and sends the user to their dashboard.
func (h *SignupConsoleHandlers) finishOwnerLogin(w http.ResponseWriter, r *http.Request, tenantID, email string) {
	sess, ok := h.mintOwnerSession(tenantID, email)
	if !ok {
		h.errorPage(w, http.StatusBadGateway, "Could not start your session.", "/admin/owner/login")
		return
	}
	h.setOwnerCookie(w, tenantID, sess.ID, sess.ExpiresAt)
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// renderTenantPicker shows the workspace chooser when an account manages more
// than one tenant.
func (h *SignupConsoleHandlers) renderTenantPicker(w http.ResponseWriter, tenants []Tenant) {
	var items strings.Builder
	for _, t := range tenants {
		items.WriteString(`<form method="post" action="/admin/owner/select" style="margin:0">` +
			`<input type="hidden" name="tenant_id" value="` + html.EscapeString(t.ID) + `">` +
			`<button type="submit" class="btn secondary" style="width:100%;justify-content:space-between">` +
			html.EscapeString(t.CompanyName) + ` <span class="muted">` + html.EscapeString(t.ID) + `</span></button></form>`)
	}
	h.page(w, http.StatusOK, "Choose a workspace", `<h1>Choose a workspace</h1>
<p class="muted">Your account manages more than one workspace. Pick the one to manage — you can switch by signing in again.</p>
<div class="panel" style="display:grid;gap:10px">`+items.String()+`</div>`)
}

// ownedTenants returns every workspace a Google email owns, slug-ordered. A
// single account may own more than one (staff can assign it), which is what
// drives the login workspace picker.
func (h *SignupConsoleHandlers) ownedTenants(email string) []Tenant {
	tenants, _ := h.Store.ListTenantsByOwnerEmail(email)
	return tenants
}

// isWorkspaceOwner reports whether email owns tenantID.
func (h *SignupConsoleHandlers) isWorkspaceOwner(tenantID, email string) bool {
	t, err := h.Store.GetTenant(tenantID)
	return err == nil && t.OwnerEmail == email
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
	h.renderDashboard(w, r, owner)
}

// dashboardTabs is the owner dashboard's section list (query ?tab=key).
var dashboardTabs = []struct{ key, label string }{
	{"overview", "Overview"},
	{"integration", "Integration"},
	{"transactions", "Transaction types"},
	{"users", "Users"},
	{"sessions", "Sessions"},
}

func (h *SignupConsoleHandlers) renderDashboard(w http.ResponseWriter, r *http.Request, owner ownerSession) {
	tab := r.URL.Query().Get("tab")
	known := false
	for _, t := range dashboardTabs {
		if t.key == tab {
			known = true
		}
	}
	if !known {
		tab = "overview"
	}

	var content string
	switch tab {
	case "integration":
		content = h.ownerIntegration(owner)
	case "transactions":
		content = h.transactionTypesSection(owner.Tenant.ID, owner.Client.ClientID)
	case "users":
		content = h.ownerUsers(owner)
	case "sessions":
		content = h.ownerSessions(owner)
	default:
		content = h.ownerOverview(owner)
	}

	var nav strings.Builder
	nav.WriteString(`<div class="actions" style="margin:18px 0 6px">`)
	for _, t := range dashboardTabs {
		cls := "btn secondary"
		if t.key == tab {
			cls = "btn"
		}
		nav.WriteString(`<a class="` + cls + `" href="/admin?tab=` + t.key + `">` + html.EscapeString(t.label) + `</a>`)
	}
	nav.WriteString(`</div>`)

	const role = "workspace owner"

	h.page(w, http.StatusOK, "Your X-Auth workspace",
		`<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap">
<div><h1 style="margin:0 0 4px">`+html.EscapeString(owner.Tenant.CompanyName)+`</h1>
<p class="muted" style="margin:0">Signed in as <strong>`+html.EscapeString(owner.User.Email)+`</strong> · `+role+`</p></div>
<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">`+h.workspaceSwitcher(owner)+`
<form method="post" action="/admin/owner/logout"><button class="secondary" type="submit">Sign out</button></form>
</div>
</div>`+nav.String()+content)
}

// workspaceSwitcher renders an inline workspace chooser for an owner who manages
// more than one workspace, so they can switch without signing in again. Empty
// when the account owns a single workspace.
func (h *SignupConsoleHandlers) workspaceSwitcher(owner ownerSession) string {
	owned := h.ownedTenants(owner.User.Email)
	if len(owned) <= 1 {
		return ""
	}
	var opts strings.Builder
	for _, t := range owned {
		sel := ""
		if t.ID == owner.Tenant.ID {
			sel = " selected"
		}
		opts.WriteString(`<option value="` + html.EscapeString(t.ID) + `"` + sel + `>` +
			html.EscapeString(t.CompanyName) + `</option>`)
	}
	return `<form method="post" action="/admin/owner/switch" style="display:flex;gap:8px;align-items:center;margin:0">
<label style="margin:0;color:var(--muted)">Workspace</label>
<select name="tenant_id" onchange="this.form.submit()" style="padding:8px 10px;background:#0d0d12;border:1px solid var(--line);color:var(--text);border-radius:6px;font:inherit">` + opts.String() + `</select>
<button class="secondary" type="submit">Switch</button>
</form>`
}

// ownerOverview is the workspace-summary tab.
func (h *SignupConsoleHandlers) ownerOverview(owner ownerSession) string {
	users, _ := h.Store.ListUsers(owner.Tenant.ID, 0, time.Time{})
	clientType := `<span class="muted">none</span>`
	if owner.HasClient {
		clientType = "Confidential"
		if owner.Client.ClientSecretHash == "" {
			clientType = "Public (PKCE)"
		}
	}
	return `<div class="panel"><table>
<tr><td>Company</td><td><strong>` + html.EscapeString(owner.Tenant.CompanyName) + `</strong></td></tr>
<tr><td>Tenant ID</td><td><code>` + html.EscapeString(owner.Tenant.ID) + `</code></td></tr>
<tr><td>Owner</td><td>` + html.EscapeString(owner.Tenant.OwnerEmail) + `</td></tr>
<tr><td>OIDC client</td><td>` + clientType + `</td></tr>
<tr><td>Users</td><td>` + itoa(len(users)) + `</td></tr>
</table></div>`
}

// ownerIntegration is the OIDC-client tab (config, redirect/origins, secret,
// browser quickstart).
func (h *SignupConsoleHandlers) ownerIntegration(owner ownerSession) string {
	if !owner.HasClient {
		return `<p class="err">No OIDC client found for this workspace.</p>`
	}
	c := owner.Client
	public := c.ClientSecretHash == ""
	notice := ""
	if len(c.RedirectURIs) == 0 {
		notice = `<p class="warn">⚠️ No redirect URI set yet — add your application's callback URL below before starting an OIDC flow.</p>`
	}
	typeLabel := "Confidential — client secret required"
	if public {
		typeLabel = "Public — PKCE, no client secret"
	}
	// Public client → offer the browser starter kit + let the owner mint a secret
	// to go confidential. Confidential → just the regenerate-secret action.
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
	return `<div class="panel"><table>
<tr><td>Client ID</td><td><code>` + html.EscapeString(c.ClientID) + `</code></td></tr>
<tr><td>Type</td><td>` + typeLabel + `</td></tr>
<tr><td>Redirect URIs</td><td>` + originList(c.RedirectURIs) + `</td></tr>
<tr><td>Web origins</td><td>` + originList(c.WebOrigins) + `</td></tr>
</table>` + notice + `</div>` + quickstart + `
<div class="panel">
<h3 style="margin:0 0 8px">Update redirect URIs &amp; web origins</h3>
<form method="post" action="/admin/owner/client">
<label>Redirect URIs (one per line)</label>
<textarea name="redirect_uris" rows="3" placeholder="https://app.` + html.EscapeString(owner.Tenant.Slug) + `.com/callback.html">` + html.EscapeString(strings.Join(c.RedirectURIs, "\n")) + `</textarea>
<label>Web origins (one per line, for browser CORS)</label>
<textarea name="web_origins" rows="2" placeholder="https://app.` + html.EscapeString(owner.Tenant.Slug) + `.com">` + html.EscapeString(strings.Join(c.WebOrigins, "\n")) + `</textarea>
<div class="actions"><button type="submit">Save</button></div>
</form></div>` + secretPanel + h.signInMethodsPanel(owner)
}

// signInMethodsPanel lets the owner toggle which methods appear on their hosted
// /login chooser. Google is always on; phone (SMS OTP) is opt-in and OFF by
// default because SMS delivery is still a stub.
func (h *SignupConsoleHandlers) signInMethodsPanel(owner ownerSession) string {
	checked := ""
	if owner.Tenant.PhoneLoginEnabled {
		checked = " checked"
	}
	return `<div class="panel">
<h3 style="margin:0 0 8px">Sign-in methods</h3>
<p class="muted">Google is always available on your hosted <code>/login</code> page. Phone (SMS one-time code) is optional.
⚠️ SMS delivery is not live yet — codes are <strong>not</strong> actually texted (the verification code is a fixed test value),
so leave phone off for real end users until it's announced.</p>
<form method="post" action="/admin/owner/phone-login">
<label style="display:flex;align-items:center;gap:8px;color:var(--text)">
<input type="checkbox" name="enabled" value="true"` + checked + ` style="width:auto"> Enable phone (SMS OTP) sign-in</label>
<div class="actions"><button type="submit">Save sign-in methods</button></div>
</form></div>`
}

// ownerUsers is the users tab.
func (h *SignupConsoleHandlers) ownerUsers(owner ownerSession) string {
	users, _ := h.Store.ListUsers(owner.Tenant.ID, 0, time.Time{})
	anchors, _ := h.Store.ListIdentityAnchors(owner.Tenant.ID)
	byUser := anchorsByUser(anchors)
	const inputStyle = `padding:8px 10px;background:#0d0d12;border:1px solid var(--line);color:var(--text);border-radius:6px;font:inherit`

	var rows strings.Builder
	if len(users) == 0 {
		rows.WriteString(`<tr><td colspan="3" class="muted">No users yet.</td></tr>`)
	}
	for _, u := range users {
		name := u.Email
		if name == "" {
			name = u.ID
		}
		// Current phone anchor (if any) with a remove control.
		phoneCell := `<span class="muted">none</span>`
		for _, a := range byUser[u.ID] {
			if a.Type != AnchorPhone {
				continue
			}
			phoneCell = `<code>` + html.EscapeString(a.Value) + `</code> ` +
				`<form method="post" action="/admin/owner/identities/remove" style="display:inline" onsubmit="return confirm('Remove this phone number?')">` +
				`<input type="hidden" name="anchor_id" value="` + html.EscapeString(a.ID) + `">` +
				`<button class="danger" type="submit" style="padding:4px 9px">Remove</button></form>`
			break
		}
		setForm := `<form method="post" action="/admin/owner/identities/phone" style="display:flex;gap:6px;margin-top:8px">` +
			`<input type="hidden" name="user_id" value="` + html.EscapeString(u.ID) + `">` +
			`<input type="tel" name="phone" placeholder="+15551234567" required style="` + inputStyle + `">` +
			`<button class="secondary" type="submit" style="padding:6px 12px">Set</button></form>`
		rows.WriteString(`<tr><td><code>` + html.EscapeString(name) + `</code></td><td>` + phoneCell + setForm +
			`</td><td class="muted">` + html.EscapeString(u.CreatedAt.UTC().Format(time.RFC3339)) + `</td></tr>`)
	}
	return `<p class="muted">Everyone who has signed in to your application. Email is the Google-verified primary anchor.
Set a verified <strong>phone number</strong> for any user manually — it enables SMS verification (step-up) and phone
sign-in for that account.</p>
<div class="panel"><table>
<thead><tr><th>User</th><th>Phone</th><th>Created (UTC)</th></tr></thead>
<tbody>` + rows.String() + `</tbody></table></div>`
}

// ownerSessions is the sessions tab (active sessions + live step-ups, revocable).
func (h *SignupConsoleHandlers) ownerSessions(owner ownerSession) string {
	now := time.Now().UTC()
	users, _ := h.Store.ListUsers(owner.Tenant.ID, 0, time.Time{})
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
	return sessionsPanel(sessions, emailByUser, now, revoke) +
		stepUpsPanel(h.StepUps.ListByTenant(owner.Tenant.ID), emailByUser, now)
}

// transactionTypesSection renders the tenant's transaction-type → protection-level
// mappings with add/delete controls. The dropdown lists all eight levels.
func (h *SignupConsoleHandlers) transactionTypesSection(tenantID, clientID string) string {
	types, _ := h.Store.ListTransactionTypes(tenantID)
	var rows strings.Builder
	if len(types) == 0 {
		rows.WriteString(`<tr><td colspan="3" class="muted">No transaction types yet — add one below.</td></tr>`)
	}
	for _, tt := range types {
		level := html.EscapeString(tt.ACR)
		if l, ok := protectionByACR(tt.ACR); ok {
			level = html.EscapeString(l.Band+" : "+l.Name) + ` <span class="muted">(rank ` + itoa(l.Rank) + `)</span>`
		}
		rows.WriteString(`<tr><td><code>` + html.EscapeString(tt.Name) + `</code></td><td>` + level + `</td><td>` +
			`<form method="post" action="/admin/owner/transaction-types/delete" onsubmit="return confirm('Delete this transaction type?')">` +
			`<input type="hidden" name="name" value="` + html.EscapeString(tt.Name) + `">` +
			`<button class="danger" type="submit">Delete</button></form></td></tr>`)
	}
	var opts strings.Builder
	for _, l := range protectionLevels {
		opts.WriteString(`<option value="` + html.EscapeString(l.ACR) + `">` +
			html.EscapeString(l.Band+" : "+l.Name) + ` — rank ` + itoa(l.Rank) + ` (` + html.EscapeString(l.ACR) + `)</option>`)
	}
	baseURL := strings.TrimRight(h.Issuer, "/")
	cid := clientID
	if cid == "" {
		cid = "YOUR_CLIENT_ID"
	}
	return `<h2 style="margin-top:28px">Transaction types</h2>
<p class="muted">Name the transactions your app performs and map each to the assurance level it requires.</p>
<div class="panel"><table>
<thead><tr><th>Transaction type</th><th>Protection level</th><th></th></tr></thead>
<tbody>` + rows.String() + `</tbody></table>
<form method="post" action="/admin/owner/transaction-types" style="margin-top:16px">
<label>Transaction type name</label>
<input type="text" name="name" placeholder="payment.high" required>
<label>Maps to protection level</label>
<select name="acr">` + opts.String() + `</select>
<div class="actions"><button type="submit">Add transaction type</button></div>
</form></div>

<h3 style="margin-top:24px">Calling the advice endpoint</h3>
<p class="muted">Once you've <strong>created your client and generated a secret</strong> (Client section above), your
backend asks X-Auth what assurance a transaction needs <em>before</em> it runs. Authenticate as your confidential
client (HTTP Basic <code>client_id:client_secret</code>) and POST the subject ids plus the
<code>transaction_type</code>:</p>
<div class="panel"><pre style="margin:0;overflow:auto"><code>curl -u "` + html.EscapeString(cid) + `:YOUR_CLIENT_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"session_id":"...","user_id":"...","device_id":"...","transaction_type":"payment.high"}' \
  ` + html.EscapeString(baseURL) + `/v1/advice</code></pre></div>
<p class="muted">The response returns a unique <code>transaction_id</code> for this lifecycle and the mapped protection
level:</p>
<div class="panel"><pre style="margin:0;overflow:auto"><code>{
  "transaction_id": "txn_…",
  "tenant_id": "` + html.EscapeString(tenantID) + `",
  "transaction_type": "payment.high",
  "advice": { "acr": "urn:xauth:protect:ultra:strict", "band": "ultra", "name": "strict", "rank": 8 }
}</code></pre></div>
<p class="muted">Send the user to <code>/authorize</code> requesting the advised <code>acr</code> via
<code>acr_values</code> <strong>and the <code>transaction_id</code></strong>. After the user authenticates, the
<code>transaction_id</code> comes back on your callback (a query parameter alongside <code>code</code>) and as a claim
in the issued <code>id_token</code> — so you can correlate the advice with the completed authentication:</p>
<div class="panel"><pre style="margin:0;overflow:auto"><code>` + html.EscapeString(baseURL) + `/authorize?client_id=` + html.EscapeString(cid) + `&amp;redirect_uri=…&amp;response_type=code
  &amp;code_challenge=…&amp;code_challenge_method=S256&amp;state=…
  &amp;acr_values=urn:xauth:protect:ultra:strict&amp;transaction_id=txn_…

→ callback: …/cb?code=…&amp;state=…&amp;transaction_id=txn_…</code></pre></div>
<p class="muted">A <strong>public</strong> client (no secret) can't call <code>/v1/advice</code> — use <strong>Regenerate
secret</strong> in the Client section to make it confidential. The <code>session_id</code>, <code>user_id</code> and
<code>device_id</code> you send are recorded with each call (X-Auth staff can review the advice history).</p>`
}

// CreateTransactionType handles POST /admin/owner/transaction-types.
func (h *SignupConsoleHandlers) CreateTransactionType(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		h.errorPage(w, http.StatusForbidden, "Sign in to your workspace first.", "/admin")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorPage(w, http.StatusBadRequest, "Could not parse the form.", "/admin")
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	acr := strings.TrimSpace(r.PostForm.Get("acr"))
	if name == "" {
		h.errorPage(w, http.StatusBadRequest, "A transaction type name is required.", "/admin")
		return
	}
	if _, ok := protectionByACR(acr); !ok {
		h.errorPage(w, http.StatusBadRequest, "Choose a valid protection level.", "/admin")
		return
	}
	err := h.Store.CreateTransactionType(TransactionType{
		TenantID: owner.Tenant.ID, Name: name, ACR: acr, CreatedAt: time.Now().UTC(),
	})
	if err == ErrConflict {
		h.errorPage(w, http.StatusConflict, "A transaction type with that name already exists.", "/admin")
		return
	}
	if err != nil {
		h.Logger.Error("owner_create_txntype_failed", "err", err, "tenant_id", owner.Tenant.ID)
		h.errorPage(w, http.StatusBadGateway, "Could not save the transaction type.", "/admin")
		return
	}
	h.Logger.Info("owner_txntype_created", "tenant_id", owner.Tenant.ID, "name", name, "acr", acr)
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// DeleteTransactionType handles POST /admin/owner/transaction-types/delete.
func (h *SignupConsoleHandlers) DeleteTransactionType(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		h.errorPage(w, http.StatusForbidden, "Sign in to your workspace first.", "/admin")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorPage(w, http.StatusBadRequest, "Could not parse the form.", "/admin")
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" {
		h.errorPage(w, http.StatusBadRequest, "name is required.", "/admin")
		return
	}
	if err := h.Store.DeleteTransactionType(owner.Tenant.ID, name); err != nil && err != ErrNotFound {
		h.Logger.Error("owner_delete_txntype_failed", "err", err, "tenant_id", owner.Tenant.ID)
		h.errorPage(w, http.StatusBadGateway, "Could not delete the transaction type.", "/admin")
		return
	}
	h.Logger.Info("owner_txntype_deleted", "tenant_id", owner.Tenant.ID, "name", name)
	http.Redirect(w, r, "/admin", http.StatusFound)
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
