package internal

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xentranet/x-auth/pkg/httpx"
)

const (
	devConsoleTenantID      = "ten_developer"
	devConsoleSessionCookie = "xauth_dev_session"
	devConsoleStateCookie   = "xauth_dev_state"
	devOIDCFlowTTL          = 10 * time.Minute
)

// DeveloperConsoleHandlers is a small hosted developer surface for local/stage
// testing. A Google-authenticated user can register a public OIDC client and
// launch a full code+PKCE round trip, optionally asking /authorize for an ACR
// such as SMS OTP. The registered client storage is the normal OIDC client
// table; the browser session is backed by the social-login session cookie.
//
// This is deliberately modest, not a full tenant admin product: registered
// clients are public PKCE clients and ownership is enforced only at the hosted
// console layer until dynamic client registration grows first-class ownership.
type DeveloperConsoleHandlers struct {
	Store  Storage
	Logger *slog.Logger
	Issuer string

	mu           sync.Mutex
	flows        map[string]devOIDCFlow
	flowsOnce    sync.Once
	registered   map[string]OIDCClient
	registerOnce sync.Once
}

type devOIDCFlow struct {
	ClientID     string
	RedirectURI  string
	CodeVerifier string
	ACR          string
	CreatedAt    time.Time
}

type developerSession struct {
	Session Session
	User    User
}

func (h *DeveloperConsoleHandlers) page(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
h1{font-size:clamp(2rem,5vw,3.5rem);line-height:1.02;margin:0 0 12px;letter-spacing:-.03em}
h2{font-size:1.15rem;margin:28px 0 12px}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:18px}.full{grid-column:1/-1}
label{display:block;color:var(--muted);font-size:.83rem;margin:12px 0 5px}input,textarea,select{width:100%;background:#0d0d12;border:1px solid var(--line);color:var(--text);border-radius:6px;padding:10px 12px;font:inherit}
textarea{min-height:94px;resize:vertical}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
button,.btn{appearance:none;border:0;border-radius:6px;background:var(--accent);color:#00150e;font-weight:800;padding:10px 14px;text-decoration:none;cursor:pointer;display:inline-flex;align-items:center;gap:8px}
.btn.secondary,button.secondary{background:#22232b;color:var(--text);border:1px solid var(--line)}.btn.warn{background:var(--warn);color:#171200}
code,pre{font-family:"JetBrains Mono",ui-monospace,Menlo,Consolas,monospace}pre{white-space:pre-wrap;word-break:break-word;background:#0b0b10;border:1px solid var(--line);border-radius:8px;padding:14px}
.err{color:#ff8e8e}.ok{color:var(--accent)}table{width:100%;border-collapse:collapse}td{border-top:1px solid var(--line);padding:9px 4px;vertical-align:top}td:first-child{color:var(--muted);width:160px}
@media(max-width:720px){.grid{grid-template-columns:1fr}}
</style>
</head><body><main>`+body+`</main></body></html>`)
}

// Home renders the hosted developer console. Signed-out users see a Google
// sign-in button; signed-in users can register and immediately test a client.
func (h *DeveloperConsoleHandlers) Home(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.currentSession(w, r)
	if !ok {
		h.page(w, "X-Auth developer console", `<h1>X-Auth developer console</h1>
<p class="muted">Sign in with Google, then register a public OIDC client and run a code+PKCE round trip with optional SMS OTP ACR.</p>
<div class="actions"><a class="btn" href="/dev/login/google">Sign in with Google</a></div>`)
		return
	}

	clients := h.registeredClients()
	clientRows := `<p class="muted">No clients registered in this process yet.</p>`
	if len(clients) > 0 {
		var b strings.Builder
		b.WriteString(`<table>`)
		for _, c := range clients {
			ruri := ""
			if len(c.RedirectURIs) > 0 {
				ruri = c.RedirectURIs[0]
			}
			b.WriteString(`<tr><td><code>` + html.EscapeString(c.ClientID) + `</code></td><td>`)
			b.WriteString(`<div class="muted">Redirect URI: <code>` + html.EscapeString(ruri) + `</code></div>`)
			b.WriteString(`<div class="actions"><a class="btn secondary" href="/dev/oidc/start?client_id=` + url.QueryEscape(c.ClientID) + `">OIDC round trip</a>`)
			b.WriteString(`<a class="btn warn" href="/dev/oidc/start?client_id=` + url.QueryEscape(c.ClientID) + `&acr=sms">OIDC + SMS OTP</a>`)
			b.WriteString(`<a class="btn warn" href="/dev/oidc/start?client_id=` + url.QueryEscape(c.ClientID) + `&acr=fido2">OIDC + FIDO2</a></div>`)
			b.WriteString(`</td></tr>`)
		}
		b.WriteString(`</table>`)
		clientRows = b.String()
	}

	suffix := strings.TrimPrefix(sess.User.ID, "usr_")
	if len(suffix) > 8 {
		suffix = suffix[:8]
	}
	if suffix == "" {
		suffix = randToken(6)
	}
	defaultClientID := "client_" + suffix
	defaultRedirect := h.devOIDCCallbackURL()
	h.page(w, "X-Auth developer console", `<h1>OIDC client lab</h1>
<p class="muted">Signed in as <strong>`+html.EscapeString(sess.User.Name)+`</strong> (`+html.EscapeString(sess.User.Email)+`).</p>
<div class="actions"><form method="post" action="/dev/logout"><button class="secondary" type="submit">Sign out</button></form></div>
<div class="grid">
<section class="panel">
<h2>Register a public OIDC client</h2>
<form method="post" action="/dev/clients">
<label for="client_id">Client ID</label>
<input id="client_id" name="client_id" value="`+html.EscapeString(defaultClientID)+`">
<label for="redirect_uris">Redirect URIs, one per line</label>
<textarea id="redirect_uris" name="redirect_uris">`+html.EscapeString(defaultRedirect)+`</textarea>
<p class="muted">Public PKCE client: no client secret. The first redirect URI is used by the built-in test round trip.</p>
<div class="actions"><button type="submit">Register client</button></div>
</form>
</section>
<section class="panel">
<h2>Registered clients</h2>`+clientRows+`</section>
</div>`)
}

// LoginGoogle starts a real/stub social login and returns to the hosted
// developer callback. The callback sets an HttpOnly browser session cookie.
func (h *DeveloperConsoleHandlers) LoginGoogle(w http.ResponseWriter, r *http.Request) {
	state := randToken(32)
	http.SetCookie(w, &http.Cookie{
		Name:     devConsoleStateCookie,
		Value:    state,
		Path:     "/dev",
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	u, _ := url.Parse(strings.TrimRight(h.Issuer, "/") + "/v1/social/google/authorize")
	q := u.Query()
	q.Set("tenant_id", devConsoleTenantID)
	q.Set("redirect_uri", h.devSocialCallbackURL())
	q.Set("state", state)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// SocialCallback consumes the social-login redirect and turns the returned
// X-Auth session into a developer-console cookie.
func (h *DeveloperConsoleHandlers) SocialCallback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(devConsoleStateCookie)
	if err != nil || c.Value == "" || c.Value != r.URL.Query().Get("state") {
		h.page(w, "Login failed", `<h1 class="err">Login failed</h1><p class="muted">State mismatch. Start again from the developer console.</p><div class="actions"><a class="btn" href="/dev">Back</a></div>`)
		return
	}
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		h.page(w, "Login failed", `<h1 class="err">Login failed</h1><p class="muted">The social callback did not include a session_id.</p><div class="actions"><a class="btn" href="/dev">Back</a></div>`)
		return
	}
	sess, err := h.Store.GetSession(devConsoleTenantID, sessionID)
	if err != nil || sess.InvalidatedAt != nil || time.Now().UTC().After(sess.ExpiresAt) {
		h.page(w, "Login failed", `<h1 class="err">Login failed</h1><p class="muted">The returned session is not valid.</p><div class="actions"><a class="btn" href="/dev">Back</a></div>`)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: devConsoleStateCookie, Path: "/dev", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{
		Name:     devConsoleSessionCookie,
		Value:    sess.ID,
		Path:     "/dev",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/dev", http.StatusFound)
}

func (h *DeveloperConsoleHandlers) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(devConsoleSessionCookie); err == nil && c.Value != "" {
		if sess, err := h.Store.GetSession(devConsoleTenantID, c.Value); err == nil && sess.InvalidatedAt == nil {
			now := time.Now().UTC()
			sess.InvalidatedAt = &now
			_, _ = h.Store.UpdateSession(sess)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: devConsoleSessionCookie, Path: "/dev", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/dev", http.StatusFound)
}

// RegisterClient registers a public PKCE client for the signed-in developer.
func (h *DeveloperConsoleHandlers) RegisterClient(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.currentSession(w, r); !ok {
		http.Redirect(w, r, "/dev", http.StatusFound)
		return
	}

	clientID := strings.TrimSpace(r.FormValue("client_id"))
	redirects := parseRedirectURIs(r.FormValue("redirect_uris"))
	if clientID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	if len(redirects) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "at least one redirect_uri is required")
		return
	}
	for _, raw := range redirects {
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must be absolute: "+raw)
			return
		}
	}
	if _, err := h.Store.GetClient(clientID); err == nil {
		httpx.WriteError(w, http.StatusConflict, "client_exists", "client_id already exists")
		return
	} else if !errors.Is(err, ErrNotFound) {
		h.Logger.Error("dev_client_lookup_failed", "err", err, "client_id", clientID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to check client_id")
		return
	}
	c := OIDCClient{
		ClientID:         clientID,
		ClientSecretHash: "",
		RedirectURIs:     redirects,
		CreatedAt:        time.Now().UTC(),
	}
	if err := h.Store.PutClient(c); err != nil {
		h.Logger.Error("dev_client_register_failed", "err", err, "client_id", clientID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to register client")
		return
	}
	h.rememberClient(c)
	http.Redirect(w, r, "/dev?client_id="+url.QueryEscape(clientID), http.StatusFound)
}

// StartOIDC acts as a tiny relying party for a registered client. It starts a
// code+PKCE flow and optionally requests the SMS OTP ACR.
func (h *DeveloperConsoleHandlers) StartOIDC(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.currentSession(w, r)
	if !ok {
		http.Redirect(w, r, "/dev", http.StatusFound)
		return
	}
	clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))
	client, err := h.Store.GetClient(clientID)
	if err != nil || len(client.RedirectURIs) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_client", "registered client_id is required")
		return
	}
	state := randToken(32)
	verifier := randToken(48)
	acr := ""
	switch r.URL.Query().Get("acr") {
	case "sms":
		acr = ACRSMSOTP
	case "fido2":
		acr = ACRFIDO2
	}
	redirectURI := client.RedirectURIs[0]
	h.storeOIDCFlow(state, devOIDCFlow{
		ClientID:     client.ClientID,
		RedirectURI:  redirectURI,
		CodeVerifier: verifier,
		ACR:          acr,
		CreatedAt:    time.Now().UTC(),
	})

	authz, _ := url.Parse(strings.TrimRight(h.Issuer, "/") + "/authorize")
	q := authz.Query()
	q.Set("client_id", client.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("tenant_id", sess.Session.TenantID)
	q.Set("user_id", sess.User.ID)
	q.Set("state", state)
	q.Set("nonce", randToken(24))
	q.Set("code_challenge", pkceS256(verifier))
	q.Set("code_challenge_method", "S256")
	if acr != "" {
		q.Set("acr_values", acr)
	}
	authz.RawQuery = q.Encode()
	http.Redirect(w, r, authz.String(), http.StatusFound)
}

// OIDCCallback completes the relying-party side of the hosted test flow by
// exchanging the code at /token and rendering the resulting claims.
func (h *DeveloperConsoleHandlers) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	flow, ok := h.takeOIDCFlow(state)
	if !ok || code == "" {
		h.page(w, "OIDC callback failed", `<h1 class="err">OIDC callback failed</h1><p class="muted">Missing or expired state/code.</p><div class="actions"><a class="btn" href="/dev">Back</a></div>`)
		return
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", flow.ClientID)
	form.Set("code", code)
	form.Set("redirect_uri", flow.RedirectURI)
	form.Set("code_verifier", flow.CodeVerifier)
	client := &http.Client{Timeout: defaultClientTimeout}
	resp, err := client.PostForm(strings.TrimRight(h.Issuer, "/")+"/token", form)
	if err != nil {
		h.Logger.Error("dev_oidc_token_exchange_failed", "err", err, "client_id", flow.ClientID)
		h.page(w, "Token exchange failed", `<h1 class="err">Token exchange failed</h1><p class="muted">Could not call the token endpoint.</p><pre>`+html.EscapeString(err.Error())+`</pre><div class="actions"><a class="btn" href="/dev">Back</a></div>`)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		h.page(w, "Token exchange failed", `<h1 class="err">Token exchange failed</h1><p class="muted">/token returned `+html.EscapeString(resp.Status)+`.</p><pre>`+html.EscapeString(string(body))+`</pre><div class="actions"><a class="btn" href="/dev">Back</a></div>`)
		return
	}

	var tok map[string]any
	_ = json.Unmarshal(body, &tok)
	idClaims := decodeJWTPayload(stringValue(tok["id_token"]))
	accessClaims := decodeJWTPayload(stringValue(tok["access_token"]))
	rendered, _ := json.MarshalIndent(map[string]any{
		"requested_acr":       flow.ACR,
		"token_response":      tok,
		"id_token_claims":     idClaims,
		"access_token_claims": accessClaims,
	}, "", "  ")
	h.page(w, "OIDC round trip complete", `<h1 class="ok">OIDC round trip complete</h1>
<p class="muted">The registered client completed authorize → token with PKCE. Check <code>acr</code>/<code>amr</code> below to compare plain vs SMS OTP flows.</p>
<pre>`+html.EscapeString(string(rendered))+`</pre>
<div class="actions"><a class="btn" href="/dev">Back to console</a></div>`)
}

func (h *DeveloperConsoleHandlers) currentSession(w http.ResponseWriter, r *http.Request) (developerSession, bool) {
	c, err := r.Cookie(devConsoleSessionCookie)
	if err != nil || c.Value == "" {
		return developerSession{}, false
	}
	sess, err := h.Store.GetSession(devConsoleTenantID, c.Value)
	if err != nil || sess.InvalidatedAt != nil || time.Now().UTC().After(sess.ExpiresAt) {
		http.SetCookie(w, &http.Cookie{Name: devConsoleSessionCookie, Path: "/dev", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		return developerSession{}, false
	}
	user, err := h.Store.GetUser(devConsoleTenantID, sess.UserID)
	if err != nil {
		return developerSession{}, false
	}
	return developerSession{Session: sess, User: user}, true
}

func (h *DeveloperConsoleHandlers) devSocialCallbackURL() string {
	return strings.TrimRight(h.Issuer, "/") + "/dev/social/callback"
}

func (h *DeveloperConsoleHandlers) devOIDCCallbackURL() string {
	return strings.TrimRight(h.Issuer, "/") + "/dev/oidc/callback"
}

func (h *DeveloperConsoleHandlers) ensureClientMemory() {
	h.registerOnce.Do(func() { h.registered = make(map[string]OIDCClient) })
}

func (h *DeveloperConsoleHandlers) rememberClient(c OIDCClient) {
	h.ensureClientMemory()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.registered[c.ClientID] = c
}

func (h *DeveloperConsoleHandlers) registeredClients() []OIDCClient {
	h.ensureClientMemory()
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]OIDCClient, 0, len(h.registered))
	for _, c := range h.registered {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (h *DeveloperConsoleHandlers) ensureFlowMemory() {
	h.flowsOnce.Do(func() { h.flows = make(map[string]devOIDCFlow) })
}

func (h *DeveloperConsoleHandlers) storeOIDCFlow(state string, f devOIDCFlow) {
	h.ensureFlowMemory()
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := time.Now().UTC().Add(-devOIDCFlowTTL)
	for k, v := range h.flows {
		if v.CreatedAt.Before(cutoff) {
			delete(h.flows, k)
		}
	}
	h.flows[state] = f
}

func (h *DeveloperConsoleHandlers) takeOIDCFlow(state string) (devOIDCFlow, bool) {
	h.ensureFlowMemory()
	h.mu.Lock()
	defer h.mu.Unlock()
	f, ok := h.flows[state]
	if !ok {
		return devOIDCFlow{}, false
	}
	delete(h.flows, state)
	if time.Since(f.CreatedAt) > devOIDCFlowTTL {
		return devOIDCFlow{}, false
	}
	return f, true
}

func parseRedirectURIs(raw string) []string {
	seen := map[string]bool{}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';'
	})
	var out []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func decodeJWTPayload(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil
	}
	return claims
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}
