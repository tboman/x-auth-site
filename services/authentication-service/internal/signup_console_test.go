package internal

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---- tenant registry (MemStorage) ----

func TestTenantRegistryMem(t *testing.T) {
	store := NewMemStorage()
	now := time.Now().UTC()
	acme := Tenant{ID: "ten_acme", CompanyName: "Acme Inc", Slug: "acme", OwnerEmail: "o@acme.test", CreatedAt: now}
	if _, err := store.CreateTenant(acme); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// Lookups.
	if got, err := store.GetTenant("ten_acme"); err != nil || got.CompanyName != "Acme Inc" {
		t.Fatalf("GetTenant: %+v err=%v", got, err)
	}
	if got, err := store.GetTenantBySlug("acme"); err != nil || got.ID != "ten_acme" {
		t.Fatalf("GetTenantBySlug: %+v err=%v", got, err)
	}
	if got, err := store.GetTenantByOwnerEmail("o@acme.test"); err != nil || got.ID != "ten_acme" {
		t.Fatalf("GetTenantByOwnerEmail: %+v err=%v", got, err)
	}
	if _, err := store.GetTenant("ten_missing"); err != ErrNotFound {
		t.Fatalf("GetTenant miss: want ErrNotFound, got %v", err)
	}

	// Duplicate slug → conflict.
	if _, err := store.CreateTenant(Tenant{ID: "ten_acme2", CompanyName: "Acme Two", Slug: "acme", OwnerEmail: "other@x.test", CreatedAt: now}); err != ErrConflict {
		t.Fatalf("dup slug: want ErrConflict, got %v", err)
	}
	// Owner email is no longer unique — one account may own several workspaces.
	if _, err := store.CreateTenant(Tenant{ID: "ten_acme3", CompanyName: "Acme Three", Slug: "acme3", OwnerEmail: "o@acme.test", CreatedAt: now}); err != nil {
		t.Fatalf("second workspace for same owner: %v", err)
	}
	if owned, _ := store.ListTenantsByOwnerEmail("o@acme.test"); len(owned) != 2 {
		t.Fatalf("owner should now own 2 workspaces, got %d", len(owned))
	}
}

// TestProvisionTenantMemAtomic asserts the all-or-nothing contract: a provision
// rejected for a slug/owner conflict must leave none of the four rows behind.
func TestProvisionTenantMemAtomic(t *testing.T) {
	store := NewMemStorage()
	now := time.Now().UTC()
	mk := func(suffix, slug, email string) (Tenant, User, Session, OIDCClient) {
		tid := "ten_" + slug
		owner := User{ID: "usr_" + suffix, TenantID: tid, Email: email, CreatedAt: now, UpdatedAt: now}
		sess := Session{ID: "ses_" + suffix, TenantID: tid, UserID: owner.ID, RiskLevel: RiskLow, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
		client := OIDCClient{ClientID: "cli_" + suffix, ClientSecretHash: "h", TenantID: tid, CreatedAt: now}
		return Tenant{ID: tid, CompanyName: slug, Slug: slug, OwnerEmail: email, CreatedAt: now}, owner, sess, client
	}

	ten1, o1, s1, c1 := mk("1", "acme", "o@acme.test")
	if err := store.ProvisionTenant(ten1, o1, s1, c1); err != nil {
		t.Fatalf("first provision: %v", err)
	}

	// A slug collision is rejected before any write — the beta rows must NOT
	// persist. (Owner email is no longer unique, so slug is the conflict axis.)
	ten2 := Tenant{ID: "ten_beta", CompanyName: "beta", Slug: "acme", OwnerEmail: "other@beta.test", CreatedAt: now}
	o2 := User{ID: "usr_2", TenantID: "ten_beta", Email: "other@beta.test", CreatedAt: now, UpdatedAt: now}
	s2 := Session{ID: "ses_2", TenantID: "ten_beta", UserID: "usr_2", RiskLevel: RiskLow, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
	c2 := OIDCClient{ClientID: "cli_2", ClientSecretHash: "h", TenantID: "ten_beta", CreatedAt: now}
	if err := store.ProvisionTenant(ten2, o2, s2, c2); err != ErrConflict {
		t.Fatalf("conflicting provision: want ErrConflict, got %v", err)
	}
	if _, err := store.GetTenant("ten_beta"); err != ErrNotFound {
		t.Fatalf("tenant must not persist, got %v", err)
	}
	if _, err := store.GetUser("ten_beta", o2.ID); err != ErrNotFound {
		t.Fatalf("owner must not persist, got %v", err)
	}
	if _, err := store.GetSession("ten_beta", s2.ID); err != ErrNotFound {
		t.Fatalf("session must not persist, got %v", err)
	}
	if _, err := store.GetClient(c2.ClientID); err != ErrNotFound {
		t.Fatalf("client must not persist, got %v", err)
	}
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Acme Inc":              "acme-inc",
		"  Spaces  Everywhere ": "spaces-everywhere",
		"Foo!!!Bar":             "foo-bar",
		"--Leading-Trailing--":  "leading-trailing",
		"Café":                  "caf", // non-ASCII dropped
		"123 Go":                "123-go",
		"":                      "",
		"!!!":                   "", // nothing usable
		strings.Repeat("a", 60): strings.Repeat("a", maxSlugLen),
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- signup flow helpers (mirror admin_console_test's crafted-cookie style) ----

const signupState = "signup-state-xyz"

// seedSignupSession creates a ten_signup user+session for email, as the Google
// leg would leave it for the signup callback.
func seedSignupSession(t *testing.T, store Storage, email string) Session {
	t.Helper()
	now := time.Now().UTC()
	// Upsert the staging user so repeat logins for the same Google account (as a
	// returning owner would do) don't collide on (tenant, email).
	u, err := store.GetUserByEmail(signupTenantID, email)
	if err != nil {
		u, err = store.CreateUser(User{ID: "usr_signup_" + email, TenantID: signupTenantID, Email: email, CreatedAt: now, UpdatedAt: now})
		if err != nil {
			t.Fatalf("seed signup user: %v", err)
		}
	}
	s, err := store.CreateSession(Session{ID: "ses_signup_" + randToken(6), TenantID: signupTenantID, UserID: u.ID, RiskLevel: RiskLow, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("seed signup session: %v", err)
	}
	return s
}

// driveSignup runs a full provisioning callback for email/company/redirect and
// returns the recorder (the one-time secret screen on success).
func driveSignup(t *testing.T, r http.Handler, store Storage, email, company, redirect string) *httptest.ResponseRecorder {
	t.Helper()
	sess := seedSignupSession(t, store, email)
	raw, _ := json.Marshal(signupIntent{Company: company, Redirect: redirect})
	req := httptest.NewRequest(http.MethodGet, "/admin/signup/callback?state="+signupState+"&session_id="+sess.ID, nil)
	req.AddCookie(&http.Cookie{Name: signupStateCookie, Value: signupState})
	req.AddCookie(&http.Cookie{Name: signupIntentCookie, Value: base64.RawURLEncoding.EncodeToString(raw)})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// extractSecret pulls the one-time secret out of the rendered secret screen.
func extractSecret(t *testing.T, body string) string {
	t.Helper()
	const open = `<div class="secret">`
	i := strings.Index(body, open)
	if i < 0 {
		t.Fatalf("no secret block in body:\n%s", body)
	}
	rest := body[i+len(open):]
	j := strings.Index(rest, `</div>`)
	if j < 0 {
		t.Fatal("unterminated secret block")
	}
	return strings.TrimSpace(rest[:j])
}

func TestSignupProvisionsTenantAndPublicClient(t *testing.T) {
	r, store := newAdminRouter(t) // no admin emails; stub social
	w := driveSignup(t, r, store, "owner@acme.test", "Acme Inc", "https://app.acme.com/callback.html")
	if w.Code != http.StatusOK {
		t.Fatalf("signup callback: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "Workspace created") || !strings.Contains(body, "ten_acme-inc") {
		t.Fatalf("ready screen missing expected content:\n%s", body)
	}
	// Public-client workspace: no secret shown, and the quickstart downloads offered.
	if strings.Contains(body, `class="secret"`) {
		t.Fatal("public-client signup must not render a client secret")
	}
	for _, asset := range []string{"auth.js", "callback.html", "landing.html"} {
		if !strings.Contains(body, "/admin/owner/download/"+asset) {
			t.Fatalf("ready screen missing quickstart download for %s", asset)
		}
	}

	// Tenant registry row.
	ten, err := store.GetTenantBySlug("acme-inc")
	if err != nil || ten.ID != "ten_acme-inc" || ten.OwnerEmail != "owner@acme.test" || ten.CompanyName != "Acme Inc" {
		t.Fatalf("tenant not provisioned correctly: %+v err=%v", ten, err)
	}
	// Owner user exists in the new tenant.
	if _, err := store.GetUserByEmail("ten_acme-inc", "owner@acme.test"); err != nil {
		t.Fatalf("owner user missing: %v", err)
	}
	// Public client bound to the tenant — empty secret hash marks it public.
	var client OIDCClient
	clients, _ := store.ListClients()
	for _, c := range clients {
		if c.TenantID == "ten_acme-inc" {
			client = c
		}
	}
	if client.ClientID == "" || !strings.HasPrefix(client.ClientID, "cli_") {
		t.Fatalf("no cli_ client bound to tenant: %+v", clients)
	}
	if client.ClientSecretHash != "" {
		t.Fatalf("client must be public (empty secret hash), got %q", client.ClientSecretHash)
	}
	if len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != "https://app.acme.com/callback.html" {
		t.Fatalf("redirect URIs not set from signup: %+v", client.RedirectURIs)
	}
	if len(client.WebOrigins) != 1 || client.WebOrigins[0] != "https://app.acme.com" {
		t.Fatalf("web origin not derived: %+v", client.WebOrigins)
	}
	// Owner cookie set.
	if sessionCookie(w, ownerSessionCookie) == "" {
		t.Fatal("signup must set the owner session cookie")
	}
}

func TestSignupDuplicateCompanyRejected(t *testing.T) {
	r, store := newAdminRouter(t)
	if w := driveSignup(t, r, store, "first@acme.test", "Acme", ""); w.Code != http.StatusOK {
		t.Fatalf("first signup: want 200, got %d", w.Code)
	}
	// Different owner, same company name → taken.
	w := driveSignup(t, r, store, "second@other.test", "Acme", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("dup company: want 409, got %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "already taken") {
		t.Fatalf("dup company message missing:\n%s", w.Body.String())
	}
}

// driveOwnerLogin runs the owner re-login callback for email (the Google leg
// leaves a verified ten_signup session), returning the recorder.
func driveOwnerLogin(t *testing.T, r http.Handler, store Storage, email string) *httptest.ResponseRecorder {
	t.Helper()
	sess := seedSignupSession(t, store, email)
	const state = "owner-state-xyz"
	req := httptest.NewRequest(http.MethodGet, "/admin/owner/callback?state="+state+"&session_id="+sess.ID, nil)
	req.AddCookie(&http.Cookie{Name: ownerStateCookie, Value: state})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestTenantOwnerStorageMem(t *testing.T) {
	s := NewMemStorage()
	now := time.Now().UTC()
	if _, err := s.CreateTenant(Tenant{ID: "ten_a", CompanyName: "A", Slug: "a", OwnerEmail: "x@a.test", CreatedAt: now}); err != nil {
		t.Fatalf("create a: %v", err)
	}
	if _, err := s.CreateTenant(Tenant{ID: "ten_b", CompanyName: "B", Slug: "b", OwnerEmail: "other@b.test", CreatedAt: now}); err != nil {
		t.Fatalf("create b: %v", err)
	}
	// Reassign ten_b to x → an account may now own more than one workspace.
	if err := s.SetTenantOwner("ten_b", "x@a.test"); err != nil {
		t.Fatalf("reassign: %v", err)
	}
	owned, _ := s.ListTenantsByOwnerEmail("x@a.test")
	if len(owned) != 2 || owned[0].ID != "ten_a" || owned[1].ID != "ten_b" {
		t.Fatalf("owned by x (slug-ordered): want [ten_a ten_b], got %+v", owned)
	}
	// Assigning an owner to a tenant with no registry row synthesizes one (a tenant
	// listed only via users/sessions), so staff can promote it.
	if err := s.SetTenantOwner("ten_orphan", "x@a.test"); err != nil {
		t.Fatalf("assign orphan: %v", err)
	}
	if tn, err := s.GetTenant("ten_orphan"); err != nil || tn.OwnerEmail != "x@a.test" {
		t.Fatalf("orphan registry row not created: %+v err=%v", tn, err)
	}
	if owned, _ := s.ListTenantsByOwnerEmail("x@a.test"); len(owned) != 3 {
		t.Fatalf("x should own 3 workspaces now, got %d", len(owned))
	}
}

// A workspace reassigned to a different account by staff lets that account sign in
// straight into the tenant, and currentOwner accepts them on the dashboard.
func TestReassignedOwnerLogsIntoTenant(t *testing.T) {
	r, store := newAdminRouter(t)
	driveSignup(t, r, store, "owner@beta.test", "Beta", "")
	if err := store.SetTenantOwner("ten_beta", "new@beta.test"); err != nil {
		t.Fatalf("reassign: %v", err)
	}

	w := driveOwnerLogin(t, r, store, "new@beta.test")
	if w.Code != http.StatusFound {
		t.Fatalf("reassigned owner login: want 302, got %d (%s)", w.Code, w.Body.String())
	}
	cookie := sessionCookie(w, ownerSessionCookie)
	if !strings.HasPrefix(cookie, "ten_beta|") {
		t.Fatalf("reassigned owner cookie should be ten_beta, got %q", cookie)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: cookie})
	dw := httptest.NewRecorder()
	r.ServeHTTP(dw, req)
	if dw.Code != http.StatusOK || !strings.Contains(dw.Body.String(), "Beta") {
		t.Fatalf("reassigned owner should see the Beta dashboard (%d):\n%s", dw.Code, dw.Body.String())
	}
}

// An account that owns more than one workspace gets the picker, then selecting
// one logs into it.
func TestOwnerLoginMultiTenantPicker(t *testing.T) {
	r, store := newAdminRouter(t)
	driveSignup(t, r, store, "x@acme.test", "Acme", "")     // x owns Acme
	driveSignup(t, r, store, "owner@beta.test", "Beta", "") // someone else owns Beta
	// Staff reassigns Beta to x → x now owns both Acme and Beta.
	if err := store.SetTenantOwner("ten_beta", "x@acme.test"); err != nil {
		t.Fatalf("reassign: %v", err)
	}

	w := driveOwnerLogin(t, r, store, "x@acme.test")
	if w.Code != http.StatusOK {
		t.Fatalf("multi-tenant login: want 200 picker, got %d", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "Choose a workspace") || !strings.Contains(body, "ten_acme") || !strings.Contains(body, "ten_beta") {
		t.Fatalf("picker missing tenants:\n%s", w.Body.String())
	}
	pick := sessionCookie(w, ownerPickCookie)
	if pick == "" {
		t.Fatal("picker must set the pick cookie")
	}

	form := url.Values{"tenant_id": {"ten_beta"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/owner/select", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: ownerPickCookie, Value: pick})
	sw := httptest.NewRecorder()
	r.ServeHTTP(sw, req)
	if sw.Code != http.StatusFound {
		t.Fatalf("select: want 302, got %d (%s)", sw.Code, sw.Body.String())
	}
	if c := sessionCookie(sw, ownerSessionCookie); !strings.HasPrefix(c, "ten_beta|") {
		t.Fatalf("selected workspace cookie should be ten_beta, got %q", c)
	}
}

// A signed-in owner who manages more than one workspace sees an in-dashboard
// switcher and can switch the active workspace without signing in again; a
// workspace they don't own is rejected.
func TestOwnerSwitchWorkspace(t *testing.T) {
	r, store := newAdminRouter(t)
	w := driveSignup(t, r, store, "x@acme.test", "Acme", "") // x owns Acme, owner cookie set
	cookie := sessionCookie(w, ownerSessionCookie)
	driveSignup(t, r, store, "owner@beta.test", "Beta", "") // someone else owns Beta
	if err := store.SetTenantOwner("ten_beta", "x@acme.test"); err != nil {
		t.Fatalf("assign beta to x: %v", err)
	}

	dash := func(c string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: c})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	switchTo := func(c, tenantID string) *httptest.ResponseRecorder {
		form := url.Values{"tenant_id": {tenantID}}
		req := httptest.NewRequest(http.MethodPost, "/admin/owner/switch", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: c})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	// Owning two workspaces → the dashboard shows the switcher.
	if body := dash(cookie).Body.String(); !strings.Contains(body, "/admin/owner/switch") || !strings.Contains(body, "ten_beta") {
		t.Fatalf("dashboard missing workspace switcher:\n%s", body)
	}

	// Switch to Beta → new owner cookie + Beta dashboard.
	sw := switchTo(cookie, "ten_beta")
	if sw.Code != http.StatusFound {
		t.Fatalf("switch: want 302, got %d (%s)", sw.Code, sw.Body.String())
	}
	newCookie := sessionCookie(sw, ownerSessionCookie)
	if !strings.HasPrefix(newCookie, "ten_beta|") {
		t.Fatalf("switched cookie should be ten_beta, got %q", newCookie)
	}
	if body := dash(newCookie).Body.String(); !strings.Contains(body, "Beta") {
		t.Fatalf("after switch should see the Beta dashboard:\n%s", body)
	}

	// A workspace the owner does not own is rejected.
	driveSignup(t, r, store, "gamma@g.test", "Gamma", "")
	if sw := switchTo(newCookie, "ten_gamma"); sw.Code != http.StatusForbidden {
		t.Fatalf("switch to unowned workspace: want 403, got %d", sw.Code)
	}
}

// An owner toggles the per-tenant phone (SMS OTP) sign-in option from the
// Integration tab; the flag flips and the /login chooser follows it.
func TestOwnerTogglesPhoneLogin(t *testing.T) {
	r, store := newAdminRouter(t)
	w := driveSignup(t, r, store, "owner@acme.test", "Acme", "")
	cookie := sessionCookie(w, ownerSessionCookie)

	get := func(tab string) string {
		req := httptest.NewRequest(http.MethodGet, "/admin?tab="+tab, nil)
		req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: cookie})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	post := func(form url.Values) int {
		req := httptest.NewRequest(http.MethodPost, "/admin/owner/phone-login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: cookie})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec.Code
	}

	// Default off: the Integration tab shows the toggle, unchecked.
	if body := get("integration"); !strings.Contains(body, "Enable phone (SMS OTP) sign-in") {
		t.Fatalf("integration tab missing phone toggle:\n%s", body)
	}

	// Enable → flag set + toggle renders checked.
	if code := post(url.Values{"enabled": {"true"}}); code != http.StatusFound {
		t.Fatalf("enable: want 302, got %d", code)
	}
	if tn, _ := store.GetTenant("ten_acme"); !tn.PhoneLoginEnabled {
		t.Fatal("phone login not enabled after toggle on")
	}
	if body := get("integration"); !strings.Contains(body, `value="true" checked`) {
		t.Errorf("toggle should render checked when enabled:\n%s", body)
	}

	// Disable (checkbox absent in the post) → flag cleared.
	if code := post(url.Values{}); code != http.StatusFound {
		t.Fatalf("disable: want 302, got %d", code)
	}
	if tn, _ := store.GetTenant("ten_acme"); tn.PhoneLoginEnabled {
		t.Fatal("phone login still enabled after toggle off")
	}
}

// The owner can set, replace, and remove a user's phone number from the Users
// tab; a set number becomes a verified phone anchor.
func TestOwnerManagesUserPhone(t *testing.T) {
	r, store := newAdminRouter(t)
	w := driveSignup(t, r, store, "owner@acme.test", "Acme", "")
	cookie := sessionCookie(w, ownerSessionCookie)
	now := time.Now().UTC()
	if _, err := store.CreateUser(User{ID: "usr_a", TenantID: "ten_acme", Email: "a@acme.test", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	get := func() string {
		req := httptest.NewRequest(http.MethodGet, "/admin?tab=users", nil)
		req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: cookie})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	post := func(path string, form url.Values) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: cookie})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec.Code
	}

	if body := get(); !strings.Contains(body, "/admin/owner/identities/phone") || !strings.Contains(body, "a@acme.test") {
		t.Fatalf("users tab missing identity management:\n%s", body)
	}

	// Set a phone (with messy formatting) → normalized, verified anchor.
	if code := post("/admin/owner/identities/phone", url.Values{"user_id": {"usr_a"}, "phone": {"+1 555 111 2222"}}); code != http.StatusFound {
		t.Fatalf("set phone: want 302, got %d", code)
	}
	a, err := store.GetIdentityAnchorByValue("ten_acme", AnchorPhone, "+15551112222")
	if err != nil || a.UserID != "usr_a" || a.VerifiedAt == nil {
		t.Fatalf("phone anchor wrong: %+v err=%v", a, err)
	}

	// Setting a different number replaces the old one.
	if code := post("/admin/owner/identities/phone", url.Values{"user_id": {"usr_a"}, "phone": {"+15553334444"}}); code != http.StatusFound {
		t.Fatalf("replace phone: want 302, got %d", code)
	}
	if _, err := store.GetIdentityAnchorByValue("ten_acme", AnchorPhone, "+15551112222"); err != ErrNotFound {
		t.Fatal("old number must be removed on replace")
	}
	newA, _ := store.GetIdentityAnchorByValue("ten_acme", AnchorPhone, "+15553334444")

	// Remove it.
	if code := post("/admin/owner/identities/remove", url.Values{"anchor_id": {newA.ID}}); code != http.StatusFound {
		t.Fatalf("remove: want 302, got %d", code)
	}
	if _, err := store.GetIdentityAnchorByValue("ten_acme", AnchorPhone, "+15553334444"); err != ErrNotFound {
		t.Fatal("anchor must be gone after remove")
	}
}

// The owner dashboard is tabbed: a nav with all sections, Overview by default,
// and each tab renders only its own content.
func TestOwnerDashboardTabs(t *testing.T) {
	r, store := newAdminRouter(t)
	w := driveSignup(t, r, store, "owner@acme.test", "Acme", "")
	cookie := sessionCookie(w, ownerSessionCookie)
	get := func(tab string) string {
		path := "/admin"
		if tab != "" {
			path += "?tab=" + tab
		}
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: cookie})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("tab %q: want 200, got %d", tab, rec.Code)
		}
		return rec.Body.String()
	}

	// Default (no tab) = Overview: nav to every tab + the workspace summary.
	overview := get("")
	for _, want := range []string{"tab=overview", "tab=integration", "tab=transactions", "tab=users", "tab=sessions", "Tenant ID", "Sign out"} {
		if !strings.Contains(overview, want) {
			t.Errorf("overview missing %q", want)
		}
	}
	// Overview must NOT inline the other tabs' bodies (e.g. the integration form).
	if strings.Contains(overview, `action="/admin/owner/client"`) {
		t.Error("overview should not inline the integration tab's client form")
	}
	// Integration tab shows the client form; transactions tab shows the advice how-to.
	if !strings.Contains(get("integration"), `action="/admin/owner/client"`) {
		t.Error("integration tab missing the client form")
	}
	if !strings.Contains(get("transactions"), "Calling the advice endpoint") {
		t.Error("transactions tab missing the advice how-to")
	}
}

func TestSignupReturningOwnerRoutedToWorkspace(t *testing.T) {
	r, store := newAdminRouter(t)
	if w := driveSignup(t, r, store, "owner@acme.test", "Acme", ""); w.Code != http.StatusOK {
		t.Fatalf("first signup: want 200, got %d", w.Code)
	}
	// Same owner re-runs signup for the SAME workspace name → routed straight to
	// the existing workspace, no duplicate tenant. (A different name now creates a
	// second workspace, since an account may own more than one.)
	w := driveSignup(t, r, store, "owner@acme.test", "Acme", "")
	if w.Code != http.StatusFound {
		t.Fatalf("returning owner: want 302, got %d (%s)", w.Code, w.Body.String())
	}
	cookie := sessionCookie(w, ownerSessionCookie)
	if !strings.HasPrefix(cookie, "ten_acme|") {
		t.Fatalf("owner cookie should point at existing tenant, got %q", cookie)
	}
}

func TestOwnerDashboardShowsOnlyOwnTenant(t *testing.T) {
	r, store := newAdminRouter(t)
	w1 := driveSignup(t, r, store, "owner1@acme.test", "Acme", "")
	driveSignup(t, r, store, "owner2@beta.test", "Beta", "")
	ownerCookie := sessionCookie(w1, ownerSessionCookie)
	if ownerCookie == "" {
		t.Fatal("missing owner1 cookie")
	}
	betaClient, _ := (&SignupConsoleHandlers{Store: store}).tenantClient("ten_beta")

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: ownerCookie})
	dw := httptest.NewRecorder()
	r.ServeHTTP(dw, req)
	if dw.Code != http.StatusOK {
		t.Fatalf("owner dashboard: want 200, got %d", dw.Code)
	}
	body := dw.Body.String()
	if !strings.Contains(body, "ten_acme") || !strings.Contains(body, "owner1@acme.test") {
		t.Fatalf("dashboard missing own tenant:\n%s", body)
	}
	for _, leak := range []string{"ten_beta", "owner2@beta.test", betaClient.ClientID} {
		if leak != "" && strings.Contains(body, leak) {
			t.Errorf("owner dashboard leaks other tenant data: %q", leak)
		}
	}
}

func TestOwnerTransactionTypesCRUD(t *testing.T) {
	r, store := newAdminRouter(t)
	w := driveSignup(t, r, store, "owner@acme.test", "Acme", "")
	cookie := sessionCookie(w, ownerSessionCookie)
	if cookie == "" {
		t.Fatal("missing owner cookie")
	}
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: cookie})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	dash := func() string {
		req := httptest.NewRequest(http.MethodGet, "/admin?tab=transactions", nil)
		req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: cookie})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec.Body.String()
	}

	// The transactions tab renders the section and the 8-level dropdown.
	if body := dash(); !strings.Contains(body, "Transaction types") || !strings.Contains(body, "urn:xauth:protect:ultra:strict") {
		t.Fatalf("dashboard missing transaction-types section or level options")
	}

	// Create maps a type to a level; it then shows on the dashboard.
	if rec := post("/admin/owner/transaction-types", url.Values{"name": {"wiretransfer"}, "acr": {"urn:xauth:protect:ultra:strict"}}); rec.Code != http.StatusFound {
		t.Fatalf("create: want 302, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(dash(), "wiretransfer") {
		t.Fatal("created transaction type not shown on dashboard")
	}
	// An invalid level is rejected.
	if rec := post("/admin/owner/transaction-types", url.Values{"name": {"x"}, "acr": {"bogus"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid acr: want 400, got %d", rec.Code)
	}
	// Delete removes it.
	if rec := post("/admin/owner/transaction-types/delete", url.Values{"name": {"wiretransfer"}}); rec.Code != http.StatusFound {
		t.Fatalf("delete: want 302, got %d", rec.Code)
	}
	if strings.Contains(dash(), "wiretransfer") {
		t.Fatal("deleted transaction type still shown")
	}
	owner, _ := store.GetTenantByOwnerEmail("owner@acme.test")
	if list, _ := store.ListTransactionTypes(owner.ID); len(list) != 0 {
		t.Errorf("expected 0 types after delete, got %d", len(list))
	}
}

func TestOwnerCannotUseStaffClientDelete(t *testing.T) {
	r, store := newAdminRouter(t, "staff@x-auth.com")
	w := driveSignup(t, r, store, "owner@acme.test", "Acme", "")
	ownerCookie := sessionCookie(w, ownerSessionCookie)

	form := url.Values{"client_id": {"cli_default"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/clients/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: ownerCookie})
	dw := httptest.NewRecorder()
	r.ServeHTTP(dw, req)
	if dw.Code != http.StatusForbidden {
		t.Fatalf("owner hitting staff delete: want 403, got %d", dw.Code)
	}
	if _, err := store.GetClient("cli_default"); err != nil {
		t.Fatal("owner must not have deleted the staff/default client")
	}
}

func TestOwnerRegenerateSecretChangesHash(t *testing.T) {
	r, store := newAdminRouter(t)
	w := driveSignup(t, r, store, "owner@acme.test", "Acme", "")
	ownerCookie := sessionCookie(w, ownerSessionCookie)
	before, _ := (&SignupConsoleHandlers{Store: store}).tenantClient("ten_acme")

	req := httptest.NewRequest(http.MethodPost, "/admin/owner/regenerate-secret", nil)
	req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: ownerCookie})
	rw := httptest.NewRecorder()
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("regenerate: want 200, got %d (%s)", rw.Code, rw.Body.String())
	}
	after, _ := (&SignupConsoleHandlers{Store: store}).tenantClient("ten_acme")
	if after.ClientSecretHash == before.ClientSecretHash {
		t.Fatal("regenerate must change the stored secret hash")
	}
	if HashToken(extractSecret(t, rw.Body.String())) != after.ClientSecretHash {
		t.Fatal("regenerated secret must hash to the new stored hash")
	}
}

func TestSignupRateLimited(t *testing.T) {
	t.Setenv("SIGNUP_RATE", "1/1h")
	r, _ := newAdminRouter(t)
	start := func() int {
		req := httptest.NewRequest(http.MethodGet, "/admin/signup/start?company=Acme", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	if code := start(); code != http.StatusFound {
		t.Fatalf("first signup start: want 302, got %d", code)
	}
	if code := start(); code != http.StatusTooManyRequests {
		t.Fatalf("second signup start: want 429, got %d", code)
	}
}

// TestSignupClientPublicTokenExchange proves the signup-minted PUBLIC client
// completes the code grant with PKCE and NO client secret — the flow the
// downloadable browser quickstart relies on.
func TestSignupClientPublicTokenExchange(t *testing.T) {
	r, store := newAdminRouter(t)
	driveSignup(t, r, store, "owner@acme.test", "Acme", "https://app.acme.com/callback.html")
	client, _ := (&SignupConsoleHandlers{Store: store}).tenantClient("ten_acme")
	if client.ClientSecretHash != "" {
		t.Fatalf("signup client must be public, got secret hash %q", client.ClientSecretHash)
	}
	owner, err := store.GetUserByEmail("ten_acme", "owner@acme.test")
	if err != nil {
		t.Fatalf("owner: %v", err)
	}

	verifier := randToken(48)
	if err := store.PutAuthCode(AuthCode{
		Code: "code-pub", ClientID: client.ClientID, TenantID: "ten_acme", UserID: owner.ID,
		RedirectURI: "https://app.acme.com/callback.html", Scope: "openid",
		CodeChallenge: pkceS256(verifier), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed code: %v", err)
	}

	// No client_secret in the body — a public client authenticates by PKCE alone.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code-pub"},
		"redirect_uri":  {"https://app.acme.com/callback.html"},
		"code_verifier": {verifier},
		"client_id":     {client.ClientID},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tw := httptest.NewRecorder()
	r.ServeHTTP(tw, req)
	if tw.Code != http.StatusOK {
		t.Fatalf("public PKCE exchange: want 200, got %d (%s)", tw.Code, tw.Body.String())
	}
	if !strings.Contains(tw.Body.String(), "access_token") {
		t.Fatalf("token response missing access_token:\n%s", tw.Body.String())
	}
}

// TestQuickstartDownload covers the per-tenant starter-kit download: owner-gated,
// pre-filled with the workspace's client/tenant ids, served as an attachment.
func TestQuickstartDownload(t *testing.T) {
	r, store := newAdminRouter(t)
	w := driveSignup(t, r, store, "owner@acme.test", "Acme Inc", "https://app.acme.com/callback.html")
	ownerCookie := sessionCookie(w, ownerSessionCookie)
	client, _ := (&SignupConsoleHandlers{Store: store}).tenantClient("ten_acme-inc")

	get := func(asset, cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/admin/owner/download/"+asset, nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: cookie})
		}
		rw := httptest.NewRecorder()
		r.ServeHTTP(rw, req)
		return rw
	}

	// Unauthenticated → forbidden.
	if rw := get("auth.js", ""); rw.Code != http.StatusForbidden {
		t.Fatalf("anon download: want 403, got %d", rw.Code)
	}

	// auth.js, customized for this workspace, served as an attachment.
	rw := get("auth.js", ownerCookie)
	if rw.Code != http.StatusOK {
		t.Fatalf("auth.js: want 200, got %d (%s)", rw.Code, rw.Body.String())
	}
	if cd := rw.Header().Get("Content-Disposition"); !strings.Contains(cd, `filename="auth.js"`) {
		t.Fatalf("missing attachment disposition: %q", cd)
	}
	body := rw.Body.String()
	if !strings.Contains(body, client.ClientID) || !strings.Contains(body, "ten_acme-inc") {
		t.Fatalf("auth.js not customized with client/tenant ids:\n%s", body)
	}
	if strings.Contains(body, "{{") || strings.Contains(body, "cryptofreight") {
		t.Fatalf("auth.js still has template artifacts / example values:\n%s", body)
	}

	// HTML asset renders with the brand.
	if rw := get("landing.html", ownerCookie); rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), "Acme Inc") {
		t.Fatalf("landing.html: code=%d brand=%v", rw.Code, strings.Contains(rw.Body.String(), "Acme Inc"))
	}

	// Unknown asset → 404.
	if rw := get("evil.sh", ownerCookie); rw.Code != http.StatusNotFound {
		t.Fatalf("unknown asset: want 404, got %d", rw.Code)
	}

	// Confidential client → starter kit is withheld.
	c := client
	c.ClientSecretHash = HashToken("s3cret")
	if err := store.PutClient(c); err != nil {
		t.Fatalf("make confidential: %v", err)
	}
	if rw := get("auth.js", ownerCookie); rw.Code != http.StatusBadRequest {
		t.Fatalf("confidential download: want 400, got %d", rw.Code)
	}
}
