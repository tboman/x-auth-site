package internal

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// newAdminRouter builds a router with an admin allowlist for the given emails.
func newAdminRouter(t *testing.T, adminEmails ...string) (http.Handler, Storage) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewMemStorage()
	r := Router(Deps{
		Store:         store,
		Logger:        logger,
		Authenticator: &mockAuthenticator{},
		Issuer:        "http://test.local",
		Signer:        testSigner,
		AdminEmails:   adminEmails,
	})
	return r, store
}

// buildRouter constructs a router with the given admin/root allowlists, running
// the boot seed against a fresh store (returned for inspection).
func buildRouter(t *testing.T, adminEmails, rootEmails []string) Storage {
	t.Helper()
	store := NewMemStorage()
	_ = Router(Deps{
		Store: store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Authenticator: &mockAuthenticator{}, Issuer: "http://test.local", Signer: testSigner,
		AdminEmails: adminEmails, RootEmails: rootEmails,
	})
	return store
}

func roleSet(t *testing.T, store Storage, email string) (StaffUser, map[string]bool) {
	t.Helper()
	staff, err := store.GetStaffUserByEmail(email)
	if err != nil {
		t.Fatalf("staff %q not seeded: %v", email, err)
	}
	roles, _ := store.GetStaffUserRoles(staff.ID)
	set := map[string]bool{}
	for _, r := range roles {
		set[r] = true
	}
	return staff, set
}

// A ROOT_EMAILS account is seeded active with every staff role (break-glass).
func TestRootEmailsSeedAllRoles(t *testing.T) {
	store := buildRouter(t, nil, []string{" Root@Example.com "}) // mixed case + spaces → normalized
	staff, roles := roleSet(t, store, "root@example.com")
	if !staff.Active {
		t.Error("root account should be active")
	}
	for _, want := range allStaffRoles {
		if !roles[want] {
			t.Errorf("root missing role %q (have %v)", want, roles)
		}
	}
	if len(roles) != len(allStaffRoles) {
		t.Errorf("root has %d roles, want exactly all %d (%v)", len(roles), len(allStaffRoles), roles)
	}
}

// Root self-heals a disabled row (reactivate + all roles); a disabled NON-root
// admin must stay disabled with no roles (deactivation must stick).
func TestRootReactivatesButAdminDeactivationSticks(t *testing.T) {
	store := NewMemStorage()
	now := time.Now().UTC()
	_ = store.PutStaffUser(StaffUser{ID: "stf_root", Email: "root@x.com", Active: false, CreatedAt: now, UpdatedAt: now})
	_ = store.PutStaffUser(StaffUser{ID: "stf_adm", Email: "adm@x.com", Active: false, CreatedAt: now, UpdatedAt: now})
	_ = Router(Deps{
		Store: store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Authenticator: &mockAuthenticator{}, Issuer: "http://test.local", Signer: testSigner,
		AdminEmails: []string{"adm@x.com"}, RootEmails: []string{"root@x.com"},
	})
	root, rootRoles := roleSet(t, store, "root@x.com")
	if !root.Active {
		t.Error("disabled root should be reactivated")
	}
	if len(rootRoles) != len(allStaffRoles) {
		t.Errorf("reactivated root should get all roles, got %v", rootRoles)
	}
	adm, admRoles := roleSet(t, store, "adm@x.com")
	if adm.Active {
		t.Error("disabled admin must NOT be reactivated")
	}
	if len(admRoles) != 0 {
		t.Errorf("disabled admin should get no roles, got %v", admRoles)
	}
}

// seedAdminLogin mints a ten_admin user+session for email and returns the
// state cookie value paired with the session, as the social leg would leave
// them for the callback.
func seedAdminSession(t *testing.T, store Storage, email string) Session {
	t.Helper()
	now := time.Now().UTC()
	u, err := store.CreateUser(User{
		ID: "usr_" + email, TenantID: adminTenantID, Email: email, Name: "Admin",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	s, err := store.CreateSession(Session{
		ID: "ses_" + email, TenantID: adminTenantID, UserID: u.ID, RiskLevel: RiskLow,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create admin session: %v", err)
	}
	return s
}

// driveAdminCallback simulates GET /admin/social/callback with a matching
// state cookie + session_id, returning the response.
func driveAdminCallback(t *testing.T, r http.Handler, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	const state = "admin-state-xyz"
	req := httptest.NewRequest(http.MethodGet, "/admin/social/callback?state="+state+"&session_id="+sessionID, nil)
	req.AddCookie(&http.Cookie{Name: adminStateCookie, Value: state})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAdminSignedOutShowsGoogleLogin(t *testing.T) {
	r, _ := newAdminRouter(t, "tomasboman@gmail.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin: expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `href="/admin/login/google"`) {
		t.Fatalf("signed-out /admin missing Google login link:\n%s", body)
	}
	if strings.Contains(body, "<table") {
		t.Fatal("signed-out /admin must not render the tenant table")
	}
}

func TestAdminAllowedEmailSeesTenants(t *testing.T) {
	r, store := newAdminRouter(t, "tomasboman@gmail.com")
	// Seed some tenants via real records.
	now := time.Now().UTC()
	mustUser(t, store, "usr_a1", "ten_acme", "a1@acme.test", now)
	mustUser(t, store, "usr_a2", "ten_acme", "a2@acme.test", now.Add(time.Second))
	mustUser(t, store, "usr_b1", "ten_beta", "b1@beta.test", now)

	sess := seedAdminSession(t, store, "tomasboman@gmail.com")
	cb := driveAdminCallback(t, r, sess.ID)
	if cb.Code != http.StatusFound {
		t.Fatalf("allowed callback: expected 302, got %d (%s)", cb.Code, cb.Body.String())
	}
	cookie := sessionCookie(cb, adminSessionCookie)
	if cookie == "" {
		t.Fatal("allowed callback must set the admin session cookie")
	}

	// The home page now lists the tenants.
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: adminSessionCookie, Value: cookie})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("admin home: expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"ten_acme", "ten_beta", "ten_admin", "tomasboman@gmail.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("admin tenant page missing %q:\n%s", want, body)
		}
	}
}

// The signed-in staff console renders the chrome header (X-Auth brand) with the
// signed-in email + a Sign out button in the top-right. (Signed-out /admin is the
// separate owner/self-service surface, not this console.)
func TestAdminHeaderAndSignOut(t *testing.T) {
	r, store := newAdminRouter(t, "tomasboman@gmail.com")

	// Signed-in: header (topbar) with the brand, email, and a Sign out form.
	sess := seedAdminSession(t, store, "tomasboman@gmail.com")
	cb := driveAdminCallback(t, r, sess.ID)
	cookie := sessionCookie(cb, adminSessionCookie)
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: adminSessionCookie, Value: cookie})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	in := w.Body.String()
	if !strings.Contains(in, `class="topbar"`) || !strings.Contains(in, `class="brand"`) {
		t.Errorf("signed-in /admin missing the chrome header:\n%s", in)
	}
	if !strings.Contains(in, `action="/admin/logout"`) {
		t.Errorf("signed-in /admin missing the Sign out form in the header")
	}
	if !strings.Contains(in, `class="who">tomasboman@gmail.com`) {
		t.Errorf("signed-in header should show the email in the who slot")
	}
}

// A break-glass root (all roles, incl. operator) sees the Monitoring domain.
func TestOperatorSeesMonitoring(t *testing.T) {
	store := NewMemStorage()
	r := Router(Deps{
		Store: store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Authenticator: &mockAuthenticator{}, Issuer: "http://test.local", Signer: testSigner,
		RootEmails: []string{"root@x.com"}, // → all roles incl operator
	})
	sess := seedAdminSession(t, store, "root@x.com")
	cb := driveAdminCallback(t, r, sess.ID)
	cookie := sessionCookie(cb, adminSessionCookie)
	if cookie == "" {
		t.Fatal("root callback must set the admin cookie")
	}
	req := httptest.NewRequest(http.MethodGet, "/admin?domain=monitoring", nil)
	req.AddCookie(&http.Cookie{Name: adminSessionCookie, Value: cookie})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("monitoring domain: want 200, got %d", w.Code)
	}
	// No Health is wired (hermetic test — no live probes), so the panel renders
	// without a service table; the recent-activity panel and chrome still render.
	body := w.Body.String()
	for _, want := range []string{">Monitoring<", "monitoring:read", "Recent activity", "domain=monitoring"} {
		if !strings.Contains(body, want) {
			t.Errorf("monitoring domain missing %q", want)
		}
	}
}

// The monitoring renderer surfaces live health probes + recent log events when
// wired. Uses a local stub server so the probe is fast and hermetic.
func TestMonitoringPanelsRenderLiveData(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewMemStorage()
	events := NewEventBuffer(50)
	logger = slog.New(NewBufferHandler(logger.Handler(), events))
	logger.Info("admin_login", "email", "root@x.com") // seed one event

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer up.Close()

	r := Router(Deps{
		Store: store, Logger: logger, Authenticator: &mockAuthenticator{},
		Issuer: "http://test.local", Signer: testSigner,
		RootEmails: []string{"root@x.com"},
		Events:     events,
		Health:     NewHealthChecker([]ServiceTarget{{Name: "risk-service", URL: up.URL, Path: "/"}}),
	})
	sess := seedAdminSession(t, store, "root@x.com")
	cb := driveAdminCallback(t, r, sess.ID)
	cookie := sessionCookie(cb, adminSessionCookie)
	req := httptest.NewRequest(http.MethodGet, "/admin?domain=monitoring", nil)
	req.AddCookie(&http.Cookie{Name: adminSessionCookie, Value: cookie})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("monitoring: want 200, got %d", w.Code)
	}
	// Service probe result (Healthy) and the seeded log event both appear.
	for _, want := range []string{"risk-service", "Healthy", "admin_login", "email=root@x.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("monitoring live data missing %q:\n%s", want, body)
		}
	}
}

// operator maps to the monitoring domain only, and the allStaffRoles list stays
// in sync with rolePermissions/allowedDomains.
func TestOperatorRoleAndStaffRoleInvariant(t *testing.T) {
	if d := allowedDomains([]string{"operator"}); len(d) != 1 || d[0] != "monitoring" {
		t.Fatalf("operator domains = %v, want [monitoring]", d)
	}
	if !hasPermission([]string{"operator"}, "monitoring:read") {
		t.Errorf("operator should have monitoring:read")
	}
	if hasPermission([]string{"operator"}, "tenants:read") {
		t.Errorf("operator must NOT have tenants:read")
	}
	for _, role := range allStaffRoles {
		if len(rolePermissions(role)) == 0 {
			t.Errorf("role %q has no permissions — allStaffRoles/rolePermissions out of sync", role)
		}
		if len(allowedDomains([]string{role})) == 0 {
			t.Errorf("role %q maps to no domain — allStaffRoles/allowedDomains out of sync", role)
		}
	}
}

func TestAdminDisallowedEmailRefused(t *testing.T) {
	r, store := newAdminRouter(t, "tomasboman@gmail.com")
	sess := seedAdminSession(t, store, "intruder@evil.test")

	cb := driveAdminCallback(t, r, sess.ID)
	if cb.Code != http.StatusForbidden {
		t.Fatalf("disallowed callback: expected 403, got %d (%s)", cb.Code, cb.Body.String())
	}
	if sessionCookie(cb, adminSessionCookie) != "" {
		t.Fatal("disallowed callback must NOT set an admin session cookie")
	}
	// The minted session must have been invalidated so it can't be reused.
	got, err := store.GetSession(adminTenantID, sess.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if got.InvalidatedAt == nil {
		t.Fatal("disallowed login must invalidate the minted session")
	}
}

// TestAdminDeauthorizedMidSession pins the every-request allowlist re-check:
// an admin whose email is later removed from the allowlist loses access even
// with a still-live cookie.
func TestAdminDeauthorizedMidSession(t *testing.T) {
	// Build with an EMPTY allowlist but hand-craft a cookie pointing at a live
	// ten_admin session — simulates a cookie minted while the email was allowed,
	// then de-authorised.
	r, store := newAdminRouter(t /* no admin emails */)
	sess := seedAdminSession(t, store, "tomasboman@gmail.com")

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: adminSessionCookie, Value: sess.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 login page, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `href="/admin/login/google"`) {
		t.Fatal("de-authorised admin must see the login page, not the tenant table")
	}
	if strings.Contains(w.Body.String(), "<table") {
		t.Fatal("de-authorised admin must not see the tenant table")
	}
}

// TestV1InternalOnlyGate pins the public /v1 lockdown: with V1_INTERNAL_ONLY
// set, POST /v1/users and POST /v1/sessions require the shared secret, while
// the admin console (which uses the Store directly) is unaffected.
func TestV1InternalOnlyGate(t *testing.T) {
	const secret = "test-internal-secret"
	t.Setenv(httpx.EnvInternalAuthSecret, secret)
	t.Setenv("V1_INTERNAL_ONLY", "true")
	r, store := newAdminRouter(t, "tomasboman@gmail.com")

	// Anonymous POST /v1/users → 401 before the tenant gate.
	body := strings.NewReader(`{"email":"x@y.test","name":"X"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/users", body)
	req.Header.Set("X-Tenant-Id", "ten_acme")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anon /v1/users: want 401, got %d (%s)", w.Code, w.Body.String())
	}

	// With the secret, it works.
	body = strings.NewReader(`{"email":"x@y.test","name":"X"}`)
	req = httptest.NewRequest(http.MethodPost, "/v1/users", body)
	req.Header.Set("X-Tenant-Id", "ten_acme")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(httpx.InternalAuthHeader, secret)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("authed /v1/users: want 201, got %d (%s)", w.Code, w.Body.String())
	}

	// The admin console keeps working with the gate on: it reads the Store
	// directly, not via HTTP /v1.
	sess := seedAdminSession(t, store, "tomasboman@gmail.com")
	cb := driveAdminCallback(t, r, sess.ID)
	if cb.Code != http.StatusFound || sessionCookie(cb, adminSessionCookie) == "" {
		t.Fatalf("admin login must still work under V1_INTERNAL_ONLY: got %d", cb.Code)
	}
}

func TestListTenantsAggregation(t *testing.T) {
	store := NewMemStorage()
	now := time.Now().UTC()
	mustUser(t, store, "u1", "ten_x", "u1@x.test", now)
	mustUser(t, store, "u2", "ten_x", "u2@x.test", now.Add(2*time.Second)) // newest in ten_x
	mustUser(t, store, "u3", "ten_y", "u3@y.test", now.Add(time.Second))
	if _, err := store.CreateSession(Session{
		ID: "s1", TenantID: "ten_x", UserID: "u1", CreatedAt: now, UpdatedAt: now.Add(5 * time.Second), ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}

	tenants, err := store.ListTenants()
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(tenants) != 2 {
		t.Fatalf("want 2 tenants, got %d: %+v", len(tenants), tenants)
	}
	// Ordered by last activity desc: ten_x has a session updated at now+5s.
	if tenants[0].TenantID != "ten_x" {
		t.Errorf("want ten_x first (newest activity), got %q", tenants[0].TenantID)
	}
	byID := map[string]TenantSummary{tenants[0].TenantID: tenants[0], tenants[1].TenantID: tenants[1]}
	if byID["ten_x"].Users != 2 || byID["ten_x"].Sessions != 1 {
		t.Errorf("ten_x counts wrong: %+v", byID["ten_x"])
	}
	if byID["ten_y"].Users != 1 || byID["ten_y"].Sessions != 0 {
		t.Errorf("ten_y counts wrong: %+v", byID["ten_y"])
	}
}

// adminCookie signs in an allowlisted admin and returns the session cookie.
func adminCookie(t *testing.T, r http.Handler, store Storage, email string) string {
	t.Helper()
	sess := seedAdminSession(t, store, email)
	cb := driveAdminCallback(t, r, sess.ID)
	c := sessionCookie(cb, adminSessionCookie)
	if c == "" {
		t.Fatalf("admin sign-in failed: %d", cb.Code)
	}
	return c
}

func TestAdminRegisterAndDeleteClient(t *testing.T) {
	r, store := newAdminRouter(t, "tomasboman@gmail.com")
	cookie := adminCookie(t, r, store, "tomasboman@gmail.com")

	// Register a client with redirect URIs + web origins.
	form := url.Values{
		"client_id":     {"unlimitedfreight-web"},
		"redirect_uris": {"https://unlimitedfreight.com/callback.html\nhttp://localhost:3000/callback.html"},
		"web_origins":   {"https://unlimitedfreight.com"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/clients", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: adminSessionCookie, Value: cookie})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("register: want 302, got %d (%s)", w.Code, w.Body.String())
	}

	got, err := store.GetClient("unlimitedfreight-web")
	if err != nil {
		t.Fatalf("client not stored: %v", err)
	}
	if len(got.RedirectURIs) != 2 || len(got.WebOrigins) != 1 || got.WebOrigins[0] != "https://unlimitedfreight.com" {
		t.Fatalf("client stored wrong: %+v", got)
	}

	// It appears on the admin page.
	home := httptest.NewRequest(http.MethodGet, "/admin", nil)
	home.AddCookie(&http.Cookie{Name: adminSessionCookie, Value: cookie})
	hw := httptest.NewRecorder()
	r.ServeHTTP(hw, home)
	if !strings.Contains(hw.Body.String(), "unlimitedfreight-web") {
		t.Fatal("registered client not shown on admin page")
	}

	// Delete it.
	del := url.Values{"client_id": {"unlimitedfreight-web"}}
	dreq := httptest.NewRequest(http.MethodPost, "/admin/clients/delete", strings.NewReader(del.Encode()))
	dreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dreq.AddCookie(&http.Cookie{Name: adminSessionCookie, Value: cookie})
	dw := httptest.NewRecorder()
	r.ServeHTTP(dw, dreq)
	if dw.Code != http.StatusFound {
		t.Fatalf("delete: want 302, got %d", dw.Code)
	}
	if _, err := store.GetClient("unlimitedfreight-web"); err != ErrNotFound {
		t.Fatalf("client should be gone, got %v", err)
	}
}

func TestAdminClientMgmtRequiresAdmin(t *testing.T) {
	r, _ := newAdminRouter(t, "tomasboman@gmail.com")
	// No admin cookie -> register and delete are both refused (403).
	for _, path := range []string{"/admin/clients", "/admin/clients/delete"} {
		form := url.Values{"client_id": {"x"}, "redirect_uris": {"https://x.test/cb"}}
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s without admin: want 403, got %d", path, w.Code)
		}
	}
}

// TestDynamicCORSFromRegisteredClient pins that a registered client's web
// origin is honored by the CORS handler without being in the env baseline.
func TestDynamicCORSFromRegisteredClient(t *testing.T) {
	r, store := newAdminRouter(t, "tomasboman@gmail.com")
	const origin = "https://unlimitedfreight.com"

	// Before registration: origin not allowed (no Allow-Origin header).
	pre := httptest.NewRequest(http.MethodOptions, "/token", nil)
	pre.Header.Set("Origin", origin)
	pw := httptest.NewRecorder()
	r.ServeHTTP(pw, pre)
	if pw.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("origin must not be allowed before registration")
	}

	if err := store.PutClient(OIDCClient{
		ClientID: "uf", RedirectURIs: []string{"https://unlimitedfreight.com/cb"},
		WebOrigins: []string{origin}, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("put client: %v", err)
	}

	// After registration: the preflight echoes the origin.
	post := httptest.NewRequest(http.MethodOptions, "/token", nil)
	post.Header.Set("Origin", origin)
	pow := httptest.NewRecorder()
	r.ServeHTTP(pow, post)
	if pow.Header().Get("Access-Control-Allow-Origin") != origin {
		t.Fatalf("registered origin must be allowed; got %q", pow.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestListAndDeleteClientsMem(t *testing.T) {
	store := NewMemStorage()
	now := time.Now().UTC()
	for _, id := range []string{"c1", "c2"} {
		if err := store.PutClient(OIDCClient{ClientID: id, RedirectURIs: []string{"https://x/cb"}, CreatedAt: now}); err != nil {
			t.Fatalf("put %s: %v", id, err)
		}
	}
	clients, err := store.ListClients()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// Includes the default seeded client + c1 + c2.
	if len(clients) < 3 {
		t.Fatalf("want >=3 clients, got %d", len(clients))
	}
	if err := store.DeleteClient("c1"); err != nil {
		t.Fatalf("delete c1: %v", err)
	}
	if err := store.DeleteClient("c1"); err != ErrNotFound {
		t.Fatalf("re-delete c1: want ErrNotFound, got %v", err)
	}
}

func mustUser(t *testing.T, store Storage, id, tenant, email string, created time.Time) {
	t.Helper()
	if _, err := store.CreateUser(User{
		ID: id, TenantID: tenant, Email: email, Name: id, CreatedAt: created, UpdatedAt: created,
	}); err != nil {
		t.Fatalf("create user %s: %v", id, err)
	}
}

// sessionCookie extracts a Set-Cookie value by name from a recorded response,
// or "" if absent / cleared (MaxAge<0).
func sessionCookie(w *httptest.ResponseRecorder, name string) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.MaxAge >= 0 && c.Value != "" {
			return c.Value
		}
	}
	return ""
}
