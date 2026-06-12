package internal

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
