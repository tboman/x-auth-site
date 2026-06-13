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
	// Duplicate owner email → conflict.
	if _, err := store.CreateTenant(Tenant{ID: "ten_acme3", CompanyName: "Acme Three", Slug: "acme3", OwnerEmail: "o@acme.test", CreatedAt: now}); err != ErrConflict {
		t.Fatalf("dup owner: want ErrConflict, got %v", err)
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

	// Reuses the owner email (UNIQUE) → conflict; the beta rows must NOT persist.
	ten2, o2, s2, c2 := mk("2", "beta", "o@acme.test")
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

func TestSignupProvisionsTenantAndConfidentialClient(t *testing.T) {
	r, store := newAdminRouter(t) // no admin emails; stub social
	w := driveSignup(t, r, store, "owner@acme.test", "Acme Inc", "https://app.acme.com/callback")
	if w.Code != http.StatusOK {
		t.Fatalf("signup callback: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "Workspace created") || !strings.Contains(body, "ten_acme-inc") {
		t.Fatalf("secret screen missing expected content:\n%s", body)
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
	// Confidential client bound to the tenant, secret hash matches the displayed secret.
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
	if client.ClientSecretHash == "" {
		t.Fatal("client must be confidential (non-empty secret hash)")
	}
	secret := extractSecret(t, body)
	if HashToken(secret) != client.ClientSecretHash {
		t.Fatal("displayed secret does not hash to the stored secret hash")
	}
	if len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != "https://app.acme.com/callback" {
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

func TestSignupReturningOwnerRoutedToWorkspace(t *testing.T) {
	r, store := newAdminRouter(t)
	if w := driveSignup(t, r, store, "owner@acme.test", "Acme", ""); w.Code != http.StatusOK {
		t.Fatalf("first signup: want 200, got %d", w.Code)
	}
	// Same owner signs up again (even with a different name) → routed to existing
	// workspace, no second tenant.
	w := driveSignup(t, r, store, "owner@acme.test", "Totally Different", "")
	if w.Code != http.StatusFound {
		t.Fatalf("returning owner: want 302, got %d (%s)", w.Code, w.Body.String())
	}
	if _, err := store.GetTenantBySlug("totally-different"); err != ErrNotFound {
		t.Fatal("returning owner must not create a second tenant")
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

// TestSignupClientEnforcedAtToken proves the signup-minted confidential client's
// secret is actually enforced end-to-end: a code exchange with the wrong secret
// is refused, the right one succeeds.
func TestSignupClientEnforcedAtToken(t *testing.T) {
	r, store := newAdminRouter(t)
	w := driveSignup(t, r, store, "owner@acme.test", "Acme", "https://app.acme.com/callback")
	secret := extractSecret(t, w.Body.String())
	client, _ := (&SignupConsoleHandlers{Store: store}).tenantClient("ten_acme")
	owner, err := store.GetUserByEmail("ten_acme", "owner@acme.test")
	if err != nil {
		t.Fatalf("owner: %v", err)
	}

	verifier := randToken(48)
	seedCode := func(code string) {
		if err := store.PutAuthCode(AuthCode{
			Code: code, ClientID: client.ClientID, TenantID: "ten_acme", UserID: owner.ID,
			RedirectURI: "https://app.acme.com/callback", Scope: "openid",
			CodeChallenge: pkceS256(verifier), CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("seed code: %v", err)
		}
	}
	exchange := func(code, secret string) *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"https://app.acme.com/callback"},
			"code_verifier": {verifier},
			"client_id":     {client.ClientID},
			"client_secret": {secret},
		}
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		tw := httptest.NewRecorder()
		r.ServeHTTP(tw, req)
		return tw
	}

	seedCode("code-wrong")
	if tw := exchange("code-wrong", "not-the-secret"); tw.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: want 401, got %d (%s)", tw.Code, tw.Body.String())
	}
	seedCode("code-right")
	tw := exchange("code-right", secret)
	if tw.Code != http.StatusOK {
		t.Fatalf("correct secret: want 200, got %d (%s)", tw.Code, tw.Body.String())
	}
	if !strings.Contains(tw.Body.String(), "access_token") {
		t.Fatalf("token response missing access_token:\n%s", tw.Body.String())
	}
}
