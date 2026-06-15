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
)

// phoneTestRouter wires a router with a tenant whose client registers the test
// redirect, so the phone flow's redirect check passes.
func phoneTestRouter(t *testing.T) (http.Handler, Storage) {
	t.Helper()
	r, store := newAdminRouter(t)
	if err := store.PutClient(OIDCClient{
		ClientID: "cli_acme", TenantID: "ten_acme",
		RedirectURIs: []string{phoneRedirect}, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	// Phone login is per-tenant opt-in (migration 000016) — the tenant must have a
	// registry row with it enabled for the flow to run.
	if _, err := store.CreateTenant(Tenant{
		ID: "ten_acme", CompanyName: "Acme", Slug: "acme",
		CreatedAt: time.Now().UTC(), PhoneLoginEnabled: true,
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return r, store
}

const phoneRedirect = "https://app.acme.com/callback.html"

func extractHidden(t *testing.T, body, name string) string {
	t.Helper()
	marker := `name="` + name + `" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("hidden field %q not found in:\n%s", name, body)
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("unterminated hidden field %q", name)
	}
	return rest[:j]
}

func postForm(t *testing.T, r http.Handler, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// submitPhone drives POST /login/phone and returns the parked flow id.
func submitPhone(t *testing.T, r http.Handler, phone string) string {
	t.Helper()
	form := url.Values{
		"tenant_id":    {"ten_acme"},
		"redirect_uri": {phoneRedirect},
		"state":        {"st-1"},
		"phone":        {phone},
	}
	w := postForm(t, r, "/login/phone", form)
	if w.Code != http.StatusOK {
		t.Fatalf("submit: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	return extractHidden(t, w.Body.String(), "flow")
}

func TestNormalizePhone(t *testing.T) {
	ok := map[string]string{
		"+15551234567":     "+15551234567",
		"+1 555 123 4567":  "+15551234567",
		"(555) 123-4567":   "+5551234567",
		"+46-70-123 45 67": "+46701234567",
	}
	for in, want := range ok {
		if got, valid := normalizePhone(in); !valid || got != want {
			t.Errorf("normalizePhone(%q) = %q,%v; want %q,true", in, got, valid, want)
		}
	}
	for _, bad := range []string{"", "123", "abc", "+1234567890123456", "12a4567"} {
		if _, valid := normalizePhone(bad); valid {
			t.Errorf("normalizePhone(%q) should be invalid", bad)
		}
	}
}

// TestPhoneLoginKnownNumber: a registered phone + correct OTP logs in as that
// user and redirects to the app with that user_id.
func TestPhoneLoginKnownNumber(t *testing.T) {
	r, store := phoneTestRouter(t)
	now := time.Now().UTC()
	mustUser(t, store, "usr_known", "ten_acme", "known@acme.test", now)
	if _, err := store.CreateIdentityAnchor(IdentityAnchor{
		ID: "ian_k", UserID: "usr_known", TenantID: "ten_acme",
		Type: AnchorPhone, Value: "+15551112222", VerifiedAt: &now, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed anchor: %v", err)
	}

	flow := submitPhone(t, r, "+15551112222")
	w := postForm(t, r, "/login/phone/verify", url.Values{"flow": {flow}, "code": {stubOTPCode}})
	if w.Code != http.StatusFound {
		t.Fatalf("verify: want 302, got %d (%s)", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("user_id") != "usr_known" {
		t.Fatalf("want user_id usr_known, got %q (loc=%s)", loc.Query().Get("user_id"), loc)
	}
	if loc.Query().Get("session_id") == "" || loc.Query().Get("state") != "st-1" {
		t.Fatalf("missing session_id/state: %s", loc)
	}
	// authz cookie set for the follow-up /authorize.
	if sessionCookie(w, AuthzSessionCookie) == "" {
		t.Fatal("phone login must set the authz session cookie")
	}
}

// TestPhoneLoginNewNumber: an unknown number + correct OTP creates an emailless
// account (phone anchor, verified) and shows the link-Google offer; Skip then
// finalises the app login.
func TestPhoneLoginNewNumber(t *testing.T) {
	r, store := phoneTestRouter(t)
	const phone = "+15559998888"

	flow := submitPhone(t, r, phone)
	w := postForm(t, r, "/login/phone/verify", url.Values{"flow": {flow}, "code": {stubOTPCode}})
	if w.Code != http.StatusOK {
		t.Fatalf("verify(new): want 200 link offer, got %d (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "Account created") || !strings.Contains(body, "/login/phone/link") || !strings.Contains(body, "/login/phone/skip") {
		t.Fatalf("link offer missing expected content:\n%s", body)
	}
	linkCookie := sessionCookie(w, phoneLinkCookie)
	if linkCookie == "" {
		t.Fatal("link offer must set the link cookie")
	}

	// The account + verified phone anchor now exist, with no email.
	anchor, err := store.GetIdentityAnchorByValue("ten_acme", AnchorPhone, phone)
	if err != nil {
		t.Fatalf("phone anchor not created: %v", err)
	}
	user, err := store.GetUser("ten_acme", anchor.UserID)
	if err != nil || user.Email != "" {
		t.Fatalf("new phone user wrong: %+v err=%v", user, err)
	}
	if anchor.VerifiedAt == nil {
		t.Fatal("phone anchor should be verified")
	}

	// Skip → finalise to the app with the new user.
	sw := postForm(t, r, "/login/phone/skip", url.Values{}, &http.Cookie{Name: phoneLinkCookie, Value: linkCookie})
	if sw.Code != http.StatusFound {
		t.Fatalf("skip: want 302, got %d (%s)", sw.Code, sw.Body.String())
	}
	loc, _ := url.Parse(sw.Header().Get("Location"))
	if loc.Query().Get("user_id") != anchor.UserID {
		t.Fatalf("skip redirect user mismatch: %s", loc)
	}
}

// TestPhoneLoginWrongCode re-renders the code form on a bad code and kills the
// flow after the attempt cap.
func TestPhoneLoginWrongCode(t *testing.T) {
	r, _ := phoneTestRouter(t)
	flow := submitPhone(t, r, "+15551110000")

	w := postForm(t, r, "/login/phone/verify", url.Values{"flow": {flow}, "code": {"000000"}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Incorrect code") {
		t.Fatalf("wrong code: want 200 retry, got %d", w.Code)
	}
	// One wrong attempt already counted; phoneMaxOTP-1 more reach the cap, and
	// the last of those kills the flow.
	var last *httptest.ResponseRecorder
	for i := 0; i < phoneMaxOTP-1; i++ {
		last = postForm(t, r, "/login/phone/verify", url.Values{"flow": {flow}, "code": {"000000"}})
	}
	if !strings.Contains(last.Body.String(), "Too many") {
		t.Fatalf("flow should be killed after %d attempts:\n%s", phoneMaxOTP, last.Body.String())
	}
}

// TestPhoneEntryValidation rejects a bad number and an unregistered redirect.
func TestPhoneEntryValidation(t *testing.T) {
	r, _ := phoneTestRouter(t)

	// Bad number.
	w := postForm(t, r, "/login/phone", url.Values{
		"tenant_id": {"ten_acme"}, "redirect_uri": {phoneRedirect}, "phone": {"abc"},
	})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Check the number") {
		t.Fatalf("bad number: want 400, got %d", w.Code)
	}

	// Unregistered redirect → blocked (open-redirect hardening) at /login/phone.
	g := httptest.NewRequest(http.MethodGet, "/login/phone?tenant_id=ten_acme&redirect_uri="+url.QueryEscape("https://evil.com/cb"), nil)
	gw := httptest.NewRecorder()
	r.ServeHTTP(gw, g)
	if gw.Code != http.StatusBadRequest {
		t.Fatalf("unregistered redirect: want 400, got %d", gw.Code)
	}
}

// TestPhoneLinkCallbackAttachesEmail exercises the link tail directly: the
// staging Google session's email is attached to the phone account, then the
// app login finalises.
func TestPhoneLinkCallbackAttachesEmail(t *testing.T) {
	store := NewMemStorage()
	h := NewPhoneLoginHandlers(store, slog.New(slog.NewTextHandler(io.Discard, nil)), "http://test.local")
	now := time.Now().UTC()

	// Emailless phone account in the real tenant.
	phoneUser, err := store.CreateUser(User{ID: "usr_phone", TenantID: "ten_acme", CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatalf("create phone user: %v", err)
	}
	// Staging Google session carrying the verified email.
	gUser, _ := store.CreateUser(User{ID: "usr_g", TenantID: signupTenantID, Email: "linked@gmail.com", CreatedAt: now, UpdatedAt: now})
	gSess, _ := store.CreateSession(Session{ID: "ses_g", TenantID: signupTenantID, UserID: gUser.ID, RiskLevel: RiskLow, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)})

	const linkID, csrf = "lid-1", "csrf-1"
	h.putLink(linkID, pendingPhoneLink{
		ID: linkID, TenantID: "ten_acme", UserID: phoneUser.ID, SessionID: "ses_app",
		RedirectURI: phoneRedirect, State: "st", CSRF: csrf, CreatedAt: now,
	})

	req := httptest.NewRequest(http.MethodGet, "/login/phone/link/callback?session_id="+gSess.ID+"&state="+csrf, nil)
	req.AddCookie(&http.Cookie{Name: phoneLinkCookie, Value: linkID})
	req.AddCookie(&http.Cookie{Name: phoneLinkState, Value: csrf})
	w := httptest.NewRecorder()
	h.LinkCallback(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("link callback: want 302, got %d (%s)", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("session_id") != "ses_app" || loc.Query().Get("user_id") != phoneUser.ID {
		t.Fatalf("finalize redirect wrong: %s", loc)
	}
	// Email now attached.
	got, _ := store.GetUser("ten_acme", phoneUser.ID)
	if got.Email != "linked@gmail.com" {
		t.Fatalf("email not linked: %q", got.Email)
	}
}

// TestPhoneAccountsNullableEmail: multiple emailless phone users coexist in a
// tenant (no false (tenant,email) conflict).
func TestPhoneAccountsNullableEmail(t *testing.T) {
	store := NewMemStorage()
	now := time.Now().UTC()
	for _, id := range []string{"usr_p1", "usr_p2"} {
		if _, err := store.CreateUser(User{ID: id, TenantID: "ten_acme", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatalf("create emailless user %s: %v", id, err)
		}
	}
	// An empty-email lookup never matches a phone-only account.
	if _, err := store.GetUserByEmail("ten_acme", ""); err != ErrNotFound {
		t.Fatalf("empty-email lookup should be ErrNotFound, got %v", err)
	}
}
