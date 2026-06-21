package internal

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// stubIDClient returns canned verification responses.
type stubIDClient struct {
	createID, createURL string
	createErr           error
	getStatus, getProof string
	getErr              error
}

func (s stubIDClient) Create(_ context.Context, _, _ string, _ []string, _ string) (string, string, error) {
	return s.createID, s.createURL, s.createErr
}
func (s stubIDClient) Get(_ context.Context, _, _ string) (string, string, error) {
	return s.getStatus, s.getProof, s.getErr
}

func newEnrollRouter(t *testing.T, id IDVerificationClient, v MDLProofVerifier) (http.Handler, Storage) {
	t.Helper()
	store := NewMemStorage()
	r := Router(Deps{
		Store: store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Authenticator: &mockAuthenticator{}, Issuer: "http://test.local", Signer: testSigner,
		MDLVerifier: v, IDClient: id,
	})
	return r, store
}

// seedEnrollSession creates a user + enrollment session and returns the cookie.
func seedEnrollSession(t *testing.T, store Storage, tenantID, userID, email string) *http.Cookie {
	t.Helper()
	now := time.Now().UTC()
	mustUser(t, store, userID, tenantID, email, now)
	sess := Session{ID: "ses_enr", TenantID: tenantID, UserID: userID, RiskLevel: RiskLow,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(15 * time.Minute)}
	if _, err := store.CreateSession(sess); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return &http.Cookie{Name: enrollSessionCookie, Value: tenantID + "|" + sess.ID}
}

func TestEnrollMDLStartRejectsUnknownClient(t *testing.T) {
	r, _ := newEnrollRouter(t, stubIDClient{}, stubMDLVerifier{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/enroll/mdl?client_id=nope", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown client: want 400, got %d", w.Code)
	}
}

func TestEnrollMDLPageRendersBothPaths(t *testing.T) {
	r, store := newEnrollRouter(t,
		stubIDClient{createID: "vrf_1", createURL: "https://id.x-auth.com/v/tok"},
		stubMDLVerifier{})
	cookie := seedEnrollSession(t, store, "ten_acme", "usr_e", "e@acme.test")
	req := httptest.NewRequest(http.MethodGet, "/enroll/mdl/page", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("page: want 200, got %d", w.Code)
	}
	b := w.Body.String()
	for _, want := range []string{"On this device", "https://id.x-auth.com/v/tok", "data:image/png;base64,", "/enroll/mdl/status"} {
		if !strings.Contains(b, want) {
			t.Errorf("page missing %q", want)
		}
	}
	// The verification id is parked in a browser-bound cookie for polling.
	if !strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), " "), enrollVrfCookie) {
		t.Error("page should set the vrf cookie")
	}
}

func TestEnrollMDLStatusPending(t *testing.T) {
	r, store := newEnrollRouter(t, stubIDClient{getStatus: "pending"}, stubMDLVerifier{})
	cookie := seedEnrollSession(t, store, "ten_acme", "usr_e", "e@acme.test")
	req := httptest.NewRequest(http.MethodGet, "/enroll/mdl/status", nil)
	req.AddCookie(cookie)
	req.AddCookie(&http.Cookie{Name: enrollVrfCookie, Value: "vrf_1"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), `"status":"pending"`) {
		t.Fatalf("want pending, got %s", w.Body.String())
	}
}

func TestEnrollMDLStatusVerifiedCreatesAnchor(t *testing.T) {
	r, store := newEnrollRouter(t,
		stubIDClient{getStatus: "verified", getProof: "proof.jwt"},
		stubMDLVerifier{proof: MDLProof{TrustAnchor: "CN=NY DMV IACA"}})
	cookie := seedEnrollSession(t, store, "ten_acme", "usr_e", "e@acme.test")
	req := httptest.NewRequest(http.MethodGet, "/enroll/mdl/status", nil)
	req.AddCookie(cookie)
	req.AddCookie(&http.Cookie{Name: enrollVrfCookie, Value: "vrf_1"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), `"status":"done"`) || !strings.Contains(w.Body.String(), "NY DMV IACA") {
		t.Fatalf("want done + anchor, got %s", w.Body.String())
	}
	anchors, _ := store.ListIdentityAnchors("ten_acme")
	var got *IdentityAnchor
	for i := range anchors {
		if anchors[i].Type == AnchorMDL {
			got = &anchors[i]
		}
	}
	if got == nil || got.UserID != "usr_e" || got.Value != "CN=NY DMV IACA" || got.VerifiedAt == nil {
		t.Fatalf("mdl anchor wrong: %+v", got)
	}
}

// Signing up for a tenant via Google also starts mDL enrollment inline on the
// workspace-ready screen (reusing the just-created owner session — no re-login).
func TestSignupStartsMDLEnrollment(t *testing.T) {
	r, store := newEnrollRouter(t,
		stubIDClient{createID: "vrf_s", createURL: "https://id.x-auth.com/v/tok"},
		stubMDLVerifier{})
	w := driveSignup(t, r, store, "founder@newco.test", "Newco", "")
	if w.Code != http.StatusOK {
		t.Fatalf("signup: want 200, got %d", w.Code)
	}
	b := w.Body.String()
	for _, want := range []string{"Workspace created", "Verify your identity", "data:image/png;base64,", "/enroll/mdl/status", "https://id.x-auth.com/v/tok"} {
		if !strings.Contains(b, want) {
			t.Errorf("workspace-ready should embed enrollment, missing %q", want)
		}
	}
	cookies := strings.Join(w.Header().Values("Set-Cookie"), " ")
	if !strings.Contains(cookies, enrollSessionCookie) || !strings.Contains(cookies, enrollVrfCookie) {
		t.Errorf("signup should set enroll session + vrf cookies: %s", cookies)
	}
}

// Without id-service configured, signup still completes (enrollment is best-effort).
func TestSignupWithoutMDLStillCompletes(t *testing.T) {
	r, store := newEnrollRouter(t, nil, nil)
	w := driveSignup(t, r, store, "founder2@newco.test", "Newco Two", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Workspace created") {
		t.Fatalf("signup should complete without enrollment: %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "Verify your identity") {
		t.Error("no enrollment section expected when id-service is unconfigured")
	}
}

// driveSocialStub runs the social authorize→callback stub for ten_a (whose mDL
// enrollment opt-in is set to mdlEnabled) and returns the callback response.
func driveSocialStub(t *testing.T, r http.Handler, store Storage, mdlEnabled bool) *httptest.ResponseRecorder {
	t.Helper()
	if _, err := store.CreateTenant(Tenant{ID: "ten_a", CompanyName: "A", Slug: "a",
		OwnerEmail: "o@a.test", CreatedAt: time.Now().UTC(), MDLEnrollEnabled: mdlEnabled}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if err := store.PutClient(OIDCClient{ClientID: "cli_a", TenantID: "ten_a",
		RedirectURIs: []string{"http://app.example.com/cb"}, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	au := "/v1/social/google/authorize?" + url.Values{"tenant_id": {"ten_a"},
		"redirect_uri": {"http://app.example.com/cb"}, "state": {"s1"}}.Encode()
	aw := httptest.NewRecorder()
	r.ServeHTTP(aw, httptest.NewRequest(http.MethodGet, au, nil))
	loc, _ := url.Parse(aw.Header().Get("Location"))
	cu := "/v1/social/google/callback?" + url.Values{"code": {loc.Query().Get("code")}, "state": {"s1"}}.Encode()
	cw := httptest.NewRecorder()
	r.ServeHTTP(cw, httptest.NewRequest(http.MethodGet, cu, nil))
	return cw
}

// A first-time OIDC social login shows the mDL interstitial (with a Continue link
// back to the app), reusing the just-created session.
func TestSocialLoginNewUserOffersMDLInterstitial(t *testing.T) {
	r, store := newEnrollRouter(t,
		stubIDClient{createID: "vrf_s", createURL: "https://id.x-auth.com/v/tok"},
		stubMDLVerifier{})
	cw := driveSocialStub(t, r, store, true)
	if cw.Code != http.StatusOK {
		t.Fatalf("first social login: want 200 interstitial, got %d", cw.Code)
	}
	b := cw.Body.String()
	for _, want := range []string{"Continue to your app", "app.example.com/cb", "data:image/png;base64,", "/enroll/mdl/status"} {
		if !strings.Contains(b, want) {
			t.Errorf("interstitial missing %q", want)
		}
	}
	if c := strings.Join(cw.Header().Values("Set-Cookie"), " "); !strings.Contains(c, enrollSessionCookie) {
		t.Error("interstitial should set the enroll session cookie")
	}
}

// A returning user (already exists) is NOT interrupted — straight redirect to app.
func TestSocialLoginReturningUserNoInterstitial(t *testing.T) {
	r, store := newEnrollRouter(t,
		stubIDClient{createID: "vrf_s", createURL: "https://id.x-auth.com/v/tok"},
		stubMDLVerifier{})
	mustUser(t, store, "usr_pre", "ten_a", "stub-google@example.com", time.Now().UTC())
	cw := driveSocialStub(t, r, store, true)
	if cw.Code != http.StatusFound {
		t.Fatalf("returning user: want 302 redirect, got %d (%s)", cw.Code, cw.Body.String())
	}
	if loc, _ := url.Parse(cw.Header().Get("Location")); loc.Host != "app.example.com" {
		t.Fatalf("should redirect to the app, got %q", loc.Host)
	}
}

// A first-time user whose tenant has NOT opted in gets the normal redirect — no
// interstitial (the per-tenant flag gates it).
func TestSocialLoginMDLDisabledNoInterstitial(t *testing.T) {
	r, store := newEnrollRouter(t,
		stubIDClient{createID: "vrf_s", createURL: "https://id.x-auth.com/v/tok"},
		stubMDLVerifier{})
	cw := driveSocialStub(t, r, store, false) // tenant opt-in OFF
	if cw.Code != http.StatusFound {
		t.Fatalf("opt-in off: want 302, got %d (%s)", cw.Code, cw.Body.String())
	}
	if loc, _ := url.Parse(cw.Header().Get("Location")); loc.Host != "app.example.com" {
		t.Fatalf("should redirect to the app, got %q", loc.Host)
	}
}

// The owner toggles the mDL-enrollment opt-in from the Integration tab.
func TestOwnerTogglesMDLEnroll(t *testing.T) {
	r, store := newEnrollRouter(t, stubIDClient{}, stubMDLVerifier{})
	w := driveSignup(t, r, store, "owner@acme.test", "Acme", "")
	oc := &http.Cookie{Name: ownerSessionCookie, Value: sessionCookie(w, ownerSessionCookie)}

	if pw := postForm(t, r, "/admin/owner/mdl-enroll", url.Values{"enabled": {"true"}}, oc); pw.Code != http.StatusFound {
		t.Fatalf("enable: want 302, got %d", pw.Code)
	}
	if tn, _ := store.GetTenant("ten_acme"); !tn.MDLEnrollEnabled {
		t.Fatal("flag should be enabled")
	}
	// Integration tab shows the toggle.
	req := httptest.NewRequest(http.MethodGet, "/admin?tab=integration", nil)
	req.AddCookie(oc)
	dw := httptest.NewRecorder()
	r.ServeHTTP(dw, req)
	if !strings.Contains(dw.Body.String(), "Offer mDL enrollment on first social login") {
		t.Error("Integration tab missing the mDL toggle")
	}
	// Disable again.
	if pw := postForm(t, r, "/admin/owner/mdl-enroll", url.Values{}, oc); pw.Code != http.StatusFound {
		t.Fatalf("disable: want 302, got %d", pw.Code)
	}
	if tn, _ := store.GetTenant("ten_acme"); tn.MDLEnrollEnabled {
		t.Fatal("flag should be disabled")
	}
}

func TestEnrollMDLStatusNoSession(t *testing.T) {
	r, _ := newEnrollRouter(t, stubIDClient{}, stubMDLVerifier{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/enroll/mdl/status", nil))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"status":"expired"`) {
		t.Fatalf("no session: want 401 expired, got %d %s", w.Code, w.Body.String())
	}
}
