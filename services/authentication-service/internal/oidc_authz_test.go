package internal

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/jwtx"
)

// seedAdvice records a minimal advice row so a transaction_id passes the
// /authorize binding checks. rank 0 means "no level requirement" (isolates a
// test from the downgrade gate); userID "" means "no subject binding".
func seedAdvice(t *testing.T, store Storage, id, tenant, userID string, rank int, acr string) {
	t.Helper()
	if err := store.RecordAdviceCall(AdviceCall{
		ID: id, TenantID: tenant, UserID: userID, Rank: rank, ACR: acr,
		TransactionType: "test", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed advice: %v", err)
	}
}

// The transaction_id from /v1/advice, carried into /authorize, is echoed on the
// final callback (alongside code+state) and recorded on the minted auth code.
func TestAuthorizeEchoesTransactionId(t *testing.T) {
	r, store := secureAuthzRouter(t)
	sess := seedAuthzSession(t, store, "ten_bound", "real@bound.test")
	seedAdvice(t, store, "txn_abc123", "ten_bound", "usr_real@bound.test", 0, "")
	req := authzReq(url.Values{"transaction_id": {"txn_abc123"}})
	req.AddCookie(&http.Cookie{Name: AuthzSessionCookie, Value: sess.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("transaction_id") != "txn_abc123" {
		t.Fatalf("final redirect missing transaction_id: %q", loc.String())
	}
	ac, err := store.ConsumeAuthCode(loc.Query().Get("code"))
	if err != nil || ac.TransactionID != "txn_abc123" {
		t.Fatalf("auth code missing transaction id: %+v err=%v", ac, err)
	}
}

// The transaction_id also rides into the issued id_token as a claim.
func TestIDTokenCarriesTransactionId(t *testing.T) {
	r, store := secureAuthzRouter(t)
	sess := seedAuthzSession(t, store, "ten_bound", "real@bound.test")
	seedAdvice(t, store, "txn_xyz", "ten_bound", "usr_real@bound.test", 0, "")
	req := authzReq(url.Values{"transaction_id": {"txn_xyz"}})
	req.AddCookie(&http.Cookie{Name: AuthzSessionCookie, Value: sess.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	code := mustQuery(t, w, "code")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"bound-web"},
		"code_verifier": {testPKCEVerifier},
	}
	treq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	treq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tw := httptest.NewRecorder()
	r.ServeHTTP(tw, treq)
	if tw.Code != http.StatusOK {
		t.Fatalf("token: want 200, got %d (%s)", tw.Code, tw.Body.String())
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(tw.Body.Bytes(), &tok); err != nil || tok.IDToken == "" {
		t.Fatalf("no id_token: %v (%s)", err, tw.Body.String())
	}
	verifier, err := jwtx.NewVerifierFromJWKS("http://test.local", testSigner.JWKS())
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	_, extra, err := verifier.Verify(tok.IDToken, time.Now())
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	if extra["transaction_id"] != "txn_xyz" {
		t.Fatalf("id_token transaction_id = %v, want txn_xyz", extra["transaction_id"])
	}
}

// On completion, the advice row is stamped completed and a CAEP SET (carrying the
// transaction id + satisfied level) is delivered to risk-service.
func TestAdviceCompletionRecordsAndEmitsCAEP(t *testing.T) {
	store := NewMemStorage()
	_ = store.RecordAdviceCall(AdviceCall{ID: "txn_done", TenantID: "ten_x", UserID: "usr_1",
		TransactionType: "pay", ACR: "urn:xauth:protect:ultra:strict", Rank: 8, CreatedAt: time.Now().UTC()})
	srv, events, mu := caepCapture(t)
	tx := NewCAEPTransmitter(testSigner, "http://test.local", srv.URL, "", discardLogger())
	h := &OIDCHandlers{Store: store, Logger: discardLogger(), CAEP: tx}

	h.completeAdviceTransaction(AuthCode{TenantID: "ten_x", UserID: "usr_1", TransactionID: "txn_done", ACR: "urn:xauth:protect:ultra:strict"})
	tx.Wait()

	calls, _ := store.ListAdviceCalls(AdviceCallFilter{})
	if len(calls) != 1 || calls[0].CompletedAt == nil || calls[0].CompletedACR != "urn:xauth:protect:ultra:strict" {
		t.Fatalf("completion not recorded: %+v", calls)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*events) != 1 {
		t.Fatalf("want 1 CAEP event, got %d", len(*events))
	}
	if e := (*events)[0]; e.uri != CAEPAssuranceLevelChange || e.payload["transaction_id"] != "txn_done" {
		t.Fatalf("unexpected CAEP event: %s %v", e.uri, e.payload)
	}
}

// Driving /authorize with a known transaction_id (matching subject) marks the
// advice row completed.
func TestAuthorizeCompletesAdviceTransaction(t *testing.T) {
	r, store := secureAuthzRouter(t)
	sess := seedAuthzSession(t, store, "ten_bound", "real@bound.test")
	seedAdvice(t, store, "txn_flow", "ten_bound", "usr_real@bound.test", 0, "")
	req := authzReq(url.Values{"transaction_id": {"txn_flow"}})
	req.AddCookie(&http.Cookie{Name: AuthzSessionCookie, Value: sess.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("authorize: want 302, got %d (%s)", w.Code, w.Body.String())
	}
	calls, _ := store.ListAdviceCalls(AdviceCallFilter{TenantID: "ten_bound"})
	var done bool
	for _, c := range calls {
		if c.ID == "txn_flow" && c.CompletedAt != nil {
			done = true
		}
	}
	if !done {
		t.Fatalf("advice transaction not marked completed: %+v", calls)
	}
}

// Hardening: a transaction_id at /authorize must be a known, not-yet-used advice
// call for this tenant, issued for this user, at >= the advised level.
func TestAuthorizeTransactionBinding(t *testing.T) {
	drive := func(r http.Handler, sessID string, extra url.Values) *httptest.ResponseRecorder {
		req := authzReq(extra)
		req.AddCookie(&http.Cookie{Name: AuthzSessionCookie, Value: sessID})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	t.Run("unknown transaction_id → 400", func(t *testing.T) {
		r, store := secureAuthzRouter(t)
		sess := seedAuthzSession(t, store, "ten_bound", "real@bound.test")
		w := drive(r, sess.ID, url.Values{"transaction_id": {"txn_nope"}})
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "unknown transaction_id") {
			t.Fatalf("want 400 unknown, got %d (%s)", w.Code, w.Body.String())
		}
	})

	t.Run("replayed (already completed) → 400", func(t *testing.T) {
		r, store := secureAuthzRouter(t)
		sess := seedAuthzSession(t, store, "ten_bound", "real@bound.test")
		seedAdvice(t, store, "txn_used", "ten_bound", "usr_real@bound.test", 0, "")
		if err := store.MarkAdviceCallCompleted("ten_bound", "txn_used", "usr_real@bound.test", "", time.Now().UTC()); err != nil {
			t.Fatalf("pre-complete: %v", err)
		}
		w := drive(r, sess.ID, url.Values{"transaction_id": {"txn_used"}})
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "already been used") {
			t.Fatalf("want 400 replay, got %d (%s)", w.Code, w.Body.String())
		}
	})

	t.Run("subject mismatch → 403", func(t *testing.T) {
		r, store := secureAuthzRouter(t)
		sess := seedAuthzSession(t, store, "ten_bound", "real@bound.test")
		seedAdvice(t, store, "txn_other", "ten_bound", "usr_someone_else", 0, "")
		w := drive(r, sess.ID, url.Values{"transaction_id": {"txn_other"}})
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "different user") {
			t.Fatalf("want 403 subject mismatch, got %d (%s)", w.Code, w.Body.String())
		}
	})

	t.Run("downgrade below advised level → 400", func(t *testing.T) {
		r, store := secureAuthzRouter(t)
		sess := seedAuthzSession(t, store, "ten_bound", "real@bound.test")
		seedAdvice(t, store, "txn_hi", "ten_bound", "usr_real@bound.test", 8, "urn:xauth:protect:ultra:strict")
		// Request rank 1 against an advised rank 8 → rejected before any challenge.
		w := drive(r, sess.ID, url.Values{
			"transaction_id": {"txn_hi"}, "acr_values": {"urn:xauth:protect:high:protected"},
		})
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "at least the advised") {
			t.Fatalf("want 400 downgrade, got %d (%s)", w.Code, w.Body.String())
		}
	})
}

func mustQuery(t *testing.T, w *httptest.ResponseRecorder, key string) string {
	t.Helper()
	loc, _ := url.Parse(w.Header().Get("Location"))
	v := loc.Query().Get(key)
	if v == "" {
		t.Fatalf("redirect %q missing %q", loc.String(), key)
	}
	return v
}

// secureAuthzRouter builds a router in production mode (DevAutologin off) with
// one tenant-bound client registered.
func secureAuthzRouter(t *testing.T) (http.Handler, Storage) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewMemStorage()
	if err := store.PutClient(OIDCClient{
		ClientID:     "bound-web",
		TenantID:     "ten_bound",
		RedirectURIs: []string{"https://bound.test/cb"},
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("put client: %v", err)
	}
	r := Router(Deps{
		Store: store, Logger: logger, Authenticator: &mockAuthenticator{},
		Issuer: "http://test.local", Signer: testSigner, // DevAutologin defaults false
	})
	return r, store
}

func authzReq(extra url.Values) *http.Request {
	q := url.Values{
		"client_id":             {"bound-web"},
		"redirect_uri":          {"https://bound.test/cb"},
		"state":                 {"st"},
		"scope":                 {"openid"},
		"code_challenge":        {testPKCEChallenge},
		"code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		q[k] = v
	}
	return httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
}

// seedSession creates a user + live session in a tenant, returning the session.
func seedAuthzSession(t *testing.T, store Storage, tenant, email string) Session {
	t.Helper()
	now := time.Now().UTC()
	u, err := store.CreateUser(User{ID: "usr_" + email, TenantID: tenant, Email: email, Name: email, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	s, err := store.CreateSession(Session{ID: "ses_" + email, TenantID: tenant, UserID: u.ID, RiskLevel: RiskLow, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return s
}

// TestAuthorizeNoCookieLoginRequired: secure mode, no session cookie -> the
// request is bounced to the client with error=login_required.
func TestAuthorizeNoCookieLoginRequired(t *testing.T) {
	r, _ := secureAuthzRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, authzReq(nil))
	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Host != "bound.test" || loc.Query().Get("error") != "login_required" {
		t.Fatalf("want login_required redirect to client, got %q", loc.String())
	}
	if loc.Query().Get("code") != "" {
		t.Fatal("must not mint a code without authentication")
	}
}

// TestAuthorizeForgedUserIDIgnored: in secure mode a user_id param is NOT
// trusted — without a cookie it still fails, even pointing at a real user.
func TestAuthorizeForgedUserIDIgnored(t *testing.T) {
	r, store := secureAuthzRouter(t)
	victim := seedAuthzSession(t, store, "ten_bound", "victim@bound.test")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, authzReq(url.Values{"user_id": {victim.UserID}}))
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "login_required" || loc.Query().Get("code") != "" {
		t.Fatalf("forged user_id must not yield a code: %q", loc.String())
	}
}

// TestAuthorizeWithSessionCookieMintsCode: a valid authz-session cookie
// identifies the user and a code is minted, tenant derived from the client.
func TestAuthorizeWithSessionCookieMintsCode(t *testing.T) {
	r, store := secureAuthzRouter(t)
	sess := seedAuthzSession(t, store, "ten_bound", "real@bound.test")

	req := authzReq(nil)
	req.AddCookie(&http.Cookie{Name: AuthzSessionCookie, Value: sess.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d (%s)", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")
	if loc.Host != "bound.test" || code == "" {
		t.Fatalf("want a code, got %q", loc.String())
	}
	// The minted auth code carries the cookie's user + the client's tenant.
	ac, err := store.ConsumeAuthCode(code)
	if err != nil {
		t.Fatalf("consume code: %v", err)
	}
	if ac.UserID != sess.UserID || ac.TenantID != "ten_bound" {
		t.Fatalf("code bound wrong: user=%s tenant=%s", ac.UserID, ac.TenantID)
	}
}

// TestAuthorizeTenantMismatchRejected: a tenant_id param contradicting the
// client's bound tenant is a hard 400.
func TestAuthorizeTenantMismatchRejected(t *testing.T) {
	r, store := secureAuthzRouter(t)
	sess := seedAuthzSession(t, store, "ten_bound", "real@bound.test")
	req := authzReq(url.Values{"tenant_id": {"ten_other"}})
	req.AddCookie(&http.Cookie{Name: AuthzSessionCookie, Value: sess.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("tenant mismatch: want 400, got %d (%s)", w.Code, w.Body.String())
	}
}

// TestAuthorizeCookieWrongTenantRejected: a cookie whose session lives in a
// different tenant than the client is bound to does not authenticate.
func TestAuthorizeCookieWrongTenantRejected(t *testing.T) {
	r, store := secureAuthzRouter(t)
	// Session in a DIFFERENT tenant than the client's ten_bound.
	other := seedAuthzSession(t, store, "ten_elsewhere", "x@elsewhere.test")
	req := authzReq(nil)
	req.AddCookie(&http.Cookie{Name: AuthzSessionCookie, Value: other.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "login_required" {
		t.Fatalf("cross-tenant cookie must not authenticate: %q", loc.String())
	}
}

// TestAuthorizeMatchingTenantParamOK: a tenant_id param that AGREES with the
// client's bound tenant is accepted.
func TestAuthorizeMatchingTenantParamOK(t *testing.T) {
	r, store := secureAuthzRouter(t)
	sess := seedAuthzSession(t, store, "ten_bound", "real@bound.test")
	req := authzReq(url.Values{"tenant_id": {"ten_bound"}})
	req.AddCookie(&http.Cookie{Name: AuthzSessionCookie, Value: sess.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound || url.Values(nil) == nil && w.Header().Get("Location") == "" {
		t.Fatalf("matching tenant param: want 302, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("want a code, got %q", loc.String())
	}
}

// TestSeedClientsParsesTenantPrefix verifies the OIDC_CLIENTS "tenant|uri"
// format binds the seeded client.
func TestSeedClientsParsesTenantPrefix(t *testing.T) {
	t.Setenv("OIDC_CLIENTS", "uf-web=ten_uf|https://uf.test/cb,http://localhost:3000/cb;legacy-web=https://legacy.test/cb")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewMemStorage()
	if err := SeedClientsFromEnv(store, logger); err != nil {
		t.Fatalf("seed: %v", err)
	}
	bound, err := store.GetClient("uf-web")
	if err != nil || bound.TenantID != "ten_uf" || len(bound.RedirectURIs) != 2 {
		t.Fatalf("bound client wrong: %+v err=%v", bound, err)
	}
	legacy, err := store.GetClient("legacy-web")
	if err != nil || legacy.TenantID != "" || len(legacy.RedirectURIs) != 1 {
		t.Fatalf("legacy client should be unbound: %+v err=%v", legacy, err)
	}
}
