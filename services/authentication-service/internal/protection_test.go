package internal

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestProtectionLevelsTable pins the public contract: 8 monotonic levels, each
// mapped to a real stub method.
func TestProtectionLevelsTable(t *testing.T) {
	if len(protectionLevels) != 8 || len(protectionACRs()) != 8 {
		t.Fatalf("want 8 protection levels, got %d", len(protectionLevels))
	}
	for i, lvl := range protectionLevels {
		if lvl.Rank != i+1 {
			t.Errorf("level %s rank = %d, want %d", lvl.ACR, lvl.Rank, i+1)
		}
		if _, ok := specForMethod(lvl.Method); !ok {
			t.Errorf("level %s method %q has no stepUpSpec", lvl.ACR, lvl.Method)
		}
	}
	if lvl, ok := matchProtection("openid urn:xauth:protect:ultra:strict"); !ok || lvl.Rank != 8 {
		t.Fatalf("matchProtection ultra:strict: %+v ok=%v", lvl, ok)
	}
	if _, ok := matchProtection("urn:xauth:otp:sms"); ok {
		t.Fatal("a method ACR must not match a protection level")
	}
}

// TestProtectionLedger covers max-rank semantics + nil/empty safety.
func TestProtectionLedger(t *testing.T) {
	l := NewProtectionLedger(time.Hour)
	if l.Achieved("ses_1") != 0 {
		t.Fatal("empty ledger should be 0")
	}
	l.Record("ses_1", 3)
	l.Record("ses_1", 2) // lower must not lower it
	if l.Achieved("ses_1") != 3 {
		t.Fatalf("want max rank 3, got %d", l.Achieved("ses_1"))
	}
	l.Record("ses_1", 6)
	if l.Achieved("ses_1") != 6 {
		t.Fatalf("want 6, got %d", l.Achieved("ses_1"))
	}
	var nilL *ProtectionLedger
	nilL.Record("x", 1)
	if nilL.Achieved("x") != 0 {
		t.Fatal("nil ledger Achieved must be 0")
	}
	l.Record("", 5)
	if l.Achieved("") != 0 {
		t.Fatal("empty session id must be 0")
	}
}

// AchievedWithin honours the recency window: a recent step-up counts, a stale
// one (or a zero window) does not.
func TestProtectionLedgerAchievedWithin(t *testing.T) {
	l := NewProtectionLedger(time.Hour)
	l.Record("ses_1", 5)
	if l.AchievedWithin("ses_1", time.Hour) != 5 {
		t.Fatalf("a just-recorded step-up should be within an hour")
	}
	time.Sleep(3 * time.Millisecond)
	if l.AchievedWithin("ses_1", time.Millisecond) != 0 {
		t.Fatalf("a step-up older than the window must be stale")
	}
	if l.AchievedWithin("ses_1", 0) != 0 {
		t.Errorf("zero window → 0")
	}
	if l.AchievedWithin("missing", time.Hour) != 0 {
		t.Errorf("unknown session → 0")
	}
	var nilL *ProtectionLedger
	if nilL.AchievedWithin("x", time.Hour) != 0 {
		t.Errorf("nil ledger → 0")
	}
}

// handleProtection re-challenges when the recent step-up is outside the freshness
// window, and passes through when it's inside.
func TestProtectionFreshnessGate(t *testing.T) {
	led := NewProtectionLedger(time.Hour)
	h := &OIDCHandlers{
		Store:  NewMemStorage(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Issuer: "http://test.local",
		Authenticator: &mockAuthenticator{ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
			return []Authenticator{{ID: "atr", Method: "fido2", Status: "active"}}, nil
		}},
		Protection: led,
	}
	pend := pendingAuthorize{ClientID: DefaultClientID, TenantID: "ten_acme", UserID: "usr_1",
		RedirectURI: "http://localhost:3000/callback", CodeChallenge: testPKCEChallenge}
	lvl, _ := matchProtection("urn:xauth:protect:high:protected") // rank 1 ≤ 8 achieved

	// Rank 8 achieved, but it's older than the freshness window → re-challenge.
	led.Record("ses_stale", 8)
	time.Sleep(3 * time.Millisecond)
	h.StepUpFreshness = time.Millisecond
	w := httptest.NewRecorder()
	h.handleProtection(w, httptest.NewRequest(http.MethodGet, "/authorize", nil), lvl, "ses_stale", pend)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/authorize/verify") {
		t.Fatalf("stale step-up should re-challenge, got %d", w.Code)
	}

	// A generous freshness lets the same recent step-up pass through to callback.
	led.Record("ses_fresh", 8)
	h.StepUpFreshness = time.Hour
	w2 := httptest.NewRecorder()
	h.handleProtection(w2, httptest.NewRequest(http.MethodGet, "/authorize", nil), lvl, "ses_fresh", pend)
	if w2.Code != http.StatusFound {
		t.Fatalf("fresh step-up should pass through (302), got %d (%s)", w2.Code, w2.Body.String())
	}
}

// TestProtectionChallengeStampsACR: a protection-level request challenges with
// the mapped method, and the minted token's acr is the PROTECTION LEVEL (not the
// method), with amr carrying the method actually used.
func TestProtectionChallengeStampsACR(t *testing.T) {
	r, _ := newOTPRouter(t, &mockAuthenticator{
		ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
			return []Authenticator{{ID: "atr", Method: "sms", Status: "active"}}, nil
		},
	})
	// high:protected (rank 1) → sms challenge.
	flowID, page := startStepUpAuthorize(t, r, "urn:xauth:protect:high:protected")
	if !strings.Contains(page, "Enter verification code") {
		t.Fatalf("expected the OTP challenge page:\n%s", page)
	}
	w := postVerify(t, r, flowID, "123456")
	if w.Code != http.StatusFound {
		t.Fatalf("verify: want 302, got %d (%s)", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"client_id": {DefaultClientID}, "redirect_uri": {"http://localhost:3000/callback"},
		"code_verifier": {testPKCEVerifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tw := httptest.NewRecorder()
	r.ServeHTTP(tw, req)
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(tw.Body.Bytes(), &tok); err != nil || tok.IDToken == "" {
		t.Fatalf("token response: %v (%s)", err, tw.Body.String())
	}
	claims := idTokenClaims(t, tok.IDToken)
	if claims["acr"] != "urn:xauth:protect:high:protected" {
		t.Fatalf("acr = %v, want the protection level", claims["acr"])
	}
	if amr, _ := claims["amr"].([]any); len(amr) == 0 {
		t.Fatalf("amr should carry the method used, got %v", claims["amr"])
	}
}

// TestProtectionPassThroughAndEscalation drives the mocked decision directly:
// a session that already satisfied rank N passes equal-or-lower levels through
// without a challenge, and a higher level re-challenges.
func TestProtectionPassThroughAndEscalation(t *testing.T) {
	store := NewMemStorage()
	led := NewProtectionLedger(time.Hour)
	h := &OIDCHandlers{
		Store:  store,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Issuer: "http://test.local",
		Authenticator: &mockAuthenticator{
			ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
				return []Authenticator{{ID: "atr", Method: "fido2", Status: "active"}}, nil
			},
		},
		Protection: led,
	}
	pend := pendingAuthorize{
		ClientID: DefaultClientID, TenantID: "ten_acme", UserID: "usr_1",
		RedirectURI: "http://localhost:3000/callback", CodeChallenge: testPKCEChallenge,
	}
	call := func(acr, sessionID string) *httptest.ResponseRecorder {
		lvl, ok := matchProtection(acr)
		if !ok {
			t.Fatalf("unknown protection acr %q", acr)
		}
		w := httptest.NewRecorder()
		h.handleProtection(w, httptest.NewRequest(http.MethodGet, "/authorize", nil), lvl, sessionID, pend)
		return w
	}

	// Session already satisfied rank 4.
	led.Record("ses_x", 4)
	if w := call("urn:xauth:protect:high:enhanced", "ses_x"); w.Code != http.StatusFound { // rank 2 ≤ 4
		t.Fatalf("pass-through (rank2≤4): want 302, got %d (%s)", w.Code, w.Body.String())
	}
	if w := call("urn:xauth:protect:high:strict", "ses_x"); w.Code != http.StatusFound { // rank 4 == 4
		t.Fatalf("pass-through (rank4==4): want 302, got %d", w.Code)
	}
	// A higher level than satisfied → challenge page.
	if w := call("urn:xauth:protect:ultra:strict", "ses_x"); w.Code != http.StatusOK || // rank 8 > 4
		!strings.Contains(w.Body.String(), "/authorize/verify") {
		t.Fatalf("escalation (rank8>4): want 200 challenge page, got %d", w.Code)
	}
	// No session id → never passes through.
	if w := call("urn:xauth:protect:high:protected", ""); w.Code != http.StatusOK {
		t.Fatalf("no-session: want 200 challenge, got %d", w.Code)
	}
}
