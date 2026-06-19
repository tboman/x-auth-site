package internal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// newOTPRouter wires a router whose authenticator mock can be shaped per test.
func newOTPRouter(t *testing.T, mock *mockAuthenticator) (http.Handler, Storage) {
	return buildOTPRouter(t, mock, false)
}

// newOTPRouterFlow is newOTPRouter with the flow engine enabled — used to prove
// the executor reproduces the legacy /authorize behavior.
func newOTPRouterFlow(t *testing.T, mock *mockAuthenticator) (http.Handler, Storage) {
	return buildOTPRouter(t, mock, true)
}

func buildOTPRouter(t *testing.T, mock *mockAuthenticator, flowEngine bool) (http.Handler, Storage) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewMemStorage()
	// Pre-seed the DevAutologin user (dev@example.com) with a verified phone
	// anchor so SMS step-up has a real number to text — without it, SMS step-up
	// now returns 409 no_phone_on_file. devAutoUser resolves by email, so this
	// exact row is the one /authorize uses.
	now := time.Now().UTC()
	devUser, _ := store.CreateUser(User{ID: "usr_dev", TenantID: "ten_acme", Email: "dev@example.com", Name: "Dev User", CreatedAt: now, UpdatedAt: now})
	_, _ = store.CreateIdentityAnchor(IdentityAnchor{ID: "ian_dev", UserID: devUser.ID, TenantID: "ten_acme", Type: AnchorPhone, Value: "+15551112222", VerifiedAt: &now, CreatedAt: now})
	r := Router(Deps{
		Store:         store,
		Logger:        logger,
		Authenticator: mock,
		Issuer:        "http://test.local",
		Signer:        testSigner,
		DevAutologin:  true, // legacy /authorize path; secure cookie path covered in oidc_authz_test.go
		FlowEngine:    flowEngine,
	})
	return r, store
}

var flowIDRe = regexp.MustCompile(`name="flow" value="([^"]+)"`)

// startStepUpAuthorize drives GET /authorize with the given acr_values and
// returns the flow id scraped from the served verification page plus the
// full page body for content assertions.
func startStepUpAuthorize(t *testing.T, r http.Handler, acrValues string) (string, string) {
	t.Helper()
	q := url.Values{
		"client_id":             {DefaultClientID},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"tenant_id":             {"ten_acme"},
		"state":                 {"st-1"},
		"scope":                 {"openid profile email"},
		"nonce":                 {"n-1"},
		"code_challenge":        {testPKCEChallenge},
		"code_challenge_method": {"S256"},
		"acr_values":            {acrValues},
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("authorize with acr: expected 200 verification page, got %d (%s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("authorize with acr: Content-Type = %q", ct)
	}
	m := flowIDRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("authorize with acr: no flow id in form:\n%s", w.Body.String())
	}
	return m[1], w.Body.String()
}

// startOTPAuthorize keeps the original SMS-flavoured helper shape for the
// pre-existing OTP tests.
func startOTPAuthorize(t *testing.T, r http.Handler) string {
	t.Helper()
	flowID, _ := startStepUpAuthorize(t, r, ACRSMSOTP)
	return flowID
}

func postVerify(t *testing.T, r http.Handler, flowID, code string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"flow": {flowID}, "code": {code}}
	req := httptest.NewRequest(http.MethodPost, "/authorize/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// idTokenClaims decodes the (already signature-verified elsewhere) claims
// section of a JWT for claim assertions.
func idTokenClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("claims decode: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("claims unmarshal: %v", err)
	}
	return claims
}

func TestOTPFlowHappyPath(t *testing.T) {
	var challengedUser string
	mock := &mockAuthenticator{
		// User already has an enrolled SMS authenticator.
		ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
			return []Authenticator{{ID: "atr_1", Method: "sms", Status: "active"}}, nil
		},
		CreateChallengeFn: func(_ context.Context, _, userID string, methods []string) (ChallengeInfo, error) {
			challengedUser = userID
			if len(methods) != 1 || methods[0] != "sms" {
				t.Errorf("challenge methods = %v", methods)
			}
			return ChallengeInfo{ChallengeID: "chl_1", Method: "sms", Prompt: "SMS OTP sent to +15551234 (stub)"}, nil
		},
		VerifyChallengeFn: func(_ context.Context, _, challengeID string, resp map[string]any) (VerifyOutcome, error) {
			if challengeID != "chl_1" {
				t.Errorf("verify challenge id = %q", challengeID)
			}
			return VerifyOutcome{Verified: resp["code"] == "123456"}, nil
		},
	}
	r, _ := newOTPRouter(t, mock)

	flowID := startOTPAuthorize(t, r)
	if challengedUser == "" {
		t.Fatal("no challenge was created")
	}

	// Correct code → 302 back to the client with a one-shot code.
	w := postVerify(t, r, flowID, "123456")
	if w.Code != http.StatusFound {
		t.Fatalf("verify: expected 302, got %d (%s)", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Host != "localhost:3000" {
		t.Fatalf("verify redirect = %q", loc.String())
	}
	code := loc.Query().Get("code")
	if code == "" || loc.Query().Get("state") != "st-1" {
		t.Fatalf("verify redirect missing code/state: %q", loc.String())
	}

	// Exchange the code; ID token must carry acr + amr, session is stepped-up.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {DefaultClientID},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"code_verifier": {testPKCEVerifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tw := httptest.NewRecorder()
	r.ServeHTTP(tw, req)
	if tw.Code != http.StatusOK {
		t.Fatalf("token: expected 200, got %d (%s)", tw.Code, tw.Body.String())
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(tw.Body.Bytes(), &tok); err != nil {
		t.Fatalf("token response: %v", err)
	}

	claims := idTokenClaims(t, tok.IDToken)
	if claims["acr"] != ACRSMSOTP {
		t.Errorf("id_token acr = %v, want %q", claims["acr"], ACRSMSOTP)
	}
	amr, _ := claims["amr"].([]any)
	if len(amr) != 2 || amr[0] != "otp" || amr[1] != "sms" {
		t.Errorf("id_token amr = %v, want [otp sms]", claims["amr"])
	}

	// The flow id is single-use.
	if w := postVerify(t, r, flowID, "123456"); w.Code != http.StatusBadRequest {
		t.Fatalf("flow replay: expected 400, got %d", w.Code)
	}
}

func TestOTPFlowSessionSteppedUp(t *testing.T) {
	r, store := newOTPRouter(t, &mockAuthenticator{
		ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
			return []Authenticator{{ID: "atr_1", Method: "sms", Status: "active"}}, nil
		},
	})

	flowID := startOTPAuthorize(t, r)
	w := postVerify(t, r, flowID, "123456") // default mock verifies anything
	loc, _ := url.Parse(w.Header().Get("Location"))

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {loc.Query().Get("code")},
		"client_id":     {DefaultClientID},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"code_verifier": {testPKCEVerifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tw := httptest.NewRecorder()
	r.ServeHTTP(tw, req)

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(tw.Body.Bytes(), &tok); err != nil {
		t.Fatalf("token response: %v (%s)", err, tw.Body.String())
	}
	sessionID, _ := idTokenClaims(t, tok.AccessToken)["session_id"].(string)
	if sessionID == "" {
		t.Fatal("access token missing session_id claim")
	}
	sess, err := store.GetSession("ten_acme", sessionID)
	if err != nil {
		t.Fatalf("session not found: %v", err)
	}
	if !sess.StepUpCompleted {
		t.Fatal("session minted after OTP must have step_up_completed=true")
	}
}

func TestOTPFlowWrongCodeRetries(t *testing.T) {
	r, _ := newOTPRouter(t, &mockAuthenticator{
		ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
			return []Authenticator{{ID: "atr_1", Method: "sms", Status: "active"}}, nil
		},
		VerifyChallengeFn: func(_ context.Context, _, _ string, resp map[string]any) (VerifyOutcome, error) {
			if resp["code"] == "123456" {
				return VerifyOutcome{Verified: true}, nil
			}
			return VerifyOutcome{Verified: false, Reason: "invalid_response"}, nil
		},
	})

	flowID := startOTPAuthorize(t, r)

	// Wrong code → form re-rendered (401), flow stays alive.
	w := postVerify(t, r, flowID, "000000")
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Incorrect code") {
		t.Fatalf("wrong code: expected re-rendered form, got %d (%s)", w.Code, w.Body.String())
	}

	// Correct code on the same flow → success.
	if w := postVerify(t, r, flowID, "123456"); w.Code != http.StatusFound {
		t.Fatalf("retry with right code: expected 302, got %d", w.Code)
	}
}

func TestOTPFlowMaxAttemptsKillsFlow(t *testing.T) {
	r, _ := newOTPRouter(t, &mockAuthenticator{
		ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
			return []Authenticator{{ID: "atr_1", Method: "sms", Status: "active"}}, nil
		},
		VerifyChallengeFn: func(_ context.Context, _, _ string, _ map[string]any) (VerifyOutcome, error) {
			return VerifyOutcome{Verified: false, Reason: "max_attempts_exceeded"}, nil
		},
	})

	flowID := startOTPAuthorize(t, r)
	if w := postVerify(t, r, flowID, "000000"); w.Code != http.StatusBadRequest {
		t.Fatalf("max attempts: expected 400, got %d", w.Code)
	}
	// Flow is gone — even a correct code can't resurrect it.
	if w := postVerify(t, r, flowID, "123456"); w.Code != http.StatusBadRequest {
		t.Fatalf("dead flow: expected 400, got %d", w.Code)
	}
}

func TestOTPFlowAutoEnrollsWhenNoSMS(t *testing.T) {
	enrolled := false
	r, _ := newOTPRouter(t, &mockAuthenticator{
		ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
			return nil, nil // user has no authenticators
		},
		EnrollFn: func(_ context.Context, _, _, method string, _ map[string]any) (Authenticator, error) {
			enrolled = true
			if method != "sms" {
				t.Errorf("enroll method = %q", method)
			}
			return Authenticator{ID: "atr_new", Method: "sms", Status: "active"}, nil
		},
	})

	startOTPAuthorize(t, r)
	if !enrolled {
		t.Fatal("expected auto-enrollment of an sms authenticator")
	}
}

func TestAuthorizeWithoutACRSkipsOTP(t *testing.T) {
	challenged := false
	r, _ := newOTPRouter(t, &mockAuthenticator{
		CreateChallengeFn: func(_ context.Context, _, _ string, _ []string) (ChallengeInfo, error) {
			challenged = true
			return ChallengeInfo{}, nil
		},
	})

	q := url.Values{
		"client_id":             {DefaultClientID},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"tenant_id":             {"ten_acme"},
		"code_challenge":        {testPKCEChallenge},
		"code_challenge_method": {"S256"},
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("plain authorize: expected 302, got %d", w.Code)
	}
	if challenged {
		t.Fatal("plain authorize must not create a challenge")
	}
}

func TestDiscoveryAdvertisesACR(t *testing.T) {
	r, _ := newOTPRouter(t, &mockAuthenticator{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	var doc struct {
		ACRValuesSupported []string `json:"acr_values_supported"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("discovery decode: %v", err)
	}
	// The method ACRs first, then the 8 protection-level ACRs.
	want := append([]string{ACRSMSOTP, ACRFIDO2}, protectionACRs()...)
	if len(doc.ACRValuesSupported) != len(want) {
		t.Fatalf("acr_values_supported = %v, want %v", doc.ACRValuesSupported, want)
	}
	have := map[string]bool{}
	for _, a := range doc.ACRValuesSupported {
		have[a] = true
	}
	for _, a := range want {
		if !have[a] {
			t.Fatalf("acr_values_supported missing %q: %v", a, doc.ACRValuesSupported)
		}
	}
}

// --- FIDO2 stub interlude -------------------------------------------------

// postAssertion drives POST /authorize/verify with a fido2 assertion body.
func postAssertion(t *testing.T, r http.Handler, flowID, assertion string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"flow": {flowID}, "assertion": {assertion}}
	req := httptest.NewRequest(http.MethodPost, "/authorize/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// With an enrolled passkey, fido2 step-up serves the assertion page, forwards
// the assertion (not a "code") to authenticator-service, and stamps the truthful
// amr the verify reported.
func TestFIDO2FlowHappyPath(t *testing.T) {
	mock := &mockAuthenticator{
		ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
			return []Authenticator{{ID: "atr_f", Method: "fido2", Status: "active"}}, nil
		},
		CreateChallengeFn: func(_ context.Context, _, _ string, methods []string) (ChallengeInfo, error) {
			if len(methods) != 1 || methods[0] != "fido2" {
				t.Errorf("challenge methods = %v, want [fido2]", methods)
			}
			return ChallengeInfo{ChallengeID: "chl_f", Method: "fido2", Prompt: "Use your passkey",
				Options: json.RawMessage(`{"publicKey":{"challenge":"abc"}}`)}, nil
		},
		VerifyChallengeFn: func(_ context.Context, _, challengeID string, resp map[string]any) (VerifyOutcome, error) {
			if challengeID != "chl_f" {
				t.Errorf("verify challenge id = %q", challengeID)
			}
			if _, hasCode := resp["code"]; hasCode {
				t.Errorf("fido2 verify must not send a \"code\" field: %v", resp)
			}
			if _, ok := resp["assertion"]; !ok {
				t.Errorf("fido2 verify must send an \"assertion\" field: %v", resp)
			}
			// Report user verification → amr ["user","pin"].
			return VerifyOutcome{Verified: true, AMR: []string{"user", "pin"}}, nil
		},
	}
	r, store := newOTPRouter(t, mock)

	flowID, page := startStepUpAuthorize(t, r, ACRFIDO2)
	if !strings.Contains(page, "Use passkey") || !strings.Contains(page, "/authorize/verify") {
		t.Fatalf("fido2 page missing assertion elements:\n%s", page)
	}

	w := postAssertion(t, r, flowID, `{"id":"x","type":"public-key"}`)
	if w.Code != http.StatusFound {
		t.Fatalf("verify: expected 302, got %d (%s)", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("verify redirect missing code: %q", loc.String())
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {DefaultClientID},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"code_verifier": {testPKCEVerifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tw := httptest.NewRecorder()
	r.ServeHTTP(tw, req)
	if tw.Code != http.StatusOK {
		t.Fatalf("token: expected 200, got %d (%s)", tw.Code, tw.Body.String())
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(tw.Body.Bytes(), &tok); err != nil {
		t.Fatalf("token response: %v", err)
	}

	claims := idTokenClaims(t, tok.IDToken)
	if claims["acr"] != ACRFIDO2 {
		t.Errorf("id_token acr = %v, want %q", claims["acr"], ACRFIDO2)
	}
	amr, _ := claims["amr"].([]any)
	if len(amr) != 2 || amr[0] != "user" || amr[1] != "pin" {
		t.Errorf("id_token amr = %v, want [user pin]", claims["amr"])
	}

	// Session minted from a fido2 step-up is stepped-up from birth.
	sessionID, _ := idTokenClaims(t, tok.AccessToken)["session_id"].(string)
	sess, err := store.GetSession("ten_acme", sessionID)
	if err != nil {
		t.Fatalf("session not found: %v", err)
	}
	if !sess.StepUpCompleted {
		t.Fatal("session minted after fido2 step-up must have step_up_completed=true")
	}
}

func TestFIDO2WrongAssertionRetries(t *testing.T) {
	r, _ := newOTPRouter(t, &mockAuthenticator{
		ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
			return []Authenticator{{ID: "atr_f", Method: "fido2", Status: "active"}}, nil
		},
		CreateChallengeFn: func(_ context.Context, _, _ string, _ []string) (ChallengeInfo, error) {
			return ChallengeInfo{ChallengeID: "chl_f", Method: "fido2",
				Options: json.RawMessage(`{"publicKey":{"challenge":"abc"}}`)}, nil
		},
		VerifyChallengeFn: func(_ context.Context, _, _ string, resp map[string]any) (VerifyOutcome, error) {
			raw, _ := resp["assertion"].(json.RawMessage)
			if strings.Contains(string(raw), "good") {
				return VerifyOutcome{Verified: true, AMR: []string{"user", "pin"}}, nil
			}
			return VerifyOutcome{Verified: false, Reason: "invalid_response"}, nil
		},
	})

	flowID, _ := startStepUpAuthorize(t, r, ACRFIDO2)

	w := postAssertion(t, r, flowID, `{"sig":"bad"}`)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Passkey verification failed") {
		t.Fatalf("wrong assertion: expected re-rendered page, got %d (%s)", w.Code, w.Body.String())
	}
	if w := postAssertion(t, r, flowID, `{"sig":"good"}`); w.Code != http.StatusFound {
		t.Fatalf("retry with valid assertion: expected 302, got %d", w.Code)
	}
}

// With no passkey on file, fido2 step-up serves the registration page
// (register-on-first-use) rather than auto-enrolling a stub.
func TestFIDO2RegisterPageWhenNoCredential(t *testing.T) {
	r, _ := newOTPRouter(t, &mockAuthenticator{
		ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
			return nil, nil // no passkey enrolled
		},
		EnrollFn: func(_ context.Context, _, _, _ string, _ map[string]any) (Authenticator, error) {
			t.Fatal("fido2 step-up must NOT auto-enroll a stub")
			return Authenticator{}, nil
		},
	})

	_, page := startStepUpAuthorize(t, r, ACRFIDO2)
	if !strings.Contains(page, "Create a passkey") || !strings.Contains(page, "register/begin") {
		t.Fatalf("expected the passkey registration page:\n%s", page)
	}
}

// TestACRPreferenceOrder pins OIDC Core §3.1.2.1 semantics: acr_values is
// ordered by client preference, so the first supported value wins regardless
// of this server's internal spec order.
func TestACRPreferenceOrder(t *testing.T) {
	for _, tc := range []struct {
		acrValues  string
		wantMethod string
	}{
		{ACRFIDO2 + " " + ACRSMSOTP, "fido2"},
		{ACRSMSOTP + " " + ACRFIDO2, "sms"},
		{"urn:unknown:acr " + ACRFIDO2, "fido2"},
	} {
		var gotMethods []string
		r, _ := newOTPRouter(t, &mockAuthenticator{
			ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
				return []Authenticator{
					{ID: "a1", Method: "sms", Status: "active"},
					{ID: "a2", Method: "fido2", Status: "active"},
				}, nil
			},
			CreateChallengeFn: func(_ context.Context, _, _ string, methods []string) (ChallengeInfo, error) {
				gotMethods = methods
				return ChallengeInfo{ChallengeID: "chl_x", Method: methods[0], Prompt: "p"}, nil
			},
		})
		startStepUpAuthorize(t, r, tc.acrValues)
		if len(gotMethods) != 1 || gotMethods[0] != tc.wantMethod {
			t.Errorf("acr_values=%q: challenged methods = %v, want [%s]", tc.acrValues, gotMethods, tc.wantMethod)
		}
	}
}
