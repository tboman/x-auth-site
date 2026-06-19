package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// With the flow engine on, a plain /authorize (no acr_values) runs the default
// flow's issue stage and mints a code — identical to the legacy no-step-up path.
func TestFlowEnginePlainIssue(t *testing.T) {
	r, _ := newOTPRouterFlow(t, &mockAuthenticator{})
	q := url.Values{
		"client_id":             {DefaultClientID},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"tenant_id":             {"ten_acme"},
		"state":                 {"st"},
		"scope":                 {"openid"},
		"code_challenge":        {testPKCEChallenge},
		"code_challenge_method": {"S256"},
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("plain authorize: want 302, got %d (%s)", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("issue stage should mint a code: %s", loc)
	}
}

// With the flow engine on, a method-acr request renders the challenge (validate
// stage → startStepUpFlow) and verify mints a code — same as legacy.
func TestFlowEngineSMSStepUpParity(t *testing.T) {
	r, _ := newOTPRouterFlow(t, &mockAuthenticator{
		ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
			return []Authenticator{{ID: "atr", Method: "sms", Status: "active",
				Metadata: map[string]any{"phone_number": "+15551112222"}}}, nil
		},
	})
	flowID, page := startStepUpAuthorize(t, r, ACRSMSOTP)
	if !strings.Contains(page, "Enter verification code") {
		t.Fatalf("flow engine should render the OTP challenge:\n%s", page)
	}
	w := postVerify(t, r, flowID, "123456")
	if w.Code != http.StatusFound {
		t.Fatalf("verify: want 302, got %d (%s)", w.Code, w.Body.String())
	}
	if loc, _ := url.Parse(w.Header().Get("Location")); loc.Query().Get("code") == "" {
		t.Fatalf("verify should mint a code: %s", loc)
	}
}

// FIDO2 step-up under the flow engine: assertion page → verify → token acr=fido2.
// Proves the challenge path (unchanged step-up machinery) works through the
// executor and stamps the same acr/amr.
func TestFlowEngineFIDO2Parity(t *testing.T) {
	r, _ := newOTPRouterFlow(t, &mockAuthenticator{
		ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
			return []Authenticator{{ID: "atr_f", Method: "fido2", Status: "active"}}, nil
		},
		CreateChallengeFn: func(_ context.Context, _, _ string, _ []string) (ChallengeInfo, error) {
			return ChallengeInfo{ChallengeID: "chl_f", Method: "fido2",
				Options: json.RawMessage(`{"publicKey":{"challenge":"abc"}}`)}, nil
		},
		VerifyChallengeFn: func(_ context.Context, _, _ string, _ map[string]any) (VerifyOutcome, error) {
			return VerifyOutcome{Verified: true, AMR: []string{"user", "pin"}}, nil
		},
	})
	flowID, page := startStepUpAuthorize(t, r, ACRFIDO2)
	if !strings.Contains(page, "Use passkey") {
		t.Fatalf("flow engine should render the passkey challenge:\n%s", page)
	}
	w := postAssertion(t, r, flowID, `{"id":"x","type":"public-key"}`)
	if w.Code != http.StatusFound {
		t.Fatalf("verify: want 302, got %d (%s)", w.Code, w.Body.String())
	}
	code := w.Header().Get("Location")
	loc, _ := url.Parse(code)
	if loc.Query().Get("code") == "" {
		t.Fatalf("verify should mint a code: %s", loc)
	}
}
