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

	"github.com/xentranet/x-auth/services/authentication-service/internal/policy"
)

// mockRiskEvaluator returns a canned assessment so flow tests can drive the
// risk-evaluation stage without a live risk-service.
type mockRiskEvaluator struct {
	fn func(RiskEvalInput) (RiskAssessment, error)
}

func (m mockRiskEvaluator) Evaluate(_ context.Context, in RiskEvalInput) (RiskAssessment, error) {
	return m.fn(in)
}

// All three example policy templates must compile — this is the lockout-
// prevention contract (the admin UI compiles before save in P3).
func TestExamplePolicyTemplatesCompile(t *testing.T) {
	for _, src := range []string{
		PolicySkipStepUpWhenLowRisk,
		PolicySkipStepUpWhenSafe,
		PolicyDenyHighRiskLocation,
		PolicyForceStrongFactorOnCheckout,
	} {
		if _, err := policy.Compile(src); err != nil {
			t.Errorf("template %q failed to compile: %v", src, err)
		}
	}
}

func riskFlowHandler(t *testing.T, risk RiskEvaluator) (*OIDCHandlers, Storage) {
	t.Helper()
	store := NewMemStorage()
	now := time.Now().UTC()
	_, _ = store.CreateUser(User{ID: "usr_1", TenantID: "ten_acme", Email: "u@example.com", CreatedAt: now, UpdatedAt: now})
	return &OIDCHandlers{
		Store:      store,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Issuer:     "http://test.local",
		Signer:     testSigner,
		Protection: NewProtectionLedger(time.Hour),
		Risk:       risk,
		Authenticator: &mockAuthenticator{ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
			return []Authenticator{{ID: "atr", Method: "fido2", Status: "active"}}, nil
		}},
	}, store
}

func runRiskFlow(t *testing.T, h *OIDCHandlers, acrValues string) *httptest.ResponseRecorder {
	t.Helper()
	flow, err := h.riskAdaptiveStepUpFlow()
	if err != nil {
		t.Fatalf("build flow: %v", err)
	}
	exec := &FlowExecution{
		ID: "exe_1", TenantID: "ten_acme", Designation: FlowAuthorizeStepUp,
		ClientID: DefaultClientID, UserID: "usr_1",
		RedirectURI: "http://localhost:3000/callback", State: "st",
		CodeChallenge: testPKCEChallenge, ACRValues: acrValues,
		AuthzSessionID: "ses_1",
		Context: map[string]any{
			"request":    map[string]any{"client_id": DefaultClientID},
			"protection": map[string]any{"achieved_rank": 0, "requested_rank": 3},
		},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/authorize?acr_values="+url.QueryEscape(acrValues), nil)
	if _, err := runFlow(w, r, exec, flow.Stages); err != nil {
		t.Fatalf("runFlow: %v", err)
	}
	return w
}

// Low risk downgrades a requested step-up: the validate stage is skipped and the
// flow issues a code without any challenge. This is the differentiator a fixed
// pipeline cannot express.
func TestRiskAdaptiveLowRiskSkipsStepUp(t *testing.T) {
	h, _ := riskFlowHandler(t, mockRiskEvaluator{fn: func(RiskEvalInput) (RiskAssessment, error) {
		return RiskAssessment{Tier: "low", Score: 0.1}, nil
	}})
	w := runRiskFlow(t, h, "urn:xauth:protect:high:restricted") // rank 3, fido2
	if w.Code != http.StatusFound {
		t.Fatalf("low risk should issue without challenge: got %d (%s)", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("expected an authorization code: %s", loc)
	}
}

// High risk keeps the challenge: the validate stage runs and renders the passkey
// page (StageRespond), exactly as the legacy path would for an unmet level.
func TestRiskAdaptiveHighRiskChallenges(t *testing.T) {
	h, _ := riskFlowHandler(t, mockRiskEvaluator{fn: func(RiskEvalInput) (RiskAssessment, error) {
		return RiskAssessment{Tier: "high", Score: 0.9}, nil
	}})
	w := runRiskFlow(t, h, "urn:xauth:protect:high:restricted")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/authorize/verify") {
		t.Fatalf("high risk should render a challenge, got %d:\n%s", w.Code, w.Body.String())
	}
}

// An impossible-travel signal hits the deny stage and refuses the authorization.
func TestRiskAdaptiveImpossibleTravelDenies(t *testing.T) {
	h, _ := riskFlowHandler(t, mockRiskEvaluator{fn: func(RiskEvalInput) (RiskAssessment, error) {
		return RiskAssessment{Tier: "high", Score: 0.95, Flags: []string{"impossible_travel"}, ImpossibleTravel: true}, nil
	}})
	w := runRiskFlow(t, h, "urn:xauth:protect:high:restricted")
	if w.Code != http.StatusFound {
		t.Fatalf("deny should redirect, got %d (%s)", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "access_denied" {
		t.Fatalf("expected access_denied, got %q (%s)", loc.Query().Get("error"), loc)
	}
}

// Fail-open: a risk-service error must not break login. With no risk signal the
// skip policy is false (tier ""), so the requested step-up still challenges —
// the secure default.
func TestRiskAdaptiveRiskErrorFailsClosed(t *testing.T) {
	h, _ := riskFlowHandler(t, mockRiskEvaluator{fn: func(RiskEvalInput) (RiskAssessment, error) {
		return RiskAssessment{}, &DownstreamError{Service: "risk-service", Status: 503}
	}})
	w := runRiskFlow(t, h, "urn:xauth:protect:high:restricted")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/authorize/verify") {
		t.Fatalf("risk outage should still challenge a requested level, got %d", w.Code)
	}
}
