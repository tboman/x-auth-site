package internal

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func discardOIDC() *OIDCHandlers {
	return &OIDCHandlers{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestBuildFlowFromRiskAdaptiveDefinition(t *testing.T) {
	h := discardOIDC()
	def := RiskAdaptiveFlowDefinition("flo_1", "ten_acme", true)
	flow, err := h.buildFlow(def)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(flow.Stages) != 4 {
		t.Fatalf("want 4 stages, got %d", len(flow.Stages))
	}
	if flow.Stages[0].Type() != StageTypeRiskEvaluation || flow.Stages[3].Type() != StageTypeUserLogin {
		t.Fatalf("unexpected stage order: %s … %s", flow.Stages[0].Type(), flow.Stages[3].Type())
	}
}

func TestBuildStageRejectsUnknownType(t *testing.T) {
	if _, err := discardOIDC().buildStage(StageConfig{Type: "nope"}); err == nil {
		t.Fatal("unknown stage type should error")
	}
}

func TestBuildStageRejectsBadPolicy(t *testing.T) {
	_, err := discardOIDC().buildStage(StageConfig{
		Type:     StageTypeAuthValidate,
		Policies: []PolicyConfig{{Name: "broken", Expression: "risk.tier ==="}},
	})
	if err == nil {
		t.Fatal("uncompilable policy should fail the build")
	}
}

func TestSelectAuthorizeFlowFallsBackToDefault(t *testing.T) {
	h := &OIDCHandlers{Store: NewMemStorage(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	// No configured flow → the code-defined default.
	if flow := h.selectAuthorizeFlow("ten_none"); flow.Slug != "default-authorization-stepup" {
		t.Fatalf("want default, got %q", flow.Slug)
	}
}

func TestSelectAuthorizeFlowUsesEnabledTenantFlow(t *testing.T) {
	store := NewMemStorage()
	if err := store.UpsertFlow(RiskAdaptiveFlowDefinition("flo_1", "ten_acme", true)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := &OIDCHandlers{Store: store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if flow := h.selectAuthorizeFlow("ten_acme"); flow.Slug != "risk-adaptive-stepup" {
		t.Fatalf("want risk-adaptive, got %q", flow.Slug)
	}
	// A broken stored flow must not break /authorize — fall back to default.
	store.UpsertFlow(FlowDefinition{ID: "flo_2", TenantID: "ten_bad", Designation: FlowAuthorizeStepUp,
		Slug: "broken", Enabled: true, Stages: []StageConfig{{Type: "nonsense"}}})
	if flow := h.selectAuthorizeFlow("ten_bad"); flow.Slug != "default-authorization-stepup" {
		t.Fatalf("broken flow should fall back to default, got %q", flow.Slug)
	}
}

func TestMemStorageFlowsRoundTrip(t *testing.T) {
	s := NewMemStorage()
	a := RiskAdaptiveFlowDefinition("flo_a", "ten_1", true)
	if err := s.UpsertFlow(a); err != nil {
		t.Fatalf("upsert a: %v", err)
	}
	got, err := s.GetFlow("ten_1", "flo_a")
	if err != nil || len(got.Stages) != 4 || got.UpdatedAt.IsZero() {
		t.Fatalf("get a: %+v err=%v", got, err)
	}
	// Tenant isolation.
	if _, err := s.GetFlow("ten_other", "flo_a"); err != ErrNotFound {
		t.Fatalf("cross-tenant get should miss, got %v", err)
	}
	// Enabling a second flow for the same designation demotes the first.
	b := RiskAdaptiveFlowDefinition("flo_b", "ten_1", true)
	b.Slug = "second"
	if err := s.UpsertFlow(b); err != nil {
		t.Fatalf("upsert b: %v", err)
	}
	en, err := s.GetEnabledFlow("ten_1", FlowAuthorizeStepUp)
	if err != nil || en.ID != "flo_b" {
		t.Fatalf("enabled flow should be flo_b, got %q err=%v", en.ID, err)
	}
	first, _ := s.GetFlow("ten_1", "flo_a")
	if first.Enabled {
		t.Fatal("flo_a should have been demoted")
	}
	if list, _ := s.ListFlows("ten_1"); len(list) != 2 {
		t.Fatalf("want 2 flows, got %d", len(list))
	}
	if err := s.DeleteFlow("ten_1", "flo_a"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetFlow("ten_1", "flo_a"); err != ErrNotFound {
		t.Fatalf("get after delete should miss, got %v", err)
	}
}

// End-to-end: a tenant with the enabled risk-adaptive flow + a low-risk
// assessment skips the requested step-up and issues a code — selection, build,
// and execution all the way through the router.
func TestFlowEngineUsesConfiguredTenantFlow(t *testing.T) {
	store := NewMemStorage()
	now := time.Now().UTC()
	devUser, _ := store.CreateUser(User{ID: "usr_dev", TenantID: "ten_acme", Email: "dev@example.com", CreatedAt: now, UpdatedAt: now})
	_, _ = store.CreateIdentityAnchor(IdentityAnchor{ID: "ian_dev", UserID: devUser.ID, TenantID: "ten_acme", Type: AnchorPhone, Value: "+15551112222", VerifiedAt: &now, CreatedAt: now})
	if err := store.UpsertFlow(RiskAdaptiveFlowDefinition("flo_1", "ten_acme", true)); err != nil {
		t.Fatalf("seed flow: %v", err)
	}
	r := Router(Deps{
		Store: store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Authenticator: &mockAuthenticator{ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
			return []Authenticator{{ID: "atr", Method: "fido2", Status: "active"}}, nil
		}},
		Issuer: "http://test.local", Signer: testSigner, DevAutologin: true, FlowEngine: true,
		Risk: mockRiskEvaluator{fn: func(RiskEvalInput) (RiskAssessment, error) {
			return RiskAssessment{Tier: "low", Score: 0.1}, nil
		}},
	})

	q := url.Values{
		"client_id": {DefaultClientID}, "redirect_uri": {"http://localhost:3000/callback"},
		"tenant_id": {"ten_acme"}, "state": {"st"}, "scope": {"openid"},
		"acr_values":     {"urn:xauth:protect:high:restricted"}, // rank 3 — normally challenges
		"code_challenge": {testPKCEChallenge}, "code_challenge_method": {"S256"},
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("low-risk configured flow should issue without challenge: got %d (%s)", w.Code, w.Body.String())
	}
	if loc, _ := url.Parse(w.Header().Get("Location")); loc.Query().Get("code") == "" {
		t.Fatalf("expected an authorization code, got %s", loc)
	}
}
