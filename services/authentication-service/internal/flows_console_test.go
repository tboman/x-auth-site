package internal

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestValidateFlowDefinition(t *testing.T) {
	ok := RiskAdaptiveFlowDefinition("f1", "ten", true)
	if err := ValidateFlowDefinition(ok); err != nil {
		t.Fatalf("valid template should pass: %v", err)
	}
	if err := ValidateFlowDefinition(FlowDefinition{Stages: nil}); err == nil {
		t.Error("empty flow should fail")
	}
	if err := ValidateFlowDefinition(FlowDefinition{Stages: []StageConfig{{Type: "bogus"}}}); err == nil {
		t.Error("unknown stage type should fail")
	}
	// Must end terminal.
	if err := ValidateFlowDefinition(FlowDefinition{Stages: []StageConfig{{Type: StageTypeRiskEvaluation}}}); err == nil {
		t.Error("non-terminal final stage should fail")
	}
	// Bad policy expression.
	bad := FlowDefinition{Stages: []StageConfig{
		{Type: StageTypeAuthValidate, Policies: []PolicyConfig{{Name: "x", Expression: "risk.tier ==="}}},
		{Type: StageTypeUserLogin},
	}}
	if err := ValidateFlowDefinition(bad); err == nil {
		t.Error("uncompilable policy should fail")
	}
}

// The owner Flows tab: apply the template, see it enabled, validate it, disable
// it, delete it — all through the signed-in owner dashboard.
func TestOwnerFlowsTabLifecycle(t *testing.T) {
	r, store := newAdminRouter(t)
	w := driveSignup(t, r, store, "owner@acme.test", "Acme", "")
	cookie := sessionCookie(w, ownerSessionCookie)
	if cookie == "" {
		t.Fatal("missing owner cookie")
	}
	oc := &http.Cookie{Name: ownerSessionCookie, Value: cookie}

	tab := func() string {
		req := httptest.NewRequest(http.MethodGet, "/admin?tab=flows", nil)
		req.AddCookie(oc)
		dw := httptest.NewRecorder()
		r.ServeHTTP(dw, req)
		if dw.Code != http.StatusOK {
			t.Fatalf("flows tab: want 200, got %d", dw.Code)
		}
		return dw.Body.String()
	}

	// Initial: empty, offers the template.
	if b := tab(); !strings.Contains(b, "Apply risk-adaptive template") || !strings.Contains(b, "No flows yet") {
		t.Fatalf("initial flows tab missing template offer:\n%s", b)
	}

	// Apply the template.
	if aw := postForm(t, r, "/admin/owner/flows/apply", url.Values{}, oc); aw.Code != http.StatusFound {
		t.Fatalf("apply: want 302, got %d (%s)", aw.Code, aw.Body.String())
	}
	flows, _ := store.ListFlows("ten_acme")
	if len(flows) != 1 || !flows[0].Enabled || flows[0].Slug != "risk-adaptive-stepup" {
		t.Fatalf("after apply: %+v", flows)
	}
	id := flows[0].ID

	// Tab now shows it enabled with a Disable action.
	if b := tab(); !strings.Contains(b, "enabled") || !strings.Contains(b, "risk-adaptive-stepup") {
		t.Fatalf("flows tab should show the enabled flow:\n%s", b)
	}

	// Validate → 200 "valid".
	vw := postForm(t, r, "/admin/owner/flows/validate", url.Values{"id": {id}}, oc)
	if vw.Code != http.StatusOK || !strings.Contains(vw.Body.String(), "Flow is valid") {
		t.Fatalf("validate: %d %s", vw.Code, vw.Body.String())
	}

	// Disable.
	if dw := postForm(t, r, "/admin/owner/flows/enable", url.Values{"id": {id}, "enabled": {"false"}}, oc); dw.Code != http.StatusFound {
		t.Fatalf("disable: want 302, got %d", dw.Code)
	}
	if f, _ := store.GetFlow("ten_acme", id); f.Enabled {
		t.Fatal("flow should be disabled")
	}

	// Delete.
	if dw := postForm(t, r, "/admin/owner/flows/delete", url.Values{"id": {id}}, oc); dw.Code != http.StatusFound {
		t.Fatalf("delete: want 302, got %d", dw.Code)
	}
	if flows, _ := store.ListFlows("ten_acme"); len(flows) != 0 {
		t.Fatalf("flow should be gone, got %d", len(flows))
	}
}

// The Flows endpoints reject unauthenticated callers.
func TestOwnerFlowsRequireAuth(t *testing.T) {
	r, _ := newAdminRouter(t)
	for _, path := range []string{
		"/admin/owner/flows/apply", "/admin/owner/flows/enable",
		"/admin/owner/flows/validate", "/admin/owner/flows/delete",
	} {
		w := postForm(t, r, path, url.Values{"id": {"x"}})
		if w.Code != http.StatusForbidden {
			t.Errorf("%s without auth: want 403, got %d", path, w.Code)
		}
	}
}
