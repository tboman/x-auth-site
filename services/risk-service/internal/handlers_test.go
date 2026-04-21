package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/logx"
)

const testTenant = "tenant-a"

// newRouter wires a full risk-service handler tree with the given clock so
// tests can control the BehaviorScorer's hour-of-day branch.
func newRouter(t *testing.T, c Clock) (http.Handler, Storage) {
	t.Helper()
	store := NewMemStorage()
	h := &Handlers{
		Store:  store,
		Logger: logx.New("risk-service-test"),
		Clock:  c,
	}
	return h.Router(), store
}

// midDayClock returns a clock fixed to 12:00 UTC — inside the "normal" hours
// window so BehaviorScorer won't flag unusual_time unless a test overrides it.
func midDayClock() Clock {
	return fixedClock{T: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)}
}

func nightClock() Clock {
	return fixedClock{T: time.Date(2026, 4, 20, 2, 0, 0, 0, time.UTC)}
}

func doJSON(t *testing.T, h http.Handler, method, path, tenant string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tenant != "" {
		req.Header.Set("X-Tenant-Id", tenant)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// ---------- Scorer unit tests ----------

func TestDeviceScorer(t *testing.T) {
	ctx := context.Background()
	store := NewMemStorage()
	clock := midDayClock()

	cases := []struct {
		name     string
		fp       string
		wantFlag string
		want     float64
	}{
		{"known", "fp_known_abc", "", 0.2},
		{"unknown", "fp_random_xyz", "unknown_device", 0.5},
		{"missing", "", "no_fingerprint", 0.5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := EvaluateRequest{Context: EvaluateCtx{DeviceFingerprint: tc.fp}}
			got := DeviceScorer(ctx, req, testTenant, store, clock)
			if got.Score != tc.want {
				t.Fatalf("score = %v, want %v", got.Score, tc.want)
			}
			if tc.wantFlag == "" && len(got.Flags) != 0 {
				t.Fatalf("unexpected flags: %v", got.Flags)
			}
			if tc.wantFlag != "" {
				if len(got.Flags) != 1 || got.Flags[0] != tc.wantFlag {
					t.Fatalf("flags = %v, want [%s]", got.Flags, tc.wantFlag)
				}
			}
		})
	}
}

func TestBehaviorScorer(t *testing.T) {
	ctx := context.Background()
	store := NewMemStorage()
	req := EvaluateRequest{}

	t.Run("normal hours", func(t *testing.T) {
		got := BehaviorScorer(ctx, req, testTenant, store, midDayClock())
		if got.Score != 0.1 {
			t.Fatalf("score = %v, want 0.1", got.Score)
		}
		if len(got.Flags) != 0 {
			t.Fatalf("unexpected flags: %v", got.Flags)
		}
	})

	t.Run("unusual night time", func(t *testing.T) {
		got := BehaviorScorer(ctx, req, testTenant, store, nightClock())
		if got.Score != 0.6 {
			t.Fatalf("score = %v, want 0.6", got.Score)
		}
		if len(got.Flags) != 1 || got.Flags[0] != "unusual_time" {
			t.Fatalf("flags = %v", got.Flags)
		}
	})

	t.Run("late evening", func(t *testing.T) {
		late := fixedClock{T: time.Date(2026, 4, 20, 23, 30, 0, 0, time.UTC)}
		got := BehaviorScorer(ctx, req, testTenant, store, late)
		if len(got.Flags) != 1 || got.Flags[0] != "unusual_time" {
			t.Fatalf("expected unusual_time for 23:30, got %v", got.Flags)
		}
	})
}

func TestNetworkScorer(t *testing.T) {
	ctx := context.Background()
	store := NewMemStorage()
	clock := midDayClock()

	cases := []struct {
		name      string
		ip        string
		wantScore float64
		wantFlags []string
	}{
		{"benign", "10.0.0.5", 0.1, nil},
		{"flagged prefix", "203.0.113.42", 0.5, []string{"flagged_ip"}},
		{"vpn suffix", "10.0.0.100", 0.4, []string{"vpn_detected"}},
		{"both", "203.0.113.100", 0.8, []string{"flagged_ip", "vpn_detected"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := EvaluateRequest{Context: EvaluateCtx{IPAddress: tc.ip}}
			got := NetworkScorer(ctx, req, testTenant, store, clock)
			if got.Score != tc.wantScore {
				t.Fatalf("score = %v, want %v", got.Score, tc.wantScore)
			}
			if len(got.Flags) != len(tc.wantFlags) {
				t.Fatalf("flags = %v, want %v", got.Flags, tc.wantFlags)
			}
			for i, f := range tc.wantFlags {
				if got.Flags[i] != f {
					t.Fatalf("flags[%d] = %q, want %q", i, got.Flags[i], f)
				}
			}
		})
	}
}

func TestUserScorerFirstHighValueAction(t *testing.T) {
	ctx := context.Background()
	store := NewMemStorage()
	clock := midDayClock()

	req := EvaluateRequest{
		UserID: "usr_new",
		Action: "transfer.initiate",
	}

	// No prior evaluations — should flag first_high_value_action.
	got := UserScorer(ctx, req, testTenant, store, clock)
	if got.Score != 0.5 {
		t.Fatalf("first high-value: score = %v, want 0.5", got.Score)
	}
	if len(got.Flags) != 1 || got.Flags[0] != "first_high_value_action" {
		t.Fatalf("flags = %v", got.Flags)
	}

	// Seed a prior evaluation for the same user; flag should no longer fire.
	_ = store.PutEvaluation(RiskEvaluation{
		ID: "rev_seed", TenantID: testTenant, UserID: "usr_new",
	})
	got = UserScorer(ctx, req, testTenant, store, clock)
	if got.Score != 0.2 {
		t.Fatalf("after prior: score = %v, want 0.2", got.Score)
	}
	if len(got.Flags) != 0 {
		t.Fatalf("after prior: unexpected flags %v", got.Flags)
	}
}

func TestUserScorerNonHighValueNeverFlags(t *testing.T) {
	ctx := context.Background()
	store := NewMemStorage()
	clock := midDayClock()

	req := EvaluateRequest{UserID: "usr_a", Action: "read.profile"}
	got := UserScorer(ctx, req, testTenant, store, clock)
	if got.Score != 0.2 || len(got.Flags) != 0 {
		t.Fatalf("non-high-value should score 0.2 with no flags, got %+v", got)
	}
}

// ---------- Aggregation / tier derivation ----------

func TestAggregateWeightsAndSensitivity(t *testing.T) {
	// Manufacture a request that yields known per-scorer scores:
	//   device   = 0.2 (known fingerprint)
	//   behavior = 0.1 (midday, no flags)
	//   network  = 0.1 (benign IP)
	//   user     = 0.2 (non-high-value)
	// Weighted: 0.2*0.25 + 0.1*0.20 + 0.1*0.30 + 0.2*0.25 = 0.05 + 0.02 + 0.03 + 0.05 = 0.15
	// Sensitivity low → *1.0 → 0.15 → tier low.
	store := NewMemStorage()
	clock := midDayClock()
	req := EvaluateRequest{
		UserID:              "usr_a",
		Action:              "read.profile",
		ResourceSensitivity: SensitivityLow,
		Context:             EvaluateCtx{DeviceFingerprint: "fp_known_laptop", IPAddress: "10.0.0.5"},
	}
	signals, score := Aggregate(context.Background(), req, testTenant, store, clock)
	if signals.Device.Score != 0.2 || signals.Behavior.Score != 0.1 ||
		signals.Network.Score != 0.1 || signals.User.Score != 0.2 {
		t.Fatalf("per-scorer scores wrong: %+v", signals)
	}
	if near(score, 0.15) == false {
		t.Fatalf("aggregate = %v, want ~0.15", score)
	}
	if DeriveTier(score) != TierLow {
		t.Fatalf("tier = %s, want low", DeriveTier(score))
	}

	// Re-run with sensitivity high — 0.15 * 1.3 = 0.195, still low.
	req.ResourceSensitivity = SensitivityHigh
	_, score = Aggregate(context.Background(), req, testTenant, store, clock)
	if near(score, 0.195) == false {
		t.Fatalf("aggregate (high) = %v, want ~0.195", score)
	}
}

func TestDeriveTierBoundaries(t *testing.T) {
	cases := []struct {
		s    float64
		want string
	}{
		{0.0, TierLow},
		{0.34, TierLow},
		{0.35, TierMedium},
		{0.5, TierMedium},
		{0.7, TierMedium},
		{0.701, TierHigh},
		{1.0, TierHigh},
	}
	for _, tc := range cases {
		if got := DeriveTier(tc.s); got != tc.want {
			t.Fatalf("DeriveTier(%v) = %s, want %s", tc.s, got, tc.want)
		}
	}
}

// near returns true when two floats are within a small epsilon — needed
// because the aggregator's arithmetic produces tiny rounding wobble.
func near(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-9
}

// ---------- Handler tests ----------

func TestHealthz(t *testing.T) {
	h, _ := newRouter(t, midDayClock())
	rec := doJSON(t, h, http.MethodGet, "/healthz", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestEvaluationRequiresTenant(t *testing.T) {
	h, _ := newRouter(t, midDayClock())
	rec := doJSON(t, h, http.MethodPost, "/v1/evaluations", "", map[string]any{
		"user_id": "u", "action": "read", "resource_sensitivity": "low",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 without tenant, got %d", rec.Code)
	}
}

func TestEvaluationValidatesSensitivity(t *testing.T) {
	h, _ := newRouter(t, midDayClock())
	rec := doJSON(t, h, http.MethodPost, "/v1/evaluations", testTenant, map[string]any{
		"user_id": "u", "action": "read", "resource_sensitivity": "bogus",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bogus sensitivity: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// Low-risk evaluation path: known device, benign IP, midday, non-high-value action.
func TestEvaluationLowTier(t *testing.T) {
	h, _ := newRouter(t, midDayClock())
	body := map[string]any{
		"user_id":              "usr_known",
		"action":               "read.profile",
		"resource_sensitivity": "low",
		"context": map[string]any{
			"device_fingerprint": "fp_known_laptop",
			"ip_address":         "10.0.0.5",
		},
	}
	rec := doJSON(t, h, http.MethodPost, "/v1/evaluations", testTenant, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var got RiskEvaluation
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Tier != TierLow {
		t.Fatalf("tier = %s, want low (score=%v, flags=%v)", got.Tier, got.Score, got.Flags)
	}
	if got.PolicyDecision != DecisionAllow {
		t.Fatalf("decision = %s, want allow", got.PolicyDecision)
	}
	if got.ID == "" || got.ID[:4] != "rev_" {
		t.Fatalf("bad id: %q", got.ID)
	}
}

// High-risk evaluation: unknown device + two network flags + unusual-time
// behavior + first high-value action. With high sensitivity the score
// comfortably clears the 0.70 threshold.
//
// Arithmetic sanity:
//   device 0.5 * 0.25 = 0.125
//   behavior 0.6 * 0.20 = 0.12   (unusual_time at 02:00)
//   network 0.8 * 0.30 = 0.24    (flagged_ip + vpn_detected)
//   user 0.5 * 0.25 = 0.125      (first_high_value_action)
//   sum = 0.61 → * 1.3 (high sensitivity) = 0.793 → tier high.
func TestEvaluationHighTier(t *testing.T) {
	h, _ := newRouter(t, nightClock())
	body := map[string]any{
		"user_id":              "usr_new_high_value",
		"action":               "transfer.initiate",
		"resource_sensitivity": "high",
		"context": map[string]any{
			"device_fingerprint": "fp_suspicious",  // unknown_device
			"ip_address":         "203.0.113.100",   // flagged_ip + vpn_detected
		},
	}
	rec := doJSON(t, h, http.MethodPost, "/v1/evaluations", testTenant, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var got RiskEvaluation
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Tier != TierHigh {
		t.Fatalf("tier = %s, want high (score=%v, flags=%v)", got.Tier, got.Score, got.Flags)
	}
	// Confirm we collected the expected flags.
	wantFlags := map[string]bool{"unknown_device": false, "flagged_ip": false, "vpn_detected": false}
	for _, f := range got.Flags {
		if _, ok := wantFlags[f]; ok {
			wantFlags[f] = true
		}
	}
	for f, seen := range wantFlags {
		if !seen {
			t.Fatalf("missing expected flag %q in %v", f, got.Flags)
		}
	}
}

func TestEvaluationGetTenantScoped(t *testing.T) {
	h, store := newRouter(t, midDayClock())

	// Seed an evaluation for tenant-a directly.
	_ = store.PutEvaluation(RiskEvaluation{
		ID: "rev_abc", TenantID: testTenant, UserID: "u", Action: "read",
		ResourceSensitivity: "low", Tier: TierLow, PolicyDecision: DecisionAllow,
	})

	// tenant-a can read.
	rec := doJSON(t, h, http.MethodGet, "/v1/evaluations/rev_abc", testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("own read: want 200, got %d", rec.Code)
	}
	// tenant-b cannot.
	rec = doJSON(t, h, http.MethodGet, "/v1/evaluations/rev_abc", "tenant-b", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant read: want 404, got %d", rec.Code)
	}
}

// ---------- Policy CRUD ----------

func TestPolicyCRUD(t *testing.T) {
	h, _ := newRouter(t, midDayClock())

	// Create.
	rec := doJSON(t, h, http.MethodPost, "/v1/policies", testTenant, map[string]any{
		"name": "block-sanctioned",
		"rules": []any{
			map[string]any{
				"condition": map[string]any{"field": "context.country", "op": "eq", "value": "XX"},
				"action":    map[string]any{"deny": true},
			},
		},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var p Policy
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	if p.ID == "" || p.ID[:4] != "pol_" {
		t.Fatalf("bad policy id: %q", p.ID)
	}

	// Get.
	rec = doJSON(t, h, http.MethodGet, "/v1/policies/"+p.ID, testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: want 200, got %d", rec.Code)
	}

	// List.
	rec = doJSON(t, h, http.MethodGet, "/v1/policies", testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", rec.Code)
	}
	var list ListPoliciesResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Items) != 1 {
		t.Fatalf("list: expected 1 item, got %d", len(list.Items))
	}

	// Patch.
	rec = doJSON(t, h, http.MethodPatch, "/v1/policies/"+p.ID, testTenant, map[string]any{
		"name": "block-sanctioned-v2",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	// Delete.
	rec = doJSON(t, h, http.MethodDelete, "/v1/policies/"+p.ID, testTenant, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", rec.Code)
	}

	// Second delete is 404.
	rec = doJSON(t, h, http.MethodDelete, "/v1/policies/"+p.ID, testTenant, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("second delete: want 404, got %d", rec.Code)
	}
}

func TestPolicyRejectsBadRule(t *testing.T) {
	h, _ := newRouter(t, midDayClock())
	rec := doJSON(t, h, http.MethodPost, "/v1/policies", testTenant, map[string]any{
		"name": "bad",
		"rules": []any{
			map[string]any{
				"condition": map[string]any{"field": "not.a.field", "op": "eq", "value": "x"},
				"action":    map[string]any{"deny": true},
			},
		},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad field: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// ---------- Policy interactions with evaluations ----------

// Policy tier_floor raises a low-risk evaluation to high.
func TestPolicyTierFloorFloorsTier(t *testing.T) {
	h, store := newRouter(t, midDayClock())

	// Seed a policy: any action containing "admin." must be at least high.
	_, _ = store.CreatePolicy(Policy{
		ID: "pol_floor", TenantID: testTenant, Name: "floor-admin",
		Rules: []PolicyRule{{
			Condition: PolicyCondition{Field: FieldAction, Op: OpContains, Value: "admin."},
			Action:    PolicyAction{TierFloor: TierHigh},
		}},
	})

	body := map[string]any{
		"user_id":              "usr_known",
		"action":               "admin.users.list",
		"resource_sensitivity": "low",
		"context": map[string]any{
			"device_fingerprint": "fp_known_laptop",
			"ip_address":         "10.0.0.5",
		},
	}
	rec := doJSON(t, h, http.MethodPost, "/v1/evaluations", testTenant, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var got RiskEvaluation
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Tier != TierHigh {
		t.Fatalf("tier = %s, want high (floored)", got.Tier)
	}
	if len(got.MatchedPolicies) != 1 || got.MatchedPolicies[0] != "pol_floor" {
		t.Fatalf("matched_policies = %v", got.MatchedPolicies)
	}
}

// Policy deny short-circuits the decision regardless of tier.
func TestPolicyDenyDecision(t *testing.T) {
	h, store := newRouter(t, midDayClock())
	_, _ = store.CreatePolicy(Policy{
		ID: "pol_deny", TenantID: testTenant, Name: "country-block",
		Rules: []PolicyRule{{
			Condition: PolicyCondition{Field: FieldContextCountry, Op: OpIn, Value: []any{"KP", "IR"}},
			Action:    PolicyAction{Deny: true},
		}},
	})

	body := map[string]any{
		"user_id":              "usr_known",
		"action":               "read.profile",
		"resource_sensitivity": "low",
		"context": map[string]any{
			"device_fingerprint": "fp_known_laptop",
			"ip_address":         "10.0.0.5",
			"country":            "KP",
		},
	}
	rec := doJSON(t, h, http.MethodPost, "/v1/evaluations", testTenant, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var got RiskEvaluation
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.PolicyDecision != DecisionDeny {
		t.Fatalf("decision = %s, want deny", got.PolicyDecision)
	}
	if len(got.MatchedPolicies) != 1 || got.MatchedPolicies[0] != "pol_deny" {
		t.Fatalf("matched_policies = %v", got.MatchedPolicies)
	}
}

// Sanity: policy from tenant A does not apply to tenant B's evaluations.
func TestPolicyIsTenantScoped(t *testing.T) {
	h, store := newRouter(t, midDayClock())
	_, _ = store.CreatePolicy(Policy{
		ID: "pol_a", TenantID: testTenant, Name: "deny-all-reads",
		Rules: []PolicyRule{{
			Condition: PolicyCondition{Field: FieldAction, Op: OpContains, Value: "read."},
			Action:    PolicyAction{Deny: true},
		}},
	})

	body := map[string]any{
		"user_id":              "u",
		"action":               "read.profile",
		"resource_sensitivity": "low",
		"context":              map[string]any{"device_fingerprint": "fp_known_x", "ip_address": "10.0.0.5"},
	}
	// Tenant B — tenant A's deny must not apply.
	rec := doJSON(t, h, http.MethodPost, "/v1/evaluations", "tenant-b", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("tenant-b: want 201, got %d", rec.Code)
	}
	var got RiskEvaluation
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.PolicyDecision != DecisionAllow {
		t.Fatalf("tenant-b decision = %s, want allow", got.PolicyDecision)
	}
}
