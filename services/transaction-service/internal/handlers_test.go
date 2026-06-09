package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

const testTenant = "tenant-a"

// -----------------------------------------------------------------------------
// Mock clients — function-field style so each test stubs exactly what it needs.
// -----------------------------------------------------------------------------

type mockRisk struct {
	mu      sync.Mutex
	Fn      func(tenantID string, req RiskEvaluateRequest) (RiskEvaluationResult, error)
	Calls   int
	LastReq RiskEvaluateRequest
	LastCtx context.Context
}

func (m *mockRisk) Evaluate(ctx context.Context, tenantID string, req RiskEvaluateRequest) (RiskEvaluationResult, error) {
	m.mu.Lock()
	m.Calls++
	m.LastReq = req
	m.LastCtx = ctx
	m.mu.Unlock()
	if m.Fn == nil {
		return RiskEvaluationResult{}, errors.New("mockRisk.Fn not set")
	}
	return m.Fn(tenantID, req)
}

type mockAuthr struct {
	mu            sync.Mutex
	CreateFn      func(tenantID string, req ChallengeCreateRequest) (Challenge, error)
	VerifyFn      func(tenantID, challengeID, method string, response map[string]any) (ChallengeVerifyResult, error)
	LastCreateReq ChallengeCreateRequest
}

func (m *mockAuthr) CreateChallenge(_ context.Context, tenantID string, req ChallengeCreateRequest) (Challenge, error) {
	m.mu.Lock()
	m.LastCreateReq = req
	m.mu.Unlock()
	if m.CreateFn == nil {
		return Challenge{}, errors.New("mockAuthr.CreateFn not set")
	}
	return m.CreateFn(tenantID, req)
}

func (m *mockAuthr) VerifyChallenge(_ context.Context, tenantID, challengeID, method string, response map[string]any) (ChallengeVerifyResult, error) {
	if m.VerifyFn == nil {
		return ChallengeVerifyResult{}, errors.New("mockAuthr.VerifyFn not set")
	}
	return m.VerifyFn(tenantID, challengeID, method, response)
}

type mockAuth struct {
	GetFn    func(tenantID, sessionID string) (Session, error)
	UpdateFn func(tenantID, sessionID string, req SessionUpdateRequest) (Session, error)
}

func (m *mockAuth) GetSession(_ context.Context, tenantID, sessionID string) (Session, error) {
	if m.GetFn == nil {
		return Session{}, errors.New("mockAuth.GetFn not set")
	}
	return m.GetFn(tenantID, sessionID)
}

func (m *mockAuth) UpdateSession(_ context.Context, tenantID, sessionID string, req SessionUpdateRequest) (Session, error) {
	if m.UpdateFn == nil {
		return Session{}, errors.New("mockAuth.UpdateFn not set")
	}
	return m.UpdateFn(tenantID, sessionID, req)
}

// -----------------------------------------------------------------------------
// Test scaffolding
// -----------------------------------------------------------------------------

func newServer(t *testing.T, risk RiskClient, auth AuthenticationClient, authr AuthenticatorClient) (http.Handler, Storage) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewMemStorage()
	return NewHandlers(store, logger, risk, auth, authr).Router(), store
}

// newTestClients builds the real HTTPClients pointed at a fake downstream URL
// (used for all three sister services), failing the test on a transport error.
func newTestClients(t *testing.T, baseURL string) *HTTPClients {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	clients, err := NewHTTPClients(logger, baseURL, baseURL, baseURL)
	if err != nil {
		t.Fatalf("NewHTTPClients: %v", err)
	}
	return clients
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

func sampleAdvice() map[string]any {
	return map[string]any{
		"user_id":              "usr_abc",
		"session_id":           "ses_xyz",
		"action":               "transfer.initiate",
		"resource":             "payments",
		"resource_sensitivity": "high",
		"context": map[string]any{
			"ip_address":         "203.0.113.42",
			"user_agent":         "UA",
			"device_fingerprint": "fp",
			"geo":                map[string]any{"lat": 37.7, "lon": -122.4},
		},
	}
}

// -----------------------------------------------------------------------------
// Healthz + tenant enforcement
// -----------------------------------------------------------------------------

func TestHealthz(t *testing.T) {
	h, _ := newServer(t, nil, nil, nil)
	rec := doJSON(t, h, http.MethodGet, "/healthz", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestAdviceRequiresTenant(t *testing.T) {
	h, _ := newServer(t, nil, nil, nil)
	rec := doJSON(t, h, http.MethodPost, "/v1/advice", "", sampleAdvice())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing tenant: want 400, got %d", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// /v1/advice happy paths
// -----------------------------------------------------------------------------

func TestAdviceAllowsLowRisk(t *testing.T) {
	risk := &mockRisk{
		Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
			return RiskEvaluationResult{
				ID:     "rev_1",
				Tier:   TierLow,
				Score:  0.1,
				Scores: map[string]float64{"device": 0.1, "network": 0.1},
			}, nil
		},
	}
	h, store := newServer(t, risk, nil, nil)

	rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp AdviceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Decision != DecisionAllow {
		t.Fatalf("want decision allow, got %s", resp.Decision)
	}
	if resp.StepUp != nil {
		t.Fatalf("low-risk should not emit step_up, got %+v", resp.StepUp)
	}
	if resp.RiskEvaluation == nil || resp.RiskEvaluation.Tier != TierLow {
		t.Fatalf("risk evaluation not surfaced: %+v", resp.RiskEvaluation)
	}

	// Persisted transaction is tenant-scoped and reflects the decision.
	saved, err := store.Get(testTenant, resp.TransactionID)
	if err != nil {
		t.Fatalf("persisted: %v", err)
	}
	if saved.Decision != DecisionAllow {
		t.Fatalf("saved decision=%s", saved.Decision)
	}
	if saved.TenantID != testTenant {
		t.Fatalf("saved tenant=%s", saved.TenantID)
	}
}

func TestAdviceIssuesChallengeForMediumRisk(t *testing.T) {
	risk := &mockRisk{
		Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
			return RiskEvaluationResult{ID: "rev_2", Tier: TierMedium, Score: 0.5}, nil
		},
	}
	authr := &mockAuthr{
		CreateFn: func(_ string, req ChallengeCreateRequest) (Challenge, error) {
			return Challenge{ID: "ch_1", ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
		},
	}
	h, _ := newServer(t, risk, nil, authr)
	rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp AdviceResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Decision != DecisionStepUpRequired {
		t.Fatalf("want step_up_required, got %s", resp.Decision)
	}
	if resp.StepUp == nil || resp.StepUp.ChallengeID != "ch_1" {
		t.Fatalf("bad step_up: %+v", resp.StepUp)
	}
	// medium -> otp, magic_link
	if got := resp.StepUp.Methods; len(got) != 2 || got[0] != "otp" || got[1] != "magic_link" {
		t.Fatalf("medium methods: %v", got)
	}
	if got := authr.LastCreateReq.Methods; len(got) != 2 || got[0] != "otp" {
		t.Fatalf("challenge request methods: %v", got)
	}
}

func TestAdviceIssuesStrongChallengeForHighRisk(t *testing.T) {
	risk := &mockRisk{Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
		return RiskEvaluationResult{ID: "rev_3", Tier: TierHigh, Score: 0.9}, nil
	}}
	authr := &mockAuthr{CreateFn: func(_ string, req ChallengeCreateRequest) (Challenge, error) {
		return Challenge{ID: "ch_h", ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
	}}
	h, _ := newServer(t, risk, nil, authr)
	rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
	var resp AdviceResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if got := resp.StepUp.Methods; len(got) != 2 || got[0] != "fido2" || got[1] != "push" {
		t.Fatalf("high methods: %v", got)
	}
}

// /v1/evaluate alias should route to the same handler.
func TestEvaluateAliasWorks(t *testing.T) {
	risk := &mockRisk{Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
		return RiskEvaluationResult{ID: "rev_a", Tier: TierLow, Score: 0.1}, nil
	}}
	h, _ := newServer(t, risk, nil, nil)
	rec := doJSON(t, h, http.MethodPost, "/v1/evaluate", testTenant, sampleAdvice())
	if rec.Code != http.StatusOK {
		t.Fatalf("evaluate alias: want 200, got %d", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// /v1/advice validation + upstream error handling
// -----------------------------------------------------------------------------

func TestAdviceValidatesRequired(t *testing.T) {
	h, _ := newServer(t, nil, nil, nil)
	// missing user_id
	rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, map[string]any{
		"action": "a", "context": map[string]any{"ip_address": "1.2.3.4"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing user_id: want 400, got %d", rec.Code)
	}
	// missing action
	rec = doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, map[string]any{
		"user_id": "u", "context": map[string]any{"ip_address": "1.2.3.4"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing action: want 400, got %d", rec.Code)
	}
	// missing context.ip_address
	rec = doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, map[string]any{
		"user_id": "u", "action": "a", "context": map[string]any{},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing ip: want 400, got %d", rec.Code)
	}
}

func TestAdviceReturns502OnRiskFailure(t *testing.T) {
	risk := &mockRisk{Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
		return RiskEvaluationResult{}, &DownstreamError{Service: "risk-service", Err: errors.New("boom")}
	}}
	h, store := newServer(t, risk, nil, nil)
	rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "upstream_unavailable" || body["service"] != "risk-service" {
		t.Fatalf("unexpected 502 body: %v", body)
	}
	// Transaction is persisted with decision "error".
	txnID, _ := body["transaction_id"].(string)
	if txnID == "" {
		t.Fatalf("no transaction_id on 502")
	}
	saved, err := store.Get(testTenant, txnID)
	if err != nil {
		t.Fatalf("txn should be persisted even on upstream failure: %v", err)
	}
	if saved.Decision != DecisionError {
		t.Fatalf("want error decision, got %s", saved.Decision)
	}
}

func TestAdviceReturns502OnChallengeFailure(t *testing.T) {
	risk := &mockRisk{Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
		return RiskEvaluationResult{ID: "rev_x", Tier: TierHigh, Score: 0.9}, nil
	}}
	authr := &mockAuthr{CreateFn: func(_ string, _ ChallengeCreateRequest) (Challenge, error) {
		return Challenge{}, &DownstreamError{Service: "authenticator-service", Err: errors.New("nope")}
	}}
	h, _ := newServer(t, risk, nil, authr)
	rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["service"] != "authenticator-service" {
		t.Fatalf("service field wrong: %v", body["service"])
	}
}

// -----------------------------------------------------------------------------
// /v1/step-up/verify
// -----------------------------------------------------------------------------

// seedStepUpTxn drives /v1/advice to create a real step_up_required transaction so
// the verify test exercises the full state machine.
func seedStepUpTxn(t *testing.T, h http.Handler) (txnID, challengeID string) {
	t.Helper()
	rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
	if rec.Code != http.StatusOK {
		t.Fatalf("seed advice: want 200, got %d", rec.Code)
	}
	var resp AdviceResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.StepUp == nil {
		t.Fatalf("seed: expected step_up challenge")
	}
	return resp.TransactionID, resp.StepUp.ChallengeID
}

func TestStepUpVerifyHappyPath(t *testing.T) {
	risk := &mockRisk{Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
		return RiskEvaluationResult{ID: "rev_v", Tier: TierHigh, Score: 0.9}, nil
	}}
	authr := &mockAuthr{
		CreateFn: func(_ string, _ ChallengeCreateRequest) (Challenge, error) {
			return Challenge{ID: "ch_v", ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
		},
		VerifyFn: func(_, _, method string, _ map[string]any) (ChallengeVerifyResult, error) {
			return ChallengeVerifyResult{Verified: true, Method: method, VerifiedAt: time.Now()}, nil
		},
	}
	auth := &mockAuth{UpdateFn: func(_, id string, req SessionUpdateRequest) (Session, error) {
		if req.RiskLevel != TierHigh || !req.StepUpCompleted {
			t.Fatalf("session update should carry tier+completed, got %+v", req)
		}
		return Session{ID: id, RiskLevel: req.RiskLevel, StepUpCompleted: true,
			ExpiresAt: time.Now().Add(time.Hour)}, nil
	}}
	h, store := newServer(t, risk, auth, authr)
	txnID, chID := seedStepUpTxn(t, h)

	rec := doJSON(t, h, http.MethodPost, "/v1/step-up/verify", testTenant, map[string]any{
		"transaction_id": txnID,
		"challenge_id":   chID,
		"method":         "fido2",
		"response":       map[string]any{"signature": "x"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp StepUpVerifyResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Decision != DecisionAllow {
		t.Fatalf("want decision allow, got %s", resp.Decision)
	}
	if resp.Session == nil || !resp.Session.StepUpCompleted {
		t.Fatalf("session should be upgraded: %+v", resp.Session)
	}

	saved, _ := store.Get(testTenant, txnID)
	if saved.Decision != DecisionStepUpSatisfied {
		t.Fatalf("saved decision=%s", saved.Decision)
	}
	if !saved.StepUpUsed || saved.StepUpMethod != "fido2" {
		t.Fatalf("step-up metadata not recorded: %+v", saved)
	}
}

func TestStepUpVerifyRejectedResponseKeepsTxnPending(t *testing.T) {
	risk := &mockRisk{Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
		return RiskEvaluationResult{ID: "rev_r", Tier: TierHigh, Score: 0.9}, nil
	}}
	rem := 2
	authr := &mockAuthr{
		CreateFn: func(_ string, _ ChallengeCreateRequest) (Challenge, error) {
			return Challenge{ID: "ch_r", ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
		},
		VerifyFn: func(_, _, _ string, _ map[string]any) (ChallengeVerifyResult, error) {
			return ChallengeVerifyResult{Verified: false, Reason: "signature_mismatch", AttemptsRemaining: &rem}, nil
		},
	}
	h, store := newServer(t, risk, nil, authr)
	txnID, chID := seedStepUpTxn(t, h)

	rec := doJSON(t, h, http.MethodPost, "/v1/step-up/verify", testTenant, map[string]any{
		"transaction_id": txnID,
		"challenge_id":   chID,
		"method":         "fido2",
		"response":       map[string]any{},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("rejected verify should be 401, got %d", rec.Code)
	}
	saved, _ := store.Get(testTenant, txnID)
	if saved.Decision != DecisionStepUpRequired {
		t.Fatalf("rejected verify should not flip decision, got %s", saved.Decision)
	}
}

func TestStepUpVerifyRejectsWrongChallenge(t *testing.T) {
	risk := &mockRisk{Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
		return RiskEvaluationResult{ID: "rev_w", Tier: TierHigh, Score: 0.9}, nil
	}}
	authr := &mockAuthr{CreateFn: func(_ string, _ ChallengeCreateRequest) (Challenge, error) {
		return Challenge{ID: "ch_real", ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
	}}
	h, _ := newServer(t, risk, nil, authr)
	txnID, _ := seedStepUpTxn(t, h)

	rec := doJSON(t, h, http.MethodPost, "/v1/step-up/verify", testTenant, map[string]any{
		"transaction_id": txnID,
		"challenge_id":   "ch_fake",
		"method":         "fido2",
		"response":       map[string]any{},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched challenge_id: want 400, got %d", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// /v1/authorize
// -----------------------------------------------------------------------------

func TestAuthorizeUsesCachedTierWhenFresh(t *testing.T) {
	risk := &mockRisk{Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
		t.Fatal("risk-service should NOT be called when session is fresh and sensitivity is low")
		return RiskEvaluationResult{}, nil
	}}
	auth := &mockAuth{GetFn: func(_, id string) (Session, error) {
		return Session{ID: id, RiskLevel: TierLow,
			ExpiresAt: time.Now().Add(time.Hour),
			UpdatedAt: time.Now().Add(-30 * time.Second), // fresh
		}, nil
	}}
	h, _ := newServer(t, risk, auth, nil)

	rec := doJSON(t, h, http.MethodPost, "/v1/authorize", testTenant, map[string]any{
		"user_id":    "usr_1",
		"session_id": "ses_1",
		"action":     "read.doc",
		"resource":   "docs",
		"attributes": map[string]any{},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var resp AuthorizeResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Decision != DecisionAllow {
		t.Fatalf("want allow, got %s", resp.Decision)
	}
	if risk.Calls != 0 {
		t.Fatalf("expected no risk-service calls, got %d", risk.Calls)
	}
}

func TestAuthorizeReEvaluatesWhenStale(t *testing.T) {
	risk := &mockRisk{Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
		return RiskEvaluationResult{ID: "rev_s", Tier: TierLow, Score: 0.1, MatchedPolicies: []string{"pol_v1"}}, nil
	}}
	auth := &mockAuth{GetFn: func(_, id string) (Session, error) {
		return Session{ID: id, RiskLevel: TierLow,
			UpdatedAt: time.Now().Add(-10 * time.Minute), // stale
			ExpiresAt: time.Now().Add(time.Hour),
		}, nil
	}}
	h, _ := newServer(t, risk, auth, nil)

	rec := doJSON(t, h, http.MethodPost, "/v1/authorize", testTenant, map[string]any{
		"user_id":    "usr_1",
		"session_id": "ses_1",
		"action":     "read.doc",
		"resource":   "docs",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if risk.Calls != 1 {
		t.Fatalf("expected risk-service call on stale session, got %d", risk.Calls)
	}
	// The matched policy flows through to the authorize response: first match as
	// the primary policy_id, full list as matched_policies.
	var resp AuthorizeResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.PolicyID != "pol_v1" {
		t.Fatalf("policy_id should carry the matched policy, got %q", resp.PolicyID)
	}
	if len(resp.MatchedPolicies) != 1 || resp.MatchedPolicies[0] != "pol_v1" {
		t.Fatalf("matched_policies not surfaced: %v", resp.MatchedPolicies)
	}
}

func TestAuthorizeReEvaluatesWhenSensitiveResource(t *testing.T) {
	risk := &mockRisk{Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
		return RiskEvaluationResult{ID: "rev_h", Tier: TierLow, Score: 0.2}, nil
	}}
	auth := &mockAuth{GetFn: func(_, id string) (Session, error) {
		return Session{ID: id, RiskLevel: TierLow,
			UpdatedAt: time.Now().Add(-30 * time.Second), // fresh
			ExpiresAt: time.Now().Add(time.Hour),
		}, nil
	}}
	h, _ := newServer(t, risk, auth, nil)

	rec := doJSON(t, h, http.MethodPost, "/v1/authorize", testTenant, map[string]any{
		"user_id":    "usr_1",
		"session_id": "ses_1",
		"action":     "transfer.initiate",
		"resource":   "payments",
		"attributes": map[string]any{"resource_sensitivity": "high"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if risk.Calls != 1 {
		t.Fatalf("sensitive resource should force re-eval, got %d calls", risk.Calls)
	}
}

func TestAuthorizeDeniesHighTier(t *testing.T) {
	risk := &mockRisk{Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
		return RiskEvaluationResult{ID: "rev_hi", Tier: TierHigh, Score: 0.9}, nil
	}}
	auth := &mockAuth{GetFn: func(_, id string) (Session, error) {
		return Session{ID: id, RiskLevel: TierLow,
			UpdatedAt: time.Now().Add(-10 * time.Minute), ExpiresAt: time.Now().Add(time.Hour),
		}, nil
	}}
	h, _ := newServer(t, risk, auth, nil)

	rec := doJSON(t, h, http.MethodPost, "/v1/authorize", testTenant, map[string]any{
		"user_id": "u", "session_id": "s", "action": "a", "resource": "r",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
	var resp AuthorizeResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Decision != DecisionDeny || resp.Reason != "step_up_required" {
		t.Fatalf("unexpected deny body: %+v", resp)
	}
}

// -----------------------------------------------------------------------------
// Transactions list/get
// -----------------------------------------------------------------------------

func TestGetTransactionTenantIsolation(t *testing.T) {
	risk := &mockRisk{Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
		return RiskEvaluationResult{ID: "rev_iso", Tier: TierLow, Score: 0.1}, nil
	}}
	h, _ := newServer(t, risk, nil, nil)

	rec := doJSON(t, h, http.MethodPost, "/v1/advice", "tenant-a", sampleAdvice())
	var resp AdviceResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	// tenant-b can't see tenant-a's transaction
	rec = doJSON(t, h, http.MethodGet, "/v1/transactions/"+resp.TransactionID, "tenant-b", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get: want 404, got %d", rec.Code)
	}

	// tenant-a can
	rec = doJSON(t, h, http.MethodGet, "/v1/transactions/"+resp.TransactionID, "tenant-a", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("same-tenant get: want 200, got %d", rec.Code)
	}
}

func TestListTransactionsPagination(t *testing.T) {
	risk := &mockRisk{Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
		return RiskEvaluationResult{ID: "rev_lp", Tier: TierLow, Score: 0.1}, nil
	}}
	h, _ := newServer(t, risk, nil, nil)

	// Seed 3 transactions so we can exercise limit + cursor without the test racing
	// on identical timestamps — we pause a millisecond between calls.
	for i := 0; i < 3; i++ {
		rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
		if rec.Code != http.StatusOK {
			t.Fatalf("seed advice %d: %d", i, rec.Code)
		}
		time.Sleep(2 * time.Millisecond)
	}

	rec := doJSON(t, h, http.MethodGet, "/v1/transactions?limit=2", testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	var list ListResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Items) != 2 {
		t.Fatalf("want 2 items, got %d", len(list.Items))
	}
	if list.NextCursor == "" {
		t.Fatalf("expected next_cursor when page is full")
	}

	rec = doJSON(t, h, http.MethodGet, "/v1/transactions?limit=2&cursor="+list.NextCursor, testTenant, nil)
	var list2 ListResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &list2)
	if len(list2.Items) != 1 {
		t.Fatalf("second page want 1 item, got %d", len(list2.Items))
	}
	if list2.NextCursor != "" {
		t.Fatalf("final page should not emit a cursor")
	}
}

// -----------------------------------------------------------------------------
// matched_policies decoding (real HTTP client against a fake risk-service)
// -----------------------------------------------------------------------------

// TestAdviceMatchedPoliciesFlowEndToEnd runs the real HTTPClients against a fake
// risk-service emitting the actual wire shape (matched_policies, nested signals,
// policy_decision — no policy_id field), drives /v1/advice through the full
// router, and asserts the matched policies land on the persisted transaction and
// are readable back via GET /v1/transactions/{id}.
func TestAdviceMatchedPoliciesFlowEndToEnd(t *testing.T) {
	riskSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/evaluations" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		// Mirrors risk-service's RiskEvaluation JSON, including fields
		// transaction-service ignores.
		_, _ = io.WriteString(w, `{
			"id": "rev_e2e",
			"tenant_id": "tenant-a",
			"user_id": "usr_abc",
			"action": "transfer.initiate",
			"resource_sensitivity": "high",
			"tier": "low",
			"score": 0.12,
			"signals": {
				"device":   {"score": 0.1, "flags": []},
				"behavior": {"score": 0.1, "flags": []},
				"network":  {"score": 0.2, "flags": ["vpn_detected"]},
				"user":     {"score": 0.1, "flags": []}
			},
			"flags": ["vpn_detected"],
			"policy_decision": "allow",
			"matched_policies": ["pol_first", "pol_second"],
			"created_at": "2026-06-09T00:00:00Z"
		}`)
	}))
	defer riskSrv.Close()

	clients := newTestClients(t, riskSrv.URL)
	h, store := newServer(t, clients, clients, clients)

	rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp AdviceResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Decision != DecisionAllow {
		t.Fatalf("want allow, got %s", resp.Decision)
	}

	// Persisted transaction carries the primary policy id + the full match list
	// in history.
	saved, err := store.Get(testTenant, resp.TransactionID)
	if err != nil {
		t.Fatalf("persisted: %v", err)
	}
	if saved.PolicyID != "pol_first" {
		t.Fatalf("txn policy_id should be the first matched policy, got %q", saved.PolicyID)
	}
	foundHistory := false
	for _, e := range saved.History {
		if e.Event == "policies_matched" && e.Detail == "pol_first,pol_second" {
			foundHistory = true
		}
	}
	if !foundHistory {
		t.Fatalf("policies_matched history entry missing: %+v", saved.History)
	}

	// And it is visible through the public audit endpoint.
	rec = doJSON(t, h, http.MethodGet, "/v1/transactions/"+resp.TransactionID, testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get txn: want 200, got %d", rec.Code)
	}
	var txn Transaction
	_ = json.Unmarshal(rec.Body.Bytes(), &txn)
	if txn.PolicyID != "pol_first" {
		t.Fatalf("GET /v1/transactions/{id} policy_id=%q, want pol_first", txn.PolicyID)
	}
}

// -----------------------------------------------------------------------------
// Service-to-service auth (ARCHITECTURE.md §10.3)
// -----------------------------------------------------------------------------

// TestOutboundCallsCarryInternalAuthHeader asserts that with
// INTERNAL_AUTH_SECRET configured, every outbound call from the real
// HTTPClients targets the /internal/v1 tree and carries the X-Internal-Auth
// header — the non-mTLS fallback the callee's httpx.InternalAuth middleware
// verifies.
func TestOutboundCallsCarryInternalAuthHeader(t *testing.T) {
	const secret = "txn-test-secret"
	t.Setenv(httpx.EnvInternalAuthSecret, secret)

	var mu sync.Mutex
	seen := map[string]string{} // path -> X-Internal-Auth header value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get(httpx.InternalAuthHeader)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	clients := newTestClients(t, srv.URL)
	ctx := context.Background()

	if _, err := clients.Evaluate(ctx, testTenant, RiskEvaluateRequest{UserID: "u", Action: "a"}); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if _, err := clients.CreateChallenge(ctx, testTenant, ChallengeCreateRequest{UserID: "u"}); err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	if _, err := clients.VerifyChallenge(ctx, testTenant, "ch_1", "otp", nil); err != nil {
		t.Fatalf("VerifyChallenge: %v", err)
	}
	if _, err := clients.GetSession(ctx, testTenant, "ses_1"); err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if _, err := clients.UpdateSession(ctx, testTenant, "ses_1", SessionUpdateRequest{RiskLevel: TierLow}); err != nil {
		t.Fatalf("UpdateSession: %v", err)
	}

	wantPaths := []string{
		"/internal/v1/evaluations",
		"/internal/v1/challenges",
		"/internal/v1/challenges/ch_1/verify",
		"/internal/v1/sessions/ses_1",
		"/internal/v1/sessions/ses_1/upgrade",
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range wantPaths {
		got, ok := seen[p]
		if !ok {
			t.Errorf("downstream never saw %s; saw %v", p, seen)
			continue
		}
		if got != secret {
			t.Errorf("%s: %s header = %q, want %q", p, httpx.InternalAuthHeader, got, secret)
		}
	}
}

// -----------------------------------------------------------------------------
// Context propagation / cancellation
// -----------------------------------------------------------------------------

// TestAdvicePassesRequestContextToRisk asserts handlers hand r.Context() (the one
// tenantx.Middleware decorated) to the risk client, not context.Background().
func TestAdvicePassesRequestContextToRisk(t *testing.T) {
	risk := &mockRisk{Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
		return RiskEvaluationResult{ID: "rev_ctx", Tier: TierLow, Score: 0.1}, nil
	}}
	h, _ := newServer(t, risk, nil, nil)
	rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if risk.LastCtx == nil {
		t.Fatal("risk client did not receive a context")
	}
	if tid, ok := tenantx.FromContext(risk.LastCtx); !ok || tid != testTenant {
		t.Fatalf("risk client should receive the request context (tenant-scoped), got tenant=%q ok=%v", tid, ok)
	}
}

// TestEvaluateUnblocksOnContextCancel exercises the raw HTTP client: a fake
// risk-service that never responds must not pin the call until the 5s client
// timeout — cancelling the context unblocks it immediately.
func TestEvaluateUnblocksOnContextCancel(t *testing.T) {
	// done unblocks the fake handler at test teardown; without it srv.Close()
	// waits forever on the still-parked handler goroutine. The handler must also
	// drain the body first — the net/http server only detects a client disconnect
	// (and cancels r.Context()) once the request body has been consumed.
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done(): // caller went away
		case <-done: // test teardown
		}
	}))
	defer srv.Close()
	defer close(done) // runs before srv.Close (LIFO), releasing the handler

	clients := newTestClients(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := clients.Evaluate(ctx, testTenant, RiskEvaluateRequest{UserID: "u", Action: "a"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error after cancel")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled in chain, got %v", err)
	}
	var de *DownstreamError
	if !errors.As(err, &de) || de.Service != "risk-service" {
		t.Fatalf("want DownstreamError{Service: risk-service}, got %v", err)
	}
	if elapsed >= defaultClientTimeout {
		t.Fatalf("cancel did not unblock the call (took %v)", elapsed)
	}
}

// TestAdviceCallerDisconnectCancelsDownstream drives the full router with a
// cancellable request context against a blocking fake downstream: the handler
// must return promptly (502) and the downstream must observe cancellation.
func TestAdviceCallerDisconnectCancelsDownstream(t *testing.T) {
	downstreamCancelled := make(chan struct{})
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Drain the body so the server's background read can observe the client
		// disconnect and cancel r.Context().
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
			close(downstreamCancelled)
		case <-done: // test teardown — keeps srv.Close from hanging on failure
		}
	}))
	defer srv.Close()
	defer close(done)

	clients := newTestClients(t, srv.URL)
	h, _ := newServer(t, clients, clients, clients)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body, _ := json.Marshal(sampleAdvice())
	req := httptest.NewRequest(http.MethodPost, "/v1/advice", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", testTenant)

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel() // simulate the caller disconnecting mid-flight
	}()

	start := time.Now()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	elapsed := time.Since(start)

	if elapsed >= defaultClientTimeout {
		t.Fatalf("handler blocked for %v — request context not propagated downstream", elapsed)
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502 after cancelled downstream call, got %d", rec.Code)
	}
	select {
	case <-downstreamCancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("downstream never observed the cancellation")
	}
}

func TestListTransactionsRejectsBadLimit(t *testing.T) {
	h, _ := newServer(t, nil, nil, nil)
	for _, q := range []string{"?limit=abc", "?limit=0", "?limit=-1", "?cursor=notatime"} {
		rec := doJSON(t, h, http.MethodGet, "/v1/transactions"+q, testTenant, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", q, rec.Code)
		}
	}
}
