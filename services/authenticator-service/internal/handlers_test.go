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
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/smsx"
)

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

const testTenant = "ten_test"

// testClock gives every test a deterministic clock it can advance.
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// newTestServer builds a Router with a controllable clock and the §10.5
// layer-3 limits DISABLED (zero-value Limits), so lifecycle tests aren't
// tripped by rate limits or lockouts. The per-challenge exponential backoff
// is not configurable and stays active — tests advance the clock past it.
// Returns the httptest server and the shared clock/store so tests can poke
// at state.
func newTestServer(t *testing.T) (*httptest.Server, *Store, *testClock) {
	t.Helper()
	return newTestServerWithLimits(t, func(func() time.Time) Limits { return Limits{} })
}

// newTestServerWithLimits is newTestServer with explicit abuse-prevention
// limits. limitsFn receives the test clock's now func so abuse_test.go can
// build limiters that share the controllable clock.
func newTestServerWithLimits(t *testing.T, limitsFn func(now func() time.Time) Limits) (*httptest.Server, *Store, *testClock) {
	t.Helper()
	clock := &testClock{t: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)}
	store := NewStore(clock.now)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	registry := NewRegistry(log, store, smsx.Stub{}, nil)
	srv := httptest.NewServer(Router(log, store, registry, limitsFn(clock.now), nil))
	t.Cleanup(srv.Close)
	return srv, store, clock
}

// do issues a request against the test server with the standard tenant header.
func do(t *testing.T, srv *httptest.Server, method, path string, body any) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Tenant-Id", testTenant)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// decode consumes the body and unmarshals into v.
func decode(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode %s: %v", resp.Request.URL.Path, err)
	}
}

// -----------------------------------------------------------------------------
// Healthz + tenant gate
// -----------------------------------------------------------------------------

func TestHealthz(t *testing.T) {
	srv, _, _ := newTestServer(t)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/healthz", nil)
	// no tenant header — healthz bypasses the gate
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

func TestTenantHeaderRequired(t *testing.T) {
	srv, _, _ := newTestServer(t)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/authenticators?user_id=u1", nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 when tenant missing, got %d", resp.StatusCode)
	}
}

// TestHandlersRejectMissingTenantContext calls every handler directly — without
// the tenantx middleware — and asserts each one refuses to run with an empty
// tenant scope. This guards the cross-tenant-safety property: if the middleware
// were ever bypassed or misconfigured, handlers must fail closed rather than
// silently query with tenantID == "".
func TestHandlersRejectMissingTenantContext(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)}
	store := NewStore(clock.now)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ah := NewAuthenticatorHandlers(log, store)
	ch := NewChallengeHandlers(log, store, NewRegistry(log, store, smsx.Stub{}, nil), Limits{})

	cases := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		path    string
	}{
		{"authenticators enroll", ah.Enroll, http.MethodPost, "/v1/authenticators"},
		{"authenticators list", ah.List, http.MethodGet, "/v1/authenticators?user_id=u1"},
		{"authenticators get", ah.Get, http.MethodGet, "/v1/authenticators/authr_x"},
		{"authenticators delete", ah.Delete, http.MethodDelete, "/v1/authenticators/authr_x"},
		{"challenges create", ch.Create, http.MethodPost, "/v1/challenges"},
		{"challenges get", ch.Get, http.MethodGet, "/v1/challenges/ch_x"},
		{"challenges verify", ch.Verify, http.MethodPost, "/v1/challenges/ch_x/verify"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			// No tenant on the context — simulates a bypassed middleware.
			rec := httptest.NewRecorder()
			tc.handler(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("want 400 without tenant context, got %d", rec.Code)
			}
			var body struct {
				Error   string `json:"error"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode error body: %v (raw: %q)", err, rec.Body.String())
			}
			if body.Error != "missing_tenant" {
				t.Fatalf("want error=missing_tenant, got %q", body.Error)
			}
			if body.Message != "X-Tenant-Id required" {
				t.Fatalf("want message %q, got %q", "X-Tenant-Id required", body.Message)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Authenticator CRUD
// -----------------------------------------------------------------------------

func TestEnrollValidation(t *testing.T) {
	srv, _, _ := newTestServer(t)

	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing user_id", map[string]any{"method": MethodTOTP}},
		{"unsupported method", map[string]any{"user_id": "u1", "method": "biometric"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(t, srv, http.MethodPost, "/v1/authenticators", tc.body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("want 400, got %d", resp.StatusCode)
			}
		})
	}
}

func TestEnrollAndGet(t *testing.T) {
	srv, _, _ := newTestServer(t)

	resp := do(t, srv, http.MethodPost, "/v1/authenticators", EnrollRequest{
		UserID:   "u1",
		Method:   MethodTOTP,
		Metadata: map[string]any{"device_name": "phone"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("want 201, got %d", resp.StatusCode)
	}
	var enrolled Authenticator
	decode(t, resp, &enrolled)
	if !strings.HasPrefix(enrolled.ID, "authr_") {
		t.Fatalf("id should start with authr_, got %q", enrolled.ID)
	}
	if enrolled.Status != AuthenticatorStatusActive {
		t.Fatalf("want active, got %q", enrolled.Status)
	}
	if enrolled.TenantID != testTenant {
		t.Fatalf("want tenant %q, got %q", testTenant, enrolled.TenantID)
	}

	// GET by id round-trips.
	getResp := do(t, srv, http.MethodGet, "/v1/authenticators/"+enrolled.ID, nil)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get: want 200, got %d", getResp.StatusCode)
	}
}

func TestListRequiresUserID(t *testing.T) {
	srv, _, _ := newTestServer(t)
	resp := do(t, srv, http.MethodGet, "/v1/authenticators", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

func TestListReturnsOnlyOwnTenant(t *testing.T) {
	srv, store, clock := newTestServer(t)

	// Enroll via HTTP (uses testTenant).
	enrollResp := do(t, srv, http.MethodPost, "/v1/authenticators", EnrollRequest{
		UserID: "u1", Method: MethodTOTP,
	})
	enrollResp.Body.Close()

	// Drop a cross-tenant record directly into the store; listing for the same
	// user id via the HTTP layer must not see it.
	if err := store.PutAuthenticator(Authenticator{
		ID: "authr_other", TenantID: "ten_other", UserID: "u1", Method: MethodTOTP,
		Status: AuthenticatorStatusActive, CreatedAt: clock.now(), UpdatedAt: clock.now(),
	}); err != nil {
		t.Fatalf("seed cross-tenant authenticator: %v", err)
	}

	resp := do(t, srv, http.MethodGet, "/v1/authenticators?user_id=u1", nil)
	var list ListResponse
	decode(t, resp, &list)
	if len(list.Authenticators) != 1 {
		t.Fatalf("want 1 item scoped to tenant, got %d", len(list.Authenticators))
	}
	if list.Authenticators[0].TenantID != testTenant {
		t.Fatalf("cross-tenant leakage: %q", list.Authenticators[0].TenantID)
	}
}

func TestDeleteIsSoftAndIdempotent(t *testing.T) {
	srv, _, _ := newTestServer(t)

	resp := do(t, srv, http.MethodPost, "/v1/authenticators", EnrollRequest{
		UserID: "u1", Method: MethodTOTP,
	})
	var a Authenticator
	decode(t, resp, &a)

	del := do(t, srv, http.MethodDelete, "/v1/authenticators/"+a.ID, nil)
	del.Body.Close()
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", del.StatusCode)
	}

	// Second delete is still 204 (idempotent).
	del2 := do(t, srv, http.MethodDelete, "/v1/authenticators/"+a.ID, nil)
	del2.Body.Close()
	if del2.StatusCode != http.StatusNoContent {
		t.Fatalf("second delete: want 204, got %d", del2.StatusCode)
	}

	// Get still returns the record, now with status=disabled.
	get := do(t, srv, http.MethodGet, "/v1/authenticators/"+a.ID, nil)
	var got Authenticator
	decode(t, get, &got)
	if got.Status != AuthenticatorStatusDisabled {
		t.Fatalf("want disabled, got %q", got.Status)
	}
}

// -----------------------------------------------------------------------------
// Challenge create + method selection
// -----------------------------------------------------------------------------

// enroll is a helper that enrolls an authenticator via HTTP and returns it.
func enroll(t *testing.T, srv *httptest.Server, userID, method string) Authenticator {
	t.Helper()
	resp := do(t, srv, http.MethodPost, "/v1/authenticators", EnrollRequest{
		UserID: userID, Method: method,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("enroll %s: want 201, got %d", method, resp.StatusCode)
	}
	var a Authenticator
	decode(t, resp, &a)
	return a
}

func TestChallengeCreateNoAuthenticator(t *testing.T) {
	srv, _, _ := newTestServer(t)

	resp := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{MethodTOTP},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("want 409, got %d", resp.StatusCode)
	}
}

func TestChallengeCreateInvalidMethod(t *testing.T) {
	srv, _, _ := newTestServer(t)
	resp := do(t, srv, http.MethodPost, "/v1/challenges", map[string]any{
		"user_id": "u1", "methods": []string{"biometric"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

func TestChallengeCreateSelectsPreferredMethod(t *testing.T) {
	srv, _, _ := newTestServer(t)

	enroll(t, srv, "u1", MethodTOTP)
	enroll(t, srv, "u1", MethodPush)

	// Prefer push; expect it even though totp enrolled first. (fido2 can't be
	// enrolled via the blind endpoint, so the selection test uses stub methods.)
	resp := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{MethodPush, MethodTOTP},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("want 201, got %d", resp.StatusCode)
	}
	var disp ChallengeDispatched
	decode(t, resp, &disp)
	if disp.Method != MethodPush {
		t.Fatalf("want method push, got %q", disp.Method)
	}
	if !strings.HasPrefix(disp.ChallengeID, "ch_") {
		t.Fatalf("challenge id prefix: %q", disp.ChallengeID)
	}
	if disp.Prompt != "Push notification sent (stub)" {
		t.Fatalf("unexpected prompt: %q", disp.Prompt)
	}
}

func TestChallengeCreateFallsThroughToSecondMethod(t *testing.T) {
	srv, _, _ := newTestServer(t)
	enroll(t, srv, "u1", MethodTOTP) // no fido2, only totp

	resp := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{MethodFIDO2, MethodTOTP},
	})
	var disp ChallengeDispatched
	decode(t, resp, &disp)
	if disp.Method != MethodTOTP {
		t.Fatalf("want totp fallback, got %q", disp.Method)
	}
}

func TestChallengeCreateIgnoresDisabled(t *testing.T) {
	srv, _, _ := newTestServer(t)
	a := enroll(t, srv, "u1", MethodTOTP)
	// Disable the one authenticator we have.
	del := do(t, srv, http.MethodDelete, "/v1/authenticators/"+a.ID, nil)
	del.Body.Close()

	resp := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{MethodTOTP},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("disabled authenticator should yield 409, got %d", resp.StatusCode)
	}
}

// TestSelectAuthenticatorOldestFirst exercises the selector directly to pin
// the "oldest wins, ID as tiebreaker" rule documented on Create.
func TestSelectAuthenticatorOldestFirst(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	active := []Authenticator{
		{ID: "authr_newer", Method: MethodTOTP, CreatedAt: base.Add(time.Hour)},
		{ID: "authr_older", Method: MethodTOTP, CreatedAt: base},
		{ID: "authr_also_older", Method: MethodTOTP, CreatedAt: base},
	}
	method, picked, ok := selectAuthenticator([]string{MethodTOTP}, active)
	if !ok {
		t.Fatalf("expected selection")
	}
	if method != MethodTOTP {
		t.Fatalf("want totp, got %q", method)
	}
	if picked.ID != "authr_also_older" {
		// Lexicographic tiebreak: "authr_also_older" < "authr_older".
		t.Fatalf("want authr_also_older (lex < authr_older), got %q", picked.ID)
	}
}

// -----------------------------------------------------------------------------
// Verify lifecycle
// -----------------------------------------------------------------------------

// createChallenge enrolls method for u1 and returns a fresh challenge id.
func createChallenge(t *testing.T, srv *httptest.Server, method string) string {
	t.Helper()
	enroll(t, srv, "u1", method)
	resp := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{method},
	})
	var disp ChallengeDispatched
	decode(t, resp, &disp)
	return disp.ChallengeID
}

func TestVerifySuccess(t *testing.T) {
	srv, _, _ := newTestServer(t)
	id := createChallenge(t, srv, MethodTOTP)

	resp := do(t, srv, http.MethodPost, "/v1/challenges/"+id+"/verify", VerifyRequest{
		Response: map[string]any{"code": "000000"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var vr VerifyResponse
	decode(t, resp, &vr)
	if !vr.Verified {
		t.Fatalf("want verified=true")
	}
	if vr.AuthenticatorID == "" {
		t.Fatalf("expected authenticator_id on success")
	}

	// Subsequent verify is 410 — challenge is completed.
	again := do(t, srv, http.MethodPost, "/v1/challenges/"+id+"/verify", VerifyRequest{
		Response: map[string]any{"code": "000000"},
	})
	defer again.Body.Close()
	if again.StatusCode != http.StatusGone {
		t.Fatalf("want 410 after completion, got %d", again.StatusCode)
	}
}

// TestVerifyFailsChallengeAfterMaxAttempts pins §10.5 layer 3 "max attempts
// per challenge (3)": exactly MaxChallengeAttempts failed verifies flip the
// challenge to terminal `failed`, and the constant itself is pinned at 3.
// The clock advances past the exponential backoff (2^attempts seconds)
// between failures so each retry is a real attempt, not a 429.
func TestVerifyFailsChallengeAfterMaxAttempts(t *testing.T) {
	if MaxChallengeAttempts != 3 {
		t.Fatalf("§10.5 pins max attempts per challenge at 3, got %d", MaxChallengeAttempts)
	}

	srv, _, clock := newTestServer(t)
	id := createChallenge(t, srv, MethodTOTP)

	for i := 1; i <= MaxChallengeAttempts; i++ {
		resp := do(t, srv, http.MethodPost, "/v1/challenges/"+id+"/verify", VerifyRequest{
			Response: map[string]any{"code": "wrong"},
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i, resp.StatusCode)
		}
		var vr VerifyResponse
		decode(t, resp, &vr)
		if vr.Verified {
			t.Fatalf("attempt %d: should not verify", i)
		}
		// Step past the backoff window for the attempt count we just reached.
		clock.advance(time.Duration(1<<uint(i))*time.Second + time.Second)
	}

	// 4th attempt: challenge is now `failed`, 410.
	resp := do(t, srv, http.MethodPost, "/v1/challenges/"+id+"/verify", VerifyRequest{
		Response: map[string]any{"code": "000000"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("want 410 after max attempts, got %d", resp.StatusCode)
	}

	// Read shows `failed`.
	getResp := do(t, srv, http.MethodGet, "/v1/challenges/"+id, nil)
	var c Challenge
	decode(t, getResp, &c)
	if c.Status != ChallengeStatusFailed {
		t.Fatalf("want status=failed, got %q", c.Status)
	}
	if c.Attempts != MaxChallengeAttempts {
		t.Fatalf("want attempts=%d, got %d", MaxChallengeAttempts, c.Attempts)
	}
}

func TestVerifyExpired(t *testing.T) {
	srv, _, clock := newTestServer(t)
	id := createChallenge(t, srv, MethodTOTP)

	// Push the clock past the TTL — lazy expiry flips status on next verify.
	clock.advance(ChallengeTTL + time.Second)

	resp := do(t, srv, http.MethodPost, "/v1/challenges/"+id+"/verify", VerifyRequest{
		Response: map[string]any{"code": "000000"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("want 410 for expired, got %d", resp.StatusCode)
	}

	getResp := do(t, srv, http.MethodGet, "/v1/challenges/"+id, nil)
	var c Challenge
	decode(t, getResp, &c)
	if c.Status != ChallengeStatusExpired {
		t.Fatalf("want status=expired, got %q", c.Status)
	}
}

func TestVerifyWrongTenantIs404(t *testing.T) {
	srv, _, _ := newTestServer(t)
	id := createChallenge(t, srv, MethodTOTP)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/challenges/"+id+"/verify",
		bytes.NewReader([]byte(`{"response":{"code":"000000"}}`)))
	req.Header.Set("X-Tenant-Id", "ten_other")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 cross-tenant, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// Storage failure → 500 (phase 2.1 widened Storage signatures)
// -----------------------------------------------------------------------------

// errStorageDown simulates a Postgres outage behind the Storage interface.
var errStorageDown = errors.New("storage down")

// failingStore wraps a healthy in-memory Store but fails every write
// (PutAuthenticator / PutChallenge / PurgeExpired) and — when failLists is
// set — the List* reads too. Reads not overridden delegate to the embedded
// Store so tests can seed state and exercise specific failure points.
type failingStore struct {
	*Store
	failLists bool
}

func (f *failingStore) PutAuthenticator(Authenticator) error { return errStorageDown }
func (f *failingStore) PutChallenge(Challenge) error         { return errStorageDown }
func (f *failingStore) PurgeExpired(time.Time) (int, error)  { return 0, errStorageDown }

func (f *failingStore) ListAuthenticators(tenantID, userID string) ([]Authenticator, error) {
	if f.failLists {
		return nil, errStorageDown
	}
	return f.Store.ListAuthenticators(tenantID, userID)
}

func (f *failingStore) ListActiveAuthenticators(tenantID, userID string) ([]Authenticator, error) {
	if f.failLists {
		return nil, errStorageDown
	}
	return f.Store.ListActiveAuthenticators(tenantID, userID)
}

// newFailingServer builds a Router on top of a failingStore.
func newFailingServer(t *testing.T, failLists bool) (*httptest.Server, *failingStore) {
	t.Helper()
	clock := &testClock{t: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)}
	store := &failingStore{Store: NewStore(clock.now), failLists: failLists}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(Router(log, store, NewRegistry(log, store, smsx.Stub{}, nil), Limits{}, nil))
	t.Cleanup(srv.Close)
	return srv, store
}

// assertInternalError checks the response is a 500 with code internal_error.
func assertInternalError(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("want 500 on storage failure, got %d", resp.StatusCode)
	}
	var body struct {
		Error string `json:"error"`
	}
	decode(t, resp, &body)
	if body.Error != "internal_error" {
		t.Fatalf("want error=internal_error, got %q", body.Error)
	}
}

// TestEnrollStorageFailureIs500 pins the phase-2.1 fix: a failed
// PutAuthenticator must surface as 500 internal_error, not a phantom 201
// claiming the enrollment was stored.
func TestEnrollStorageFailureIs500(t *testing.T) {
	srv, _ := newFailingServer(t, false)
	resp := do(t, srv, http.MethodPost, "/v1/authenticators", EnrollRequest{
		UserID: "u1", Method: MethodTOTP,
	})
	assertInternalError(t, resp)
}

func TestListStorageFailureIs500(t *testing.T) {
	srv, _ := newFailingServer(t, true)
	resp := do(t, srv, http.MethodGet, "/v1/authenticators?user_id=u1", nil)
	assertInternalError(t, resp)
}

func TestChallengeCreateListFailureIs500(t *testing.T) {
	srv, _ := newFailingServer(t, true)
	resp := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{MethodTOTP},
	})
	assertInternalError(t, resp)
}

// TestChallengeCreatePutFailureIs500 seeds an active authenticator into the
// healthy embedded store (so method selection and adapter dispatch succeed)
// and asserts the failed PutChallenge yields 500, not a phantom 201 with a
// challenge_id that was never persisted.
func TestChallengeCreatePutFailureIs500(t *testing.T) {
	srv, store := newFailingServer(t, false)
	if err := store.Store.PutAuthenticator(Authenticator{
		ID: "authr_seed", TenantID: testTenant, UserID: "u1", Method: MethodTOTP,
		Status:    AuthenticatorStatusActive,
		CreatedAt: store.Now(), UpdatedAt: store.Now(),
	}); err != nil {
		t.Fatalf("seed authenticator: %v", err)
	}
	resp := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{MethodTOTP},
	})
	assertInternalError(t, resp)
}

// -----------------------------------------------------------------------------
// Expired-challenge purge (in-memory)
// -----------------------------------------------------------------------------

// TestStorePurgeExpired pins the purge predicate: pending-past-expiry and
// lazily-flipped `expired` rows go; live pending and terminal completed/failed
// rows (the audit trail) stay.
func TestStorePurgeExpired(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)}
	store := NewStore(clock.now)
	now := clock.now()

	seed := []Challenge{
		{ID: "ch_live", TenantID: testTenant, Status: ChallengeStatusPending,
			CreatedAt: now, ExpiresAt: now.Add(time.Minute)}, // kept: pending, still live
		{ID: "ch_stale", TenantID: testTenant, Status: ChallengeStatusPending,
			CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Second)}, // purged: pending past expiry
		{ID: "ch_boundary", TenantID: testTenant, Status: ChallengeStatusPending,
			CreatedAt: now.Add(-ChallengeTTL), ExpiresAt: now}, // purged: expires_at == now (verify treats now >= expires_at as expired)
		{ID: "ch_flipped", TenantID: testTenant, Status: ChallengeStatusExpired,
			CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Hour)}, // purged: already flipped to expired
		{ID: "ch_done", TenantID: testTenant, Status: ChallengeStatusCompleted,
			CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Hour)}, // kept: audit trail
		{ID: "ch_locked", TenantID: testTenant, Status: ChallengeStatusFailed,
			CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Hour)}, // kept: audit trail
	}
	for _, c := range seed {
		if err := store.PutChallenge(c); err != nil {
			t.Fatalf("seed %s: %v", c.ID, err)
		}
	}

	n, err := store.PurgeExpired(now)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 3 {
		t.Fatalf("want 3 purged, got %d", n)
	}

	for _, id := range []string{"ch_live", "ch_done", "ch_locked"} {
		if _, err := store.GetChallenge(testTenant, id); err != nil {
			t.Fatalf("%s should survive purge, got %v", id, err)
		}
	}
	for _, id := range []string{"ch_stale", "ch_boundary", "ch_flipped"} {
		if _, err := store.GetChallenge(testTenant, id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s should be purged, got %v", id, err)
		}
	}

	// Purge is idempotent: a second sweep finds nothing.
	n, err = store.PurgeExpired(now)
	if err != nil || n != 0 {
		t.Fatalf("second purge: want (0, nil), got (%d, %v)", n, err)
	}
}

// -----------------------------------------------------------------------------
// Adapter stub behavior (direct-call tests)
// -----------------------------------------------------------------------------

func TestAdapterStubs(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := &testClock{t: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)}
	store := NewStore(clock.now)
	// The SMS adapter reads the enrolled number off the authenticator referenced
	// by the challenge, so seed one (the stub verifier accepts smsx.StubCode).
	if err := store.PutAuthenticator(Authenticator{
		ID: "authr_sms", TenantID: "ten_sms", UserID: "usr_x", Method: MethodSMS, Status: "active",
		Metadata: map[string]any{"phone_number": "+15551112222"}, CreatedAt: clock.now(), UpdatedAt: clock.now(),
	}); err != nil {
		t.Fatalf("seed sms authenticator: %v", err)
	}
	reg := NewRegistry(log, store, smsx.Stub{}, nil)
	ctx := context.Background()

	// The expected-prompt + golden-response table pins every adapter's
	// canned behavior, including the negative path (wrong response → false). For
	// SMS, tenantID/authID point at the seeded authenticator.
	cases := []struct {
		method      string
		wantPrompt  string
		tenantID    string
		authID      string
		validResp   map[string]any
		invalidResp map[string]any
	}{
		// fido2 is real crypto now — exercised in webauthn_test.go, not this stub table.
		{MethodTOTP, "Enter 6-digit code from your authenticator app", "", "",
			map[string]any{"code": "000000"},
			map[string]any{"code": "111111"}},
		{MethodPush, "Push notification sent (stub)", "", "",
			map[string]any{"approved": true},
			map[string]any{"approved": false}},
		{MethodSMS, "We texted a verification code to your phone", "ten_sms", "authr_sms",
			map[string]any{"code": smsx.StubCode},
			map[string]any{"code": "000000"}},
		{MethodMagicLink, "Magic link sent to user@example.com (stub)", "", "",
			map[string]any{"token": "stub_magic_token"},
			map[string]any{"token": "wrong"}},
	}

	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			adapter, ok := reg.Lookup(tc.method)
			if !ok {
				t.Fatalf("no adapter for %s", tc.method)
			}
			chal := Challenge{ID: "ch_stub", Method: tc.method, TenantID: tc.tenantID, AuthenticatorID: tc.authID}
			res, err := adapter.Dispatch(ctx, chal)
			if err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			if res.Prompt != tc.wantPrompt {
				t.Fatalf("prompt: want %q, got %q", tc.wantPrompt, res.Prompt)
			}
			v1, err := adapter.Verify(ctx, chal, tc.validResp)
			if err != nil || !v1.OK {
				t.Fatalf("expected valid verify: ok=%v err=%v", v1.OK, err)
			}
			v2, err := adapter.Verify(ctx, chal, tc.invalidResp)
			if err != nil {
				t.Fatalf("invalid verify errored: %v", err)
			}
			if v2.OK {
				t.Fatalf("expected invalid response to return false")
			}
			// Missing fields / wrong types must never panic and must not verify.
			v3, err := adapter.Verify(ctx, chal, nil)
			if err != nil || v3.OK {
				t.Fatalf("nil response: ok=%v err=%v", v3.OK, err)
			}
		})
	}
}

func TestRegistryUnknownMethod(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := NewRegistry(log, nil, smsx.Stub{}, nil)
	if _, ok := reg.Lookup("nope"); ok {
		t.Fatal("expected Lookup of unknown method to return false")
	}
}
