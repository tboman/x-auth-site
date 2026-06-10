package internal

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/xentranet/x-auth/pkg/ratex"
)

// newLimitedServer is newServer with an injected §10.5 limiter, so tests can
// use a tight limit instead of going through the RATE_LIMIT env var.
func newLimitedServer(t *testing.T, limiter ratex.Allower, risk RiskClient) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewHandlers(NewMemStorage(), logger, risk, nil, nil).Router(limiter)
}

// lowRisk is a risk-service stub that always returns tier low, so POST
// /v1/advice succeeds without a step-up leg.
func lowRisk() *mockRisk {
	return &mockRisk{Fn: func(_ string, _ RiskEvaluateRequest) (RiskEvaluationResult, error) {
		return RiskEvaluationResult{ID: "rev_rl", Tier: TierLow, Score: 0.1}, nil
	}}
}

func TestRateLimitThirdCallSameTenantEndpoint429(t *testing.T) {
	h := newLimitedServer(t, ratex.New(2, time.Minute), lowRisk())

	for i := 1; i <= 2; i++ {
		rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d: want 200, got %d body=%s", i, rec.Code, rec.Body.String())
		}
	}

	rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd call: want 429, got %d", rec.Code)
	}
	ra := rec.Header().Get("Retry-After")
	if ra == "" {
		t.Fatal("429 response missing Retry-After header")
	}
	if secs, err := strconv.Atoi(ra); err != nil || secs <= 0 {
		t.Fatalf("Retry-After should be a positive integer, got %q", ra)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("429 body is not JSON: %v (%s)", err, rec.Body.String())
	}
	if body["error"] != "rate_limited" {
		t.Fatalf(`429 body error=%v, want "rate_limited"`, body["error"])
	}

	// The /v1/evaluate alias shares the limit bucket only by its own class
	// ("POST|/v1/evaluate"), so it is still allowed — proving the key includes
	// the endpoint class, not just the tenant.
	rec = doJSON(t, h, http.MethodPost, "/v1/evaluate", testTenant, sampleAdvice())
	if rec.Code != http.StatusOK {
		t.Fatalf("different endpoint class after 429: want 200, got %d", rec.Code)
	}
}

func TestRateLimitDifferentTenantUnaffected(t *testing.T) {
	h := newLimitedServer(t, ratex.New(2, time.Minute), lowRisk())

	for i := 0; i < 3; i++ {
		doJSON(t, h, http.MethodPost, "/v1/advice", "tenant-a", sampleAdvice())
	}
	if rec := doJSON(t, h, http.MethodPost, "/v1/advice", "tenant-a", sampleAdvice()); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("tenant-a should be limited, got %d", rec.Code)
	}
	if rec := doJSON(t, h, http.MethodPost, "/v1/advice", "tenant-b", sampleAdvice()); rec.Code != http.StatusOK {
		t.Fatalf("tenant-b should be unaffected, got %d", rec.Code)
	}
}

func TestRateLimitDifferentEndpointClassUnaffected(t *testing.T) {
	h := newLimitedServer(t, ratex.New(2, time.Minute), lowRisk())

	// Exhaust POST|/v1/advice for the tenant.
	for i := 0; i < 3; i++ {
		doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
	}
	// GET|/v1/transactions is a different class (different method AND segments).
	if rec := doJSON(t, h, http.MethodGet, "/v1/transactions", testTenant, nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/transactions should be unaffected, got %d", rec.Code)
	}
}

func TestRateLimitHealthzNeverLimited(t *testing.T) {
	h := newLimitedServer(t, ratex.New(1, time.Minute), nil)

	for i := 0; i < 5; i++ {
		// Even with a tenant header set, /healthz sits outside the limited tree.
		rec := doJSON(t, h, http.MethodGet, "/healthz", testTenant, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("healthz call %d: want 200, got %d", i+1, rec.Code)
		}
	}
}

func TestRateLimitMissingTenantBypassesLimiter(t *testing.T) {
	h := newLimitedServer(t, ratex.New(1, time.Minute), nil)

	// No X-Tenant-Id -> empty key -> limiter bypassed; tenantx still 400s.
	for i := 0; i < 3; i++ {
		rec := doJSON(t, h, http.MethodGet, "/v1/transactions", "", nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("tenantless call %d: want 400 (never 429), got %d", i+1, rec.Code)
		}
	}
}

// TestRateLimitOffDisablesLimiting proves the RATE_LIMIT=off wiring still
// bypasses now that Router takes a ratex.Allower: main.go leaves the Allower
// an UNTYPED nil when ParseRateLimit reports enabled=false, and Middleware
// bypasses on a nil interface.
func TestRateLimitOffDisablesLimiting(t *testing.T) {
	_, _, enabled, err := ParseRateLimit(RateLimitOff)
	if err != nil {
		t.Fatalf(`ParseRateLimit("off"): %v`, err)
	}
	if enabled {
		t.Fatal(`ParseRateLimit("off") must report enabled=false`)
	}

	// Untyped nil Allower — exactly what main.go passes when off.
	h := newLimitedServer(t, nil, lowRisk())
	for i := 0; i < 10; i++ {
		rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
		if rec.Code != http.StatusOK {
			t.Fatalf("off: call %d got %d", i+1, rec.Code)
		}
	}
}

// TestRateLimitTypedNilLimiterStillBypasses guards the typed-nil-in-interface
// trap: a nil *ratex.Limiter wrapped in the Allower interface is a NON-nil
// interface, so Middleware's nil check does not fire — the limiter's own
// nil-receiver guard in Allow must keep "off" behaving as bypass.
func TestRateLimitTypedNilLimiterStillBypasses(t *testing.T) {
	var typedNil *ratex.Limiter
	h := newLimitedServer(t, typedNil, lowRisk())
	for i := 0; i < 10; i++ {
		rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
		if rec.Code != http.StatusOK {
			t.Fatalf("typed-nil: call %d got %d", i+1, rec.Code)
		}
	}
}

func TestParseRateLimitParsesAndRejects(t *testing.T) {
	limit, window, enabled, err := ParseRateLimit("600/1m")
	if err != nil || !enabled || limit != 600 || window != time.Minute {
		t.Fatalf("default spec: got limit=%d window=%v enabled=%v err=%v", limit, window, enabled, err)
	}

	for _, bad := range []string{"", "garbage", "600", "/1m", "0/1m", "-5/1m", "10/0s", "10/xyz"} {
		if _, _, _, err := ParseRateLimit(bad); err == nil {
			t.Errorf("ParseRateLimit(%q): want error, got nil", bad)
		}
	}
}

// TestRateLimitRedisThroughRouter runs the real Redis-backed limiter (the
// phase-2 production path: shared rate:txn:* counters, §6.3) through the
// service router: with limit 2/min the 3rd same-tenant call must 429 with a
// Retry-After header, same contract as the in-memory limiter.
func TestRateLimitRedisThroughRouter(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	limiter := ratex.NewRedis(client, 2, time.Minute, "rate:txn", logger)
	h := newLimitedServer(t, limiter, lowRisk())

	for i := 1; i <= 2; i++ {
		rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d: want 200, got %d body=%s", i, rec.Code, rec.Body.String())
		}
	}

	rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd call: want 429, got %d", rec.Code)
	}
	ra := rec.Header().Get("Retry-After")
	if ra == "" {
		t.Fatal("429 response missing Retry-After header")
	}
	if secs, err := strconv.Atoi(ra); err != nil || secs <= 0 {
		t.Fatalf("Retry-After should be a positive integer, got %q", ra)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("429 body is not JSON: %v (%s)", err, rec.Body.String())
	}
	if body["error"] != "rate_limited" {
		t.Fatalf(`429 body error=%v, want "rate_limited"`, body["error"])
	}

	// The counter lives in Redis under the §6.3 rate: prefix, not in-process —
	// the property that makes the limit hold across replicas.
	if got := len(mr.Keys()); got == 0 {
		t.Fatal("expected rate:txn:* counter keys in Redis, found none")
	}

	// A different tenant has its own budget against the same shared backend.
	if rec := doJSON(t, h, http.MethodPost, "/v1/advice", "tenant-b", sampleAdvice()); rec.Code != http.StatusOK {
		t.Fatalf("tenant-b should be unaffected, got %d", rec.Code)
	}
}

func TestEndpointClass(t *testing.T) {
	for path, want := range map[string]string{
		"/v1/advice":              "/v1/advice",
		"/v1/transactions":        "/v1/transactions",
		"/v1/transactions/txn_42": "/v1/transactions",
		"/v1/step-up/verify":      "/v1/step-up",
		"/v1":                     "/v1",
		"/":                       "/",
	} {
		if got := endpointClass(path); got != want {
			t.Errorf("endpointClass(%q) = %q, want %q", path, got, want)
		}
	}
}
