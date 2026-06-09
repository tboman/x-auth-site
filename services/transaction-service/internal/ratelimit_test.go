package internal

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/ratex"
)

// newLimitedServer is newServer with an injected §10.5 limiter, so tests can
// use a tight limit instead of going through the RATE_LIMIT env var.
func newLimitedServer(t *testing.T, limiter *ratex.Limiter, risk RiskClient) http.Handler {
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

func TestRateLimitOffDisablesLimiting(t *testing.T) {
	limiter, err := NewRateLimiter(RateLimitOff)
	if err != nil {
		t.Fatalf(`NewRateLimiter("off"): %v`, err)
	}
	if limiter != nil {
		t.Fatalf(`NewRateLimiter("off") should return nil, got %v`, limiter)
	}

	h := newLimitedServer(t, limiter, lowRisk())
	for i := 0; i < 10; i++ {
		rec := doJSON(t, h, http.MethodPost, "/v1/advice", testTenant, sampleAdvice())
		if rec.Code != http.StatusOK {
			t.Fatalf("off: call %d got %d", i+1, rec.Code)
		}
	}
}

func TestNewRateLimiterParsesAndRejects(t *testing.T) {
	limiter, err := NewRateLimiter("600/1m")
	if err != nil || limiter == nil {
		t.Fatalf("default spec should parse, got limiter=%v err=%v", limiter, err)
	}

	for _, bad := range []string{"", "garbage", "600", "/1m", "0/1m", "-5/1m", "10/0s", "10/xyz"} {
		if _, err := NewRateLimiter(bad); err == nil {
			t.Errorf("NewRateLimiter(%q): want error, got nil", bad)
		}
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
