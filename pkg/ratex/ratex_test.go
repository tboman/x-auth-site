package ratex

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fixedClock returns a settable clock for deterministic window math.
type fixedClock struct{ t time.Time }

func (c *fixedClock) now() time.Time          { return c.t }
func (c *fixedClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestLimiter(limit int, window time.Duration) (*Limiter, *fixedClock) {
	clock := &fixedClock{t: time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)}
	l := New(limit, window)
	l.Now = clock.now
	return l, clock
}

func TestAllowWithinLimit(t *testing.T) {
	l, _ := newTestLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("k"); !ok {
			t.Fatalf("call %d should be allowed", i)
		}
	}
	ok, retryAfter := l.Allow("k")
	if ok {
		t.Fatal("4th call must be limited")
	}
	if retryAfter <= 0 || retryAfter > time.Minute {
		t.Fatalf("retryAfter out of range: %v", retryAfter)
	}
}

func TestWindowSlides(t *testing.T) {
	l, clock := newTestLimiter(2, time.Minute)
	l.Allow("k")
	clock.advance(30 * time.Second)
	l.Allow("k")
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("limit reached, must deny")
	}
	// 31s later the first event leaves the window; one slot frees up.
	clock.advance(31 * time.Second)
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("slot must free after the window slides")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l, _ := newTestLimiter(1, time.Minute)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("a/1")
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("b must have its own budget")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("a is exhausted")
	}
}

func TestDisabledLimiter(t *testing.T) {
	l, _ := newTestLimiter(0, time.Minute)
	for i := 0; i < 100; i++ {
		if ok, _ := l.Allow("k"); !ok {
			t.Fatal("limit<=0 must always allow")
		}
	}
	var nilLimiter *Limiter
	if ok, _ := nilLimiter.Allow("k"); !ok {
		t.Fatal("nil limiter must always allow")
	}
}

func TestIdleKeySweep(t *testing.T) {
	l, clock := newTestLimiter(1, time.Minute)
	l.Allow("idle")
	clock.advance(2 * time.Minute)
	// Drive enough calls to trigger the periodic sweep.
	for i := 0; i <= sweepEvery; i++ {
		l.Allow("hot")
	}
	l.mu.Lock()
	_, exists := l.hits["idle"]
	l.mu.Unlock()
	if exists {
		t.Fatal("idle key should have been swept")
	}
}

func TestMiddleware(t *testing.T) {
	l, _ := newTestLimiter(1, time.Minute)
	h := Middleware(l, func(r *http.Request) string {
		return r.Header.Get("X-Tenant-Id")
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	req.Header.Set("X-Tenant-Id", "ten_a")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first call: want 200, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second call: want 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
	if !strings.Contains(rec.Body.String(), "rate_limited") {
		t.Fatalf("want structured body, got %s", rec.Body.String())
	}

	// Empty key bypasses.
	noTenant := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	for i := 0; i < 5; i++ {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, noTenant)
		if rec.Code != http.StatusOK {
			t.Fatalf("empty key must bypass, got %d", rec.Code)
		}
	}
}

func TestParseRate(t *testing.T) {
	n, d, err := ParseRate("100/1m")
	if err != nil || n != 100 || d != time.Minute {
		t.Fatalf("100/1m: got %d %v %v", n, d, err)
	}
	if _, _, err := ParseRate("abc"); err == nil {
		t.Fatal("garbage must error")
	}
	if _, _, err := ParseRate("0/1m"); err == nil {
		t.Fatal("zero limit must error")
	}
	if _, _, err := ParseRate("5/0s"); err == nil {
		t.Fatal("zero window must error")
	}
}
