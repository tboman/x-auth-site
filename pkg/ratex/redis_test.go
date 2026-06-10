package ratex

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/xentranet/x-auth/pkg/logx"
)

func newRedisLimiter(t *testing.T, limit int, window time.Duration) (*RedisLimiter, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewRedis(client, limit, window, "rate:test", logx.New("ratex-test")), mr
}

func TestRedisAllowWithinLimit(t *testing.T) {
	l, _ := newRedisLimiter(t, 3, time.Minute)
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

func TestRedisWindowResets(t *testing.T) {
	l, mr := newRedisLimiter(t, 2, time.Minute)
	l.Allow("k")
	l.Allow("k")
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("limit reached, must deny")
	}
	// miniredis TTLs advance via FastForward, not wall clock.
	mr.FastForward(61 * time.Second)
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("budget must reset after the window expires")
	}
}

func TestRedisKeysAreIndependentAndShared(t *testing.T) {
	l, mr := newRedisLimiter(t, 1, time.Minute)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("a/1")
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("b must have its own budget")
	}

	// A SECOND limiter instance over the same Redis (≈ another replica) sees
	// the same counters — the distributed property the in-memory Limiter lacks.
	client2 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client2.Close() })
	replica := NewRedis(client2, 1, time.Minute, "rate:test", logx.New("ratex-test"))
	if ok, _ := replica.Allow("a"); ok {
		t.Fatal("replica must see key a as exhausted")
	}
}

func TestRedisFailOpen(t *testing.T) {
	l, mr := newRedisLimiter(t, 1, time.Minute)
	mr.Close() // simulate Redis outage
	for i := 0; i < 5; i++ {
		if ok, _ := l.Allow("k"); !ok {
			t.Fatal("must fail open when Redis is unreachable")
		}
	}
}

func TestRedisDisabledAndNil(t *testing.T) {
	l, _ := newRedisLimiter(t, 0, time.Minute)
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("limit<=0 must always allow")
	}
	var nilLimiter *RedisLimiter
	if ok, _ := nilLimiter.Allow("k"); !ok {
		t.Fatal("nil limiter must always allow")
	}
}

func TestRedisLimiterThroughMiddleware(t *testing.T) {
	l, _ := newRedisLimiter(t, 1, time.Minute)
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
		t.Fatalf("first: want 200, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second: want 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
}
