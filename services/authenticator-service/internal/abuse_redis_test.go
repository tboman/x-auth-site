package internal

// Redis-backed §10.5 layer-3 tests: the same abuse controls as abuse_test.go,
// but with the counters on shared Redis (miniredis) the way cmd/main.go wires
// them when REDIS_URL/REDIS_ADDR is set — including the property the
// in-memory limiters lack, namely that two "replicas" (two Routers over the
// same Redis) draw from the SAME per-user budget.

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/xentranet/x-auth/pkg/ratex"
)

// newRedisLimitedServer builds one "replica": a Router over the shared store
// and clock, with Redis-backed limits on the given miniredis using the same
// prefixes cmd/main.go uses. createLimit/lockThreshold <= 0 disable the
// respective control, mirroring main.go's "off" path.
func newRedisLimitedServer(t *testing.T, mr *miniredis.Miniredis, store *Store, clock *testClock, createLimit, lockThreshold int, lockWindow time.Duration) *httptest.Server {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	var limits Limits
	if createLimit > 0 {
		limits.ChallengeCreate = ratex.NewRedis(client, createLimit, time.Minute, "rate:authr:challenge", log)
	}
	if lockThreshold > 0 {
		limits.Lockout = NewRedisLockout(lockThreshold, lockWindow, client, "rate:authr:lockout", log, clock.now)
	}
	srv := httptest.NewServer(Router(log, store, NewRegistry(log), limits))
	t.Cleanup(srv.Close)
	return srv
}

// TestChallengeCreateRateLimitedRedis pins the CHALLENGE_RATE_LIMIT control
// through the handler with a real RedisLimiter: the N+1th create for the same
// tenant|user is a structured 429 + Retry-After, and the budget resets once
// the fixed window's TTL expires.
func TestChallengeCreateRateLimitedRedis(t *testing.T) {
	mr := miniredis.RunT(t)
	clock := &testClock{t: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)}
	store := NewStore(clock.now)
	srv := newRedisLimitedServer(t, mr, store, clock, 2, 0, 0)
	enroll(t, srv, "u1", MethodTOTP)

	for i := 1; i <= 2; i++ {
		resp := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
			UserID: "u1", Methods: []string{MethodTOTP},
		})
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %d: want 201, got %d", i, resp.StatusCode)
		}
	}

	// N+1th create → 429 rate_limited + Retry-After.
	resp := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{MethodTOTP},
	})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over-limit create: want 429, got %d", resp.StatusCode)
	}
	assertRetryAfter(t, resp)
	var body errorBody
	decode(t, resp, &body)
	if body.Error != "rate_limited" {
		t.Fatalf("want error=rate_limited, got %q", body.Error)
	}

	// The fixed window ages on Redis TTLs (miniredis: FastForward).
	mr.FastForward(61 * time.Second)
	again := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{MethodTOTP},
	})
	again.Body.Close()
	if again.StatusCode != http.StatusCreated {
		t.Fatalf("post-window create: want 201, got %d", again.StatusCode)
	}
}

// TestChallengeRateLimitSharedAcrossReplicas pins the distributed property:
// two Limits built over the SAME Redis (≈ two replicas) share the per-user
// counter — exhausting the budget through replica A makes replica B deny.
func TestChallengeRateLimitSharedAcrossReplicas(t *testing.T) {
	mr := miniredis.RunT(t)
	clock := &testClock{t: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)}
	store := NewStore(clock.now) // replicas share storage, like PG in prod
	replicaA := newRedisLimitedServer(t, mr, store, clock, 2, 0, 0)
	replicaB := newRedisLimitedServer(t, mr, store, clock, 2, 0, 0)
	enroll(t, replicaA, "u1", MethodTOTP)

	// Exhaust the budget entirely through replica A.
	for i := 1; i <= 2; i++ {
		resp := do(t, replicaA, http.MethodPost, "/v1/challenges", ChallengeRequest{
			UserID: "u1", Methods: []string{MethodTOTP},
		})
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("replica A create %d: want 201, got %d", i, resp.StatusCode)
		}
	}

	// Replica B's FIRST create for the same user must be denied — with the
	// in-memory limiter it would have its own untouched budget.
	resp := do(t, replicaB, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{MethodTOTP},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("replica B must share the counter: want 429, got %d", resp.StatusCode)
	}
	var body errorBody
	decode(t, resp, &body)
	if body.Error != "rate_limited" {
		t.Fatalf("want error=rate_limited, got %q", body.Error)
	}
}

// TestAccountLockoutRedis pins the LOCKOUT_THRESHOLD control with Redis-backed
// failure counting: the threshold-th failed verification trips the lock, after
// which creation and verification both answer 423 account_locked.
func TestAccountLockoutRedis(t *testing.T) {
	mr := miniredis.RunT(t)
	clock := &testClock{t: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)}
	store := NewStore(clock.now)
	srv := newRedisLimitedServer(t, mr, store, clock, 0, 2, 15*time.Minute)
	enroll(t, srv, "u1", MethodTOTP)

	mkChallenge := func() string {
		t.Helper()
		resp := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
			UserID: "u1", Methods: []string{MethodTOTP},
		})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create: want 201, got %d", resp.StatusCode)
		}
		var disp ChallengeDispatched
		decode(t, resp, &disp)
		return disp.ChallengeID
	}
	chal := mkChallenge()

	// Two failed verifications (clock stepped past the per-challenge backoff
	// in between) — the second trips the Redis-counted lockout.
	for i := 1; i <= 2; i++ {
		resp := do(t, srv, http.MethodPost, "/v1/challenges/"+chal+"/verify", VerifyRequest{
			Response: map[string]any{"code": "wrong"},
		})
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("failure %d: want 401, got %d", i, resp.StatusCode)
		}
		clock.advance(time.Duration(1<<uint(i))*time.Second + time.Second)
	}

	assertLocked423(t, "create while locked", do(t, srv, http.MethodPost, "/v1/challenges",
		ChallengeRequest{UserID: "u1", Methods: []string{MethodTOTP}}))
	assertLocked423(t, "verify while locked", do(t, srv, http.MethodPost,
		"/v1/challenges/"+chal+"/verify", VerifyRequest{Response: map[string]any{"code": "000000"}}))
}

// TestAccountLockoutCountingSharedAcrossReplicas pins the documented
// cross-replica semantics: failure COUNTING is shared through Redis (replica
// B's first local failure is the fleet's second and trips B's lock), while
// the lockedUntil map stays per-replica (A is not locked until A itself
// records a counted failure).
func TestAccountLockoutCountingSharedAcrossReplicas(t *testing.T) {
	mr := miniredis.RunT(t)
	clock := &testClock{t: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)}
	store := NewStore(clock.now) // shared storage: both replicas see all challenges
	replicaA := newRedisLimitedServer(t, mr, store, clock, 0, 2, 15*time.Minute)
	replicaB := newRedisLimitedServer(t, mr, store, clock, 0, 2, 15*time.Minute)
	enroll(t, replicaA, "u1", MethodTOTP)

	mkChallenge := func(srv *httptest.Server) string {
		t.Helper()
		resp := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
			UserID: "u1", Methods: []string{MethodTOTP},
		})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create: want 201, got %d", resp.StatusCode)
		}
		var disp ChallengeDispatched
		decode(t, resp, &disp)
		return disp.ChallengeID
	}
	failVerify := func(srv *httptest.Server, chal, label string) {
		t.Helper()
		resp := do(t, srv, http.MethodPost, "/v1/challenges/"+chal+"/verify", VerifyRequest{
			Response: map[string]any{"code": "wrong"},
		})
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: want 401, got %d", label, resp.StatusCode)
		}
	}

	// Distinct challenges per replica so the per-challenge backoff (which is
	// persisted state, shared via the store) never interferes.
	chalA := mkChallenge(replicaA)
	chalB := mkChallenge(replicaB)

	// Failure 1 on A (counter → 1, under threshold-1=1): nobody locks.
	failVerify(replicaA, chalA, "failure 1 via A")
	// Failure 2 on B (counter → 2, over): B locks u1 LOCALLY.
	failVerify(replicaB, chalB, "failure 2 via B")

	assertLocked423(t, "replica B create after shared threshold", do(t, replicaB,
		http.MethodPost, "/v1/challenges", ChallengeRequest{UserID: "u1", Methods: []string{MethodTOTP}}))

	// The lockedUntil map is per-replica: A has not recorded an over-threshold
	// failure yet, so A still serves u1 — the documented convergence nuance.
	chalA2Resp := do(t, replicaA, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{MethodTOTP},
	})
	if chalA2Resp.StatusCode != http.StatusCreated {
		t.Fatalf("replica A before converging: want 201 (per-replica lockedUntil), got %d", chalA2Resp.StatusCode)
	}
	var chalA2 ChallengeDispatched
	decode(t, chalA2Resp, &chalA2)

	// A's next counted failure (counter → 3, over) converges A onto its own
	// local lock within the same window.
	failVerify(replicaA, chalA2.ChallengeID, "failure 3 via A")
	assertLocked423(t, "replica A create after converging", do(t, replicaA,
		http.MethodPost, "/v1/challenges", ChallengeRequest{UserID: "u1", Methods: []string{MethodTOTP}}))
}

// assertLocked423 checks a 423 account_locked response with Retry-After.
func assertLocked423(t *testing.T, label string, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != http.StatusLocked {
		t.Fatalf("%s: want 423, got %d", label, resp.StatusCode)
	}
	assertRetryAfter(t, resp)
	var body errorBody
	decode(t, resp, &body)
	if body.Error != "account_locked" {
		t.Fatalf("%s: want error=account_locked, got %q", label, body.Error)
	}
}
