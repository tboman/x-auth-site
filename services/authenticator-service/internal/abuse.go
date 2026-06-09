package internal

// ARCHITECTURE.md §10.5 layer 3 — authenticator-service abuse prevention:
//
//	├── Per-user challenge rate limit            (Limits.ChallengeCreate)
//	├── Max attempts per challenge (3)           (MaxChallengeAttempts, models.go)
//	├── Exponential backoff on failed verifies   (backoffRemaining)
//	└── Account lockout after N failures         (Lockout)
//
// The rate limit and the lockout are built on pkg/ratex sliding-window
// limiters keyed "tenant|user_id". Like ratex itself, all state here is
// in-memory and PER REPLICA: each process enforces its own window, which is
// the phase-2.1 stance until shared Redis lands. The backoff control is the
// exception — it derives entirely from persisted challenge fields (attempts +
// last_attempt_at), so it holds across replicas and restarts.

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/ratex"
)

// Limits bundles the §10.5 layer-3 knobs threaded from cmd/main.go into the
// challenge handlers. The zero value disables both controls (unit tests, and
// both env vars set to "off"). Enforcement lives inside the handlers — not on
// a route-tree middleware — because the /v1 and /internal/v1 mounts share the
// same handler instances, so one check covers both trees, and the key needs
// the user_id from the request body anyway.
type Limits struct {
	// ChallengeCreate limits challenge CREATION per tenant|user key
	// (CHALLENGE_RATE_LIMIT, default "10/1m"). nil disables.
	ChallengeCreate *ratex.Limiter

	// Lockout tracks FAILED verifications per tenant|user key across
	// challenges (LOCKOUT_THRESHOLD, default "5/15m"). nil disables.
	Lockout *Lockout
}

// abuseKey is the per-user limiter key shared by the challenge-creation
// limiter and the lockout tracker.
func abuseKey(tenantID, userID string) string { return tenantID + "|" + userID }

// -----------------------------------------------------------------------------
// Account lockout
// -----------------------------------------------------------------------------

// Lockout implements "account lockout after N consecutive failures": once a
// tenant|user key accumulates `threshold` failed verifications inside the
// sliding window, both challenge creation and verification answer
// 423 `account_locked` until the window slides past the oldest counted
// failure.
//
// Counting is delegated to a ratex.Limiter sized threshold-1: the Allow call
// that comes back over-limit IS the threshold-th failure, and its retryAfter
// (time until the oldest counted failure leaves the window) becomes the lock
// duration. Locked-out requests are rejected before any adapter work, so they
// never extend the lock.
//
// "Consecutive" is approximated by the sliding window: a successful verify
// does not reset the counter (ratex cannot remove events), but failures age
// out of the window naturally. Per-replica, like every ratex-backed control.
type Lockout struct {
	window   time.Duration
	failures *ratex.Limiter // nil when threshold == 1 (every failure locks)
	now      func() time.Time

	mu          sync.Mutex
	lockedUntil map[string]time.Time
}

// NewLockout builds a Lockout tripping after threshold failures per window.
// now is the clock (nil = wall clock; tests inject a fake). threshold <= 0 or
// window <= 0 returns nil — a nil *Lockout is a valid, disabled tracker.
func NewLockout(threshold int, window time.Duration, now func() time.Time) *Lockout {
	if threshold <= 0 || window <= 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	l := &Lockout{
		window:      window,
		now:         now,
		lockedUntil: make(map[string]time.Time),
	}
	if threshold > 1 {
		l.failures = ratex.New(threshold-1, window)
		l.failures.Now = now
	}
	return l
}

// RecordFailure registers one failed verification for key. When this failure
// is the threshold-th inside the window, the key is locked until the window
// slides past the oldest counted failure.
func (l *Lockout) RecordFailure(key string) {
	if l == nil {
		return
	}
	if l.failures == nil {
		// threshold == 1: every failure locks for the full window.
		l.lock(key, l.window)
		return
	}
	if ok, retryAfter := l.failures.Allow(key); !ok {
		l.lock(key, retryAfter)
	}
}

func (l *Lockout) lock(key string, d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lockedUntil[key] = l.now().Add(d)
}

// Locked reports whether key is currently locked out and, if so, how long
// until the lock expires (for the Retry-After header). Expired entries are
// pruned lazily on lookup. A nil *Lockout is never locked.
func (l *Lockout) Locked(key string) (bool, time.Duration) {
	if l == nil {
		return false, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.lockedUntil[key]
	if !ok {
		return false, 0
	}
	now := l.now()
	if now.Before(until) {
		return true, until.Sub(now)
	}
	delete(l.lockedUntil, key)
	return false, 0
}

// -----------------------------------------------------------------------------
// Exponential backoff on failed verifications
// -----------------------------------------------------------------------------

// maxBackoffShift caps the exponent defensively. With MaxChallengeAttempts=3
// the verify flow can never exceed shift 3, but a hand-seeded challenge row
// must not overflow the Duration math.
const maxBackoffShift = 30

// backoffRemaining returns how much longer the challenge may not be retried:
// after a failed verification the next attempt is allowed 2^attempts seconds
// after the last failed attempt (2s after the 1st failure, 4s after the 2nd).
// Zero means no backoff applies (no failures yet, or the window elapsed).
// Derived purely from persisted fields, so it survives restarts and is
// consistent across replicas.
func backoffRemaining(c Challenge, now time.Time) time.Duration {
	if c.Attempts <= 0 || c.LastAttemptAt == nil {
		return 0
	}
	shift := c.Attempts
	if shift > maxBackoffShift {
		shift = maxBackoffShift
	}
	next := c.LastAttemptAt.Add(time.Duration(1<<uint(shift)) * time.Second)
	if now.Before(next) {
		return next.Sub(now)
	}
	return 0
}

// -----------------------------------------------------------------------------
// Structured error writers
// -----------------------------------------------------------------------------

// retryAfterSeconds renders a duration for the Retry-After header: whole
// seconds, rounded up, minimum 1 (0 confuses clients).
func retryAfterSeconds(d time.Duration) int {
	secs := int(d / time.Second)
	if d%time.Second != 0 || secs < 1 {
		secs++
	}
	return secs
}

// writeRetryAfterError emits a structured error body plus a Retry-After
// header — the §10.5 shape for both 429s and the 423 lockout.
func writeRetryAfterError(w http.ResponseWriter, status int, code, msg string, retryAfter time.Duration) {
	secs := retryAfterSeconds(retryAfter)
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	httpx.WriteError(w, status, code, msg+"; retry after "+strconv.Itoa(secs)+"s")
}

// writeAccountLocked is the shared 423 `account_locked` response for both
// challenge creation and verification once the lockout has tripped.
func writeAccountLocked(w http.ResponseWriter, retryAfter time.Duration) {
	writeRetryAfterError(w, http.StatusLocked, "account_locked",
		"account temporarily locked after repeated failed verifications", retryAfter)
}
