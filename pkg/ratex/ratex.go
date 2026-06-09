// Package ratex is a small in-process sliding-window rate limiter for the
// ARCHITECTURE.md §10.5 abuse-prevention layers (per-tenant/per-endpoint in
// transaction-service, per-user challenge limits in authenticator-service).
//
// State is in-memory and per-replica: limits are enforced per process, which
// is the phase-2.1 stance. When shared Redis lands, this package keeps its
// interface and gains a Redis-backed store; callers don't change.
package ratex

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// Limiter enforces "at most Limit events per Window per key" using a sliding
// window log. Safe for concurrent use.
type Limiter struct {
	limit  int
	window time.Duration

	mu   sync.Mutex
	hits map[string][]time.Time
	// calls counts Allow invocations to amortize the idle-key sweep.
	calls int

	// Now is overridable from tests.
	Now func() time.Time
}

// sweepEvery is how many Allow calls pass between full idle-key sweeps. The
// per-key slice is pruned on every call; the periodic sweep only exists to
// drop keys that stopped sending entirely.
const sweepEvery = 4096

// New builds a Limiter allowing limit events per window per key.
// limit <= 0 disables the limiter: Allow always succeeds.
func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		limit:  limit,
		window: window,
		hits:   make(map[string][]time.Time),
		Now:    func() time.Time { return time.Now() },
	}
}

// Allow records an event for key and reports whether it is within the limit.
// When the limit is exceeded, retryAfter is how long until the oldest counted
// event leaves the window — suitable for a Retry-After header.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	if l == nil || l.limit <= 0 {
		return true, 0
	}
	now := l.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	l.calls++
	if l.calls%sweepEvery == 0 {
		l.sweepLocked(cutoff)
	}

	window := l.hits[key]
	// Prune entries that fell out of the window.
	keep := 0
	for _, t := range window {
		if t.After(cutoff) {
			window[keep] = t
			keep++
		}
	}
	window = window[:keep]

	if len(window) >= l.limit {
		l.hits[key] = window
		return false, window[0].Sub(cutoff)
	}
	l.hits[key] = append(window, now)
	return true, 0
}

func (l *Limiter) sweepLocked(cutoff time.Time) {
	for key, window := range l.hits {
		live := false
		for _, t := range window {
			if t.After(cutoff) {
				live = true
				break
			}
		}
		if !live {
			delete(l.hits, key)
		}
	}
}

// Middleware wraps next with the limiter, keyed by keyFn. Over-limit requests
// get a structured 429 with a Retry-After header (§10.5). A keyFn returning ""
// bypasses the limiter for that request.
func Middleware(l *Limiter, keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}
			if ok, retryAfter := l.Allow(key); !ok {
				secs := int(retryAfter.Seconds()) + 1 // round up; 0 confuses clients
				w.Header().Set("Retry-After", strconv.Itoa(secs))
				httpx.WriteError(w, http.StatusTooManyRequests, "rate_limited",
					"rate limit exceeded; retry after "+strconv.Itoa(secs)+"s")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ParseRate parses "N/duration" (e.g. "100/1m", "10/30s") into (limit,
// window) for env-driven configuration.
func ParseRate(s string) (int, time.Duration, error) {
	var n int
	var rest string
	if _, err := fmt.Sscanf(s, "%d/%s", &n, &rest); err != nil {
		return 0, 0, fmt.Errorf("ratex: %q is not N/duration: %w", s, err)
	}
	d, err := time.ParseDuration(rest)
	if err != nil {
		return 0, 0, fmt.Errorf("ratex: %q window: %w", s, err)
	}
	if n <= 0 || d <= 0 {
		return 0, 0, fmt.Errorf("ratex: %q must be positive", s)
	}
	return n, d, nil
}
