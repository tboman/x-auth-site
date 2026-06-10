package internal

// Tests for the §10.5 layer-3 abuse-prevention controls: the per-user
// challenge-creation rate limit, the exponential backoff on failed
// verifications, and the cross-challenge account lockout. (The fourth
// control, max attempts per challenge, is pinned in handlers_test.go.)

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/ratex"
)

// errorBody is the structured error envelope httpx.WriteError emits.
type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// assertRetryAfter checks the Retry-After header is present and positive,
// returning its value in seconds.
func assertRetryAfter(t *testing.T, resp *http.Response) int {
	t.Helper()
	h := resp.Header.Get("Retry-After")
	if h == "" {
		t.Fatalf("want a Retry-After header on %d response", resp.StatusCode)
	}
	secs, err := strconv.Atoi(h)
	if err != nil || secs < 1 {
		t.Fatalf("Retry-After must be a positive integer, got %q", h)
	}
	return secs
}

// -----------------------------------------------------------------------------
// Per-user challenge-creation rate limit
// -----------------------------------------------------------------------------

// TestChallengeCreateRateLimited pins the CHALLENGE_RATE_LIMIT control: the
// N+1th create for the same tenant|user inside the window is a structured 429
// with Retry-After; a different user is unaffected; the window slides.
func TestChallengeCreateRateLimited(t *testing.T) {
	srv, _, clock := newTestServerWithLimits(t, func(now func() time.Time) Limits {
		lim := ratex.New(2, time.Minute)
		lim.Now = now
		return Limits{ChallengeCreate: lim}
	})
	enroll(t, srv, "u1", MethodTOTP)
	enroll(t, srv, "u2", MethodTOTP)

	// First N creates for u1 pass.
	for i := 1; i <= 2; i++ {
		resp := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
			UserID: "u1", Methods: []string{MethodTOTP},
		})
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %d: want 201, got %d", i, resp.StatusCode)
		}
	}

	// N+1th create for u1 → 429 rate_limited + Retry-After.
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

	// A different user under the same tenant is unaffected.
	other := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u2", Methods: []string{MethodTOTP},
	})
	other.Body.Close()
	if other.StatusCode != http.StatusCreated {
		t.Fatalf("other user: want 201, got %d", other.StatusCode)
	}

	// Once the window slides, u1 may create again.
	clock.advance(time.Minute + time.Second)
	again := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{MethodTOTP},
	})
	again.Body.Close()
	if again.StatusCode != http.StatusCreated {
		t.Fatalf("post-window create: want 201, got %d", again.StatusCode)
	}
}

// TestChallengeCreateRateLimitCoversInternalAlias pins that the limiter is
// enforced inside the shared handler, so creates through /v1 and
// /internal/v1 draw from the SAME per-user window — mounting the limit on
// only one tree would leave the other unmetered.
func TestChallengeCreateRateLimitCoversInternalAlias(t *testing.T) {
	t.Setenv(httpx.EnvInternalAuthSecret, "") // dev mode: internal gate open
	srv, _, _ := newTestServerWithLimits(t, func(now func() time.Time) Limits {
		lim := ratex.New(1, time.Minute)
		lim.Now = now
		return Limits{ChallengeCreate: lim}
	})
	enroll(t, srv, "u1", MethodTOTP)

	resp := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{MethodTOTP},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("public create: want 201, got %d", resp.StatusCode)
	}

	aliased := do(t, srv, http.MethodPost, "/internal/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{MethodTOTP},
	})
	defer aliased.Body.Close()
	if aliased.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("internal-alias create must share the window: want 429, got %d", aliased.StatusCode)
	}
}

// TestLimitsDisabledNilSafety pins the zero/disabled paths now that
// Limits.ChallengeCreate is the ratex.Allower INTERFACE: a nil interface
// (control disabled) must never be invoked — calling a method on a nil
// interface panics — and a typed nil stored in the interface (the classic
// typed-nil-in-interface trap: it compares != nil) must still behave as
// "always allow" through the implementations' nil-receiver-safe Allow.
func TestLimitsDisabledNilSafety(t *testing.T) {
	cases := []struct {
		name   string
		limits Limits
	}{
		{"zero-value Limits (nil interface)", Limits{}},
		{"typed-nil in-memory limiter", Limits{ChallengeCreate: (*ratex.Limiter)(nil)}},
		{"typed-nil redis limiter", Limits{ChallengeCreate: (*ratex.RedisLimiter)(nil)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := newTestServerWithLimits(t, func(func() time.Time) Limits { return tc.limits })
			enroll(t, srv, "u1", MethodTOTP)
			// Well past the default 10/1m budget — every create must pass.
			for i := 1; i <= 12; i++ {
				resp := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
					UserID: "u1", Methods: []string{MethodTOTP},
				})
				resp.Body.Close()
				if resp.StatusCode != http.StatusCreated {
					t.Fatalf("create %d with disabled limits: want 201, got %d", i, resp.StatusCode)
				}
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Exponential backoff on failed verifications
// -----------------------------------------------------------------------------

// TestVerifyExponentialBackoff pins the backoff contract: after a failed
// verify, a premature retry is a 429 retry_backoff with Retry-After and does
// NOT consume an attempt; once 2^attempts seconds have elapsed the retry is
// processed. The delay doubles per failure (2s, then 4s).
func TestVerifyExponentialBackoff(t *testing.T) {
	srv, _, clock := newTestServer(t)
	id := createChallenge(t, srv, MethodTOTP)

	failVerify := func(label string) {
		t.Helper()
		resp := do(t, srv, http.MethodPost, "/v1/challenges/"+id+"/verify", VerifyRequest{
			Response: map[string]any{"code": "wrong"},
		})
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: want 401, got %d", label, resp.StatusCode)
		}
	}
	attemptsNow := func() int {
		t.Helper()
		resp := do(t, srv, http.MethodGet, "/v1/challenges/"+id, nil)
		var c Challenge
		decode(t, resp, &c)
		return c.Attempts
	}

	// 1st failure → 2s backoff.
	failVerify("failure 1")

	// Immediate retry (even with the CORRECT code) → 429, attempt not consumed.
	premature := do(t, srv, http.MethodPost, "/v1/challenges/"+id+"/verify", VerifyRequest{
		Response: map[string]any{"code": "000000"},
	})
	if premature.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("premature retry: want 429, got %d", premature.StatusCode)
	}
	if secs := assertRetryAfter(t, premature); secs != 2 {
		t.Fatalf("want Retry-After=2 after 1st failure, got %d", secs)
	}
	var body errorBody
	decode(t, premature, &body)
	if body.Error != "retry_backoff" {
		t.Fatalf("want error=retry_backoff, got %q", body.Error)
	}
	if got := attemptsNow(); got != 1 {
		t.Fatalf("premature retry must not consume an attempt: want 1, got %d", got)
	}

	// After the 2s window the retry is processed — this one fails too.
	clock.advance(2 * time.Second)
	failVerify("failure 2")
	if got := attemptsNow(); got != 2 {
		t.Fatalf("want attempts=2 after second processed failure, got %d", got)
	}

	// 2nd failure → 4s backoff: 3s in is still too soon...
	clock.advance(3 * time.Second)
	tooSoon := do(t, srv, http.MethodPost, "/v1/challenges/"+id+"/verify", VerifyRequest{
		Response: map[string]any{"code": "000000"},
	})
	tooSoon.Body.Close()
	if tooSoon.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("3s into a 4s backoff: want 429, got %d", tooSoon.StatusCode)
	}
	if got := attemptsNow(); got != 2 {
		t.Fatalf("backoff retry consumed an attempt: want 2, got %d", got)
	}

	// ...but at 4s the verify goes through and can succeed.
	clock.advance(time.Second)
	ok := do(t, srv, http.MethodPost, "/v1/challenges/"+id+"/verify", VerifyRequest{
		Response: map[string]any{"code": "000000"},
	})
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("post-backoff verify: want 200, got %d", ok.StatusCode)
	}
	var vr VerifyResponse
	decode(t, ok, &vr)
	if !vr.Verified {
		t.Fatal("want verified=true after backoff elapsed")
	}
}

// -----------------------------------------------------------------------------
// Account lockout
// -----------------------------------------------------------------------------

// TestAccountLockout pins the LOCKOUT_THRESHOLD control: once a tenant|user
// accumulates the threshold of failed verifications across challenges, both
// challenge creation and verification answer 423 account_locked until the
// window slides; other users are unaffected.
func TestAccountLockout(t *testing.T) {
	const window = 15 * time.Minute
	srv, _, clock := newTestServerWithLimits(t, func(now func() time.Time) Limits {
		return Limits{Lockout: NewLockout(2, window, now)} // 2 failures lock
	})

	enroll(t, srv, "u1", MethodTOTP)
	enroll(t, srv, "u2", MethodTOTP)

	mkChallenge := func(user string) string {
		t.Helper()
		resp := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
			UserID: user, Methods: []string{MethodTOTP},
		})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create for %s: want 201, got %d", user, resp.StatusCode)
		}
		var disp ChallengeDispatched
		decode(t, resp, &disp)
		return disp.ChallengeID
	}
	u1Chal := mkChallenge("u1")
	u2Chal := mkChallenge("u2")

	// Two failed verifications for u1 (clock stepped past the per-challenge
	// backoff in between) — the second one trips the lockout.
	for i := 1; i <= 2; i++ {
		resp := do(t, srv, http.MethodPost, "/v1/challenges/"+u1Chal+"/verify", VerifyRequest{
			Response: map[string]any{"code": "wrong"},
		})
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("u1 failure %d: want 401, got %d", i, resp.StatusCode)
		}
		clock.advance(time.Duration(1<<uint(i))*time.Second + time.Second)
	}

	assertLocked := func(label string, resp *http.Response) {
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

	// Locked: creation AND verification both 423 for u1.
	assertLocked("u1 create while locked", do(t, srv, http.MethodPost, "/v1/challenges",
		ChallengeRequest{UserID: "u1", Methods: []string{MethodTOTP}}))
	assertLocked("u1 verify while locked", do(t, srv, http.MethodPost,
		"/v1/challenges/"+u1Chal+"/verify", VerifyRequest{Response: map[string]any{"code": "000000"}}))

	// u2 is untouched: can create and verify normally.
	u2Extra := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u2", Methods: []string{MethodTOTP},
	})
	u2Extra.Body.Close()
	if u2Extra.StatusCode != http.StatusCreated {
		t.Fatalf("u2 create during u1 lockout: want 201, got %d", u2Extra.StatusCode)
	}
	u2Verify := do(t, srv, http.MethodPost, "/v1/challenges/"+u2Chal+"/verify", VerifyRequest{
		Response: map[string]any{"code": "000000"},
	})
	u2Verify.Body.Close()
	if u2Verify.StatusCode != http.StatusOK {
		t.Fatalf("u2 verify during u1 lockout: want 200, got %d", u2Verify.StatusCode)
	}

	// Once the failure window slides past, u1 is unlocked again.
	clock.advance(window + time.Second)
	unlocked := do(t, srv, http.MethodPost, "/v1/challenges", ChallengeRequest{
		UserID: "u1", Methods: []string{MethodTOTP},
	})
	unlocked.Body.Close()
	if unlocked.StatusCode != http.StatusCreated {
		t.Fatalf("u1 create after lock expiry: want 201, got %d", unlocked.StatusCode)
	}
}

// TestLockoutDirect exercises the Lockout tracker without HTTP: threshold
// semantics (the Nth failure locks), nil-safety, lock expiry, and the
// threshold==1 special case.
func TestLockoutDirect(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)}

	t.Run("nil tracker never locks", func(t *testing.T) {
		var l *Lockout
		l.RecordFailure("k") // must not panic
		if locked, _ := l.Locked("k"); locked {
			t.Fatal("nil Lockout must never report locked")
		}
	})

	t.Run("locks on the threshold-th failure and expires", func(t *testing.T) {
		l := NewLockout(3, time.Minute, clock.now)
		l.RecordFailure("k")
		l.RecordFailure("k")
		if locked, _ := l.Locked("k"); locked {
			t.Fatal("2 of 3 failures must not lock")
		}
		l.RecordFailure("k")
		locked, retryAfter := l.Locked("k")
		if !locked {
			t.Fatal("3rd failure must lock")
		}
		if retryAfter <= 0 || retryAfter > time.Minute {
			t.Fatalf("retryAfter out of range: %v", retryAfter)
		}
		if locked, _ := l.Locked("other"); locked {
			t.Fatal("other keys must be unaffected")
		}
		clock.advance(time.Minute + time.Second)
		if locked, _ := l.Locked("k"); locked {
			t.Fatal("lock must expire once the window slides")
		}
	})

	t.Run("threshold 1 locks on first failure", func(t *testing.T) {
		l := NewLockout(1, time.Minute, clock.now)
		l.RecordFailure("k")
		if locked, _ := l.Locked("k"); !locked {
			t.Fatal("threshold 1 must lock immediately")
		}
	})

	t.Run("invalid config disables", func(t *testing.T) {
		if NewLockout(0, time.Minute, clock.now) != nil {
			t.Fatal("threshold 0 must return a nil (disabled) tracker")
		}
		if NewLockout(5, 0, clock.now) != nil {
			t.Fatal("zero window must return a nil (disabled) tracker")
		}
	})
}
