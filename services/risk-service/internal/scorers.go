package internal

import (
	"context"
	"strings"
	"time"
)

// Clock is injected so scorer unit tests can control "now". The aggregator and
// handlers hold a Clock value; production wiring uses SystemClock.
type Clock interface {
	Now() time.Time
}

// SystemClock is the production Clock, returning time.Now in UTC.
type SystemClock struct{}

// Now returns the current UTC time.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// fixedClock is a tiny helper the tests use. Kept unexported — real code uses
// SystemClock.
type fixedClock struct{ T time.Time }

func (f fixedClock) Now() time.Time { return f.T }

// Scorer is the shape of a phase-1 scorer. Each scorer is a pure function of
// the request plus read-only storage (so the user scorer can ask "has this
// user been seen before?") — no mutation, no external I/O. Context is passed
// through for cancellation/tracing.
//
// Phase 1 deliberately keeps the signatures identical so the aggregator can
// iterate over a []Scorer slice without type-switching. Phase 2 will likely
// need per-scorer configuration (e.g. device reputation DB handle); a
// Dependencies struct will replace the bare Storage interface at that point.
type Scorer func(ctx context.Context, req EvaluateRequest, tenantID string, store Storage, clock Clock) ScorerResult

// DeviceScorer rules:
//
//   - missing fingerprint     → base 0.2 + 0.3 = 0.5, flag "no_fingerprint"
//   - fingerprint starts with "fp_known_" → base 0.2 (recognised device)
//   - any other fingerprint   → 0.5, flag "unknown_device"
//
// The "recognised" check is deliberately a prefix match so tests can exercise
// multiple recognised devices (fp_known_abc, fp_known_xyz) without a live DB.
func DeviceScorer(_ context.Context, req EvaluateRequest, _ string, _ Storage, _ Clock) ScorerResult {
	fp := strings.TrimSpace(req.Context.DeviceFingerprint)
	if fp == "" {
		return ScorerResult{Score: 0.5, Flags: []string{"no_fingerprint"}}
	}
	if strings.HasPrefix(fp, "fp_known_") {
		return ScorerResult{Score: 0.2, Flags: []string{}}
	}
	return ScorerResult{Score: 0.5, Flags: []string{"unknown_device"}}
}

// BehaviorScorer rules:
//
//   - base 0.1
//   - server-local hour < 6 or > 22 → +0.5, flag "unusual_time"
//   - high-velocity heuristic       → +0.3, flag "high_velocity" (stubbed false in phase 1)
//
// The velocity branch is intentionally a dead path for phase 1 — behavioral
// drift detection needs a baseline model that doesn't exist yet. Leaving the
// branch here (and in the test matrix) keeps the shape obvious for phase 2.
func BehaviorScorer(_ context.Context, _ EvaluateRequest, _ string, _ Storage, clock Clock) ScorerResult {
	score := 0.1
	flags := []string{}

	hour := clock.Now().Hour()
	if hour < 6 || hour > 22 {
		score += 0.5
		flags = append(flags, "unusual_time")
	}

	if highVelocityStub() {
		score += 0.3
		flags = append(flags, "high_velocity")
	}

	return ScorerResult{Score: clamp01(score), Flags: flags}
}

// highVelocityStub returns false in phase 1. Kept as a named function so the
// phase-2 replacement is an obvious one-line swap.
func highVelocityStub() bool { return false }

// NetworkScorer rules:
//
//   - base 0.1
//   - ip_address starts with "203.0.113."     → +0.4, flag "flagged_ip"    (mock blocklist)
//   - ip_address ends with   ".100"            → +0.3, flag "vpn_detected"  (mock VPN range)
//
// Both flags can fire on the same IP (e.g. 203.0.113.100 → both). The TEST-NET-3
// prefix is chosen deliberately — RFC 5737 documentation range, safe to hard-code.
func NetworkScorer(_ context.Context, req EvaluateRequest, _ string, _ Storage, _ Clock) ScorerResult {
	score := 0.1
	flags := []string{}

	ip := strings.TrimSpace(req.Context.IPAddress)
	if strings.HasPrefix(ip, "203.0.113.") {
		score += 0.4
		flags = append(flags, "flagged_ip")
	}
	if strings.HasSuffix(ip, ".100") {
		score += 0.3
		flags = append(flags, "vpn_detected")
	}

	return ScorerResult{Score: clamp01(score), Flags: flags}
}

// UserScorer rules:
//
//   - base 0.2
//   - action contains "transfer." or "payment." AND no prior evaluations exist
//     for (tenant, user) → +0.3, flag "first_high_value_action"
//
// The "no prior evaluations" check is a phase-1 stand-in for "new account";
// phase 2 will join against authentication-service's user table for actual
// account age.
func UserScorer(_ context.Context, req EvaluateRequest, tenantID string, store Storage, _ Clock) ScorerResult {
	score := 0.2
	flags := []string{}

	if isHighValueAction(req.Action) {
		if tenantID != "" && req.UserID != "" && !store.UserHasPriorEvaluation(tenantID, req.UserID) {
			score += 0.3
			flags = append(flags, "first_high_value_action")
		}
	}

	return ScorerResult{Score: clamp01(score), Flags: flags}
}

// isHighValueAction encodes the phase-1 rule: any action containing the
// "transfer." or "payment." namespace is treated as high-value.
func isHighValueAction(action string) bool {
	a := strings.ToLower(action)
	return strings.Contains(a, "transfer.") || strings.Contains(a, "payment.")
}

// clamp01 squeezes x into [0, 1]. Used everywhere to keep scorer outputs
// well-formed regardless of how many flags fire.
func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}
