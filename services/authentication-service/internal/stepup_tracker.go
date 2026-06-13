package internal

import (
	"sort"
	"sync"
	"time"
)

// stepup_tracker.go gives the consoles visibility into who is CURRENTLY mid
// step-up on an /authorize call. The OTP interlude (otp.go) parks the authorize
// request in process memory keyed by a one-time flow id; this tracker mirrors
// the live subset needed for display — tenant, user, method, start time — so
// the session-management views can answer "which X-Auth user is attempting
// step-up right now" without reaching into the OIDC handler's private flow map.
//
// In-process and single-replica, exactly like the parked flows it shadows.
// Entries are dropped when the flow finishes (OIDCHandlers.dropFlow) or, as a
// backstop, once they age past the TTL (the parked flow's own lifetime).

// StepUpAttempt is one in-progress step-up, as surfaced to the consoles.
type StepUpAttempt struct {
	FlowID    string
	TenantID  string
	UserID    string
	Method    string // authenticator method, e.g. "sms"
	StartedAt time.Time
}

// StepUpTracker is a thread-safe registry of live step-up attempts.
type StepUpTracker struct {
	mu  sync.Mutex
	m   map[string]StepUpAttempt
	ttl time.Duration
}

// NewStepUpTracker returns a tracker whose entries self-expire after ttl (use
// the same value as the parked-flow TTL).
func NewStepUpTracker(ttl time.Duration) *StepUpTracker {
	return &StepUpTracker{m: make(map[string]StepUpAttempt), ttl: ttl}
}

// Start records a newly parked step-up. No-op on a nil tracker so tests and
// callers that don't wire one stay simple.
func (t *StepUpTracker) Start(a StepUpAttempt) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gcLocked()
	t.m[a.FlowID] = a
}

// Done removes a finished (verified, failed, or abandoned) attempt.
func (t *StepUpTracker) Done(flowID string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, flowID)
}

// ListByTenant returns the live attempts for tenantID, newest first.
func (t *StepUpTracker) ListByTenant(tenantID string) []StepUpAttempt {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gcLocked()
	out := make([]StepUpAttempt, 0)
	for _, a := range t.m {
		if a.TenantID == tenantID {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out
}

// gcLocked drops aged-out entries. Caller holds t.mu.
func (t *StepUpTracker) gcLocked() {
	cutoff := time.Now().UTC().Add(-t.ttl)
	for id, a := range t.m {
		if a.StartedAt.Before(cutoff) {
			delete(t.m, id)
		}
	}
}
