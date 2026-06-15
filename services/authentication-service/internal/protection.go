package internal

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// protection.go is the MOCKED protection-level interface to auth-service. A
// client no longer asks for a specific auth METHOD on /authorize
// (acr_values=urn:xauth:otp:sms); instead it asks for a target PROTECTION LEVEL
// for the action it is guarding, and auth-service decides — mocked for now —
// whether to challenge, with what, or to pass through.
//
// This is the seam where transaction-service + risk-service will later plug in:
// today the decision is a static escalation ladder plus a per-session "assurance
// ledger"; tomorrow the required level (and whether the current context already
// satisfies it) comes from a real risk evaluation.
//
// Public contract: eight protection levels across two bands, monotonically
// increasing in strength (rank 1..8):
//
//	urn:xauth:protect:high:protected   (1)
//	urn:xauth:protect:high:enhanced    (2)
//	urn:xauth:protect:high:restricted  (3)
//	urn:xauth:protect:high:strict      (4)
//	urn:xauth:protect:ultra:protected  (5)
//	urn:xauth:protect:ultra:enhanced   (6)
//	urn:xauth:protect:ultra:restricted (7)
//	urn:xauth:protect:ultra:strict     (8)
//
// The token's `acr` claim is stamped with the requested protection level (what
// the relying party asked for); `amr` carries the method actually used.

// ProtectionLevel is one rung of the protection ladder.
type ProtectionLevel struct {
	ACR    string // the acr_values URN the client sends / the token's acr claim
	Band   string // "high" | "ultra"
	Name   string // protected | enhanced | restricted | strict
	Rank   int    // 1..8, monotonic — higher is stronger
	Method string // authenticator method a challenge uses to satisfy this level
}

// protectionLevels is the ordered ladder. Method mapping is a MOCK: only the
// sms and fido2 stub methods exist today, so the upper rungs reuse fido2 as a
// placeholder for the stronger ceremonies (UV-required FIDO2, hardware-bound,
// push + knowledge factor) that real adapters will provide. Edit freely — this
// table is the whole policy.
var protectionLevels = []ProtectionLevel{
	{ACR: "urn:xauth:protect:high:protected", Band: "high", Name: "protected", Rank: 1, Method: "sms"},
	{ACR: "urn:xauth:protect:high:enhanced", Band: "high", Name: "enhanced", Rank: 2, Method: "sms"},
	{ACR: "urn:xauth:protect:high:restricted", Band: "high", Name: "restricted", Rank: 3, Method: "fido2"},
	{ACR: "urn:xauth:protect:high:strict", Band: "high", Name: "strict", Rank: 4, Method: "fido2"},
	{ACR: "urn:xauth:protect:ultra:protected", Band: "ultra", Name: "protected", Rank: 5, Method: "fido2"},
	{ACR: "urn:xauth:protect:ultra:enhanced", Band: "ultra", Name: "enhanced", Rank: 6, Method: "fido2"},
	{ACR: "urn:xauth:protect:ultra:restricted", Band: "ultra", Name: "restricted", Rank: 7, Method: "fido2"},
	{ACR: "urn:xauth:protect:ultra:strict", Band: "ultra", Name: "strict", Rank: 8, Method: "fido2"},
}

// protectionByACR returns the protection level for an exact ACR (the form a
// transaction-type mapping stores), or false if it isn't one of the eight.
func protectionByACR(acr string) (ProtectionLevel, bool) {
	for _, lvl := range protectionLevels {
		if lvl.ACR == acr {
			return lvl, true
		}
	}
	return ProtectionLevel{}, false
}

// matchProtection returns the first requested acr value that is a protection
// level. acr_values is space-delimited, client-preference ordered (OIDC Core
// §3.1.2.1), so iteration follows the request.
func matchProtection(acrValues string) (ProtectionLevel, bool) {
	for _, want := range strings.Fields(acrValues) {
		for _, lvl := range protectionLevels {
			if lvl.ACR == want {
				return lvl, true
			}
		}
	}
	return ProtectionLevel{}, false
}

// protectionACRs lists the protection-level ACRs for discovery's
// acr_values_supported.
func protectionACRs() []string {
	out := make([]string, len(protectionLevels))
	for i, lvl := range protectionLevels {
		out[i] = lvl.ACR
	}
	return out
}

// ---- per-session assurance ledger (mock) ----

// ProtectionLedger remembers the highest protection rank a session has
// satisfied, so an equal-or-lower level passes through without re-challenging
// (the "session memory" half of the decision). In-process and single-replica,
// like the other /authorize flow state; entries expire after ttl (use the
// session TTL so assurance lasts as long as the session).
type ProtectionLedger struct {
	mu  sync.Mutex
	m   map[string]protAchieved
	ttl time.Duration
}

type protAchieved struct {
	rank int
	at   time.Time
}

// NewProtectionLedger builds a ledger whose entries self-expire after ttl.
func NewProtectionLedger(ttl time.Duration) *ProtectionLedger {
	return &ProtectionLedger{m: make(map[string]protAchieved), ttl: ttl}
}

// Record raises a session's achieved rank (keeping the max). No-op on a nil
// ledger or empty session id.
func (l *ProtectionLedger) Record(sessionID string, rank int) {
	if l == nil || sessionID == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gcLocked()
	cur := l.m[sessionID]
	if rank > cur.rank {
		cur.rank = rank
	}
	cur.at = time.Now().UTC()
	l.m[sessionID] = cur
}

// Achieved returns the highest rank the session has satisfied, or 0.
func (l *ProtectionLedger) Achieved(sessionID string) int {
	if l == nil || sessionID == "" {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gcLocked()
	return l.m[sessionID].rank
}

func (l *ProtectionLedger) gcLocked() {
	cutoff := time.Now().UTC().Add(-l.ttl)
	for k, e := range l.m {
		if e.at.Before(cutoff) {
			delete(l.m, k)
		}
	}
}

// handleProtection applies the mocked protection-level decision on /authorize:
// pass through when the session already satisfies the requested level, else
// challenge with the level's mapped method (stamping the token acr with the
// protection level, not the method).
func (h *OIDCHandlers) handleProtection(w http.ResponseWriter, r *http.Request, lvl ProtectionLevel, sessionID string, p pendingAuthorize) {
	if sessionID != "" && h.Protection.Achieved(sessionID) >= lvl.Rank {
		h.Logger.Info("protection_passthrough", "acr", lvl.ACR, "rank", lvl.Rank, "user_id", p.UserID, "tenant_id", p.TenantID)
		h.mintCodeAndRedirect(w, r, AuthCode{
			ClientID: p.ClientID, TenantID: p.TenantID, UserID: p.UserID,
			RedirectURI: p.RedirectURI, Scope: p.Scope, State: p.State, Nonce: p.Nonce,
			CodeChallenge: p.CodeChallenge, ACR: lvl.ACR, TransactionID: p.TransactionID,
		})
		return
	}

	spec, ok := specForMethod(lvl.Method)
	if !ok {
		h.Logger.Error("protection_method_unknown", "method", lvl.Method, "acr", lvl.ACR)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "protection level has no challenge method")
		return
	}
	p.TargetACR = lvl.ACR
	p.TargetRank = lvl.Rank
	p.AuthzSessionID = sessionID
	h.Logger.Info("protection_challenge", "acr", lvl.ACR, "rank", lvl.Rank, "method", lvl.Method, "user_id", p.UserID, "tenant_id", p.TenantID)
	h.startStepUpFlow(w, r, spec, p)
}
