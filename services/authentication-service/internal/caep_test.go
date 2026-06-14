package internal

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/jwtx"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// capturedEvent is one CAEP event a test receiver decoded from a SET.
type capturedEvent struct {
	uri     string
	payload map[string]any
}

// caepCapture stands up an HTTP receiver that verifies each SET against the test
// signer's JWKS and records the carried events.
func caepCapture(t *testing.T) (*httptest.Server, *[]capturedEvent, *sync.Mutex) {
	t.Helper()
	verifier, err := jwtx.NewVerifierFromJWKS("http://test.local", testSigner.JWKS())
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	var mu sync.Mutex
	events := &[]capturedEvent{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, extra, err := verifier.Verify(strings.TrimSpace(string(body)), time.Now())
		if err != nil {
			t.Errorf("receiver: SET verify failed: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		evs, _ := extra["events"].(map[string]any)
		mu.Lock()
		for uri, raw := range evs {
			p, _ := raw.(map[string]any)
			*events = append(*events, capturedEvent{uri: uri, payload: p})
		}
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return srv, events, &mu
}

// TestCAEPAnalyzerEmits drives the device analyzer through its decision ladder
// and asserts the SETs it emits (verified end-to-end by the capture receiver).
func TestCAEPAnalyzerEmits(t *testing.T) {
	store := NewMemStorage()
	srv, events, mu := caepCapture(t)
	tx := NewCAEPTransmitter(testSigner, "http://test.local", srv.URL, "", discardLogger())
	a := NewDeviceAnalyzer(store, discardLogger(), tx)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	obs := func(user, sess, stage, fp string) { a.Observe(req, "ten_a", user, sess, stage, fp) }

	// Seed the session used in the anomaly case so revoke has something to kill.
	now := time.Now().UTC()
	_, _ = store.CreateSession(Session{ID: "sD", TenantID: "ten_a", UserID: "u2", RiskLevel: RiskLow, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)})

	obs("u1", "sA", DeviceStageSocial, "fpX") // first device → baseline, no event
	obs("u1", "sB", DeviceStageSocial, "fpY") // changed device → assurance DOWN
	obs("u1", "sC", DeviceStageOTP, "fpX")    // known device + step-up → assurance UP
	obs("u2", "sD", DeviceStageSocial, "fpZ") // first device for u2 → baseline
	obs("u2", "sD", DeviceStageOTP, "fpW")    // same session, new fp → session-revoked
	tx.Wait()                                 // recording is sync; drain async SET deliveries before asserting

	mu.Lock()
	defer mu.Unlock()
	got := *events
	if len(got) != 3 {
		t.Fatalf("expected 3 emitted events, got %d: %+v", len(got), got)
	}
	// Deliveries are detached goroutines, so arrival order isn't guaranteed —
	// assert the multiset instead of fixed positions.
	var decrease, increase, revoked int
	for _, e := range got {
		switch {
		case e.uri == CAEPAssuranceLevelChange && e.payload["change_direction"] == "decrease":
			decrease++
		case e.uri == CAEPAssuranceLevelChange && e.payload["change_direction"] == "increase":
			increase++
		case e.uri == CAEPSessionRevoked:
			revoked++
		}
	}
	if decrease != 1 || increase != 1 || revoked != 1 {
		t.Fatalf("want one each of decrease/increase/session-revoked, got d=%d i=%d r=%d: %+v", decrease, increase, revoked, got)
	}
	// The anomalous session must have been invalidated locally.
	sess, _ := store.GetSession("ten_a", "sD")
	if sess.InvalidatedAt == nil {
		t.Error("session sD should be invalidated by the anomaly")
	}
}

// TestCAEPSessionAnomalyRevokesTokenFamily: a mid-session fingerprint change is
// a possible session replay — it must kill not just the session cookie but every
// refresh-token family minted against that session.
func TestCAEPSessionAnomalyRevokesTokenFamily(t *testing.T) {
	store := NewMemStorage()
	tx := NewCAEPTransmitter(testSigner, "http://test.local", "", "", discardLogger()) // log-only is fine
	a := NewDeviceAnalyzer(store, discardLogger(), tx)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	now := time.Now().UTC()

	_, _ = store.CreateSession(Session{ID: "sX", TenantID: "ten_a", UserID: "u9", RiskLevel: RiskLow, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)})
	// A live access+refresh family minted against that session.
	_ = store.PutToken(Token{TokenHash: "h_access", SessionID: "sX", UserID: "u9", TenantID: "ten_a", FamilyID: "famX", TokenType: "access", IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	_ = store.PutToken(Token{TokenHash: "h_refresh", SessionID: "sX", UserID: "u9", TenantID: "ten_a", FamilyID: "famX", TokenType: "refresh", IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour)})

	a.Observe(req, "ten_a", "u9", "sX", DeviceStageSocial, "fpA") // baseline fingerprint
	a.Observe(req, "ten_a", "u9", "sX", DeviceStageOTP, "fpB")    // same session, new fp → anomaly (sync revoke)

	if sess, _ := store.GetSession("ten_a", "sX"); sess.InvalidatedAt == nil {
		t.Error("session sX should be invalidated by the anomaly")
	}
	for _, h := range []string{"h_access", "h_refresh"} {
		tok, err := store.GetTokenByHash(h)
		if err != nil {
			t.Fatalf("token %s: %v", h, err)
		}
		if tok.RevokedAt == nil {
			t.Errorf("token %s should be revoked along with its family", h)
		}
	}
}

// TestCAEPTransmitterLogOnly: with no EventsURL, Emit is a no-op (no panic, no
// delivery) — the analyzer still works without risk-service.
func TestCAEPTransmitterLogOnly(t *testing.T) {
	store := NewMemStorage()
	tx := NewCAEPTransmitter(testSigner, "http://test.local", "", "", discardLogger())
	a := NewDeviceAnalyzer(store, discardLogger(), tx)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	a.Observe(req, "ten_a", "u1", "s1", DeviceStageSocial, "fp1")
	a.Observe(req, "ten_a", "u1", "s2", DeviceStageSocial, "fp2") // would emit — but log-only
	if sigs, _ := store.ListDeviceSignals("ten_a", 0); len(sigs) != 2 {
		t.Fatalf("signals should still be recorded: %d", len(sigs))
	}
}
