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

	mu.Lock()
	defer mu.Unlock()
	got := *events
	if len(got) != 3 {
		t.Fatalf("expected 3 emitted events, got %d: %+v", len(got), got)
	}
	if got[0].uri != CAEPAssuranceLevelChange || got[0].payload["change_direction"] != "decrease" {
		t.Errorf("event 0: want assurance decrease, got %s %v", got[0].uri, got[0].payload["change_direction"])
	}
	if got[1].uri != CAEPAssuranceLevelChange || got[1].payload["change_direction"] != "increase" {
		t.Errorf("event 1: want assurance increase, got %s %v", got[1].uri, got[1].payload["change_direction"])
	}
	if got[2].uri != CAEPSessionRevoked {
		t.Errorf("event 2: want session-revoked, got %s", got[2].uri)
	}
	// The anomalous session must have been invalidated locally.
	sess, _ := store.GetSession("ten_a", "sD")
	if sess.InvalidatedAt == nil {
		t.Error("session sD should be invalidated by the anomaly")
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
