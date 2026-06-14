package internal

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The ring buffer caps at capacity and returns newest-first.
func TestEventBufferRingAndOrder(t *testing.T) {
	b := NewEventBuffer(3)
	for i := 0; i < 5; i++ {
		b.add(LogEvent{Msg: "e" + itoa(i)})
	}
	got := b.Recent(10)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (capacity)", len(got))
	}
	if got[0].Msg != "e4" || got[1].Msg != "e3" || got[2].Msg != "e2" {
		t.Fatalf("wrong order/eviction: %q %q %q", got[0].Msg, got[1].Msg, got[2].Msg)
	}
}

// The handler records app events with their inline attrs, delegates to the inner
// handler, and skips the high-volume http_request access log.
func TestBufferHandlerCapturesAndSkipsAccessLog(t *testing.T) {
	buf := NewEventBuffer(10)
	logger := slog.New(NewBufferHandler(slog.NewTextHandler(io.Discard, nil), buf))
	logger.Info("admin_login", "email", "a@b.test")
	logger.Info("http_request", "path", "/admin") // must be skipped
	logger.Warn("device_fp_session_anomaly", "tenant_id", "ten_a")

	got := buf.Recent(10)
	if len(got) != 2 {
		t.Fatalf("captured %d, want 2 (http_request skipped): %+v", len(got), got)
	}
	if got[0].Msg != "device_fp_session_anomaly" || got[1].Msg != "admin_login" {
		t.Fatalf("unexpected feed order: %+v", got)
	}
	if !strings.Contains(got[1].Attrs, "email=a@b.test") {
		t.Errorf("inline attrs not captured: %q", got[1].Attrs)
	}
}

// probeService maps responses to up / errors / down / unknown.
func TestProbeServiceClassifies(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }))
	defer okSrv.Close()
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer errSrv.Close()
	closedSrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closedSrv.URL
	closedSrv.Close() // now refuses connections → "down"

	client := &http.Client{Timeout: 2 * time.Second}
	cases := []struct{ url, want string }{
		{okSrv.URL, "up"},      // <500 response = reachable
		{errSrv.URL, "errors"}, // 5xx
		{closedURL, "down"},    // unreachable
		{"", "unknown"},        // no target
	}
	for _, c := range cases {
		h := probeService(context.Background(), client, ServiceTarget{Name: "x", URL: c.url, Path: "/"})
		if h.Status != c.want {
			t.Errorf("probe %q: status = %q, want %q (code=%d)", c.url, h.Status, c.want, h.Code)
		}
	}
}

func TestRiskBaseURL(t *testing.T) {
	if got := RiskBaseURL("https://risk-123.run.app/internal/v1/ssf/events"); got != "https://risk-123.run.app" {
		t.Errorf("RiskBaseURL = %q", got)
	}
	if got := RiskBaseURL(""); got != "" {
		t.Errorf("empty → %q, want empty", got)
	}
}
