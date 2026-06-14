package internal

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// monitoring.go provides the live data behind the operator Monitoring console
// (admin_console.go renderMonitoringDomain): an in-process ring buffer of recent
// log events ("recent activity") and a cached health-probe of the platform
// services. Both are self-contained — no Cloud Monitoring / Logging API or extra
// IAM — so the panel works wherever authn runs. The event buffer is per-instance
// (fine for the single-replica, scale-to-zero deployment) and resets on restart.

// ----------------------------------------------------------------------------
// Recent activity — in-process log ring buffer
// ----------------------------------------------------------------------------

// LogEvent is one captured log record for the recent-activity feed.
type LogEvent struct {
	Time  time.Time
	Level slog.Level
	Msg   string
	Attrs string // compact "k=v k=v" of the record's inline attributes
}

// EventBuffer is a bounded, thread-safe ring of the most recent log events,
// populated by the bufferHandler and read by the monitoring panel.
type EventBuffer struct {
	mu  sync.Mutex
	buf []LogEvent
	cap int
}

// NewEventBuffer returns a buffer holding the last `capacity` events.
func NewEventBuffer(capacity int) *EventBuffer {
	if capacity <= 0 {
		capacity = 200
	}
	return &EventBuffer{cap: capacity}
}

func (b *EventBuffer) add(e LogEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, e)
	if len(b.buf) > b.cap {
		b.buf = b.buf[len(b.buf)-b.cap:]
	}
}

// Recent returns up to n events, newest first.
func (b *EventBuffer) Recent(n int) []LogEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]LogEvent, 0, n)
	for i := len(b.buf) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, b.buf[i])
	}
	return out
}

// bufferHandler is a slog.Handler that records each entry into an EventBuffer and
// delegates to an inner handler (so normal JSON logging is unaffected). Attrs set
// via WithAttrs aren't captured — the feed shows each record's own inline attrs,
// which is where the interesting per-event context lives (email, tenant_id, …).
type bufferHandler struct {
	inner slog.Handler
	buf   *EventBuffer
}

// NewBufferHandler wraps inner so every record is also appended to buf.
func NewBufferHandler(inner slog.Handler, buf *EventBuffer) slog.Handler {
	return &bufferHandler{inner: inner, buf: buf}
}

func (h *bufferHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *bufferHandler) Handle(ctx context.Context, r slog.Record) error {
	// The per-request access log (httpx.Logging "http_request") is high-volume
	// noise that would flood the feed — keep it in stdout but out of the buffer.
	if r.Message != "http_request" {
		var sb strings.Builder
		r.Attrs(func(a slog.Attr) bool {
			if sb.Len() > 0 {
				sb.WriteByte(' ')
			}
			sb.WriteString(a.Key)
			sb.WriteByte('=')
			sb.WriteString(a.Value.String())
			return true
		})
		h.buf.add(LogEvent{Time: r.Time, Level: r.Level, Msg: r.Message, Attrs: sb.String()})
	}
	return h.inner.Handle(ctx, r)
}

func (h *bufferHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &bufferHandler{inner: h.inner.WithAttrs(as), buf: h.buf}
}

func (h *bufferHandler) WithGroup(name string) slog.Handler {
	return &bufferHandler{inner: h.inner.WithGroup(name), buf: h.buf}
}

// ----------------------------------------------------------------------------
// Service health — cached concurrent probes
// ----------------------------------------------------------------------------

// ServiceTarget is one platform service to health-probe. Path must reach the
// container: do NOT use /healthz on run.app — Google's frontend answers it at the
// edge (404) without ever hitting the container, so it tells us nothing.
type ServiceTarget struct {
	Name string
	URL  string // base URL ("" → reported as "unknown")
	Path string // path appended to URL for the probe
}

// ServiceHealth is the probe result for one service.
type ServiceHealth struct {
	Name    string
	Status  string // "up" | "errors" | "down" | "unknown"
	Code    int
	Latency time.Duration
}

// HealthChecker probes its targets concurrently and caches the result for a
// short TTL, so refreshing the monitoring page doesn't repeatedly cold-start the
// scale-to-zero internal services.
type HealthChecker struct {
	targets []ServiceTarget
	http    *http.Client
	ttl     time.Duration

	mu       sync.Mutex
	cached   []ServiceHealth
	cachedAt time.Time
}

// NewHealthChecker builds a checker over the given targets (15s cache TTL).
func NewHealthChecker(targets []ServiceTarget) *HealthChecker {
	return &HealthChecker{
		targets: targets,
		http:    &http.Client{Timeout: 4 * time.Second},
		ttl:     15 * time.Second,
	}
}

// Snapshot returns the latest health, re-probing only when the cache is stale.
func (c *HealthChecker) Snapshot(ctx context.Context) []ServiceHealth {
	c.mu.Lock()
	if c.cached != nil && time.Since(c.cachedAt) < c.ttl {
		out := c.cached
		c.mu.Unlock()
		return out
	}
	c.mu.Unlock()

	results := make([]ServiceHealth, len(c.targets))
	var wg sync.WaitGroup
	for i, t := range c.targets {
		wg.Add(1)
		go func(i int, t ServiceTarget) {
			defer wg.Done()
			results[i] = probeService(ctx, c.http, t)
		}(i, t)
	}
	wg.Wait()

	c.mu.Lock()
	c.cached = results
	c.cachedAt = time.Now()
	c.mu.Unlock()
	return results
}

// probeService issues one GET and classifies the outcome. Any response < 500 is
// "up" (the container is serving — a 404 on a probe path still proves liveness);
// 5xx is "errors"; a transport error/timeout is "down".
func probeService(ctx context.Context, client *http.Client, t ServiceTarget) ServiceHealth {
	h := ServiceHealth{Name: t.Name, Status: "down"}
	if t.URL == "" {
		h.Status = "unknown"
		return h
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(t.URL, "/")+t.Path, nil)
	if err != nil {
		h.Status = "unknown"
		return h
	}
	start := time.Now()
	resp, err := client.Do(req)
	h.Latency = time.Since(start)
	if err != nil {
		return h // down — unreachable
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	h.Code = resp.StatusCode
	if resp.StatusCode >= 500 {
		h.Status = "errors"
	} else {
		h.Status = "up"
	}
	return h
}

// RiskBaseURL derives the risk-service base from its CAEP events URL
// (https://risk-…/internal/v1/ssf/events → https://risk-…). Empty in → empty out.
func RiskBaseURL(eventsURL string) string {
	return strings.TrimSuffix(strings.TrimRight(eventsURL, "/"), "/internal/v1/ssf/events")
}
