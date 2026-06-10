package internal

import (
	"net/http"
	"strings"
	"time"

	"github.com/xentranet/x-auth/pkg/ratex"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// RateLimitOff is the RATE_LIMIT value that disables layer-2 rate limiting.
const RateLimitOff = "off"

// ParseRateLimit interprets a RATE_LIMIT env value ("N/window", e.g. "600/1m")
// for the §10.5 layer-2 limiter. The literal "off" reports enabled=false (the
// caller then passes a nil ratex.Allower to Router, which always allows);
// anything else must parse via ratex.ParseRate. The backend choice (shared
// Redis vs. per-replica in-memory) is made by the caller — see cmd/main.go.
func ParseRateLimit(spec string) (limit int, window time.Duration, enabled bool, err error) {
	if spec == RateLimitOff {
		return 0, 0, false, nil
	}
	limit, window, err = ratex.ParseRate(spec)
	if err != nil {
		return 0, 0, false, err
	}
	return limit, window, true, nil
}

// rateLimitKey keys §10.5 layer-2 limits by tenant + method + endpoint class,
// e.g. "tenant-a|POST|/v1/advice" or "tenant-a|GET|/v1/transactions". The
// endpoint class is the first two path segments (Go 1.22 has no
// http.Request.Pattern), so GET /v1/transactions and GET /v1/transactions/{id}
// share a bucket by design.
//
// The tenant comes straight from the X-Tenant-Id header — limiting runs BEFORE
// tenant validation because it is cheaper. Requests without a tenant header
// return "", which bypasses the limiter; tenantx rejects them with 400 anyway.
func rateLimitKey(r *http.Request) string {
	tenant := r.Header.Get(tenantx.Header)
	if tenant == "" {
		return ""
	}
	return tenant + "|" + r.Method + "|" + endpointClass(r.URL.Path)
}

// endpointClass returns "/" plus at most the first two path segments.
func endpointClass(path string) string {
	segs := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
	if len(segs) > 2 {
		segs = segs[:2]
	}
	return "/" + strings.Join(segs, "/")
}
