package internal

import (
	"net/url"
	"strconv"
	"time"
)

// parseAuditFilter builds an AuditFilter from query-string values, applying defaults
// and clamps. Returns an error with a short code on malformed input so the handler can
// map it to a 400.
func parseAuditFilter(q url.Values) (AuditFilter, string) {
	f := AuditFilter{
		InstallID: q.Get("install_id"),
		GrantID:   q.Get("grant_id"),
		Type:      q.Get("type"),
		Limit:     DefaultAuditLimit,
	}

	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return AuditFilter{}, "invalid_since"
		}
		f.Since = t
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return AuditFilter{}, "invalid_until"
		}
		f.Until = t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return AuditFilter{}, "invalid_limit"
		}
		if n > MaxAuditLimit {
			n = MaxAuditLimit
		}
		f.Limit = n
	}
	return f, ""
}
