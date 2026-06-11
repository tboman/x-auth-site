package internal

import (
	"net/http"
	"strings"
)

// corsHandler grants the configured web origins cross-origin access to the
// public OIDC surface — browser-based clients (SPAs) must call /token,
// /userinfo, and /revoke with fetch, which the same-origin policy blocks
// without these headers. Origins come from CORS_ALLOWED_ORIGINS
// (comma-separated, exact scheme://host[:port] matches, or "*").
//
// Scope deliberately excludes the tenant-scoped admin API: nothing should
// encourage browsers to call /v1/users or /v1/sessions directly.
func corsHandler(origins []string, next http.Handler) http.Handler {
	allowed := make(map[string]bool, len(origins))
	wildcard := false
	for _, o := range origins {
		o = strings.TrimRight(strings.TrimSpace(o), "/")
		switch o {
		case "":
		case "*":
			wildcard = true
		default:
			allowed[o] = true
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && (wildcard || allowed[origin]) {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			h.Set("Access-Control-Max-Age", "3600")
		}
		// Preflight terminates here regardless of origin match — a 204
		// without allow headers is a denial the browser enforces.
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
