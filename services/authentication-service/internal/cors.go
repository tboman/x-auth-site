package internal

import (
	"net/http"
	"strings"
)

// corsHandler grants web origins cross-origin access to the public OIDC
// surface — browser-based clients (SPAs) must call /token, /userinfo, and
// /revoke with fetch, which the same-origin policy blocks without these
// headers.
//
// An origin is allowed if it is in the CORS_ALLOWED_ORIGINS env baseline
// (comma-separated, exact scheme://host[:port] matches, or "*") OR it is a
// registered OIDC client's web origin. The latter is consulted from the store
// per request, so a client registered through the admin console can call
// /token from its SPA immediately, without an env change + redeploy.
//
// Scope deliberately excludes the tenant-scoped admin API: nothing should
// encourage browsers to call /v1/users or /v1/sessions directly.
func corsHandler(origins []string, store Storage, next http.Handler) http.Handler {
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

	// clientOriginAllowed reports whether any registered client declares this
	// origin. Only called for origins not already in the static env set.
	clientOriginAllowed := func(origin string) bool {
		clients, err := store.ListClients()
		if err != nil {
			return false
		}
		for _, c := range clients {
			for _, o := range c.WebOrigins {
				if strings.TrimRight(strings.TrimSpace(o), "/") == origin {
					return true
				}
			}
		}
		return false
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			match := strings.TrimRight(origin, "/")
			if wildcard || allowed[match] || clientOriginAllowed(match) {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Add("Vary", "Origin")
				h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				h.Set("Access-Control-Max-Age", "3600")
			}
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
