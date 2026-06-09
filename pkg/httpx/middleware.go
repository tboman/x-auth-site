package httpx

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// InternalAuthHeader carries the shared secret on service-to-service calls
// when mTLS is not in play (local dev, or transitional deployments).
const InternalAuthHeader = "X-Internal-Auth"

// EnvInternalAuthSecret names the env var holding the shared secret. Callers
// setting the header and servers verifying it read the same variable.
const EnvInternalAuthSecret = "INTERNAL_AUTH_SECRET"

// InternalAuth guards service-to-service routes (the /internal/v1/ tree,
// ARCHITECTURE.md §10.3). A request is accepted when either:
//
//  1. it arrived over mTLS with a verified client certificate (the TLS layer
//     already authenticated the peer against TLS_CLIENT_CA_FILE), or
//  2. INTERNAL_AUTH_SECRET is set and the X-Internal-Auth header matches it
//     (constant-time compare) — the non-mesh fallback.
//
// With no TLS and no secret configured, requests pass through and a warning is
// logged once at construction: that is the local-dev mode, mirroring the
// plaintext/ephemeral-key fallbacks elsewhere. Once either mechanism is
// configured, unauthenticated requests get a structured 401.
func InternalAuth(logger *slog.Logger) func(http.Handler) http.Handler {
	secret := os.Getenv(EnvInternalAuthSecret)
	if secret == "" {
		logger.Warn("internal_auth_open",
			"reason", EnvInternalAuthSecret+" unset; /internal routes rely on mTLS or run unauthenticated (dev)")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// mTLS: the server's TLS config already verified the chain; a
			// populated peer-certificate list is the post-handshake signal.
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				next.ServeHTTP(w, r)
				return
			}
			if secret != "" {
				header := r.Header.Get(InternalAuthHeader)
				if subtle.ConstantTimeCompare([]byte(header), []byte(secret)) != 1 {
					WriteError(w, http.StatusUnauthorized, "internal_auth_required",
						"service-to-service authentication required")
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			// Dev mode: nothing configured, allow.
			next.ServeHTTP(w, r)
		})
	}
}

// SetInternalAuth adds the shared-secret header to an outbound
// service-to-service request when INTERNAL_AUTH_SECRET is configured. Under
// full mTLS the header is redundant but harmless.
func SetInternalAuth(r *http.Request) {
	if secret := os.Getenv(EnvInternalAuthSecret); secret != "" {
		r.Header.Set(InternalAuthHeader, secret)
	}
}

// Logging writes one structured log line per completed request.
func Logging(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)
			logger.Info("http_request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.status,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

// Recover catches panics in handlers and returns a 500.
func Recover(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error("handler_panic", "err", rec, "path", r.URL.Path)
					WriteError(w, http.StatusInternalServerError, "internal_error", "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// WriteJSON writes v as JSON with the given status code. The returned error is
// non-nil when encoding fails after the header was already sent (the response is
// truncated at that point); callers that can act on it should log it.
func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// WriteError writes a standard error body with status.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, map[string]any{
		"error":   code,
		"message": message,
	})
}

// MaxBodyBytes caps how much of a JSON request body ReadJSON will consume.
// No X-Auth API accepts payloads anywhere near this; the cap exists so a
// misbehaving client can't make a handler buffer unbounded input.
const MaxBodyBytes = 1 << 20 // 1 MiB

// ReadJSON decodes a JSON request body into v. Returns an error on malformed
// input or when the body exceeds MaxBodyBytes.
func ReadJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, MaxBodyBytes+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.InputOffset() > MaxBodyBytes {
		return errors.New("request body exceeds size limit")
	}
	return nil
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}
