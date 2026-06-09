package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"
)

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
