// Package tenantx extracts the tenant id from incoming requests.
package tenantx

import (
	"context"
	"errors"
	"net/http"
)

// Header is the HTTP header name carrying the tenant id in phase 1.
const Header = "X-Tenant-Id"

type ctxKey struct{}

// ErrMissing indicates the tenant id was not present on the request.
var ErrMissing = errors.New("missing tenant id")

// From extracts the tenant id from the request, returning ErrMissing if absent.
func From(r *http.Request) (string, error) {
	id := r.Header.Get(Header)
	if id == "" {
		return "", ErrMissing
	}
	return id, nil
}

// WithContext stores the tenant id on the context.
func WithContext(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, ctxKey{}, tenant)
}

// FromContext reads the tenant id previously stored via WithContext.
func FromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxKey{}).(string)
	return v, ok
}

// Middleware enforces that X-Tenant-Id is present and stashes it on the context.
// Requests without the header get a 400.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, err := From(r)
		if err != nil {
			http.Error(w, "missing X-Tenant-Id header", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithContext(r.Context(), tenant)))
	})
}
