package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xentranet/x-auth/pkg/logx"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestInternalAuthSecretMode(t *testing.T) {
	t.Setenv(EnvInternalAuthSecret, "s3cret")
	h := InternalAuth(logx.New("test"))(okHandler())

	// Missing header → 401 structured body.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/v1/x", nil))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "internal_auth_required") {
		t.Fatalf("want structured 401, got %d %s", rec.Code, rec.Body.String())
	}

	// Wrong secret → 401.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/internal/v1/x", nil)
	req.Header.Set(InternalAuthHeader, "wrong")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: want 401, got %d", rec.Code)
	}

	// Correct secret → pass.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/internal/v1/x", nil)
	req.Header.Set(InternalAuthHeader, "s3cret")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("correct secret: want 200, got %d", rec.Code)
	}
}

func TestInternalAuthDevModeOpen(t *testing.T) {
	t.Setenv(EnvInternalAuthSecret, "")
	h := InternalAuth(logx.New("test"))(okHandler())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/v1/x", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("dev mode must pass through, got %d", rec.Code)
	}
}

func TestInternalAuthMTLSBypassesSecret(t *testing.T) {
	t.Setenv(EnvInternalAuthSecret, "s3cret")
	h := InternalAuth(logx.New("test"))(okHandler())

	// A request that arrived over mTLS carries verified peer certificates; the
	// middleware must accept it without the header.
	req := httptest.NewRequest(http.MethodGet, "/internal/v1/x", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mTLS peer must pass without header, got %d", rec.Code)
	}

	// TLS without a client cert (server-only TLS) does NOT bypass the secret.
	req = httptest.NewRequest(http.MethodGet, "/internal/v1/x", nil)
	req.TLS = &tls.ConnectionState{}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("server-only TLS must still require the secret, got %d", rec.Code)
	}
}

func TestSetInternalAuth(t *testing.T) {
	t.Setenv(EnvInternalAuthSecret, "s3cret")
	req := httptest.NewRequest(http.MethodGet, "/internal/v1/x", nil)
	SetInternalAuth(req)
	if got := req.Header.Get(InternalAuthHeader); got != "s3cret" {
		t.Fatalf("want header set, got %q", got)
	}

	t.Setenv(EnvInternalAuthSecret, "")
	req = httptest.NewRequest(http.MethodGet, "/internal/v1/x", nil)
	SetInternalAuth(req)
	if got := req.Header.Get(InternalAuthHeader); got != "" {
		t.Fatalf("unset secret must not set header, got %q", got)
	}
}
