package internal

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Both favicon paths serve the X-Auth SVG with the right content type.
func TestFaviconRouteServesSVG(t *testing.T) {
	r, _ := newAdminRouter(t)
	for _, path := range []string{"/favicon.ico", "/favicon.svg"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d", path, w.Code)
		}
		if ct := w.Header().Get("Content-Type"); ct != "image/svg+xml" {
			t.Errorf("%s: content-type %q, want image/svg+xml", path, ct)
		}
		if b := w.Body.String(); !strings.Contains(b, "<svg") || !strings.Contains(b, "#00e096") {
			t.Errorf("%s: body is not the X-Auth brand SVG: %s", path, b)
		}
	}
}

// A rendered hosted page carries the favicon <link> in its head.
func TestFaviconLinkInHostedHead(t *testing.T) {
	r, store := newAdminRouter(t)
	if err := store.PutClient(OIDCClient{
		ClientID: "cli", TenantID: "ten_acme", RedirectURIs: []string{"https://app.acme.test/cb"}, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet,
		"/login?tenant_id=ten_acme&redirect_uri="+url.QueryEscape("https://app.acme.test/cb")+"&state=s", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), `rel="icon" type="image/svg+xml" href="/favicon.svg"`) {
		t.Errorf("/login head is missing the favicon link")
	}
}
