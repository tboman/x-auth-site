package internal

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/logx"
)

const testTenant = "tenant-a"

func newServer(t *testing.T) http.Handler {
	t.Helper()
	return NewHandlers(NewMemStorage(), logx.New("persona-service-test")).Router()
}

func doJSON(t *testing.T, h http.Handler, method, path, tenant string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONAuth(t, h, method, path, tenant, "", body)
}

// doJSONAuth is doJSON with an optional X-Internal-Auth shared secret for
// requests against the /internal/v1/ tree.
func doJSONAuth(t *testing.T, h http.Handler, method, path, tenant, internalSecret string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tenant != "" {
		req.Header.Set("X-Tenant-Id", tenant)
	}
	if internalSecret != "" {
		req.Header.Set(httpx.InternalAuthHeader, internalSecret)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthz(t *testing.T) {
	rec := doJSON(t, newServer(t), http.MethodGet, "/healthz", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestCreateRequiresTenant(t *testing.T) {
	rec := doJSON(t, newServer(t), http.MethodPost, "/v1/personas", "", map[string]any{"name": "x"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 without tenant, got %d", rec.Code)
	}
}

func TestCreateValidatesName(t *testing.T) {
	h := newServer(t)
	rec := doJSON(t, h, http.MethodPost, "/v1/personas", testTenant, map[string]any{"name": ""})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty name want 400, got %d", rec.Code)
	}
	rec = doJSON(t, h, http.MethodPost, "/v1/personas", testTenant, map[string]any{"name": strings.Repeat("a", 101)})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("long name want 400, got %d", rec.Code)
	}
}

func TestCreateValidatesTTL(t *testing.T) {
	rec := doJSON(t, newServer(t), http.MethodPost, "/v1/personas", testTenant, map[string]any{
		"name":              "ok",
		"token_ttl_seconds": 99999,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for ttl > max, got %d", rec.Code)
	}
}

func TestPersonaRoundTrip(t *testing.T) {
	h := newServer(t)

	// Create
	rec := doJSON(t, h, http.MethodPost, "/v1/personas", testTenant, map[string]any{
		"name":   "analytics-reader",
		"scopes": []string{"read:reports"},
		"claims": map[string]any{"role": "analyst"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create want 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	var created Persona
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal created: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected server-generated id")
	}
	if created.TenantID != testTenant {
		t.Fatalf("tenant mismatch: %q", created.TenantID)
	}
	if created.TokenTTLSeconds != DefaultTokenTTLSeconds {
		t.Fatalf("expected default ttl %d, got %d", DefaultTokenTTLSeconds, created.TokenTTLSeconds)
	}

	// Get
	rec = doJSON(t, h, http.MethodGet, "/v1/personas/"+created.ID, testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get want 200, got %d", rec.Code)
	}

	// List
	rec = doJSON(t, h, http.MethodGet, "/v1/personas", testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list want 200, got %d", rec.Code)
	}
	var list ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(list.Items) != 1 || list.Items[0].ID != created.ID {
		t.Fatalf("unexpected list items: %+v", list.Items)
	}

	// Patch
	newName := "analytics-reader-v2"
	newTTL := 1800
	rec = doJSON(t, h, http.MethodPatch, "/v1/personas/"+created.ID, testTenant, map[string]any{
		"name":              newName,
		"token_ttl_seconds": newTTL,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var updated Persona
	_ = json.Unmarshal(rec.Body.Bytes(), &updated)
	if updated.Name != newName || updated.TokenTTLSeconds != newTTL {
		t.Fatalf("patch did not apply: %+v", updated)
	}

	// Delete
	rec = doJSON(t, h, http.MethodDelete, "/v1/personas/"+created.ID, testTenant, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete want 204, got %d", rec.Code)
	}

	// Get after delete
	rec = doJSON(t, h, http.MethodGet, "/v1/personas/"+created.ID, testTenant, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete want 404, got %d", rec.Code)
	}
}

func TestTenantIsolation(t *testing.T) {
	h := newServer(t)

	rec := doJSON(t, h, http.MethodPost, "/v1/personas", "tenant-a", map[string]any{"name": "a"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create want 201, got %d", rec.Code)
	}
	var created Persona
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	// tenant-b must not see tenant-a's persona
	rec = doJSON(t, h, http.MethodGet, "/v1/personas/"+created.ID, "tenant-b", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get want 404, got %d", rec.Code)
	}

	// tenant-b list is empty
	rec = doJSON(t, h, http.MethodGet, "/v1/personas", "tenant-b", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list want 200, got %d", rec.Code)
	}
	var list ListResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Items) != 0 {
		t.Fatalf("expected empty list for other tenant, got %d", len(list.Items))
	}
}

func TestGetUnknownReturns404(t *testing.T) {
	rec := doJSON(t, newServer(t), http.MethodGet, "/v1/personas/does-not-exist", testTenant, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestListRejectsInvalidLimit(t *testing.T) {
	h := newServer(t)
	for _, q := range []string{"?limit=abc", "?limit=0", "?limit=-1"} {
		rec := doJSON(t, h, http.MethodGet, "/v1/personas"+q, testTenant, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", q, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "invalid_limit") {
			t.Fatalf("%s: want invalid_limit error, got %s", q, rec.Body.String())
		}
	}
}

func TestListRejectsInvalidCursor(t *testing.T) {
	rec := doJSON(t, newServer(t), http.MethodGet, "/v1/personas?cursor=notatime", testTenant, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid_cursor") {
		t.Fatalf("want invalid_cursor error, got %s", rec.Body.String())
	}
}

// TestInternalV1ParityDevMode verifies that the /internal/v1/ alias serves the
// exact same route tree as /v1 when neither mTLS nor INTERNAL_AUTH_SECRET is
// configured (local-dev open mode).
func TestInternalV1ParityDevMode(t *testing.T) {
	h := newServer(t)

	// Create through the internal tree.
	rec := doJSON(t, h, http.MethodPost, "/internal/v1/personas", testTenant, map[string]any{
		"name":   "internal-made",
		"scopes": []string{"read:reports"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("internal create want 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	var created Persona
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal created: %v", err)
	}

	// Same persona is visible on both trees — including broker-service's
	// exact call shape, GET /internal/v1/personas/{id}.
	for _, path := range []string{
		"/v1/personas/" + created.ID,
		"/internal/v1/personas/" + created.ID,
	} {
		rec = doJSON(t, h, http.MethodGet, path, testTenant, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s want 200, got %d body=%s", path, rec.Code, rec.Body.String())
		}
		var got Persona
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("GET %s unmarshal: %v", path, err)
		}
		if got.ID != created.ID || got.Name != "internal-made" {
			t.Fatalf("GET %s returned wrong persona: %+v", path, got)
		}
	}

	// List parity.
	for _, path := range []string{"/v1/personas", "/internal/v1/personas"} {
		rec = doJSON(t, h, http.MethodGet, path, testTenant, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s want 200, got %d", path, rec.Code)
		}
		var list ListResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Fatalf("GET %s unmarshal: %v", path, err)
		}
		if len(list.Items) != 1 || list.Items[0].ID != created.ID {
			t.Fatalf("GET %s unexpected items: %+v", path, list.Items)
		}
	}

	// Tenant enforcement applies on the internal tree too.
	rec = doJSON(t, h, http.MethodGet, "/internal/v1/personas", "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("internal list without tenant want 400, got %d", rec.Code)
	}
}

// TestInternalV1SharedSecret verifies the INTERNAL_AUTH_SECRET gate on the
// /internal/v1/ tree: missing/wrong header -> structured 401, correct header
// -> through to the handler, and the public /v1 tree stays open.
func TestInternalV1SharedSecret(t *testing.T) {
	const secret = "test-internal-secret"
	t.Setenv(httpx.EnvInternalAuthSecret, secret)
	// InternalAuth captures the secret at construction, so the router must be
	// built after t.Setenv.
	h := newServer(t)

	// Missing header -> structured 401.
	rec := doJSON(t, h, http.MethodGet, "/internal/v1/personas", testTenant, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing header want 401, got %d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("401 want application/json, got %q", ct)
	}
	var errBody struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("unmarshal 401 body: %v (body=%s)", err, rec.Body.String())
	}
	if errBody.Error != "internal_auth_required" || errBody.Message == "" {
		t.Fatalf("unexpected 401 body: %+v", errBody)
	}

	// Wrong secret -> 401.
	rec = doJSONAuth(t, h, http.MethodGet, "/internal/v1/personas", testTenant, "wrong-secret", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret want 401, got %d", rec.Code)
	}

	// Correct secret -> 200.
	rec = doJSONAuth(t, h, http.MethodGet, "/internal/v1/personas", testTenant, secret, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("correct secret want 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	// Public /v1 tree is unaffected by the secret.
	rec = doJSON(t, h, http.MethodGet, "/v1/personas", testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/v1 without header want 200, got %d", rec.Code)
	}
}

// spyStorage wraps MemStorage and records the limit passed to List, so the
// handler's limit defaulting/capping can be asserted directly.
type spyStorage struct {
	*MemStorage
	lastLimit int
}

func (s *spyStorage) List(tenantID string, limit int, cursor time.Time) ([]Persona, error) {
	s.lastLimit = limit
	return s.MemStorage.List(tenantID, limit, cursor)
}

func TestListLimitDefaultAndCap(t *testing.T) {
	spy := &spyStorage{MemStorage: NewMemStorage()}
	h := NewHandlers(spy, logx.New("persona-service-test")).Router()

	// No limit param -> DefaultListLimit.
	rec := doJSON(t, h, http.MethodGet, "/v1/personas", testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", rec.Code)
	}
	if spy.lastLimit != DefaultListLimit {
		t.Fatalf("default limit: want %d, got %d", DefaultListLimit, spy.lastLimit)
	}

	// Oversized limit -> capped at MaxListLimit, not rejected.
	rec = doJSON(t, h, http.MethodGet, "/v1/personas?limit=9999", testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("capped list: want 200, got %d", rec.Code)
	}
	if spy.lastLimit != MaxListLimit {
		t.Fatalf("capped limit: want %d, got %d", MaxListLimit, spy.lastLimit)
	}
}

func TestListPaginationTwoPageWalk(t *testing.T) {
	h := newServer(t)

	// Seed 3 personas with distinct CreatedAt values (the handler stamps time.Now,
	// so pause between creates to avoid identical timestamps).
	for i := 0; i < 3; i++ {
		rec := doJSON(t, h, http.MethodPost, "/v1/personas", testTenant, map[string]any{"name": "p"})
		if rec.Code != http.StatusCreated {
			t.Fatalf("seed %d: want 201, got %d", i, rec.Code)
		}
		time.Sleep(2 * time.Millisecond)
	}

	rec := doJSON(t, h, http.MethodGet, "/v1/personas?limit=2", testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	var page1 ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &page1); err != nil {
		t.Fatalf("unmarshal page1: %v", err)
	}
	if len(page1.Items) != 2 {
		t.Fatalf("first page want 2 items, got %d", len(page1.Items))
	}
	// Newest first.
	if page1.Items[0].CreatedAt.Before(page1.Items[1].CreatedAt) {
		t.Fatalf("expected created_at DESC ordering: %v then %v",
			page1.Items[0].CreatedAt, page1.Items[1].CreatedAt)
	}
	if page1.NextCursor == "" {
		t.Fatal("expected next_cursor when page is full")
	}

	rec = doJSON(t, h, http.MethodGet, "/v1/personas?limit=2&cursor="+page1.NextCursor, testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list page2: %d", rec.Code)
	}
	var page2 ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &page2); err != nil {
		t.Fatalf("unmarshal page2: %v", err)
	}
	if len(page2.Items) != 1 {
		t.Fatalf("second page want 1 item, got %d", len(page2.Items))
	}
	if page2.NextCursor != "" {
		t.Fatalf("final page should not emit a cursor, got %q", page2.NextCursor)
	}
	// No overlap between pages.
	seen := map[string]bool{page1.Items[0].ID: true, page1.Items[1].ID: true}
	if seen[page2.Items[0].ID] {
		t.Fatalf("page 2 repeated item %s from page 1", page2.Items[0].ID)
	}
}
