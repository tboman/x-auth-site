package internal

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xentranet/x-auth/pkg/logx"
)

const testTenant = "tenant-a"

func newServer(t *testing.T) http.Handler {
	t.Helper()
	return NewHandlers(NewMemStorage(), logx.New("persona-service-test")).Router()
}

func doJSON(t *testing.T, h http.Handler, method, path, tenant string, body any) *httptest.ResponseRecorder {
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
