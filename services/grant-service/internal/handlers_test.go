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

	"github.com/xentranet/x-auth/pkg/logx"
)

const testTenant = "tenant-a"

func newServer(t *testing.T) *Handlers {
	t.Helper()
	return NewHandlers(NewMemGrantStore(), NewMemAuditStore(), logx.New("grant-service-test"))
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
	rec := doJSON(t, newServer(t).Router(), http.MethodGet, "/healthz", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestCreateRequiresTenant(t *testing.T) {
	rec := doJSON(t, newServer(t).Router(), http.MethodPost, "/v1/grants", "", map[string]any{
		"install_id": "i", "identity_id": "id", "persona_id": "p", "access_token_hash": HashToken("tok"),
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 without tenant, got %d", rec.Code)
	}
}

func TestCreateValidatesFields(t *testing.T) {
	h := newServer(t).Router()
	cases := []map[string]any{
		{"identity_id": "id", "persona_id": "p", "access_token_hash": HashToken("t")},                                                 // missing install_id
		{"install_id": "i", "persona_id": "p", "access_token_hash": HashToken("t")},                                                   // missing identity_id
		{"install_id": "i", "identity_id": "id", "access_token_hash": HashToken("t")},                                                 // missing persona_id
		{"install_id": "i", "identity_id": "id", "persona_id": "p"},                                                                   // missing access_token_hash
		{"install_id": "i", "identity_id": "id", "persona_id": "p", "access_token_hash": "not-a-hash"},                                // malformed hash
		{"install_id": "i", "identity_id": "id", "persona_id": "p", "access_token_hash": HashToken("t"), "refresh_token_hash": "xyz"}, // malformed refresh hash
		{"install_id": "i", "identity_id": "id", "persona_id": "p", "access_token_hash": HashToken("t"), "ttl_seconds": 99999},
	}
	for i, body := range cases {
		rec := doJSON(t, h, http.MethodPost, "/v1/grants", testTenant, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("case %d: want 400, got %d body=%s", i, rec.Code, rec.Body.String())
		}
	}
}

func TestCreateHashesTokens(t *testing.T) {
	h := newServer(t).Router()
	rec := doJSON(t, h, http.MethodPost, "/v1/grants", testTenant, map[string]any{
		"install_id":         "install-1",
		"identity_id":        "identity-1",
		"persona_id":         "persona-1",
		"access_token_hash":  HashToken("super-secret-access"),
		"refresh_token_hash": HashToken("super-secret-refresh"),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	var g Grant
	if err := json.Unmarshal(rec.Body.Bytes(), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if g.ID == "" || g.TenantID != testTenant {
		t.Fatalf("bad grant: %+v", g)
	}
	if g.Status != StatusActive {
		t.Fatalf("want active, got %q", g.Status)
	}
	// Hashes: 64 hex chars and definitely not the plaintext.
	if len(g.AccessTokenHash) != 64 || strings.Contains(g.AccessTokenHash, "secret") {
		t.Fatalf("access hash looks wrong: %q", g.AccessTokenHash)
	}
	if len(g.RefreshTokenHash) != 64 || strings.Contains(g.RefreshTokenHash, "secret") {
		t.Fatalf("refresh hash looks wrong: %q", g.RefreshTokenHash)
	}
	// Response body must not leak plaintext tokens.
	if strings.Contains(rec.Body.String(), "super-secret") {
		t.Fatalf("response leaks plaintext token: %s", rec.Body.String())
	}
	if g.ExpiresAt.Sub(g.IssuedAt) != DefaultTTLSeconds*time.Second {
		t.Fatalf("unexpected ttl: issued=%v expires=%v", g.IssuedAt, g.ExpiresAt)
	}
}

func TestIntrospectRoundTrip(t *testing.T) {
	h := newServer(t).Router()
	token := "tok-abc-123"

	rec := doJSON(t, h, http.MethodPost, "/v1/grants", testTenant, map[string]any{
		"install_id": "i", "identity_id": "id", "persona_id": "p",
		"access_token_hash": HashToken(token), "ttl_seconds": 300,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create want 201, got %d", rec.Code)
	}
	var g Grant
	_ = json.Unmarshal(rec.Body.Bytes(), &g)

	// Introspect: active
	rec = doJSON(t, h, http.MethodPost, "/v1/introspect", testTenant, map[string]any{"token": token})
	if rec.Code != http.StatusOK {
		t.Fatalf("introspect want 200, got %d", rec.Code)
	}
	var intro IntrospectResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &intro)
	if !intro.Active || intro.InstallID != "i" || intro.TenantID != testTenant {
		t.Fatalf("expected active tenant-scoped introspection, got %+v", intro)
	}

	// Revoke
	rec = doJSON(t, h, http.MethodPost, "/v1/grants/"+g.ID+"/revoke", testTenant, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke want 204, got %d", rec.Code)
	}

	// Introspect again: inactive
	rec = doJSON(t, h, http.MethodPost, "/v1/introspect", testTenant, map[string]any{"token": token})
	if rec.Code != http.StatusOK {
		t.Fatalf("introspect-after-revoke want 200, got %d", rec.Code)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &intro)
	if intro.Active {
		t.Fatalf("expected inactive after revoke, got %+v", intro)
	}

	// Second revoke is idempotent.
	rec = doJSON(t, h, http.MethodPost, "/v1/grants/"+g.ID+"/revoke", testTenant, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("second revoke want 204, got %d", rec.Code)
	}

	// Get grant: status reflects revoked.
	rec = doJSON(t, h, http.MethodGet, "/v1/grants/"+g.ID, testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get want 200, got %d", rec.Code)
	}
	var got Grant
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Status != StatusRevoked || got.RevokedAt == nil {
		t.Fatalf("expected revoked status, got %+v", got)
	}
}

func TestIntrospectUnknownTokenReturnsInactive(t *testing.T) {
	h := newServer(t).Router()
	rec := doJSON(t, h, http.MethodPost, "/v1/introspect", testTenant, map[string]any{"token": "never-issued"})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var intro IntrospectResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &intro)
	if intro.Active {
		t.Fatalf("unknown token must be inactive, got %+v", intro)
	}
}

func TestIntrospectCrossTenantReturnsInactive(t *testing.T) {
	h := newServer(t).Router()
	token := "shared-token"

	rec := doJSON(t, h, http.MethodPost, "/v1/grants", "tenant-a", map[string]any{
		"install_id": "i", "identity_id": "id", "persona_id": "p", "access_token_hash": HashToken(token),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create want 201, got %d", rec.Code)
	}

	// tenant-b introspecting tenant-a's token must see `active: false` and no grant details.
	rec = doJSON(t, h, http.MethodPost, "/v1/introspect", "tenant-b", map[string]any{"token": token})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	var intro IntrospectResponse
	_ = json.Unmarshal([]byte(body), &intro)
	if intro.Active {
		t.Fatalf("cross-tenant introspection must be inactive, got %+v", intro)
	}
	// No tenant-a metadata leaked.
	if strings.Contains(body, "tenant-a") {
		t.Fatalf("response leaks other tenant info: %s", body)
	}
}

func TestIntrospectExpiredReturnsInactive(t *testing.T) {
	// Override Now so the grant is already expired when we introspect.
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	handlers := newServer(t)
	handlers.Now = func() time.Time { return start }
	h := handlers.Router()

	rec := doJSON(t, h, http.MethodPost, "/v1/grants", testTenant, map[string]any{
		"install_id": "i", "identity_id": "id", "persona_id": "p",
		"access_token_hash": HashToken("tok"), "ttl_seconds": 60,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create want 201, got %d", rec.Code)
	}

	// Jump past expiry.
	handlers.Now = func() time.Time { return start.Add(time.Hour) }

	rec = doJSON(t, h, http.MethodPost, "/v1/introspect", testTenant, map[string]any{"token": "tok"})
	var intro IntrospectResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &intro)
	if intro.Active {
		t.Fatalf("expired token must be inactive, got %+v", intro)
	}
}

func TestGrantTenantIsolation(t *testing.T) {
	h := newServer(t).Router()

	rec := doJSON(t, h, http.MethodPost, "/v1/grants", "tenant-a", map[string]any{
		"install_id": "i", "identity_id": "id", "persona_id": "p", "access_token_hash": HashToken("t"),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create want 201, got %d", rec.Code)
	}
	var g Grant
	_ = json.Unmarshal(rec.Body.Bytes(), &g)

	rec = doJSON(t, h, http.MethodGet, "/v1/grants/"+g.ID, "tenant-b", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get want 404, got %d", rec.Code)
	}

	rec = doJSON(t, h, http.MethodPost, "/v1/grants/"+g.ID+"/revoke", "tenant-b", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant revoke want 404, got %d", rec.Code)
	}
}

func TestRevokeUnknownGrant(t *testing.T) {
	rec := doJSON(t, newServer(t).Router(), http.MethodPost, "/v1/grants/does-not-exist/revoke", testTenant, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestAppendAuditValidation(t *testing.T) {
	h := newServer(t).Router()
	cases := []map[string]any{
		{"actor": "system"},
		{"type": "x"},
		{"type": "", "actor": ""},
	}
	for i, body := range cases {
		rec := doJSON(t, h, http.MethodPost, "/v1/audit", testTenant, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("case %d: want 400, got %d", i, rec.Code)
		}
	}
}

func TestAuditRoundTrip(t *testing.T) {
	h := newServer(t).Router()

	// Seed with a create (which auto-emits grant_issued) + manual event.
	rec := doJSON(t, h, http.MethodPost, "/v1/grants", testTenant, map[string]any{
		"install_id": "install-1", "identity_id": "id", "persona_id": "p", "access_token_hash": HashToken("t"),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create grant want 201, got %d", rec.Code)
	}
	var g Grant
	_ = json.Unmarshal(rec.Body.Bytes(), &g)

	rec = doJSON(t, h, http.MethodPost, "/v1/audit", testTenant, map[string]any{
		"type":       "install_created",
		"actor":      "admin:42",
		"install_id": "install-1",
		"payload":    map[string]any{"runtime": "claude"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("append want 201, got %d body=%s", rec.Code, rec.Body.String())
	}

	// Query all: should include grant_issued + install_created.
	rec = doJSON(t, h, http.MethodGet, "/v1/audit", testTenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("query want 200, got %d", rec.Code)
	}
	var list AuditListResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Items) != 2 {
		t.Fatalf("expected 2 events, got %d", len(list.Items))
	}

	// Filter by install_id.
	rec = doJSON(t, h, http.MethodGet, "/v1/audit?install_id=install-1", testTenant, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Items) != 2 {
		t.Fatalf("filter install_id: want 2, got %d", len(list.Items))
	}

	// Filter by grant_id: only the auto grant_issued event.
	rec = doJSON(t, h, http.MethodGet, "/v1/audit?grant_id="+g.ID, testTenant, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Items) != 1 || list.Items[0].Type != "grant_issued" {
		t.Fatalf("filter grant_id: unexpected items %+v", list.Items)
	}

	// Filter by type.
	rec = doJSON(t, h, http.MethodGet, "/v1/audit?type=install_created", testTenant, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Items) != 1 || list.Items[0].Type != "install_created" {
		t.Fatalf("filter type: unexpected items %+v", list.Items)
	}

	// Limit.
	rec = doJSON(t, h, http.MethodGet, "/v1/audit?limit=1", testTenant, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Items) != 1 {
		t.Fatalf("limit=1: want 1 item, got %d", len(list.Items))
	}

	// Other tenant sees nothing.
	rec = doJSON(t, h, http.MethodGet, "/v1/audit", "tenant-b", nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Items) != 0 {
		t.Fatalf("other tenant: want 0 items, got %d", len(list.Items))
	}
}

func TestAuditInvalidQueryParams(t *testing.T) {
	h := newServer(t).Router()
	for _, q := range []string{"?since=notatime", "?until=notatime", "?limit=abc", "?limit=0", "?limit=-1"} {
		rec := doJSON(t, h, http.MethodGet, "/v1/audit"+q, testTenant, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", q, rec.Code)
		}
	}
}

func TestAuditSinceUntilFilter(t *testing.T) {
	handlers := newServer(t)
	base := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	handlers.Now = func() time.Time { return base }
	h := handlers.Router()

	// Seed event at base.
	rec := doJSON(t, h, http.MethodPost, "/v1/audit", testTenant, map[string]any{"type": "a", "actor": "system"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("append: %d", rec.Code)
	}
	// Event at base + 10m.
	handlers.Now = func() time.Time { return base.Add(10 * time.Minute) }
	_ = doJSON(t, h, http.MethodPost, "/v1/audit", testTenant, map[string]any{"type": "b", "actor": "system"})

	// since = base+5m → only "b".
	rec = doJSON(t, h, http.MethodGet, "/v1/audit?since="+base.Add(5*time.Minute).Format(time.RFC3339), testTenant, nil)
	var list AuditListResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Items) != 1 || list.Items[0].Type != "b" {
		t.Fatalf("since filter: got %+v", list.Items)
	}

	// until = base+5m (exclusive) → only "a".
	rec = doJSON(t, h, http.MethodGet, "/v1/audit?until="+base.Add(5*time.Minute).Format(time.RFC3339), testTenant, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Items) != 1 || list.Items[0].Type != "a" {
		t.Fatalf("until filter: got %+v", list.Items)
	}
}
