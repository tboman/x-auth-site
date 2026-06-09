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

// newTestServer returns a Server backed by MemStorage with a deterministic clock and id sequence.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	var n int
	s := NewServer(NewMemStorage(), logx.New("pool-service-test"))
	s.Now = func() time.Time { return time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC) }
	s.NewID = func() string {
		n++
		// Keep id shape stable and distinguishable across tests.
		return "id-" + padInt(n)
	}
	return s
}

func padInt(n int) string {
	// Tiny 4-digit zero-pad without importing strconv twice.
	return string(rune('0'+n/1000%10)) + string(rune('0'+n/100%10)) +
		string(rune('0'+n/10%10)) + string(rune('0'+n%10))
}

func doJSON(t *testing.T, h http.Handler, method, path, tenant string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		buf = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, buf)
	if tenant != "" {
		req.Header.Set("X-Tenant-Id", tenant)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestHealthz(t *testing.T) {
	h := newTestServer(t).Handler()
	w := doJSON(t, h, http.MethodGet, "/healthz", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"ok"`) {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestCreatePool_MissingTenant(t *testing.T) {
	h := newTestServer(t).Handler()
	w := doJSON(t, h, http.MethodPost, "/v1/pools", "",
		CreatePoolRequest{Name: "n", Size: 5, PersonaIDs: []string{"p1"}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestMissingTenantContext_AllHandlers calls every tenant-scoped handler directly —
// bypassing tenantx.Middleware — to prove each one fails closed with the shared
// structured missing_tenant error instead of running an unscoped storage query.
func TestMissingTenantContext_AllHandlers(t *testing.T) {
	srv := newTestServer(t)
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"create_pool", srv.handleCreatePool},
		{"list_pools", srv.handleListPools},
		{"get_pool", srv.handleGetPool},
		{"delete_pool", srv.handleDeletePool},
		{"add_identity", srv.handleAddIdentity},
		{"list_identities", srv.handleListIdentities},
		{"claim", srv.handleClaim},
		{"release", srv.handleRelease},
		{"revoke", srv.handleRevoke},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/anything", nil)
			w := httptest.NewRecorder()
			tc.handler(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
			var body struct {
				Error   string `json:"error"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not structured JSON: %v: %s", err, w.Body.String())
			}
			if body.Error != "missing_tenant" {
				t.Fatalf("expected error code missing_tenant, got %q", body.Error)
			}
			if body.Message == "" {
				t.Fatalf("expected non-empty message, got: %s", w.Body.String())
			}
		})
	}
}

func TestCreatePool_ValidationErrors(t *testing.T) {
	h := newTestServer(t).Handler()
	cases := []struct {
		name string
		body CreatePoolRequest
	}{
		{"empty name", CreatePoolRequest{Size: 5}},
		{"zero size", CreatePoolRequest{Name: "a", Size: 0}},
		{"oversize", CreatePoolRequest{Name: "a", Size: MaxSize + 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := doJSON(t, h, http.MethodPost, "/v1/pools", "tenant-1", tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestPoolCRUD_HappyPath(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	// Create
	w := doJSON(t, h, http.MethodPost, "/v1/pools", "tenant-1",
		CreatePoolRequest{Name: "my-pool", Size: 3, PersonaIDs: []string{"persona-a"}})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created Pool
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if created.ID == "" || created.TenantID != "tenant-1" || created.Size != 3 {
		t.Fatalf("unexpected pool: %+v", created)
	}

	// List
	w = doJSON(t, h, http.MethodGet, "/v1/pools", "tenant-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", w.Code)
	}
	var list PoolListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("expected 1 pool, got %d", len(list.Items))
	}

	// Get
	w = doJSON(t, h, http.MethodGet, "/v1/pools/"+created.ID, "tenant-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d", w.Code)
	}

	// Tenant isolation — different tenant must NOT see it.
	w = doJSON(t, h, http.MethodGet, "/v1/pools/"+created.ID, "tenant-2", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get: expected 404, got %d", w.Code)
	}

	// Delete
	w = doJSON(t, h, http.MethodDelete, "/v1/pools/"+created.ID, "tenant-1", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d", w.Code)
	}

	// Gone
	w = doJSON(t, h, http.MethodGet, "/v1/pools/"+created.ID, "tenant-1", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("get after delete: expected 404, got %d", w.Code)
	}
}

func TestClaimAndRelease_HappyPath(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	// Create a pool with persona-a eligible.
	w := doJSON(t, h, http.MethodPost, "/v1/pools", "tenant-1",
		CreatePoolRequest{Name: "pool", Size: 2, PersonaIDs: []string{"persona-a"}})
	if w.Code != http.StatusCreated {
		t.Fatalf("create pool: %d %s", w.Code, w.Body.String())
	}
	var pool Pool
	_ = json.Unmarshal(w.Body.Bytes(), &pool)

	// Add an identity.
	w = doJSON(t, h, http.MethodPost, "/v1/pools/"+pool.ID+"/identities", "tenant-1",
		AddIdentityRequest{SubjectID: "sub-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("add identity: %d %s", w.Code, w.Body.String())
	}
	var ident Identity
	_ = json.Unmarshal(w.Body.Bytes(), &ident)
	if ident.Status != StatusAvailable {
		t.Fatalf("new identity should be available, got %s", ident.Status)
	}

	// Claim it.
	w = doJSON(t, h, http.MethodPost, "/v1/pools/"+pool.ID+"/claim", "tenant-1",
		ClaimRequest{PersonaID: "persona-a", InstallID: "install-1"})
	if w.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", w.Code, w.Body.String())
	}
	var claimed Identity
	_ = json.Unmarshal(w.Body.Bytes(), &claimed)
	if claimed.Status != StatusClaimed {
		t.Fatalf("expected claimed, got %s", claimed.Status)
	}
	if claimed.ClaimedByInstallID == nil || *claimed.ClaimedByInstallID != "install-1" {
		t.Fatalf("expected install-1, got %v", claimed.ClaimedByInstallID)
	}
	if claimed.ID != ident.ID {
		t.Fatalf("claimed id mismatch: %s vs %s", claimed.ID, ident.ID)
	}

	// Second claim with no more available identities must 409.
	w = doJSON(t, h, http.MethodPost, "/v1/pools/"+pool.ID+"/claim", "tenant-1",
		ClaimRequest{PersonaID: "persona-a", InstallID: "install-2"})
	if w.Code != http.StatusConflict {
		t.Fatalf("second claim: expected 409, got %d: %s", w.Code, w.Body.String())
	}

	// Claim with ineligible persona must 404.
	w = doJSON(t, h, http.MethodPost, "/v1/pools/"+pool.ID+"/claim", "tenant-1",
		ClaimRequest{PersonaID: "persona-other", InstallID: "install-x"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("ineligible persona: expected 404, got %d", w.Code)
	}

	// Release.
	w = doJSON(t, h, http.MethodPost, "/v1/identities/"+claimed.ID+"/release", "tenant-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("release: %d %s", w.Code, w.Body.String())
	}
	var released Identity
	_ = json.Unmarshal(w.Body.Bytes(), &released)
	if released.Status != StatusAvailable {
		t.Fatalf("expected available after release, got %s", released.Status)
	}
	if released.ClaimedByInstallID != nil {
		t.Fatalf("expected install id cleared, got %v", released.ClaimedByInstallID)
	}

	// Release again — idempotent, still 200 + available.
	w = doJSON(t, h, http.MethodPost, "/v1/identities/"+claimed.ID+"/release", "tenant-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("release idempotent: %d", w.Code)
	}

	// Now a new claim must succeed again.
	w = doJSON(t, h, http.MethodPost, "/v1/pools/"+pool.ID+"/claim", "tenant-1",
		ClaimRequest{PersonaID: "persona-a", InstallID: "install-3"})
	if w.Code != http.StatusOK {
		t.Fatalf("re-claim after release: %d %s", w.Code, w.Body.String())
	}
}

// withTickingClock makes srv.Now return a strictly increasing timestamp (one second
// per call) so created_at values are distinct and keyset pagination is observable.
func withTickingClock(srv *Server) {
	base := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
	var n int
	srv.Now = func() time.Time {
		n++
		return base.Add(time.Duration(n) * time.Second)
	}
}

func TestListPagination_InvalidParams(t *testing.T) {
	h := newTestServer(t).Handler()
	cases := []struct {
		name     string
		path     string
		wantCode string
	}{
		{"pools limit not a number", "/v1/pools?limit=abc", "invalid_limit"},
		{"pools limit zero", "/v1/pools?limit=0", "invalid_limit"},
		{"pools limit negative", "/v1/pools?limit=-5", "invalid_limit"},
		{"pools bad cursor", "/v1/pools?cursor=not-a-timestamp", "invalid_cursor"},
		{"identities limit not a number", "/v1/pools/p-1/identities?limit=abc", "invalid_limit"},
		{"identities limit zero", "/v1/pools/p-1/identities?limit=0", "invalid_limit"},
		{"identities bad cursor", "/v1/pools/p-1/identities?cursor=2026-13-99", "invalid_cursor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := doJSON(t, h, http.MethodGet, tc.path, "tenant-1", nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal error body: %v: %s", err, w.Body.String())
			}
			if body.Error != tc.wantCode {
				t.Fatalf("expected error code %q, got %q", tc.wantCode, body.Error)
			}
		})
	}
}

// limitSpyStorage records the limit the handlers pass to the list methods so the
// MaxListLimit cap is observable without seeding 500+ rows.
type limitSpyStorage struct {
	Storage
	poolLimit  int
	identLimit int
}

func (s *limitSpyStorage) ListPools(tenantID string, limit int, cursor time.Time) ([]Pool, error) {
	s.poolLimit = limit
	return s.Storage.ListPools(tenantID, limit, cursor)
}

func (s *limitSpyStorage) ListIdentities(tenantID, poolID string, limit int, cursor time.Time) ([]Identity, error) {
	s.identLimit = limit
	return s.Storage.ListIdentities(tenantID, poolID, limit, cursor)
}

func TestListPagination_LimitDefaultAndCap(t *testing.T) {
	srv := newTestServer(t)
	spy := &limitSpyStorage{Storage: srv.Storage}
	srv.Storage = spy
	h := srv.Handler()

	// Seed a pool so the identities endpoint reaches storage.
	w := doJSON(t, h, http.MethodPost, "/v1/pools", "tenant-1",
		CreatePoolRequest{Name: "pool", Size: 1, PersonaIDs: []string{"p"}})
	var pool Pool
	_ = json.Unmarshal(w.Body.Bytes(), &pool)

	// Above MaxListLimit -> capped, not an error.
	w = doJSON(t, h, http.MethodGet, "/v1/pools?limit=9999", "tenant-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("oversized limit should be capped, got %d: %s", w.Code, w.Body.String())
	}
	if spy.poolLimit != MaxListLimit {
		t.Fatalf("pool limit: want %d, got %d", MaxListLimit, spy.poolLimit)
	}
	w = doJSON(t, h, http.MethodGet, "/v1/pools/"+pool.ID+"/identities?limit=9999", "tenant-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("oversized identity limit should be capped, got %d: %s", w.Code, w.Body.String())
	}
	if spy.identLimit != MaxListLimit {
		t.Fatalf("identity limit: want %d, got %d", MaxListLimit, spy.identLimit)
	}

	// No limit param -> default.
	w = doJSON(t, h, http.MethodGet, "/v1/pools", "tenant-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("default list: %d", w.Code)
	}
	if spy.poolLimit != DefaultListLimit {
		t.Fatalf("default pool limit: want %d, got %d", DefaultListLimit, spy.poolLimit)
	}
}

func TestListPools_TwoPageWalk(t *testing.T) {
	srv := newTestServer(t)
	withTickingClock(srv)
	h := srv.Handler()

	var ids []string
	for _, name := range []string{"pool-a", "pool-b", "pool-c"} {
		w := doJSON(t, h, http.MethodPost, "/v1/pools", "tenant-1",
			CreatePoolRequest{Name: name, Size: 1, PersonaIDs: []string{"p"}})
		if w.Code != http.StatusCreated {
			t.Fatalf("create %s: %d", name, w.Code)
		}
		var p Pool
		_ = json.Unmarshal(w.Body.Bytes(), &p)
		ids = append(ids, p.ID)
	}

	// Page 1: two newest, DESC, full page -> next_cursor present.
	w := doJSON(t, h, http.MethodGet, "/v1/pools?limit=2", "tenant-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("page1: %d %s", w.Code, w.Body.String())
	}
	var page1 PoolListResponse
	_ = json.Unmarshal(w.Body.Bytes(), &page1)
	if len(page1.Items) != 2 || page1.Items[0].ID != ids[2] || page1.Items[1].ID != ids[1] {
		t.Fatalf("page1 wrong: %+v", page1.Items)
	}
	if page1.NextCursor == "" {
		t.Fatalf("expected next_cursor on a full page")
	}

	// Page 2: strictly older than the cursor, short page -> no next_cursor.
	w = doJSON(t, h, http.MethodGet, "/v1/pools?limit=2&cursor="+page1.NextCursor, "tenant-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("page2: %d %s", w.Code, w.Body.String())
	}
	var page2 PoolListResponse
	_ = json.Unmarshal(w.Body.Bytes(), &page2)
	if len(page2.Items) != 1 || page2.Items[0].ID != ids[0] {
		t.Fatalf("page2 wrong: %+v", page2.Items)
	}
	if page2.NextCursor != "" {
		t.Fatalf("final page should not emit a cursor, got %q", page2.NextCursor)
	}
}

func TestListIdentities_TwoPageWalk(t *testing.T) {
	srv := newTestServer(t)
	withTickingClock(srv)
	h := srv.Handler()

	w := doJSON(t, h, http.MethodPost, "/v1/pools", "tenant-1",
		CreatePoolRequest{Name: "pool", Size: 3, PersonaIDs: []string{"p"}})
	if w.Code != http.StatusCreated {
		t.Fatalf("create pool: %d", w.Code)
	}
	var pool Pool
	_ = json.Unmarshal(w.Body.Bytes(), &pool)

	var ids []string
	for _, sub := range []string{"sub-a", "sub-b", "sub-c"} {
		w := doJSON(t, h, http.MethodPost, "/v1/pools/"+pool.ID+"/identities", "tenant-1",
			AddIdentityRequest{SubjectID: sub})
		if w.Code != http.StatusCreated {
			t.Fatalf("add %s: %d", sub, w.Code)
		}
		var ident Identity
		_ = json.Unmarshal(w.Body.Bytes(), &ident)
		ids = append(ids, ident.ID)
	}

	// Page 1: two newest, DESC, full page -> next_cursor present.
	w = doJSON(t, h, http.MethodGet, "/v1/pools/"+pool.ID+"/identities?limit=2", "tenant-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("page1: %d %s", w.Code, w.Body.String())
	}
	var page1 IdentityListResponse
	_ = json.Unmarshal(w.Body.Bytes(), &page1)
	if len(page1.Items) != 2 || page1.Items[0].ID != ids[2] || page1.Items[1].ID != ids[1] {
		t.Fatalf("page1 wrong: %+v", page1.Items)
	}
	if page1.NextCursor == "" {
		t.Fatalf("expected next_cursor on a full page")
	}

	// Page 2: the oldest identity, short page -> no next_cursor.
	w = doJSON(t, h, http.MethodGet,
		"/v1/pools/"+pool.ID+"/identities?limit=2&cursor="+page1.NextCursor, "tenant-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("page2: %d %s", w.Code, w.Body.String())
	}
	var page2 IdentityListResponse
	_ = json.Unmarshal(w.Body.Bytes(), &page2)
	if len(page2.Items) != 1 || page2.Items[0].ID != ids[0] {
		t.Fatalf("page2 wrong: %+v", page2.Items)
	}
	if page2.NextCursor != "" {
		t.Fatalf("final page should not emit a cursor, got %q", page2.NextCursor)
	}

	// Pagination doesn't change claim semantics: claim still picks the OLDEST available.
	w = doJSON(t, h, http.MethodPost, "/v1/pools/"+pool.ID+"/claim", "tenant-1",
		ClaimRequest{PersonaID: "p", InstallID: "inst-1"})
	if w.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", w.Code, w.Body.String())
	}
	var claimed Identity
	_ = json.Unmarshal(w.Body.Bytes(), &claimed)
	if claimed.ID != ids[0] {
		t.Fatalf("claim should still pick the oldest identity %s, got %s", ids[0], claimed.ID)
	}
}

func TestAddIdentity_PoolFull(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	w := doJSON(t, h, http.MethodPost, "/v1/pools", "tenant-1",
		CreatePoolRequest{Name: "pool", Size: 1, PersonaIDs: []string{"p"}})
	var pool Pool
	_ = json.Unmarshal(w.Body.Bytes(), &pool)

	// First fits.
	w = doJSON(t, h, http.MethodPost, "/v1/pools/"+pool.ID+"/identities", "tenant-1",
		AddIdentityRequest{SubjectID: "a"})
	if w.Code != http.StatusCreated {
		t.Fatalf("first add: %d", w.Code)
	}
	// Second exceeds.
	w = doJSON(t, h, http.MethodPost, "/v1/pools/"+pool.ID+"/identities", "tenant-1",
		AddIdentityRequest{SubjectID: "b"})
	if w.Code != http.StatusConflict {
		t.Fatalf("second add: expected 409, got %d", w.Code)
	}
}

func TestRevoke_IsTerminal(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	w := doJSON(t, h, http.MethodPost, "/v1/pools", "tenant-1",
		CreatePoolRequest{Name: "pool", Size: 1, PersonaIDs: []string{"p"}})
	var pool Pool
	_ = json.Unmarshal(w.Body.Bytes(), &pool)

	w = doJSON(t, h, http.MethodPost, "/v1/pools/"+pool.ID+"/identities", "tenant-1",
		AddIdentityRequest{SubjectID: "s"})
	var ident Identity
	_ = json.Unmarshal(w.Body.Bytes(), &ident)

	w = doJSON(t, h, http.MethodPost, "/v1/identities/"+ident.ID+"/revoke", "tenant-1", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", w.Code)
	}
	// Release of revoked must 409.
	w = doJSON(t, h, http.MethodPost, "/v1/identities/"+ident.ID+"/release", "tenant-1", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("release after revoke: expected 409, got %d", w.Code)
	}
	// Claim must 409 — no available.
	w = doJSON(t, h, http.MethodPost, "/v1/pools/"+pool.ID+"/claim", "tenant-1",
		ClaimRequest{PersonaID: "p", InstallID: "i"})
	if w.Code != http.StatusConflict {
		t.Fatalf("claim after revoke: expected 409, got %d", w.Code)
	}
}
