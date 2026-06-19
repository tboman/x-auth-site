package internal

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func loadedManager(entries ...mdsEntry) *Manager {
	m := &Manager{log: testLogger()}
	idx := buildIndex(
		&mdsPayload{Number: 42, NextUpdate: "2030-01-01", Entries: entries},
		SnapshotMeta{Number: 42, NextUpdate: "2030-01-01", FetchedAt: "2026-06-19T00:00:00Z", Source: "network"},
	)
	m.idx.Store(idx)
	return m
}

func do(t *testing.T, h http.Handler, method, target, body string, tenant bool) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rdr)
	if tenant {
		req.Header.Set("X-Tenant-Id", "demo")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestGetAuthenticator(t *testing.T) {
	e := testEntry("ee882879-721c-4913-9775-3dfcce97072a", "YubiKey 5",
		[]string{"hardware"}, "FIDO_CERTIFIED_L2", "hmac-secret")
	h := NewHandlers(loadedManager(e), testLogger()).Router(nil)

	rec := do(t, h, http.MethodGet, "/v1/authenticators/ee882879-721c-4913-9775-3dfcce97072a", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var p RiskProfile
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.AAGUID != "ee882879-721c-4913-9775-3dfcce97072a" || p.Binding != BindingHardware {
		t.Fatalf("unexpected profile: %+v", p)
	}
}

func TestGetAuthenticator_NotFound(t *testing.T) {
	h := NewHandlers(loadedManager(), testLogger()).Router(nil)
	rec := do(t, h, http.MethodGet, "/v1/authenticators/00000000-0000-0000-0000-000000000000", "", true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", rec.Code)
	}
}

func TestGetAuthenticator_MissingTenant(t *testing.T) {
	h := NewHandlers(loadedManager(), testLogger()).Router(nil)
	rec := do(t, h, http.MethodGet, "/v1/authenticators/x", "", false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 (missing tenant)", rec.Code)
	}
}

func TestEndpoints_UnavailableBeforeLoad(t *testing.T) {
	m := &Manager{log: testLogger()}
	h := NewHandlers(m, testLogger()).Router(nil)
	rec := do(t, h, http.MethodGet, "/v1/authenticators/x", "", true)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503 before first load", rec.Code)
	}
}

func TestPostAttestation(t *testing.T) {
	const flagUP, flagUV, flagBE = 1, 4, 8
	obj := makeAttestationObject(t, flagUP|flagUV|flagBE)
	h := NewHandlers(loadedManager(), testLogger()).Router(nil)

	rec := do(t, h, http.MethodPost, "/v1/attestation", `{"attestationObject":"`+obj+`"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var p RiskProfile
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.Binding != BindingSynced {
		t.Fatalf("binding=%q, want synced (backup-eligible)", p.Binding)
	}
	if p.Attestation == nil || !p.Attestation.BackupEligible {
		t.Fatalf("attestation flags missing: %+v", p.Attestation)
	}
}

func TestPostAttestation_BadBody(t *testing.T) {
	h := NewHandlers(loadedManager(), testLogger()).Router(nil)
	rec := do(t, h, http.MethodPost, "/v1/attestation", `{}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 for empty attestation", rec.Code)
	}
}

func TestListAndStatus(t *testing.T) {
	e1 := testEntry("ee882879-721c-4913-9775-3dfcce97072a", "B Key", []string{"hardware"}, "FIDO_CERTIFIED_L1")
	e2 := testEntry("11111111-2222-3333-4444-555555555555", "A Key", []string{"software"}, "NOT_FIDO_CERTIFIED")
	h := NewHandlers(loadedManager(e1, e2), testLogger()).Router(nil)

	rec := do(t, h, http.MethodGet, "/v1/authenticators?limit=10", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status=%d", rec.Code)
	}
	var lr ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if lr.Total != 2 || len(lr.Profiles) != 2 {
		t.Fatalf("list=%+v, want total 2", lr)
	}
	// Stable order by description: "A Key" before "B Key".
	if lr.Profiles[0].Description != "A Key" {
		t.Fatalf("order wrong: %q first", lr.Profiles[0].Description)
	}

	rec = do(t, h, http.MethodGet, "/v1/mds/status", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status endpoint=%d", rec.Code)
	}
	var st MDSStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if !st.Loaded || st.EntryCount != 2 || st.BlobNumber != 42 {
		t.Fatalf("status=%+v, want loaded/2/42", st)
	}
}
