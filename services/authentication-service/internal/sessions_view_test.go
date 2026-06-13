package internal

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestListSessionsMem covers tenant-scoping, newest-first order, and the cap.
func TestListSessionsMem(t *testing.T) {
	store := NewMemStorage()
	base := time.Now().UTC()
	mk := func(id, tenant string, ts time.Time) {
		if _, err := store.CreateSession(Session{
			ID: id, TenantID: tenant, UserID: "u", RiskLevel: RiskLow,
			CreatedAt: ts, UpdatedAt: ts, ExpiresAt: ts.Add(time.Hour),
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	mk("ses_a1", "ten_a", base)
	mk("ses_a2", "ten_a", base.Add(time.Second)) // newest in ten_a
	mk("ses_b1", "ten_b", base)

	got, err := store.ListSessions("ten_a", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 || got[0].ID != "ses_a2" || got[1].ID != "ses_a1" {
		t.Fatalf("ten_a sessions wrong/order: %+v", got)
	}
	// Cap.
	if capped, _ := store.ListSessions("ten_a", 1); len(capped) != 1 || capped[0].ID != "ses_a2" {
		t.Fatalf("cap not applied: %+v", capped)
	}
}

// TestStepUpTracker covers Start/Done/ListByTenant and tenant scoping.
func TestStepUpTracker(t *testing.T) {
	tr := NewStepUpTracker(10 * time.Minute)
	now := time.Now().UTC()
	tr.Start(StepUpAttempt{FlowID: "f1", TenantID: "ten_a", UserID: "u1", Method: "sms", StartedAt: now})
	tr.Start(StepUpAttempt{FlowID: "f2", TenantID: "ten_a", UserID: "u2", Method: "sms", StartedAt: now.Add(time.Second)})
	tr.Start(StepUpAttempt{FlowID: "f3", TenantID: "ten_b", UserID: "u3", Method: "sms", StartedAt: now})

	got := tr.ListByTenant("ten_a")
	if len(got) != 2 || got[0].FlowID != "f2" { // newest first
		t.Fatalf("ten_a attempts wrong: %+v", got)
	}
	tr.Done("f2")
	if got := tr.ListByTenant("ten_a"); len(got) != 1 || got[0].FlowID != "f1" {
		t.Fatalf("after Done: %+v", got)
	}
	// nil tracker is a no-op.
	var nilTr *StepUpTracker
	nilTr.Start(StepUpAttempt{FlowID: "x"})
	if nilTr.ListByTenant("ten_a") != nil {
		t.Fatal("nil tracker should list nil")
	}
}

// TestRevokeSessionHelper: invalidates, idempotent, ErrNotFound, tenant-scoped.
func TestRevokeSessionHelper(t *testing.T) {
	store := NewMemStorage()
	now := time.Now().UTC()
	if _, err := store.CreateSession(Session{
		ID: "ses_1", TenantID: "ten_a", UserID: "u", RiskLevel: RiskLow,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Wrong tenant → ErrNotFound.
	if err := revokeSession(store, "ten_b", "ses_1"); err != ErrNotFound {
		t.Fatalf("cross-tenant revoke: want ErrNotFound, got %v", err)
	}
	if err := revokeSession(store, "ten_a", "ses_1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, _ := store.GetSession("ten_a", "ses_1")
	if got.InvalidatedAt == nil {
		t.Fatal("session should be invalidated")
	}
	// Idempotent.
	if err := revokeSession(store, "ten_a", "ses_1"); err != nil {
		t.Fatalf("second revoke should be no-op: %v", err)
	}
}

// TestOwnerDashboardSessionsAndRevoke: the owner dashboard lists sessions, shows
// the in-progress step-up block, and the owner can revoke a workspace session.
func TestOwnerDashboardSessionsAndRevoke(t *testing.T) {
	r, store := newAdminRouter(t)
	w := driveSignup(t, r, store, "owner@acme.test", "Acme", "")
	ownerCookie := sessionCookie(w, ownerSessionCookie)
	if ownerCookie == "" {
		t.Fatal("missing owner cookie")
	}
	// An end-user session to revoke (not the owner's own, so the cookie survives).
	now := time.Now().UTC()
	mustUser(t, store, "usr_end", "ten_acme", "enduser@acme.test", now)
	if _, err := store.CreateSession(Session{
		ID: "ses_end", TenantID: "ten_acme", UserID: "usr_end", RiskLevel: RiskLow,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	body := func() string {
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: ownerCookie})
		dw := httptest.NewRecorder()
		r.ServeHTTP(dw, req)
		if dw.Code != http.StatusOK {
			t.Fatalf("dashboard: want 200, got %d", dw.Code)
		}
		return dw.Body.String()
	}

	b := body()
	for _, want := range []string{">Sessions<", "enduser@acme.test", "In-progress step-up", "/admin/owner/sessions/revoke"} {
		if !strings.Contains(b, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}

	// Revoke the end-user session.
	rw := postForm(t, r, "/admin/owner/sessions/revoke", url.Values{"session_id": {"ses_end"}},
		&http.Cookie{Name: ownerSessionCookie, Value: ownerCookie})
	if rw.Code != http.StatusFound {
		t.Fatalf("revoke: want 302, got %d (%s)", rw.Code, rw.Body.String())
	}
	got, _ := store.GetSession("ten_acme", "ses_end")
	if got.InvalidatedAt == nil {
		t.Fatal("end-user session should be revoked")
	}
}

// TestAdminTenantSessionsAndRevoke: the staff tenant view lists sessions and
// staff can revoke any tenant's session.
func TestAdminTenantSessionsAndRevoke(t *testing.T) {
	r, store := newAdminRouter(t, "tomasboman@gmail.com")
	now := time.Now().UTC()
	mustUser(t, store, "usr_a1", "ten_acme", "a1@acme.test", now)
	if _, err := store.CreateSession(Session{
		ID: "ses_a1", TenantID: "ten_acme", UserID: "usr_a1", RiskLevel: RiskHigh,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	cookie := adminCookie(t, r, store, "tomasboman@gmail.com")

	det := httptest.NewRequest(http.MethodGet, "/admin/tenants/ten_acme", nil)
	det.AddCookie(&http.Cookie{Name: adminSessionCookie, Value: cookie})
	dw := httptest.NewRecorder()
	r.ServeHTTP(dw, det)
	if dw.Code != http.StatusOK {
		t.Fatalf("tenant detail: want 200, got %d", dw.Code)
	}
	b := dw.Body.String()
	for _, want := range []string{">Sessions<", "a1@acme.test", "ses_a1", "In-progress step-up", "/admin/sessions/revoke"} {
		if !strings.Contains(b, want) {
			t.Errorf("tenant detail missing %q", want)
		}
	}

	// Staff revoke.
	rw := postForm(t, r, "/admin/sessions/revoke",
		url.Values{"session_id": {"ses_a1"}, "tenant_id": {"ten_acme"}},
		&http.Cookie{Name: adminSessionCookie, Value: cookie})
	if rw.Code != http.StatusFound {
		t.Fatalf("staff revoke: want 302, got %d (%s)", rw.Code, rw.Body.String())
	}
	got, _ := store.GetSession("ten_acme", "ses_a1")
	if got.InvalidatedAt == nil {
		t.Fatal("session should be revoked by staff")
	}
}

// TestSessionRevokeRequiresAuth: both revoke endpoints reject unauthenticated callers.
func TestSessionRevokeRequiresAuth(t *testing.T) {
	r, _ := newAdminRouter(t, "tomasboman@gmail.com")
	for _, path := range []string{"/admin/sessions/revoke", "/admin/owner/sessions/revoke"} {
		w := postForm(t, r, path, url.Values{"session_id": {"x"}, "tenant_id": {"ten_x"}})
		if w.Code != http.StatusForbidden {
			t.Errorf("%s without auth: want 403, got %d", path, w.Code)
		}
	}
}
