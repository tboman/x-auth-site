package internal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestIdentityAnchorMem covers the in-memory anchor store: create, the
// (tenant, type, value) conflict, and tenant-scoped newest-first listing.
func TestIdentityAnchorMem(t *testing.T) {
	store := NewMemStorage()
	now := time.Now().UTC()

	phone := IdentityAnchor{
		ID: "ian_1", UserID: "usr_a", TenantID: "ten_acme",
		Type: AnchorPhone, Value: "+15551230001", CreatedAt: now,
	}
	if _, err := store.CreateIdentityAnchor(phone); err != nil {
		t.Fatalf("create phone anchor: %v", err)
	}
	// Passkey for the same user, slightly newer.
	pk := IdentityAnchor{
		ID: "ian_2", UserID: "usr_a", TenantID: "ten_acme",
		Type: AnchorPasskey, Value: "cred-abc", CreatedAt: now.Add(time.Second),
	}
	if _, err := store.CreateIdentityAnchor(pk); err != nil {
		t.Fatalf("create passkey anchor: %v", err)
	}
	// A phone anchor in a different tenant must not leak in.
	if _, err := store.CreateIdentityAnchor(IdentityAnchor{
		ID: "ian_3", UserID: "usr_b", TenantID: "ten_beta",
		Type: AnchorPhone, Value: "+15551239999", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create beta anchor: %v", err)
	}

	// Re-using (tenant, type, value) → conflict.
	if _, err := store.CreateIdentityAnchor(IdentityAnchor{
		ID: "ian_dup", UserID: "usr_c", TenantID: "ten_acme",
		Type: AnchorPhone, Value: "+15551230001", CreatedAt: now,
	}); err != ErrConflict {
		t.Fatalf("dup anchor: want ErrConflict, got %v", err)
	}

	got, err := store.ListIdentityAnchors("ten_acme")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ten_acme should have 2 anchors, got %d: %+v", len(got), got)
	}
	// Newest-first: the passkey (now+1s) precedes the phone (now).
	if got[0].ID != "ian_2" || got[1].ID != "ian_1" {
		t.Fatalf("anchors not newest-first: %+v", got)
	}
}

// TestIdentityTableRows is a focused unit test on the shared renderer: the
// primary email, phone/passkey chips, and the verified/unverified markers.
func TestIdentityTableRows(t *testing.T) {
	now := time.Now().UTC()
	verified := now.Add(-time.Hour)
	users := []User{{ID: "usr_a", Email: "a@acme.test", CreatedAt: now}}
	anchors := []IdentityAnchor{
		{ID: "ian_p", UserID: "usr_a", Type: AnchorPhone, Value: "+15551230001", CreatedAt: now}, // unverified
		{ID: "ian_k", UserID: "usr_a", Type: AnchorPasskey, Value: "cred-xyz", VerifiedAt: &verified, CreatedAt: now},
	}
	out := identityTableRows(users, anchors)
	for _, want := range []string{"a@acme.test", "+15551230001", "cred-xyz", "unverified", "verified"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered rows missing %q:\n%s", want, out)
		}
	}

	// Empty set → single placeholder row.
	if empty := identityTableRows(nil, nil); !strings.Contains(empty, "No identities yet") {
		t.Errorf("empty rows missing placeholder:\n%s", empty)
	}
}

// TestAdminTenantDetailShowsIdentities pins the master-admin drill-down: the
// tenant list links to the detail page, which lists every identity with its
// email plus phone/passkey anchors.
func TestAdminTenantDetailShowsIdentities(t *testing.T) {
	r, store := newAdminRouter(t, "tomasboman@gmail.com")
	now := time.Now().UTC()
	mustUser(t, store, "usr_a1", "ten_acme", "a1@acme.test", now)
	mustUser(t, store, "usr_a2", "ten_acme", "a2@acme.test", now.Add(time.Second))
	verified := now
	if _, err := store.CreateIdentityAnchor(IdentityAnchor{
		ID: "ian_p", UserID: "usr_a1", TenantID: "ten_acme",
		Type: AnchorPhone, Value: "+15551230001", CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed phone: %v", err)
	}
	if _, err := store.CreateIdentityAnchor(IdentityAnchor{
		ID: "ian_k", UserID: "usr_a2", TenantID: "ten_acme",
		Type: AnchorPasskey, Value: "cred-xyz", VerifiedAt: &verified, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed passkey: %v", err)
	}

	cookie := adminCookie(t, r, store, "tomasboman@gmail.com")

	// The tenant list links to the detail page.
	home := httptest.NewRequest(http.MethodGet, "/admin", nil)
	home.AddCookie(&http.Cookie{Name: adminSessionCookie, Value: cookie})
	hw := httptest.NewRecorder()
	r.ServeHTTP(hw, home)
	if !strings.Contains(hw.Body.String(), `href="/admin/tenants/ten_acme"`) {
		t.Fatalf("tenant list missing detail link:\n%s", hw.Body.String())
	}

	// The detail page lists the identities and their anchors.
	det := httptest.NewRequest(http.MethodGet, "/admin/tenants/ten_acme", nil)
	det.AddCookie(&http.Cookie{Name: adminSessionCookie, Value: cookie})
	dw := httptest.NewRecorder()
	r.ServeHTTP(dw, det)
	if dw.Code != http.StatusOK {
		t.Fatalf("tenant detail: want 200, got %d (%s)", dw.Code, dw.Body.String())
	}
	body := dw.Body.String()
	for _, want := range []string{"a1@acme.test", "a2@acme.test", "+15551230001", "cred-xyz", "unverified", "verified"} {
		if !strings.Contains(body, want) {
			t.Errorf("tenant detail missing %q:\n%s", want, body)
		}
	}
}

// TestAdminTenantDetailRequiresAdmin rejects a non-admin (no staff cookie).
func TestAdminTenantDetailRequiresAdmin(t *testing.T) {
	r, _ := newAdminRouter(t, "tomasboman@gmail.com")
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/ten_acme", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("anon tenant detail: want 403, got %d", w.Code)
	}
}

// TestOwnerDashboardListsUsers pins that the tenant-owner dashboard exposes the
// workspace's user list (not just a count), including anchor columns.
func TestOwnerDashboardListsUsers(t *testing.T) {
	r, store := newAdminRouter(t)
	w := driveSignup(t, r, store, "owner@acme.test", "Acme", "")
	ownerCookie := sessionCookie(w, ownerSessionCookie)
	if ownerCookie == "" {
		t.Fatal("missing owner cookie")
	}
	// An end user signs into the tenant, with a phone anchor on file.
	now := time.Now().UTC()
	mustUser(t, store, "usr_end", "ten_acme", "enduser@acme.test", now)
	if _, err := store.CreateIdentityAnchor(IdentityAnchor{
		ID: "ian_end", UserID: "usr_end", TenantID: "ten_acme",
		Type: AnchorPhone, Value: "+15557654321", CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed anchor: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: ownerSessionCookie, Value: ownerCookie})
	dw := httptest.NewRecorder()
	r.ServeHTTP(dw, req)
	if dw.Code != http.StatusOK {
		t.Fatalf("owner dashboard: want 200, got %d", dw.Code)
	}
	body := dw.Body.String()
	for _, want := range []string{">Users<", "enduser@acme.test", "+15557654321"} {
		if !strings.Contains(body, want) {
			t.Errorf("owner dashboard missing %q:\n%s", want, body)
		}
	}
}
