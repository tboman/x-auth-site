package internal

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newPGStorage connects to the DSN in GRANT_PG_DSN and returns a clean PGStorage.
// The test is skipped when the env var is unset so unit-test CI without a DB
// (and routine `go test ./...` runs on developer laptops) stays green. When it
// IS set, the test truncates the grants and audit_events tables so it's safe to
// re-run.
//
// Recommended local setup:
//
//	docker run --rm -d --name xauth-pg -e POSTGRES_PASSWORD=postgres \
//	  -e POSTGRES_DB=grant_db -p 5432:5432 postgres:16
//	# then apply services/grant-service/migrations/000001_init.up.sql
//	GRANT_PG_DSN="postgres://postgres:postgres@localhost:5432/grant_db?sslmode=disable" \
//	  go test ./services/grant-service/internal/ -run PG
func newPGStorage(t *testing.T) *PGStorage {
	t.Helper()
	dsn := os.Getenv("GRANT_PG_DSN")
	if dsn == "" {
		t.Skip("GRANT_PG_DSN not set; skipping PGStorage integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("pool.Ping: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE grants, audit_events"); err != nil {
		pool.Close()
		t.Fatalf("truncate: %v (is the migration applied?)", err)
	}
	t.Cleanup(func() { pool.Close() })
	return NewPGStorage(pool)
}

func seedGrant(t *testing.T, s *PGStorage, tenantID, installID string, issuedAt time.Time) Grant {
	t.Helper()
	g := Grant{
		ID:               uuid.NewString(),
		TenantID:         tenantID,
		InstallID:        installID,
		IdentityID:       "identity-1",
		PersonaID:        "persona-1",
		AccessTokenHash:  HashToken("tok-" + uuid.NewString()),
		RefreshTokenHash: HashToken("ref-" + uuid.NewString()),
		IssuedAt:         issuedAt,
		ExpiresAt:        issuedAt.Add(15 * time.Minute),
	}
	if _, err := s.Create(g); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	return g
}

func TestPGGrantRoundTrip(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	g := seedGrant(t, s, "tenant-a", "install-1", now)

	got, err := s.Get("tenant-a", g.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.InstallID != "install-1" || got.IdentityID != "identity-1" || got.PersonaID != "persona-1" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if got.AccessTokenHash != g.AccessTokenHash || got.RefreshTokenHash != g.RefreshTokenHash {
		t.Fatalf("hashes lost: %+v", got)
	}
	if !got.IssuedAt.Equal(now) || !got.ExpiresAt.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("timestamps mismatch: %+v", got)
	}
	if got.Status != StatusActive {
		t.Fatalf("status should derive active, got %q", got.Status)
	}

	// Tenant isolation: other tenant can't see it.
	if _, err := s.Get("tenant-b", g.ID); err != ErrNotFound {
		t.Fatalf("cross-tenant get should be ErrNotFound, got %v", err)
	}
}

func TestPGGrantStatusDerivedExpired(t *testing.T) {
	s := newPGStorage(t)
	past := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	g := seedGrant(t, s, "tenant-a", "install-1", past) // expired 45m ago

	got, err := s.Get("tenant-a", g.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != StatusExpired {
		t.Fatalf("status should derive expired, got %q", got.Status)
	}
}

func TestPGGrantRevokeIdempotent(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	g := seedGrant(t, s, "tenant-a", "install-1", now)

	first, alreadyRevoked, err := s.Revoke("tenant-a", g.ID, now.Add(time.Second))
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if alreadyRevoked {
		t.Fatalf("first revoke should report alreadyRevoked=false")
	}
	if first.RevokedAt == nil || !first.RevokedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("revoked_at not set: %+v", first.RevokedAt)
	}
	if first.Status != StatusRevoked {
		t.Fatalf("status should derive revoked, got %q", first.Status)
	}

	// Second revoke is a no-op: alreadyRevoked=true, original revoked_at preserved.
	second, alreadyRevoked, err := s.Revoke("tenant-a", g.ID, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("revoke again: %v", err)
	}
	if !alreadyRevoked {
		t.Fatalf("second revoke should report alreadyRevoked=true")
	}
	if second.RevokedAt == nil || !second.RevokedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("second revoke should preserve original revoked_at, got %+v", second.RevokedAt)
	}

	// Cross-tenant revoke is ErrNotFound.
	if _, _, err := s.Revoke("tenant-b", g.ID, now); err != ErrNotFound {
		t.Fatalf("cross-tenant revoke should be ErrNotFound, got %v", err)
	}
	// Unknown id is ErrNotFound.
	if _, _, err := s.Revoke("tenant-a", uuid.NewString(), now); err != ErrNotFound {
		t.Fatalf("unknown revoke should be ErrNotFound, got %v", err)
	}
}

func TestPGGrantListByInstall(t *testing.T) {
	s := newPGStorage(t)
	base := time.Now().UTC().Truncate(time.Microsecond)
	g0 := seedGrant(t, s, "tenant-a", "install-1", base)
	g1 := seedGrant(t, s, "tenant-a", "install-1", base.Add(time.Second))
	seedGrant(t, s, "tenant-a", "install-2", base) // other install
	seedGrant(t, s, "tenant-b", "install-1", base) // other tenant

	got, err := s.ListByInstall("tenant-a", "install-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 grants, got %d", len(got))
	}
	// Sorted by issued_at ascending.
	if got[0].ID != g0.ID || got[1].ID != g1.ID {
		t.Fatalf("order mismatch: got [%s, %s] want [%s, %s]", got[0].ID, got[1].ID, g0.ID, g1.ID)
	}

	empty, err := s.ListByInstall("tenant-a", "install-none")
	if err != nil {
		t.Fatalf("list empty: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("want 0 grants, got %d", len(empty))
	}
}

func TestPGGrantFindByAccessTokenHash(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	g := seedGrant(t, s, "tenant-a", "install-1", now)

	// Lookup is cross-tenant by design; the handler enforces tenancy on the result.
	got, err := s.FindByAccessTokenHash(g.AccessTokenHash)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.ID != g.ID || got.TenantID != "tenant-a" {
		t.Fatalf("find mismatch: %+v", got)
	}
	if got.Status != StatusActive {
		t.Fatalf("status should derive active, got %q", got.Status)
	}

	if _, err := s.FindByAccessTokenHash(HashToken("unknown-token")); err != ErrNotFound {
		t.Fatalf("unknown hash should be ErrNotFound, got %v", err)
	}
	if _, err := s.FindByAccessTokenHash(""); err != ErrNotFound {
		t.Fatalf("empty hash should be ErrNotFound, got %v", err)
	}
}

func TestPGAuditAppendAndQuery(t *testing.T) {
	s := newPGStorage(t)
	base := time.Now().UTC().Truncate(time.Microsecond)

	mk := func(typ, installID, grantID string, at time.Time, payload map[string]any) AuditEvent {
		e := AuditEvent{
			ID:        uuid.NewString(),
			TenantID:  "tenant-a",
			Type:      typ,
			Actor:     "system",
			InstallID: installID,
			GrantID:   grantID,
			Payload:   payload,
			CreatedAt: at,
		}
		if _, err := s.Append(e); err != nil {
			t.Fatalf("append %s: %v", typ, err)
		}
		return e
	}

	mk("grant_issued", "install-1", "grant-1", base, map[string]any{"persona_id": "persona-1"})
	mk("grant_revoked", "install-1", "grant-1", base.Add(time.Second), nil)
	mk("grant_issued", "install-2", "grant-2", base.Add(2*time.Second), nil)

	// Other tenant's event must never surface.
	if _, err := s.Append(AuditEvent{
		ID: uuid.NewString(), TenantID: "tenant-b", Type: "grant_issued",
		Actor: "system", InstallID: "install-1", CreatedAt: base,
	}); err != nil {
		t.Fatalf("append tenant-b: %v", err)
	}

	// Unfiltered: all 3 tenant-a events, most recent first.
	all, err := s.Query("tenant-a", AuditFilter{Limit: DefaultAuditLimit})
	if err != nil {
		t.Fatalf("query all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("want 3 events, got %d", len(all))
	}
	if all[0].Type != "grant_issued" || all[0].InstallID != "install-2" {
		t.Fatalf("order should be created_at DESC, got first %+v", all[0])
	}
	if all[2].Payload == nil || all[2].Payload["persona_id"] != "persona-1" {
		t.Fatalf("payload lost: %+v", all[2].Payload)
	}
	if all[1].Payload != nil {
		t.Fatalf("nil payload should round-trip nil, got %+v", all[1].Payload)
	}

	// install_id filter.
	byInstall, err := s.Query("tenant-a", AuditFilter{InstallID: "install-1", Limit: 10})
	if err != nil {
		t.Fatalf("query install: %v", err)
	}
	if len(byInstall) != 2 {
		t.Fatalf("install filter want 2, got %d", len(byInstall))
	}

	// type + grant_id filters.
	byType, err := s.Query("tenant-a", AuditFilter{Type: "grant_revoked", GrantID: "grant-1", Limit: 10})
	if err != nil {
		t.Fatalf("query type: %v", err)
	}
	if len(byType) != 1 || byType[0].Type != "grant_revoked" {
		t.Fatalf("type filter mismatch: %+v", byType)
	}

	// since inclusive, until exclusive: [base+1s, base+2s) -> only the revoke event.
	window, err := s.Query("tenant-a", AuditFilter{
		Since: base.Add(time.Second), Until: base.Add(2 * time.Second), Limit: 10,
	})
	if err != nil {
		t.Fatalf("query window: %v", err)
	}
	if len(window) != 1 || window[0].Type != "grant_revoked" {
		t.Fatalf("window filter mismatch: %+v", window)
	}

	// Limit clamps the result set.
	limited, err := s.Query("tenant-a", AuditFilter{Limit: 2})
	if err != nil {
		t.Fatalf("query limit: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("limit want 2, got %d", len(limited))
	}
}
