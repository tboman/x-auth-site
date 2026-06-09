package internal

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// newPGStorage connects to the DSN in POOL_PG_DSN and returns a clean PGStorage.
// The test is skipped when the env var is unset so unit-test CI without a DB
// (and routine `go test ./...` runs on developer laptops) stays green. When it
// IS set, the test truncates the pools + identities tables so it's safe to re-run.
//
// Recommended local setup:
//   docker run --rm -d --name xauth-pg -e POSTGRES_PASSWORD=postgres \
//     -e POSTGRES_DB=pool_db -p 5432:5432 postgres:16
//   # then apply services/pool-service/migrations/000001_init.up.sql
//   POOL_PG_DSN="postgres://postgres:postgres@localhost:5432/pool_db?sslmode=disable" \
//     go test ./services/pool-service/internal/ -run PG
func newPGStorage(t *testing.T) *PGStorage {
	t.Helper()
	dsn := os.Getenv("POOL_PG_DSN")
	if dsn == "" {
		t.Skip("POOL_PG_DSN not set; skipping PGStorage integration test")
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
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE identities, pools"); err != nil {
		pool.Close()
		t.Fatalf("truncate: %v (is the migration applied?)", err)
	}
	t.Cleanup(func() { pool.Close() })
	return NewPGStorage(pool)
}

// seedPool creates a pool for tenant-a and returns it.
func seedPool(t *testing.T, s *PGStorage, size int, personaIDs []string, createdAt time.Time) Pool {
	t.Helper()
	p, err := s.CreatePool(Pool{
		ID:         newUUID(),
		TenantID:   "tenant-a",
		Name:       "support-agents",
		Size:       size,
		PersonaIDs: personaIDs,
		CreatedAt:  createdAt,
		UpdatedAt:  createdAt,
	})
	if err != nil {
		t.Fatalf("seed pool: %v", err)
	}
	return p
}

func TestPGStoragePoolRoundTrip(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := seedPool(t, s, 5, []string{"p-support", "p-billing"}, now)

	got, err := s.GetPool("tenant-a", p.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "support-agents" || got.Size != 5 {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if len(got.PersonaIDs) != 2 || got.PersonaIDs[0] != "p-support" {
		t.Fatalf("persona_ids lost: %+v", got.PersonaIDs)
	}
	if !got.CreatedAt.Equal(now) {
		t.Fatalf("created_at mismatch: got %v want %v", got.CreatedAt, now)
	}

	// Tenant isolation: other tenant can't see it.
	if _, err := s.GetPool("tenant-b", p.ID); !errors.Is(err, ErrPoolNotFound) {
		t.Fatalf("cross-tenant get should be ErrPoolNotFound, got %v", err)
	}

	// List is ordered by created_at ASC, id ASC.
	older := seedPool(t, s, 1, nil, now.Add(-time.Hour))
	pools, err := s.ListPools("tenant-a")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(pools) != 2 || pools[0].ID != older.ID {
		t.Fatalf("list order wrong: %+v", pools)
	}
	// nil persona_ids round-trips as an empty (non-nil) slice.
	if pools[0].PersonaIDs == nil || len(pools[0].PersonaIDs) != 0 {
		t.Fatalf("nil persona_ids should round-trip as []: %+v", pools[0].PersonaIDs)
	}
}

func TestPGStorageDeletePoolCascades(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := seedPool(t, s, 5, nil, now)
	ident, err := s.AddIdentity("tenant-a", p.ID, Identity{
		ID: newUUID(), PoolID: p.ID, SubjectID: "agent-001",
		Status: StatusAvailable, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("add identity: %v", err)
	}

	// Cross-tenant delete is invisible.
	if err := s.DeletePool("tenant-b", p.ID); !errors.Is(err, ErrPoolNotFound) {
		t.Fatalf("cross-tenant delete should be ErrPoolNotFound, got %v", err)
	}
	if err := s.DeletePool("tenant-a", p.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.DeletePool("tenant-a", p.ID); !errors.Is(err, ErrPoolNotFound) {
		t.Fatalf("double delete should be ErrPoolNotFound, got %v", err)
	}
	// Identity went with the pool (FK ON DELETE CASCADE).
	if _, err := s.GetIdentity("tenant-a", ident.ID); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("identity should cascade-delete, got %v", err)
	}
}

func TestPGStorageAddIdentityPoolFull(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := seedPool(t, s, 1, nil, now)

	first := Identity{
		ID: newUUID(), PoolID: p.ID, SubjectID: "agent-001",
		Status: StatusAvailable, CreatedAt: now, UpdatedAt: now,
	}
	if _, err := s.AddIdentity("tenant-a", p.ID, first); err != nil {
		t.Fatalf("add 1: %v", err)
	}
	second := first
	second.ID = newUUID()
	second.SubjectID = "agent-002"
	if _, err := s.AddIdentity("tenant-a", p.ID, second); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("add beyond size should be ErrPoolFull, got %v", err)
	}
	// Missing / cross-tenant pool.
	if _, err := s.AddIdentity("tenant-b", p.ID, second); !errors.Is(err, ErrPoolNotFound) {
		t.Fatalf("cross-tenant add should be ErrPoolNotFound, got %v", err)
	}

	idents, err := s.ListIdentities("tenant-a", p.ID)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(idents) != 1 || idents[0].SubjectID != "agent-001" {
		t.Fatalf("list mismatch: %+v", idents)
	}
	if _, err := s.ListIdentities("tenant-b", p.ID); !errors.Is(err, ErrPoolNotFound) {
		t.Fatalf("cross-tenant list should be ErrPoolNotFound, got %v", err)
	}
}

func TestPGStorageClaimReleaseRevoke(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := seedPool(t, s, 5, []string{"p-support"}, now)

	// Oldest available identity wins the claim.
	older := Identity{
		ID: newUUID(), PoolID: p.ID, SubjectID: "agent-old",
		Status: StatusAvailable, CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
	}
	newer := Identity{
		ID: newUUID(), PoolID: p.ID, SubjectID: "agent-new",
		Status: StatusAvailable, CreatedAt: now, UpdatedAt: now,
	}
	for _, ident := range []Identity{newer, older} {
		if _, err := s.AddIdentity("tenant-a", p.ID, ident); err != nil {
			t.Fatalf("seed identity: %v", err)
		}
	}

	// Persona not in pool.persona_ids -> ErrPersonaNotEligible.
	if _, err := s.ClaimIdentity("tenant-a", p.ID, "p-other", "inst-1"); !errors.Is(err, ErrPersonaNotEligible) {
		t.Fatalf("want ErrPersonaNotEligible, got %v", err)
	}

	claimed, err := s.ClaimIdentity("tenant-a", p.ID, "p-support", "inst-1")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if claimed.ID != older.ID || claimed.Status != StatusClaimed {
		t.Fatalf("claim should pick oldest available: %+v", claimed)
	}
	if claimed.ClaimedByInstallID == nil || *claimed.ClaimedByInstallID != "inst-1" {
		t.Fatalf("claimed_by_install_id not set: %+v", claimed)
	}

	// Exhaust the pool, then claim again -> ErrNoAvailableIdentity.
	if _, err := s.ClaimIdentity("tenant-a", p.ID, "p-support", "inst-2"); err != nil {
		t.Fatalf("claim 2: %v", err)
	}
	if _, err := s.ClaimIdentity("tenant-a", p.ID, "p-support", "inst-3"); !errors.Is(err, ErrNoAvailableIdentity) {
		t.Fatalf("want ErrNoAvailableIdentity, got %v", err)
	}

	// Release: claimed -> available, install id cleared.
	released, err := s.ReleaseIdentity("tenant-a", claimed.ID)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if released.Status != StatusAvailable || released.ClaimedByInstallID != nil {
		t.Fatalf("release mismatch: %+v", released)
	}
	if !released.CreatedAt.Equal(older.CreatedAt) {
		t.Fatalf("release should preserve created_at: got %v want %v", released.CreatedAt, older.CreatedAt)
	}
	// Idempotent: releasing an available identity returns it unchanged.
	again, err := s.ReleaseIdentity("tenant-a", claimed.ID)
	if err != nil {
		t.Fatalf("idempotent release: %v", err)
	}
	if !again.UpdatedAt.Equal(released.UpdatedAt) {
		t.Fatalf("idempotent release should not rewrite updated_at: %v vs %v", again.UpdatedAt, released.UpdatedAt)
	}
	// Cross-tenant release is invisible.
	if _, err := s.ReleaseIdentity("tenant-b", claimed.ID); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("cross-tenant release should be ErrIdentityNotFound, got %v", err)
	}

	// Revoke is terminal; revoked identities cannot be released.
	if err := s.RevokeIdentity("tenant-a", claimed.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.ReleaseIdentity("tenant-a", claimed.ID); !errors.Is(err, ErrIdentityRevoked) {
		t.Fatalf("release of revoked should be ErrIdentityRevoked, got %v", err)
	}
	if err := s.RevokeIdentity("tenant-b", claimed.ID); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("cross-tenant revoke should be ErrIdentityNotFound, got %v", err)
	}
}
