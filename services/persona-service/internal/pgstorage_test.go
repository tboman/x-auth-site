package internal

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newPGStorage connects to the DSN in PERSONA_PG_DSN and returns a clean PGStorage.
// The test is skipped when the env var is unset so unit-test CI without a DB
// (and routine `go test ./...` runs on developer laptops) stays green. When it
// IS set, the test truncates the personas table so it's safe to re-run.
//
// Recommended local setup:
//
//	docker run --rm -d --name xauth-pg -e POSTGRES_PASSWORD=postgres \
//	  -e POSTGRES_DB=persona_db -p 5432:5432 postgres:16
//	# then apply services/persona-service/migrations/000001_init.up.sql
//	PERSONA_PG_DSN="postgres://postgres:postgres@localhost:5432/persona_db?sslmode=disable" \
//	  go test ./services/persona-service/internal/ -run PG
func newPGStorage(t *testing.T) *PGStorage {
	t.Helper()
	dsn := os.Getenv("PERSONA_PG_DSN")
	if dsn == "" {
		t.Skip("PERSONA_PG_DSN not set; skipping PGStorage integration test")
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
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE personas"); err != nil {
		pool.Close()
		t.Fatalf("truncate: %v (is the migration applied?)", err)
	}
	t.Cleanup(func() { pool.Close() })
	return NewPGStorage(pool)
}

func TestPGStorageRoundTrip(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.NewString()
	p := Persona{
		ID:              id,
		TenantID:        "tenant-a",
		Name:            "analytics-reader",
		Scopes:          []string{"read:reports", "read:dashboards"},
		Claims:          map[string]any{"role": "analyst", "level": float64(2)},
		TokenTTLSeconds: 900,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if _, err := s.Create(p); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Get("tenant-a", id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "analytics-reader" || got.TokenTTLSeconds != 900 {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "read:reports" {
		t.Fatalf("scopes lost: %+v", got.Scopes)
	}
	if got.Claims["role"] != "analyst" || got.Claims["level"] != float64(2) {
		t.Fatalf("claims lost: %+v", got.Claims)
	}
	if !got.CreatedAt.Equal(now) || !got.UpdatedAt.Equal(now) {
		t.Fatalf("timestamps mismatch: %+v", got)
	}

	// Tenant isolation: other tenant can't see it.
	if _, err := s.Get("tenant-b", id); err != ErrNotFound {
		t.Fatalf("cross-tenant get should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageNilClaimsRoundTrip(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.NewString()
	if _, err := s.Create(Persona{
		ID: id, TenantID: "tenant-a", Name: "bare", Scopes: []string{},
		TokenTTLSeconds: DefaultTokenTTLSeconds, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Get("tenant-a", id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Claims != nil {
		t.Fatalf("nil claims should stay nil, got %+v", got.Claims)
	}
	if got.Scopes == nil || len(got.Scopes) != 0 {
		t.Fatalf("empty scopes should round-trip as []: %+v", got.Scopes)
	}
}

func TestPGStorageListOrdering(t *testing.T) {
	s := newPGStorage(t)
	base := time.Now().UTC().Truncate(time.Microsecond)
	ids := make([]string, 3)
	for i := 0; i < 3; i++ {
		ids[i] = uuid.NewString()
		ts := base.Add(time.Duration(i) * time.Second)
		_, err := s.Create(Persona{
			ID: ids[i], TenantID: "tenant-a", Name: "p", Scopes: []string{},
			TokenTTLSeconds: DefaultTokenTTLSeconds, CreatedAt: ts, UpdatedAt: ts,
		})
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	// Another tenant's persona must not leak into the list.
	other := time.Now().UTC()
	if _, err := s.Create(Persona{
		ID: uuid.NewString(), TenantID: "tenant-b", Name: "other", Scopes: []string{},
		TokenTTLSeconds: DefaultTokenTTLSeconds, CreatedAt: other, UpdatedAt: other,
	}); err != nil {
		t.Fatalf("seed other tenant: %v", err)
	}

	items, err := s.List("tenant-a")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("want 3 personas, got %d", len(items))
	}
	// CreatedAt ascending, same as MemStorage.List.
	for i, want := range ids {
		if items[i].ID != want {
			t.Fatalf("ordering mismatch at %d: got %s want %s", i, items[i].ID, want)
		}
	}
}

func TestPGStorageUpdatePreservesCreatedAt(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.NewString()
	base := Persona{
		ID: id, TenantID: "tenant-a", Name: "before", Scopes: []string{"a"},
		TokenTTLSeconds: 900, CreatedAt: now, UpdatedAt: now,
	}
	if _, err := s.Create(base); err != nil {
		t.Fatalf("create: %v", err)
	}
	updated := base
	updated.Name = "after"
	updated.Scopes = []string{"a", "b"}
	updated.TokenTTLSeconds = 1800
	// Caller may have mutated CreatedAt — the Update contract says it gets restored
	// from the persisted row.
	updated.CreatedAt = now.Add(time.Hour)
	out, err := s.Update(updated)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !out.CreatedAt.Equal(now) {
		t.Fatalf("update should preserve created_at: got %v want %v", out.CreatedAt, now)
	}
	if out.Name != "after" || out.TokenTTLSeconds != 1800 || len(out.Scopes) != 2 {
		t.Fatalf("fields not updated: %+v", out)
	}
	if !out.UpdatedAt.After(now) {
		t.Fatalf("updated_at should advance: got %v base %v", out.UpdatedAt, now)
	}

	// ErrNotFound for wrong tenant.
	wrong := updated
	wrong.TenantID = "tenant-b"
	if _, err := s.Update(wrong); err != ErrNotFound {
		t.Fatalf("cross-tenant update should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageDelete(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.NewString()
	if _, err := s.Create(Persona{
		ID: id, TenantID: "tenant-a", Name: "doomed", Scopes: []string{},
		TokenTTLSeconds: DefaultTokenTTLSeconds, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Cross-tenant delete is a no-op that returns ErrNotFound.
	if err := s.Delete("tenant-b", id); err != ErrNotFound {
		t.Fatalf("cross-tenant delete should be ErrNotFound, got %v", err)
	}
	if err := s.Delete("tenant-a", id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Get("tenant-a", id); err != ErrNotFound {
		t.Fatalf("get after delete should be ErrNotFound, got %v", err)
	}
	if err := s.Delete("tenant-a", id); err != ErrNotFound {
		t.Fatalf("double delete should be ErrNotFound, got %v", err)
	}
}
