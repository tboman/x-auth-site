package internal

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newPGStorage connects to the DSN in BROKER_PG_DSN and returns a clean PGStorage.
// The test is skipped when the env var is unset so unit-test CI without a DB
// (and routine `go test ./...` runs on developer laptops) stays green. When it
// IS set, the test truncates the broker tables so it's safe to re-run.
//
// Recommended local setup:
//
//	docker run --rm -d --name xauth-pg -e POSTGRES_PASSWORD=postgres \
//	  -e POSTGRES_DB=broker_db -p 5432:5432 postgres:16
//	# then apply services/broker-service/migrations/000001_init.up.sql
//	BROKER_PG_DSN="postgres://postgres:postgres@localhost:5432/broker_db?sslmode=disable" \
//	  go test ./services/broker-service/internal/ -run PG
func newPGStorage(t *testing.T) *PGStorage {
	t.Helper()
	dsn := os.Getenv("BROKER_PG_DSN")
	if dsn == "" {
		t.Skip("BROKER_PG_DSN not set; skipping PGStorage integration test")
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
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE installs, dcr_clients, auth_codes, tokens"); err != nil {
		pool.Close()
		t.Fatalf("truncate: %v (is the migration applied?)", err)
	}
	t.Cleanup(func() { pool.Close() })
	return NewPGStorage(pool)
}

func TestPGStorageInstallRoundTrip(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.NewString()
	install := Install{
		ID:        id,
		TenantID:  "tenant-a",
		Runtime:   RuntimeClaude,
		PersonaID: "persona-1",
		ClientID:  "client-1",
		Status:    InstallStatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if _, err := s.CreateInstall(install); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetInstall("tenant-a", id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Runtime != RuntimeClaude || got.PersonaID != "persona-1" || got.Status != InstallStatusPending {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if got.IdentityID != "" {
		t.Fatalf("identity_id should be empty, got %q", got.IdentityID)
	}

	// Tenant isolation: other tenant can't see it.
	if _, err := s.GetInstall("tenant-b", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageUpdateInstallPreservesCreatedAt(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.NewString()
	base := Install{
		ID:        id,
		TenantID:  "tenant-a",
		Runtime:   RuntimeCursor,
		PersonaID: "persona-1",
		ClientID:  "client-1",
		Status:    InstallStatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if _, err := s.CreateInstall(base); err != nil {
		t.Fatalf("create: %v", err)
	}
	updated := base
	updated.Status = InstallStatusActive
	updated.IdentityID = "identity-9"
	// Caller may have mutated CreatedAt — the Update contract says it gets restored
	// from the persisted row.
	updated.CreatedAt = now.Add(time.Hour)
	out, err := s.UpdateInstall(updated)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !out.CreatedAt.Equal(now) {
		t.Fatalf("update should preserve created_at: got %v want %v", out.CreatedAt, now)
	}
	if out.Status != InstallStatusActive || out.IdentityID != "identity-9" {
		t.Fatalf("update not applied: %+v", out)
	}
	if !out.UpdatedAt.After(out.CreatedAt) {
		t.Fatalf("updated_at should be stamped after created_at: %v vs %v", out.UpdatedAt, out.CreatedAt)
	}

	// ErrNotFound for wrong tenant.
	wrong := updated
	wrong.TenantID = "tenant-b"
	if _, err := s.UpdateInstall(wrong); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant update should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageListInstallsOrdered(t *testing.T) {
	s := newPGStorage(t)
	base := time.Now().UTC().Truncate(time.Microsecond)
	// Insert out of chronological order; ListInstalls must return CreatedAt asc.
	for _, offset := range []int{2, 0, 1} {
		ts := base.Add(time.Duration(offset) * time.Second)
		_, err := s.CreateInstall(Install{
			ID: uuid.NewString(), TenantID: "tenant-a", Runtime: RuntimeCustom,
			PersonaID: "p", ClientID: "c", Status: InstallStatusPending,
			CreatedAt: ts, UpdatedAt: ts,
		})
		if err != nil {
			t.Fatalf("seed offset %d: %v", offset, err)
		}
	}
	// A foreign-tenant row that must not appear.
	if _, err := s.CreateInstall(Install{
		ID: uuid.NewString(), TenantID: "tenant-b", Runtime: RuntimeCustom,
		PersonaID: "p", ClientID: "c", Status: InstallStatusPending,
		CreatedAt: base, UpdatedAt: base,
	}); err != nil {
		t.Fatalf("seed tenant-b: %v", err)
	}

	got, err := s.ListInstalls("tenant-a")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 installs, got %d", len(got))
	}
	for n := 1; n < len(got); n++ {
		if got[n].CreatedAt.Before(got[n-1].CreatedAt) {
			t.Fatalf("not sorted asc: %v before %v", got[n].CreatedAt, got[n-1].CreatedAt)
		}
	}
}

func TestPGStorageClientUpsert(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.NewString()
	if err := s.PutClient(DCRClient{
		ClientID:     id,
		ClientSecret: "secret-1",
		ClientMetadata: map[string]any{
			"client_name":   "Test MCP Client",
			"redirect_uris": []any{"https://app.example.com/cb"},
		},
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.GetClient(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ClientSecret != "secret-1" {
		t.Fatalf("secret mismatch: %q", got.ClientSecret)
	}
	if got.ClientMetadata["client_name"] != "Test MCP Client" {
		t.Fatalf("metadata lost: %+v", got.ClientMetadata)
	}

	// Upsert replaces the record (MemStorage map-assignment semantics).
	if err := s.PutClient(DCRClient{ClientID: id, ClientSecret: "secret-2", CreatedAt: now}); err != nil {
		t.Fatalf("re-put: %v", err)
	}
	got, err = s.GetClient(id)
	if err != nil {
		t.Fatalf("re-get: %v", err)
	}
	if got.ClientSecret != "secret-2" || got.ClientMetadata != nil {
		t.Fatalf("upsert should replace record: %+v", got)
	}

	if _, err := s.GetClient("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing client should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageAuthCodeOneShot(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	code := uuid.NewString()
	if err := s.PutAuthCode(AuthCode{
		Code:        code,
		TenantID:    "tenant-a",
		Runtime:     RuntimeClaude,
		PersonaID:   "persona-1",
		PoolID:      "pool-1",
		ClientID:    "client-1",
		RedirectURI: "https://app.example.com/cb",
		State:       "xyz",
		Scope:       "openid mcp",
		CreatedAt:   now,
	}); err != nil {
		t.Fatalf("put: %v", err)
	}
	ac, err := s.ConsumeAuthCode(code)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if ac.TenantID != "tenant-a" || ac.PoolID != "pool-1" || ac.State != "xyz" || ac.Scope != "openid mcp" {
		t.Fatalf("roundtrip mismatch: %+v", ac)
	}
	if !ac.CreatedAt.Equal(now) {
		t.Fatalf("created_at mismatch: got %v want %v", ac.CreatedAt, now)
	}

	// One-shot: replay must fail.
	if _, err := s.ConsumeAuthCode(code); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replay should be ErrNotFound, got %v", err)
	}

	// Direct-seed path: zero CreatedAt gets stamped to now.
	seeded := uuid.NewString()
	if err := s.PutAuthCode(AuthCode{
		Code: seeded, TenantID: "tenant-a", Runtime: RuntimeCustom,
		PersonaID: "persona-1", ClientID: "client-1",
	}); err != nil {
		t.Fatalf("seed put: %v", err)
	}
	got, err := s.ConsumeAuthCode(seeded)
	if err != nil {
		t.Fatalf("seed consume: %v", err)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("zero CreatedAt should be stamped on Put")
	}
}

func TestPGStorageTokenLifecycle(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	access := uuid.NewString()
	rec := TokenRecord{
		AccessToken:  access,
		RefreshToken: uuid.NewString(),
		InstallID:    "install-1",
		PersonaID:    "persona-1",
		IdentityID:   "identity-1",
		Subject:      "agent-bot@tenant-a",
		Scope:        "mcp",
		TenantID:     "tenant-a",
		ExpiresAt:    now.Add(15 * time.Minute),
	}
	if err := s.PutToken(rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.GetToken(access)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.InstallID != "install-1" || got.Subject != "agent-bot@tenant-a" || got.TenantID != "tenant-a" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if !got.ExpiresAt.Equal(rec.ExpiresAt) {
		t.Fatalf("expires_at mismatch: got %v want %v", got.ExpiresAt, rec.ExpiresAt)
	}

	if err := s.DeleteToken(access); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetToken(access); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted token should be ErrNotFound, got %v", err)
	}
	if err := s.DeleteToken(access); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete should be ErrNotFound, got %v", err)
	}
}
