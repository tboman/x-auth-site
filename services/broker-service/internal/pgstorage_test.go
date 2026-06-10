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
//	# then apply the migrations under services/broker-service/migrations/ in order
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
	// Insert out of chronological order; ListInstalls must return CreatedAt desc.
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

	got, err := s.ListInstalls("tenant-a", 0, time.Time{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 installs, got %d", len(got))
	}
	for n := 1; n < len(got); n++ {
		if got[n].CreatedAt.After(got[n-1].CreatedAt) {
			t.Fatalf("not sorted desc: %v after %v", got[n].CreatedAt, got[n-1].CreatedAt)
		}
	}
}

func TestPGStorageListInstallsKeyset(t *testing.T) {
	s := newPGStorage(t)
	base := time.Now().UTC().Truncate(time.Microsecond)
	ids := make([]string, 5)
	for n := 0; n < 5; n++ {
		ids[n] = uuid.NewString()
		ts := base.Add(time.Duration(n) * time.Second)
		if _, err := s.CreateInstall(Install{
			ID: ids[n], TenantID: "tenant-a", Runtime: RuntimeCustom,
			PersonaID: "p", ClientID: "c", Status: InstallStatusPending,
			CreatedAt: ts, UpdatedAt: ts,
		}); err != nil {
			t.Fatalf("seed %d: %v", n, err)
		}
	}

	// Page 1: limit applies, newest first.
	page1, err := s.ListInstalls("tenant-a", 2, time.Time{})
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(page1) != 2 || page1[0].ID != ids[4] || page1[1].ID != ids[3] {
		t.Fatalf("page 1: want [%s %s], got %+v", ids[4], ids[3], page1)
	}

	// Page 2: rows strictly older than the last CreatedAt of page 1.
	page2, err := s.ListInstalls("tenant-a", 2, page1[1].CreatedAt)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(page2) != 2 || page2[0].ID != ids[2] || page2[1].ID != ids[1] {
		t.Fatalf("page 2: want [%s %s], got %+v", ids[2], ids[1], page2)
	}

	// Page 3: final partial page.
	page3, err := s.ListInstalls("tenant-a", 2, page2[1].CreatedAt)
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}
	if len(page3) != 1 || page3[0].ID != ids[0] {
		t.Fatalf("page 3: want [%s], got %+v", ids[0], page3)
	}
}

func TestPGStoragePurgeExpired(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Tokens: one expired, one live.
	if err := s.PutToken(TokenRecord{
		AccessToken: "tok-expired", InstallID: "i1", TenantID: "t",
		ExpiresAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("put expired token: %v", err)
	}
	if err := s.PutToken(TokenRecord{
		AccessToken: "tok-live", InstallID: "i1", TenantID: "t",
		ExpiresAt: now.Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("put live token: %v", err)
	}

	// Auth codes: one past the AuthCodeTTLSeconds window, one fresh.
	if err := s.PutAuthCode(AuthCode{
		Code: "code-expired", TenantID: "t", Runtime: RuntimeClaude,
		PersonaID: "p", ClientID: "c",
		CreatedAt: now.Add(-time.Duration(AuthCodeTTLSeconds+60) * time.Second),
	}); err != nil {
		t.Fatalf("put expired code: %v", err)
	}
	if err := s.PutAuthCode(AuthCode{
		Code: "code-live", TenantID: "t", Runtime: RuntimeClaude,
		PersonaID: "p", ClientID: "c", CreatedAt: now,
	}); err != nil {
		t.Fatalf("put live code: %v", err)
	}

	removed, err := s.PurgeExpired(now)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2 (one token + one code)", removed)
	}

	if _, err := s.GetToken("tok-expired"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired token should be gone, got %v", err)
	}
	if _, err := s.GetToken("tok-live"); err != nil {
		t.Fatalf("live token should survive the purge: %v", err)
	}
	if _, err := s.ConsumeAuthCode("code-expired"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired code should be gone, got %v", err)
	}
	if _, err := s.ConsumeAuthCode("code-live"); err != nil {
		t.Fatalf("live code should survive the purge: %v", err)
	}

	// Idempotent: a second sweep finds nothing left to remove.
	removed, err = s.PurgeExpired(now)
	if err != nil || removed != 0 {
		t.Fatalf("second purge: removed=%d err=%v, want 0/nil", removed, err)
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
		Code:          code,
		TenantID:      "tenant-a",
		Runtime:       RuntimeClaude,
		PersonaID:     "persona-1",
		PoolID:        "pool-1",
		ClientID:      "client-1",
		RedirectURI:   "https://app.example.com/cb",
		State:         "xyz",
		Scope:         "openid mcp",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CreatedAt:     now,
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
	if ac.CodeChallenge != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("code_challenge mismatch: %q", ac.CodeChallenge)
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

func TestPGStorageGetTokenByRefresh(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	refresh := uuid.NewString()
	rec := TokenRecord{
		AccessToken:  uuid.NewString(),
		RefreshToken: refresh,
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

	got, err := s.GetTokenByRefresh(refresh)
	if err != nil {
		t.Fatalf("get by refresh: %v", err)
	}
	if got.AccessToken != rec.AccessToken || got.InstallID != "install-1" || got.Subject != rec.Subject {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if got.RotatedAt != nil {
		t.Fatalf("fresh record should have nil RotatedAt, got %v", got.RotatedAt)
	}

	// Unknown / empty refresh tokens miss with ErrNotFound. The empty case must
	// never match rows whose refresh_token is NULL.
	if err := s.PutToken(TokenRecord{
		AccessToken: uuid.NewString(), InstallID: "i-nr", TenantID: "t",
		ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("put refresh-less token: %v", err)
	}
	if _, err := s.GetTokenByRefresh(uuid.NewString()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown refresh should be ErrNotFound, got %v", err)
	}
	if _, err := s.GetTokenByRefresh(""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty refresh should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageRotatedAtPersistence(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	rec := TokenRecord{
		AccessToken:  uuid.NewString(),
		RefreshToken: uuid.NewString(),
		InstallID:    "install-1",
		TenantID:     "tenant-a",
		ExpiresAt:    now.Add(15 * time.Minute),
	}
	if err := s.PutToken(rec); err != nil {
		t.Fatalf("put: %v", err)
	}

	// Re-Put with RotatedAt stamped — the upsert must write the column.
	rotated := now.Add(time.Minute)
	rec.RotatedAt = &rotated
	if err := s.PutToken(rec); err != nil {
		t.Fatalf("re-put rotated: %v", err)
	}
	got, err := s.GetToken(rec.AccessToken)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.RotatedAt == nil || !got.RotatedAt.Equal(rotated) {
		t.Fatalf("rotated_at did not round-trip: got %v want %v", got.RotatedAt, rotated)
	}
	byRefresh, err := s.GetTokenByRefresh(rec.RefreshToken)
	if err != nil || byRefresh.RotatedAt == nil {
		t.Fatalf("rotated_at missing via refresh lookup: rec=%+v err=%v", byRefresh, err)
	}
}

func TestPGStorageDeleteTokensForInstall(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	for range 2 {
		if err := s.PutToken(TokenRecord{
			AccessToken: uuid.NewString(), RefreshToken: uuid.NewString(),
			InstallID: "install-doomed", TenantID: "t", ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("seed doomed token: %v", err)
		}
	}
	survivor := uuid.NewString()
	if err := s.PutToken(TokenRecord{
		AccessToken: survivor, RefreshToken: uuid.NewString(),
		InstallID: "install-other", TenantID: "t", ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed survivor: %v", err)
	}

	removed, err := s.DeleteTokensForInstall("install-doomed")
	if err != nil {
		t.Fatalf("delete for install: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2", removed)
	}
	if _, err := s.GetToken(survivor); err != nil {
		t.Fatalf("other install's token must survive: %v", err)
	}

	// Idempotent: deleting again removes nothing and is not an error.
	removed, err = s.DeleteTokensForInstall("install-doomed")
	if err != nil || removed != 0 {
		t.Fatalf("second delete: removed=%d err=%v, want 0/nil", removed, err)
	}
}
