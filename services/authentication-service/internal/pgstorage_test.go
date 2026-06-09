package internal

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newPGStorage connects to the DSN in AUTHN_PG_DSN and returns a clean PGStorage.
// The test is skipped when the env var is unset so unit-test CI without a DB
// (and routine `go test ./...` runs on developer laptops) stays green. When it
// IS set, the test truncates every authentication-service table so it's safe to
// re-run.
//
// Recommended local setup:
//
//	docker run --rm -d --name xauth-pg -e POSTGRES_PASSWORD=postgres \
//	  -e POSTGRES_DB=auth_db -p 5432:5432 postgres:16
//	# then apply services/authentication-service/migrations/000001_init.up.sql
//	AUTHN_PG_DSN="postgres://postgres:postgres@localhost:5432/auth_db?sslmode=disable" \
//	  go test ./services/authentication-service/internal/ -run PG
func newPGStorage(t *testing.T) *PGStorage {
	t.Helper()
	dsn := os.Getenv("AUTHN_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHN_PG_DSN not set; skipping PGStorage integration test")
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
	if _, err := pool.Exec(ctx,
		"TRUNCATE TABLE users, sessions, tokens, auth_codes, oidc_clients",
	); err != nil {
		pool.Close()
		t.Fatalf("truncate: %v (is the migration applied?)", err)
	}
	t.Cleanup(func() { pool.Close() })
	return NewPGStorage(pool)
}

func seedPGUser(t *testing.T, s *PGStorage, tenantID, email string) User {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	u, err := s.CreateUser(User{
		ID:        "usr_" + uuid.NewString(),
		TenantID:  tenantID,
		Email:     email,
		Name:      "Test User",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

func TestPGStorageUserRoundTrip(t *testing.T) {
	s := newPGStorage(t)
	u := seedPGUser(t, s, "tenant-a", "alice@acme.test")

	got, err := s.GetUser("tenant-a", u.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Email != "alice@acme.test" || got.Name != "Test User" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	byEmail, err := s.GetUserByEmail("tenant-a", "alice@acme.test")
	if err != nil || byEmail.ID != u.ID {
		t.Fatalf("get by email: %v %+v", err, byEmail)
	}

	// Tenant isolation: other tenant can't see it.
	if _, err := s.GetUser("tenant-b", u.ID); err != ErrNotFound {
		t.Fatalf("cross-tenant get should be ErrNotFound, got %v", err)
	}
	if _, err := s.GetUserByEmail("tenant-b", "alice@acme.test"); err != ErrNotFound {
		t.Fatalf("cross-tenant get by email should be ErrNotFound, got %v", err)
	}

	// Duplicate (tenant, email) is ErrConflict; same email in another tenant is fine.
	if _, err := s.CreateUser(User{
		ID: "usr_" + uuid.NewString(), TenantID: "tenant-a",
		Email: "alice@acme.test", CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}); err != ErrConflict {
		t.Fatalf("duplicate email should be ErrConflict, got %v", err)
	}
	if _, err := s.CreateUser(User{
		ID: "usr_" + uuid.NewString(), TenantID: "tenant-b",
		Email: "alice@acme.test", CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}); err != nil {
		t.Fatalf("same email in another tenant should succeed, got %v", err)
	}
}

func TestPGStorageUserUpdateAndDelete(t *testing.T) {
	s := newPGStorage(t)
	u := seedPGUser(t, s, "tenant-a", "alice@acme.test")
	other := seedPGUser(t, s, "tenant-a", "bob@acme.test")

	// Update preserves created_at even if the caller mutated it.
	mod := u
	mod.Name = "Alice Renamed"
	mod.CreatedAt = u.CreatedAt.Add(time.Hour)
	out, err := s.UpdateUser(mod)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !out.CreatedAt.Equal(u.CreatedAt) {
		t.Fatalf("update should preserve created_at: got %v want %v", out.CreatedAt, u.CreatedAt)
	}
	if out.Name != "Alice Renamed" {
		t.Fatalf("name not updated: %+v", out)
	}
	if !out.UpdatedAt.After(u.UpdatedAt) {
		t.Fatalf("updated_at should be bumped: got %v, was %v", out.UpdatedAt, u.UpdatedAt)
	}

	// Email collision with another user in the same tenant is ErrConflict.
	mod.Email = other.Email
	if _, err := s.UpdateUser(mod); err != ErrConflict {
		t.Fatalf("email collision should be ErrConflict, got %v", err)
	}

	// ErrNotFound for wrong tenant.
	wrong := u
	wrong.TenantID = "tenant-b"
	if _, err := s.UpdateUser(wrong); err != ErrNotFound {
		t.Fatalf("cross-tenant update should be ErrNotFound, got %v", err)
	}

	// Delete is tenant-scoped, then idempotently ErrNotFound.
	if err := s.DeleteUser("tenant-b", u.ID); err != ErrNotFound {
		t.Fatalf("cross-tenant delete should be ErrNotFound, got %v", err)
	}
	if err := s.DeleteUser("tenant-a", u.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.DeleteUser("tenant-a", u.ID); err != ErrNotFound {
		t.Fatalf("second delete should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageListUsersOrder(t *testing.T) {
	s := newPGStorage(t)
	base := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		if _, err := s.CreateUser(User{
			ID: "usr_" + uuid.NewString(), TenantID: "tenant-a",
			Email: string(rune('a'+i)) + "@acme.test", CreatedAt: ts, UpdatedAt: ts,
		}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	seedPGUser(t, s, "tenant-b", "other@acme.test")

	users, err := s.ListUsers("tenant-a")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("want 3 users got %d", len(users))
	}
	for i := 1; i < len(users); i++ {
		if users[i].CreatedAt.Before(users[i-1].CreatedAt) {
			t.Fatalf("list not sorted by created_at asc: %v then %v",
				users[i-1].CreatedAt, users[i].CreatedAt)
		}
	}
}

func TestPGStorageSessionLifecycle(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	sess := Session{
		ID:        "ses_" + uuid.NewString(),
		TenantID:  "tenant-a",
		UserID:    "usr_1",
		RiskLevel: RiskLow,
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	if _, err := s.CreateSession(sess); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetSession("tenant-a", sess.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.UserID != "usr_1" || got.RiskLevel != RiskLow || got.StepUpCompleted {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if got.InvalidatedAt != nil {
		t.Fatalf("fresh session should not be invalidated: %+v", got)
	}

	// Tenant isolation.
	if _, err := s.GetSession("tenant-b", sess.ID); err != ErrNotFound {
		t.Fatalf("cross-tenant get should be ErrNotFound, got %v", err)
	}

	// Update flips posture, preserves created_at, persists invalidated_at.
	upd := got
	upd.RiskLevel = RiskHigh
	upd.StepUpCompleted = true
	inv := now.Add(2 * time.Second)
	upd.InvalidatedAt = &inv
	upd.CreatedAt = now.Add(time.Hour) // caller mutation must be ignored
	out, err := s.UpdateSession(upd)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !out.CreatedAt.Equal(now) {
		t.Fatalf("update should preserve created_at: got %v want %v", out.CreatedAt, now)
	}
	if !out.StepUpCompleted || out.RiskLevel != RiskHigh {
		t.Fatalf("posture not updated: %+v", out)
	}
	reread, err := s.GetSession("tenant-a", sess.ID)
	if err != nil {
		t.Fatalf("reread: %v", err)
	}
	if reread.InvalidatedAt == nil || !reread.InvalidatedAt.Equal(inv) {
		t.Fatalf("invalidated_at lost: %+v", reread.InvalidatedAt)
	}

	// Cross-tenant update is ErrNotFound.
	wrong := upd
	wrong.TenantID = "tenant-b"
	if _, err := s.UpdateSession(wrong); err != ErrNotFound {
		t.Fatalf("cross-tenant update should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageTokens(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	hash := HashToken(uuid.NewString())
	tok := Token{
		TokenHash: hash,
		SessionID: "ses_1",
		UserID:    "usr_1",
		TenantID:  "tenant-a",
		TokenType: TokenTypeAccess,
		Scope:     "openid profile",
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
	}
	if err := s.PutToken(tok); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.GetTokenByHash(hash)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.TokenType != TokenTypeAccess || got.Scope != "openid profile" || got.RevokedAt != nil {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	// Re-put replaces the record (map-write parity).
	tok.TokenType = TokenTypeRefresh
	if err := s.PutToken(tok); err != nil {
		t.Fatalf("re-put: %v", err)
	}
	got, err = s.GetTokenByHash(hash)
	if err != nil || got.TokenType != TokenTypeRefresh {
		t.Fatalf("upsert not applied: %v %+v", err, got)
	}

	// Revoke stamps revoked_at; unknown hashes are ErrNotFound.
	if err := s.RevokeTokenByHash(hash); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, err = s.GetTokenByHash(hash)
	if err != nil || got.RevokedAt == nil {
		t.Fatalf("revoked_at not stamped: %v %+v", err, got)
	}
	if err := s.RevokeTokenByHash(HashToken("never-issued")); err != ErrNotFound {
		t.Fatalf("unknown revoke should be ErrNotFound, got %v", err)
	}
	if _, err := s.GetTokenByHash(HashToken("never-issued")); err != ErrNotFound {
		t.Fatalf("unknown get should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageAuthCodeOneShot(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	code := uuid.NewString()
	ac := AuthCode{
		Code:        code,
		ClientID:    DefaultClientID,
		TenantID:    "tenant-a",
		UserID:      "usr_1",
		RedirectURI: "http://localhost:3000/callback",
		Scope:       "openid",
		State:       "xyz",
		Nonce:       "n-0S6_WzA2Mj",
		CreatedAt:   now,
	}
	if err := s.PutAuthCode(ac); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.ConsumeAuthCode(code)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.ClientID != DefaultClientID || got.UserID != "usr_1" ||
		got.RedirectURI != ac.RedirectURI || got.State != "xyz" || got.Nonce != ac.Nonce {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if !got.CreatedAt.Equal(now) {
		t.Fatalf("created_at mismatch: got %v want %v", got.CreatedAt, now)
	}

	// One-shot: replay must fail.
	if _, err := s.ConsumeAuthCode(code); err != ErrNotFound {
		t.Fatalf("replay should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageClients(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	c := OIDCClient{
		ClientID:         "cli_" + uuid.NewString(),
		ClientSecretHash: HashToken("s3cret"),
		RedirectURIs:     []string{"https://app.acme.test/cb", "http://localhost:3000/callback"},
		CreatedAt:        now,
	}
	if err := s.PutClient(c); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.GetClient(c.ClientID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ClientSecretHash != c.ClientSecretHash || len(got.RedirectURIs) != 2 ||
		got.RedirectURIs[0] != "https://app.acme.test/cb" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	// Upsert replaces the row (map-write parity); empty hash = public client.
	c.ClientSecretHash = ""
	c.RedirectURIs = []string{"https://app.acme.test/cb2"}
	if err := s.PutClient(c); err != nil {
		t.Fatalf("re-put: %v", err)
	}
	got, err = s.GetClient(c.ClientID)
	if err != nil || got.ClientSecretHash != "" || len(got.RedirectURIs) != 1 {
		t.Fatalf("upsert not applied: %v %+v", err, got)
	}

	if _, err := s.GetClient("cli_unknown"); err != ErrNotFound {
		t.Fatalf("unknown client should be ErrNotFound, got %v", err)
	}
}
