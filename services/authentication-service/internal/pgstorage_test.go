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
//	# then apply services/authentication-service/migrations/ in order
//	# (000001_init.up.sql, 000002_token_families_pkce.up.sql)
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

func TestPGStorageListTenants(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	seedPGUser(t, s, "ten_x", "u1@x.test")
	seedPGUser(t, s, "ten_x", "u2@x.test")
	seedPGUser(t, s, "ten_y", "u3@y.test")
	// ten_x also has a session, updated later than any user — drives ordering.
	if _, err := s.CreateSession(Session{
		ID: "ses_" + uuid.NewString(), TenantID: "ten_x", UserID: "u1",
		RiskLevel: RiskLow, CreatedAt: now, UpdatedAt: now.Add(10 * time.Second),
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}

	tenants, err := s.ListTenants()
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(tenants) != 2 {
		t.Fatalf("want 2 tenants, got %d: %+v", len(tenants), tenants)
	}
	if tenants[0].TenantID != "ten_x" {
		t.Errorf("want ten_x first (newest activity), got %q", tenants[0].TenantID)
	}
	byID := map[string]TenantSummary{tenants[0].TenantID: tenants[0], tenants[1].TenantID: tenants[1]}
	if byID["ten_x"].Users != 2 || byID["ten_x"].Sessions != 1 {
		t.Errorf("ten_x counts wrong: %+v", byID["ten_x"])
	}
	if byID["ten_y"].Users != 1 || byID["ten_y"].Sessions != 0 {
		t.Errorf("ten_y counts wrong: %+v", byID["ten_y"])
	}
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

func TestPGStorageListUsersKeyset(t *testing.T) {
	s := newPGStorage(t)
	base := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)

	// Three users at distinct timestamps plus two sharing a fourth (newest)
	// timestamp to exercise the id desc tie-break.
	seed := func(id string, ts time.Time, email string) {
		t.Helper()
		if _, err := s.CreateUser(User{
			ID: id, TenantID: "tenant-a", Email: email, CreatedAt: ts, UpdatedAt: ts,
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("usr_00", base, "u0@acme.test")
	seed("usr_01", base.Add(time.Second), "u1@acme.test")
	seed("usr_02", base.Add(2*time.Second), "u2@acme.test")
	tie := base.Add(3 * time.Second)
	seed("usr_tie_a", tie, "tie-a@acme.test")
	seed("usr_tie_b", tie, "tie-b@acme.test")
	seedPGUser(t, s, "tenant-b", "other@acme.test")

	// Full list: created_at desc, id desc tie-break, tenant-isolated.
	users, err := s.ListUsers("tenant-a", 0, time.Time{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	wantOrder := []string{"usr_tie_b", "usr_tie_a", "usr_02", "usr_01", "usr_00"}
	if len(users) != len(wantOrder) {
		t.Fatalf("want %d users got %d", len(wantOrder), len(users))
	}
	for i, want := range wantOrder {
		if users[i].ID != want {
			t.Fatalf("position %d: got %s want %s", i, users[i].ID, want)
		}
	}

	// Keyset walk: limit 2 yields three pages with no overlap and no gaps.
	page1, err := s.ListUsers("tenant-a", 2, time.Time{})
	if err != nil || len(page1) != 2 {
		t.Fatalf("page1: %v len=%d", err, len(page1))
	}
	if page1[0].ID != "usr_tie_b" || page1[1].ID != "usr_tie_a" {
		t.Fatalf("page1 order: %s, %s", page1[0].ID, page1[1].ID)
	}
	page2, err := s.ListUsers("tenant-a", 2, page1[1].CreatedAt)
	if err != nil || len(page2) != 2 {
		t.Fatalf("page2: %v len=%d", err, len(page2))
	}
	if page2[0].ID != "usr_02" || page2[1].ID != "usr_01" {
		t.Fatalf("page2 order: %s, %s", page2[0].ID, page2[1].ID)
	}
	page3, err := s.ListUsers("tenant-a", 2, page2[1].CreatedAt)
	if err != nil || len(page3) != 1 || page3[0].ID != "usr_00" {
		t.Fatalf("page3: %v %+v", err, page3)
	}

	// Cursor at the oldest row: nothing strictly older remains.
	empty, err := s.ListUsers("tenant-a", 2, page3[0].CreatedAt)
	if err != nil || len(empty) != 0 {
		t.Fatalf("past-the-end page should be empty: %v len=%d", err, len(empty))
	}
}

func TestPGStoragePurgeExpired(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	putToken := func(hash string, expiresAt time.Time) {
		t.Helper()
		if err := s.PutToken(Token{
			TokenHash: hash, SessionID: "ses_1", UserID: "usr_1", TenantID: "tenant-a",
			TokenType: TokenTypeAccess, IssuedAt: now.Add(-time.Hour), ExpiresAt: expiresAt,
		}); err != nil {
			t.Fatalf("put token: %v", err)
		}
	}
	expiredHash := HashToken("expired")
	liveHash := HashToken("live")
	putToken(expiredHash, now.Add(-time.Minute))
	putToken(liveHash, now.Add(time.Hour))

	putCode := func(code string, createdAt time.Time) {
		t.Helper()
		if err := s.PutAuthCode(AuthCode{
			Code: code, ClientID: DefaultClientID, TenantID: "tenant-a",
			UserID: "usr_1", RedirectURI: "http://localhost:3000/callback", CreatedAt: createdAt,
		}); err != nil {
			t.Fatalf("put code: %v", err)
		}
	}
	putCode("stale-code", now.Add(-time.Duration(AuthCodeTTLSeconds+60)*time.Second))
	putCode("fresh-code", now)

	putSession := func(id string, expiresAt time.Time) {
		t.Helper()
		if _, err := s.CreateSession(Session{
			ID: id, TenantID: "tenant-a", UserID: "usr_1", RiskLevel: RiskLow,
			CreatedAt: now.Add(-48 * time.Hour), UpdatedAt: now.Add(-48 * time.Hour), ExpiresAt: expiresAt,
		}); err != nil {
			t.Fatalf("put session: %v", err)
		}
	}
	// Dead: expired longer ago than the refresh-token grace window.
	putSession("ses_dead", now.Add(-time.Duration(RefreshTokenTTLSeconds)*time.Second-time.Hour))
	// Recently expired: still within the grace window — must be kept.
	putSession("ses_recent", now.Add(-time.Minute))
	// Live.
	putSession("ses_live", now.Add(time.Hour))

	removed, err := s.PurgeExpired(now)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if removed != 3 {
		t.Fatalf("removed = %d, want 3 (expired token + stale code + dead session)", removed)
	}

	// Expired artefacts are gone.
	if _, err := s.GetTokenByHash(expiredHash); err != ErrNotFound {
		t.Fatalf("expired token should be purged, got %v", err)
	}
	if _, err := s.ConsumeAuthCode("stale-code"); err != ErrNotFound {
		t.Fatalf("stale code should be purged, got %v", err)
	}
	if _, err := s.GetSession("tenant-a", "ses_dead"); err != ErrNotFound {
		t.Fatalf("dead session should be purged, got %v", err)
	}

	// Live (and grace-window) artefacts are kept.
	if _, err := s.GetTokenByHash(liveHash); err != nil {
		t.Fatalf("live token should be kept: %v", err)
	}
	if _, err := s.ConsumeAuthCode("fresh-code"); err != nil {
		t.Fatalf("fresh code should be kept: %v", err)
	}
	if _, err := s.GetSession("tenant-a", "ses_recent"); err != nil {
		t.Fatalf("recently expired session should be kept (grace window): %v", err)
	}
	if _, err := s.GetSession("tenant-a", "ses_live"); err != nil {
		t.Fatalf("live session should be kept: %v", err)
	}

	// Idempotent: a second sweep finds nothing.
	removed, err = s.PurgeExpired(now)
	if err != nil || removed != 0 {
		t.Fatalf("second purge: removed=%d err=%v, want 0 nil", removed, err)
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
		ClientID:  DefaultClientID,
		FamilyID:  "fam_" + uuid.NewString(),
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
	if got.ClientID != DefaultClientID || got.FamilyID != tok.FamilyID {
		t.Fatalf("client_id/family_id roundtrip mismatch: %+v", got)
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

func TestPGStorageRevokeTokenFamily(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	famA := "fam_" + uuid.NewString()
	famB := "fam_" + uuid.NewString()

	put := func(name, family, tokenType string, revoked bool) string {
		t.Helper()
		hash := HashToken(name)
		tok := Token{
			TokenHash: hash, SessionID: "ses_1", UserID: "usr_1", TenantID: "tenant-a",
			ClientID: DefaultClientID, FamilyID: family, TokenType: tokenType,
			IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		}
		if revoked {
			rev := now.Add(-time.Minute)
			tok.RevokedAt = &rev
		}
		if err := s.PutToken(tok); err != nil {
			t.Fatalf("put %s: %v", name, err)
		}
		return hash
	}
	// Family A: one live refresh, one live access, one already-revoked refresh.
	liveRefreshA := put("refresh-a-live", famA, TokenTypeRefresh, false)
	liveAccessA := put("access-a-live", famA, TokenTypeAccess, false)
	deadRefreshA := put("refresh-a-dead", famA, TokenTypeRefresh, true)
	// Family B must be untouched.
	otherFamily := put("refresh-b", famB, TokenTypeRefresh, false)

	revoked, err := s.RevokeTokenFamily(famA)
	if err != nil {
		t.Fatalf("revoke family: %v", err)
	}
	if revoked != 2 {
		t.Fatalf("revoked = %d, want 2 (live refresh + live access; pre-revoked row untouched)", revoked)
	}

	for _, hash := range []string{liveRefreshA, liveAccessA, deadRefreshA} {
		got, err := s.GetTokenByHash(hash)
		if err != nil || got.RevokedAt == nil {
			t.Fatalf("family member %s should be revoked: %v %+v", hash, err, got)
		}
	}
	// The pre-revoked member keeps its original (earlier) revocation instant.
	preRevoked, _ := s.GetTokenByHash(deadRefreshA)
	if !preRevoked.RevokedAt.Before(now) {
		t.Fatalf("pre-revoked member's revoked_at was overwritten: %v", preRevoked.RevokedAt)
	}
	// The other family is untouched.
	other, err := s.GetTokenByHash(otherFamily)
	if err != nil || other.RevokedAt != nil {
		t.Fatalf("other family should be untouched: %v %+v", err, other)
	}

	// Empty family id is a guarded no-op (legacy rows).
	if n, err := s.RevokeTokenFamily(""); err != nil || n != 0 {
		t.Fatalf("empty family revoke: n=%d err=%v, want 0 nil", n, err)
	}
	// Unknown family revokes nothing.
	if n, err := s.RevokeTokenFamily("fam_" + uuid.NewString()); err != nil || n != 0 {
		t.Fatalf("unknown family revoke: n=%d err=%v, want 0 nil", n, err)
	}
}

func TestPGStorageAuthCodeOneShot(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	code := uuid.NewString()
	ac := AuthCode{
		Code:          code,
		ClientID:      DefaultClientID,
		TenantID:      "tenant-a",
		UserID:        "usr_1",
		RedirectURI:   "http://localhost:3000/callback",
		Scope:         "openid",
		State:         "xyz",
		Nonce:         "n-0S6_WzA2Mj",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CreatedAt:     now,
		ACR:           ACRSMSOTP,
		AMR:           []string{"otp", "sms"},
	}
	if err := s.PutAuthCode(ac); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.ConsumeAuthCode(code)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.ClientID != DefaultClientID || got.UserID != "usr_1" ||
		got.RedirectURI != ac.RedirectURI || got.State != "xyz" || got.Nonce != ac.Nonce ||
		got.CodeChallenge != ac.CodeChallenge {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if !got.CreatedAt.Equal(now) {
		t.Fatalf("created_at mismatch: got %v want %v", got.CreatedAt, now)
	}
	if got.ACR != ACRSMSOTP || len(got.AMR) != 2 || got.AMR[0] != "otp" || got.AMR[1] != "sms" {
		t.Fatalf("acr/amr roundtrip mismatch: acr=%q amr=%v", got.ACR, got.AMR)
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
