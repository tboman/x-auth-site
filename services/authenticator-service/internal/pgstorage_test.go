package internal

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newPGStorage connects to the DSN in AUTHENTICATOR_PG_DSN and returns a clean
// PGStorage. The test is skipped when the env var is unset so unit-test CI
// without a DB (and routine `go test ./...` runs on developer laptops) stays
// green. When it IS set, the test truncates both tables so it's safe to re-run.
//
// Recommended local setup:
//
//	docker run --rm -d --name xauth-pg -e POSTGRES_PASSWORD=postgres \
//	  -e POSTGRES_DB=authr_db -p 5432:5432 postgres:16
//	# then apply services/authenticator-service/migrations (000001 + 000002 up)
//	AUTHENTICATOR_PG_DSN="postgres://postgres:postgres@localhost:5432/authr_db?sslmode=disable" \
//	  go test ./services/authenticator-service/internal/ -run PG
func newPGStorage(t *testing.T) *PGStorage {
	t.Helper()
	dsn := os.Getenv("AUTHENTICATOR_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHENTICATOR_PG_DSN not set; skipping PGStorage integration test")
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
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE authenticators, challenges"); err != nil {
		pool.Close()
		t.Fatalf("truncate: %v (is the migration applied?)", err)
	}
	t.Cleanup(func() { pool.Close() })
	// Discard logs: the tests assert on returned errors and observable state,
	// not log output.
	return NewPGStorage(pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// mustPutAuthenticator / mustPutChallenge fail the test on a write error so
// seeding code stays terse.
func mustPutAuthenticator(t *testing.T, s *PGStorage, a Authenticator) {
	t.Helper()
	if err := s.PutAuthenticator(a); err != nil {
		t.Fatalf("put authenticator %s: %v", a.ID, err)
	}
}

func mustPutChallenge(t *testing.T, s *PGStorage, c Challenge) {
	t.Helper()
	if err := s.PutChallenge(c); err != nil {
		t.Fatalf("put challenge %s: %v", c.ID, err)
	}
}

func TestPGStorageAuthenticatorRoundTrip(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "authr_" + uuid.NewString()
	a := Authenticator{
		ID:        id,
		TenantID:  "tenant-a",
		UserID:    "usr_1",
		Method:    MethodTOTP,
		Metadata:  map[string]any{"device_name": "phone"},
		Status:    AuthenticatorStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	mustPutAuthenticator(t, s, a)

	got, err := s.GetAuthenticator("tenant-a", id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.UserID != "usr_1" || got.Method != MethodTOTP || got.Status != AuthenticatorStatusActive {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if !got.CreatedAt.Equal(now) || !got.UpdatedAt.Equal(now) {
		t.Fatalf("timestamps drifted: %+v", got)
	}
	if got.Metadata["device_name"] != "phone" {
		t.Fatalf("metadata lost: %+v", got.Metadata)
	}

	// Tenant isolation: other tenant can't see it.
	if _, err := s.GetAuthenticator("tenant-b", id); err != ErrNotFound {
		t.Fatalf("cross-tenant get should be ErrNotFound, got %v", err)
	}

	// Put is an upsert — re-putting with a new status overwrites in place.
	a.Status = AuthenticatorStatusDisabled
	a.UpdatedAt = now.Add(time.Minute)
	mustPutAuthenticator(t, s, a)
	got, err = s.GetAuthenticator("tenant-a", id)
	if err != nil {
		t.Fatalf("get after upsert: %v", err)
	}
	if got.Status != AuthenticatorStatusDisabled || !got.UpdatedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("upsert not applied: %+v", got)
	}
}

func TestPGStorageListAuthenticators(t *testing.T) {
	s := newPGStorage(t)
	base := time.Now().UTC().Truncate(time.Microsecond)
	seed := []Authenticator{
		{ID: "authr_" + uuid.NewString(), TenantID: "tenant-a", UserID: "usr_1",
			Method: MethodTOTP, Status: AuthenticatorStatusActive,
			CreatedAt: base, UpdatedAt: base},
		{ID: "authr_" + uuid.NewString(), TenantID: "tenant-a", UserID: "usr_1",
			Method: MethodFIDO2, Status: AuthenticatorStatusActive,
			CreatedAt: base.Add(time.Second), UpdatedAt: base.Add(time.Second)},
		{ID: "authr_" + uuid.NewString(), TenantID: "tenant-a", UserID: "usr_1",
			Method: MethodSMS, Status: AuthenticatorStatusDisabled,
			CreatedAt: base.Add(2 * time.Second), UpdatedAt: base.Add(2 * time.Second)},
		// Different user and different tenant must never leak in.
		{ID: "authr_" + uuid.NewString(), TenantID: "tenant-a", UserID: "usr_2",
			Method: MethodTOTP, Status: AuthenticatorStatusActive,
			CreatedAt: base, UpdatedAt: base},
		{ID: "authr_" + uuid.NewString(), TenantID: "tenant-b", UserID: "usr_1",
			Method: MethodTOTP, Status: AuthenticatorStatusActive,
			CreatedAt: base, UpdatedAt: base},
	}
	for _, a := range seed {
		mustPutAuthenticator(t, s, a)
	}

	all, err := s.ListAuthenticators("tenant-a", "usr_1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("list want 3 (incl. disabled) got %d", len(all))
	}
	// Deterministic ordering: created_at DESC, id DESC.
	for i := 1; i < len(all); i++ {
		if all[i].CreatedAt.After(all[i-1].CreatedAt) {
			t.Fatalf("list not ordered created_at DESC: %v then %v", all[i-1].CreatedAt, all[i].CreatedAt)
		}
	}

	active, err := s.ListActiveAuthenticators("tenant-a", "usr_1")
	if err != nil {
		t.Fatalf("active list: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("active list want 2 got %d", len(active))
	}
	for _, a := range active {
		if a.Status != AuthenticatorStatusActive {
			t.Fatalf("active list contains %s authenticator: %+v", a.Status, a)
		}
	}

	got, err := s.ListAuthenticators("tenant-a", "usr_unknown")
	if err != nil {
		t.Fatalf("unknown user list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("unknown user should list empty, got %d", len(got))
	}
}

func TestPGStorageDisableAuthenticator(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	id := "authr_" + uuid.NewString()
	mustPutAuthenticator(t, s, Authenticator{
		ID: id, TenantID: "tenant-a", UserID: "usr_1",
		Method: MethodPush, Status: AuthenticatorStatusActive,
		CreatedAt: now, UpdatedAt: now,
	})

	if err := s.DisableAuthenticator("tenant-a", id); err != nil {
		t.Fatalf("disable: %v", err)
	}
	got, err := s.GetAuthenticator("tenant-a", id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != AuthenticatorStatusDisabled {
		t.Fatalf("status not flipped: %s", got.Status)
	}
	if !got.UpdatedAt.After(now) {
		t.Fatalf("updated_at not bumped: %v", got.UpdatedAt)
	}
	firstUpdate := got.UpdatedAt

	// Idempotent: a second disable returns nil and leaves updated_at untouched.
	if err := s.DisableAuthenticator("tenant-a", id); err != nil {
		t.Fatalf("second disable: %v", err)
	}
	got, err = s.GetAuthenticator("tenant-a", id)
	if err != nil {
		t.Fatalf("get after second disable: %v", err)
	}
	if !got.UpdatedAt.Equal(firstUpdate) {
		t.Fatalf("idempotent disable bumped updated_at: %v -> %v", firstUpdate, got.UpdatedAt)
	}

	// Cross-tenant and unknown ids are ErrNotFound.
	if err := s.DisableAuthenticator("tenant-b", id); err != ErrNotFound {
		t.Fatalf("cross-tenant disable should be ErrNotFound, got %v", err)
	}
	if err := s.DisableAuthenticator("tenant-a", "authr_missing"); err != ErrNotFound {
		t.Fatalf("unknown id disable should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageChallengeRoundTrip(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "ch_" + uuid.NewString()
	c := Challenge{
		ID:              id,
		TenantID:        "tenant-a",
		UserID:          "usr_1",
		Method:          MethodTOTP,
		AuthenticatorID: "authr_x",
		Prompt:          "Enter 6-digit code from your authenticator app",
		Status:          ChallengeStatusPending,
		CreatedAt:       now,
		ExpiresAt:       now.Add(ChallengeTTL),
	}
	mustPutChallenge(t, s, c)

	got, err := s.GetChallenge("tenant-a", id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Method != MethodTOTP || got.AuthenticatorID != "authr_x" || got.Status != ChallengeStatusPending {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if got.Prompt != c.Prompt || got.Attempts != 0 || got.CompletedAt != nil {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if got.LastAttemptAt != nil {
		t.Fatalf("last_attempt_at must round-trip as nil before any failure: %+v", got.LastAttemptAt)
	}
	if !got.ExpiresAt.Equal(now.Add(ChallengeTTL)) {
		t.Fatalf("expires_at drifted: %v", got.ExpiresAt)
	}

	// Tenant isolation.
	if _, err := s.GetChallenge("tenant-b", id); err != ErrNotFound {
		t.Fatalf("cross-tenant get should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageUpdateChallenge(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "ch_" + uuid.NewString()
	mustPutChallenge(t, s, Challenge{
		ID: id, TenantID: "tenant-a", UserID: "usr_1",
		Method: MethodSMS, AuthenticatorID: "authr_x",
		Status:    ChallengeStatusPending,
		CreatedAt: now, ExpiresAt: now.Add(ChallengeTTL),
	})

	// Failed attempt: bump the counter and stamp the failure time (the §10.5
	// backoff input persisted by migration 000002).
	lastAttempt := now.Add(30 * time.Second)
	updated, err := s.UpdateChallenge("tenant-a", id, func(ch *Challenge) {
		ch.Attempts++
		ch.LastAttemptAt = &lastAttempt
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Attempts != 1 || updated.Status != ChallengeStatusPending {
		t.Fatalf("attempt bump not applied: %+v", updated)
	}
	got0, err := s.GetChallenge("tenant-a", id)
	if err != nil {
		t.Fatalf("get after failed attempt: %v", err)
	}
	if got0.LastAttemptAt == nil || !got0.LastAttemptAt.Equal(lastAttempt) {
		t.Fatalf("last_attempt_at not persisted: %+v", got0.LastAttemptAt)
	}

	// Success: terminal state + completion stamp, persisted across a fresh Get.
	completedAt := now.Add(time.Minute)
	if _, err := s.UpdateChallenge("tenant-a", id, func(ch *Challenge) {
		ch.Status = ChallengeStatusCompleted
		ch.CompletedAt = &completedAt
	}); err != nil {
		t.Fatalf("update completed: %v", err)
	}
	got, err := s.GetChallenge("tenant-a", id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != ChallengeStatusCompleted || got.Attempts != 1 {
		t.Fatalf("update not persisted: %+v", got)
	}
	if got.CompletedAt == nil || !got.CompletedAt.Equal(completedAt) {
		t.Fatalf("completed_at not persisted: %+v", got.CompletedAt)
	}

	// Cross-tenant update is ErrNotFound.
	if _, err := s.UpdateChallenge("tenant-b", id, func(ch *Challenge) {
		ch.Attempts++
	}); err != ErrNotFound {
		t.Fatalf("cross-tenant update should be ErrNotFound, got %v", err)
	}

	// Mutating immutable fields is refused and nothing is persisted.
	if _, err := s.UpdateChallenge("tenant-a", id, func(ch *Challenge) {
		ch.TenantID = "tenant-evil"
		ch.Attempts = 99
	}); err == nil || err == ErrNotFound {
		t.Fatalf("immutable-field mutation should error, got %v", err)
	}
	got, err = s.GetChallenge("tenant-a", id)
	if err != nil {
		t.Fatalf("get after refused update: %v", err)
	}
	if got.Attempts != 1 || got.TenantID != "tenant-a" {
		t.Fatalf("refused update leaked state: %+v", got)
	}
}

// TestPGStoragePurgeExpired mirrors TestStorePurgeExpired against Postgres:
// pending-past-expiry and `expired` rows are deleted, live pending and
// terminal completed/failed rows (audit trail) survive.
func TestPGStoragePurgeExpired(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	mk := func(suffix, status string, expiresAt time.Time) Challenge {
		return Challenge{
			ID: "ch_purge_" + suffix, TenantID: "tenant-a", UserID: "usr_1",
			Method: MethodTOTP, AuthenticatorID: "authr_x",
			Status:    status,
			CreatedAt: now.Add(-time.Hour), ExpiresAt: expiresAt,
		}
	}
	seed := []Challenge{
		mk("live", ChallengeStatusPending, now.Add(time.Minute)),   // kept
		mk("stale", ChallengeStatusPending, now.Add(-time.Second)), // purged
		mk("boundary", ChallengeStatusPending, now),                // purged (expires_at <= now)
		mk("flipped", ChallengeStatusExpired, now.Add(-time.Hour)), // purged
		mk("done", ChallengeStatusCompleted, now.Add(-time.Hour)),  // kept
		mk("locked", ChallengeStatusFailed, now.Add(-time.Hour)),   // kept
	}
	for _, c := range seed {
		mustPutChallenge(t, s, c)
	}

	n, err := s.PurgeExpired(now)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 3 {
		t.Fatalf("want 3 purged, got %d", n)
	}

	for _, suffix := range []string{"live", "done", "locked"} {
		if _, err := s.GetChallenge("tenant-a", "ch_purge_"+suffix); err != nil {
			t.Fatalf("ch_purge_%s should survive purge, got %v", suffix, err)
		}
	}
	for _, suffix := range []string{"stale", "boundary", "flipped"} {
		if _, err := s.GetChallenge("tenant-a", "ch_purge_"+suffix); err != ErrNotFound {
			t.Fatalf("ch_purge_%s should be purged, got %v", suffix, err)
		}
	}

	// Idempotent: nothing left to purge.
	n, err = s.PurgeExpired(now)
	if err != nil || n != 0 {
		t.Fatalf("second purge: want (0, nil), got (%d, %v)", n, err)
	}
}
