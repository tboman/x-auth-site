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
//	# then apply services/authenticator-service/migrations/000001_init.up.sql
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
	// Discard logs: the error-less Put*/List* paths log instead of returning,
	// and the tests assert on observable state, not log output.
	return NewPGStorage(pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
	s.PutAuthenticator(a)

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
	s.PutAuthenticator(a)
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
		s.PutAuthenticator(a)
	}

	all := s.ListAuthenticators("tenant-a", "usr_1")
	if len(all) != 3 {
		t.Fatalf("list want 3 (incl. disabled) got %d", len(all))
	}
	// Deterministic ordering: created_at DESC, id DESC.
	for i := 1; i < len(all); i++ {
		if all[i].CreatedAt.After(all[i-1].CreatedAt) {
			t.Fatalf("list not ordered created_at DESC: %v then %v", all[i-1].CreatedAt, all[i].CreatedAt)
		}
	}

	active := s.ListActiveAuthenticators("tenant-a", "usr_1")
	if len(active) != 2 {
		t.Fatalf("active list want 2 got %d", len(active))
	}
	for _, a := range active {
		if a.Status != AuthenticatorStatusActive {
			t.Fatalf("active list contains %s authenticator: %+v", a.Status, a)
		}
	}

	if got := s.ListAuthenticators("tenant-a", "usr_unknown"); len(got) != 0 {
		t.Fatalf("unknown user should list empty, got %d", len(got))
	}
}

func TestPGStorageDisableAuthenticator(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	id := "authr_" + uuid.NewString()
	s.PutAuthenticator(Authenticator{
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
	s.PutChallenge(c)

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
	s.PutChallenge(Challenge{
		ID: id, TenantID: "tenant-a", UserID: "usr_1",
		Method: MethodSMS, AuthenticatorID: "authr_x",
		Status:    ChallengeStatusPending,
		CreatedAt: now, ExpiresAt: now.Add(ChallengeTTL),
	})

	// Failed attempt: bump the counter.
	updated, err := s.UpdateChallenge("tenant-a", id, func(ch *Challenge) {
		ch.Attempts++
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Attempts != 1 || updated.Status != ChallengeStatusPending {
		t.Fatalf("attempt bump not applied: %+v", updated)
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
