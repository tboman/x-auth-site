package internal

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newPGStorage connects to the DSN in TXN_PG_DSN and returns a clean PGStorage.
// The test is skipped when the env var is unset so unit-test CI without a DB
// (and routine `go test ./...` runs on developer laptops) stays green. When it
// IS set, the test truncates the transactions table so it's safe to re-run.
//
// Recommended local setup:
//   docker run --rm -d --name xauth-pg -e POSTGRES_PASSWORD=postgres \
//     -e POSTGRES_DB=txn_db -p 5432:5432 postgres:16
//   # then apply services/transaction-service/migrations/000001_init.up.sql
//   TXN_PG_DSN="postgres://postgres:postgres@localhost:5432/txn_db?sslmode=disable" \
//     go test ./services/transaction-service/internal/ -run PG
func newPGStorage(t *testing.T) *PGStorage {
	t.Helper()
	dsn := os.Getenv("TXN_PG_DSN")
	if dsn == "" {
		t.Skip("TXN_PG_DSN not set; skipping PGStorage integration test")
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
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE transactions"); err != nil {
		pool.Close()
		t.Fatalf("truncate: %v (is the migration applied?)", err)
	}
	t.Cleanup(func() { pool.Close() })
	return NewPGStorage(pool)
}

func TestPGStorageRoundTrip(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "txn_" + uuid.NewString()
	txn := Transaction{
		ID:        id,
		TenantID:  "tenant-a",
		UserID:    "usr_1",
		SessionID: "ses_1",
		Action:    "login",
		Decision:  "pending",
		CreatedAt: now,
		History: []HistoryEntry{
			{At: now, Event: "advice_received", Detail: "login"},
		},
	}
	if _, err := s.Create(txn); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Get("tenant-a", id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.UserID != "usr_1" || got.Action != "login" || got.Decision != "pending" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if len(got.History) != 1 || got.History[0].Event != "advice_received" {
		t.Fatalf("history lost: %+v", got.History)
	}

	// Tenant isolation: other tenant can't see it.
	if _, err := s.Get("tenant-b", id); err != ErrNotFound {
		t.Fatalf("cross-tenant get should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageUpdatePreservesCreatedAt(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "txn_" + uuid.NewString()
	base := Transaction{
		ID:        id,
		TenantID:  "tenant-a",
		UserID:    "usr_1",
		Action:    "login",
		Decision:  "pending",
		CreatedAt: now,
	}
	if _, err := s.Create(base); err != nil {
		t.Fatalf("create: %v", err)
	}
	updated := base
	updated.Decision = DecisionAllow
	decidedAt := now.Add(time.Second)
	updated.DecidedAt = &decidedAt
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
	if out.Decision != DecisionAllow {
		t.Fatalf("decision not updated: %s", out.Decision)
	}

	// ErrNotFound for wrong tenant.
	wrong := updated
	wrong.TenantID = "tenant-b"
	if _, err := s.Update(wrong); err != ErrNotFound {
		t.Fatalf("cross-tenant update should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageListPagination(t *testing.T) {
	s := newPGStorage(t)
	base := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 3; i++ {
		id := "txn_" + uuid.NewString()
		_, err := s.Create(Transaction{
			ID: id, TenantID: "tenant-a", UserID: "u", Action: "a",
			Decision: "pending", CreatedAt: base.Add(time.Duration(i) * time.Second),
		})
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	first, err := s.List("tenant-a", 2, time.Time{})
	if err != nil {
		t.Fatalf("list1: %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("first page want 2 got %d", len(first))
	}
	second, err := s.List("tenant-a", 2, first[len(first)-1].CreatedAt)
	if err != nil {
		t.Fatalf("list2: %v", err)
	}
	if len(second) != 1 {
		t.Fatalf("second page want 1 got %d", len(second))
	}
}

func TestPGStorageAppendHistory(t *testing.T) {
	s := newPGStorage(t)
	id := "txn_" + uuid.NewString()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := s.Create(Transaction{
		ID: id, TenantID: "tenant-a", UserID: "u", Action: "a",
		Decision: "pending", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.AppendHistory("tenant-a", id, HistoryEntry{
		At: now.Add(time.Second), Event: "decision", Detail: DecisionAllow,
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	got, err := s.Get("tenant-a", id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.History) != 1 || got.History[0].Event != "decision" {
		t.Fatalf("history not appended: %+v", got.History)
	}

	// Cross-tenant append is a no-op that returns ErrNotFound.
	if err := s.AppendHistory("tenant-b", id, HistoryEntry{Event: "x"}); err != ErrNotFound {
		t.Fatalf("cross-tenant append: want ErrNotFound, got %v", err)
	}
}
