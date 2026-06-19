package internal

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Snapshot is a verified MDS blob plus the metadata we persist for warm starts
// and audit. Raw holds the original compact-JWS bytes so a reload re-verifies
// rather than trusting stored derived state.
type Snapshot struct {
	Raw        []byte
	Number     int
	NextUpdate string
	EntryCount int
	SHA256     string
	FetchedAt  time.Time
}

// SnapshotStore persists the latest verified blob. Both implementations are
// best-effort durability around the in-memory index — the service runs without
// either (live fetch on every cold start).
type SnapshotStore interface {
	Save(ctx context.Context, s Snapshot) error
	Load(ctx context.Context) (Snapshot, bool, error)
}

// MemSnapshotStore is the no-DB fallback: it keeps the last snapshot in memory,
// so it survives a refresh but not a process restart.
type MemSnapshotStore struct {
	mu   sync.RWMutex
	snap *Snapshot
}

func NewMemSnapshotStore() *MemSnapshotStore { return &MemSnapshotStore{} }

func (m *MemSnapshotStore) Save(_ context.Context, s Snapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := s
	m.snap = &cp
	return nil
}

func (m *MemSnapshotStore) Load(_ context.Context) (Snapshot, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.snap == nil {
		return Snapshot{}, false, nil
	}
	return *m.snap, true, nil
}

// PGSnapshotStore persists snapshots in fido_db. One row per blob number; Load
// returns the most recently fetched.
type PGSnapshotStore struct {
	pool *pgxpool.Pool
}

func NewPGSnapshotStore(pool *pgxpool.Pool) *PGSnapshotStore {
	return &PGSnapshotStore{pool: pool}
}

func (p *PGSnapshotStore) Save(ctx context.Context, s Snapshot) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO mds_snapshots (blob_number, next_update, entry_count, blob_sha256, raw, fetched_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (blob_number) DO UPDATE SET
			next_update = EXCLUDED.next_update,
			entry_count = EXCLUDED.entry_count,
			blob_sha256 = EXCLUDED.blob_sha256,
			raw         = EXCLUDED.raw,
			fetched_at  = EXCLUDED.fetched_at
	`, s.Number, s.NextUpdate, s.EntryCount, s.SHA256, s.Raw, s.FetchedAt)
	return err
}

func (p *PGSnapshotStore) Load(ctx context.Context) (Snapshot, bool, error) {
	var s Snapshot
	err := p.pool.QueryRow(ctx, `
		SELECT blob_number, next_update, entry_count, blob_sha256, raw, fetched_at
		FROM mds_snapshots
		ORDER BY fetched_at DESC
		LIMIT 1
	`).Scan(&s.Number, &s.NextUpdate, &s.EntryCount, &s.SHA256, &s.Raw, &s.FetchedAt)
	if err != nil {
		if isNoRows(err) {
			return Snapshot{}, false, nil
		}
		return Snapshot{}, false, err
	}
	return s, true, nil
}
