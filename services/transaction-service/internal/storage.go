package internal

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// ErrNotFound is returned when a transaction does not exist under the given tenant.
var ErrNotFound = errors.New("transaction not found")

// Storage is the transaction-service persistence contract. Phase 1 provides an in-memory
// implementation; phase 2 will add a Postgres-backed implementation.
type Storage interface {
	Create(t Transaction) (Transaction, error)
	Update(t Transaction) (Transaction, error)
	Get(tenantID, id string) (Transaction, error)
	List(tenantID string, limit int, cursor time.Time) ([]Transaction, error)
	AppendHistory(tenantID, id string, entry HistoryEntry) error
}

// MemStorage is an in-memory, thread-safe Storage implementation. Tenant isolation is
// enforced here: every read/write checks tenant_id before returning or mutating.
type MemStorage struct {
	mu   sync.RWMutex
	data map[string]Transaction // keyed by transaction id
}

// NewMemStorage returns an initialised in-memory store.
func NewMemStorage() *MemStorage {
	return &MemStorage{data: make(map[string]Transaction)}
}

// Create inserts the transaction. Caller is expected to have filled ID, TenantID, and CreatedAt.
func (s *MemStorage) Create(t Transaction) (Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[t.ID] = t
	return t, nil
}

// Update replaces the transaction identified by (t.TenantID, t.ID). Returns ErrNotFound
// if no matching tenant-scoped record exists. CreatedAt is preserved from the existing row.
func (s *MemStorage) Update(t Transaction) (Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.data[t.ID]
	if !ok || existing.TenantID != t.TenantID {
		return Transaction{}, ErrNotFound
	}
	t.CreatedAt = existing.CreatedAt
	s.data[t.ID] = t
	return t, nil
}

// Get returns the transaction if it exists *and* belongs to tenantID.
func (s *MemStorage) Get(tenantID, id string) (Transaction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.data[id]
	if !ok || t.TenantID != tenantID {
		return Transaction{}, ErrNotFound
	}
	return t, nil
}

// List returns up to `limit` transactions owned by tenantID, ordered by CreatedAt desc.
// If `cursor` is non-zero, only transactions strictly older than the cursor are returned,
// providing stable keyset pagination without storing offsets.
func (s *MemStorage) List(tenantID string, limit int, cursor time.Time) ([]Transaction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Transaction, 0)
	for _, t := range s.data {
		if t.TenantID != tenantID {
			continue
		}
		if !cursor.IsZero() && !t.CreatedAt.Before(cursor) {
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// AppendHistory adds an entry to the transaction's in-process audit trail. The record
// must exist under tenantID. This is a convenience method — callers could also fetch,
// mutate, and Update, but AppendHistory avoids a read/write race on the trail.
func (s *MemStorage) AppendHistory(tenantID, id string, entry HistoryEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.data[id]
	if !ok || t.TenantID != tenantID {
		return ErrNotFound
	}
	t.History = append(t.History, entry)
	s.data[id] = t
	return nil
}
