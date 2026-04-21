package internal

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// ErrNotFound is returned when a persona does not exist (or belongs to a different tenant).
var ErrNotFound = errors.New("persona not found")

// Storage is the persona-service persistence contract. Phase 1 provides an in-memory
// implementation; phase 2 will add a Postgres-backed implementation.
type Storage interface {
	Create(p Persona) (Persona, error)
	Get(tenantID, id string) (Persona, error)
	List(tenantID string) ([]Persona, error)
	Update(p Persona) (Persona, error)
	Delete(tenantID, id string) error
}

// MemStorage is an in-memory, thread-safe Storage implementation. Tenant isolation is
// enforced here: every read/write checks tenant_id against the stored persona before
// returning or mutating. Callers cannot cross tenants even if they know another tenant's id.
type MemStorage struct {
	mu   sync.RWMutex
	data map[string]Persona // keyed by persona id
}

// NewMemStorage returns an initialised in-memory store.
func NewMemStorage() *MemStorage {
	return &MemStorage{data: make(map[string]Persona)}
}

// Create inserts the persona. Caller is expected to have filled ID, TenantID, and timestamps.
func (s *MemStorage) Create(p Persona) (Persona, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[p.ID] = p
	return p, nil
}

// Get returns the persona if it exists *and* belongs to tenantID.
func (s *MemStorage) Get(tenantID, id string) (Persona, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.data[id]
	if !ok || p.TenantID != tenantID {
		return Persona{}, ErrNotFound
	}
	return p, nil
}

// List returns all personas owned by tenantID, sorted by CreatedAt ascending for determinism.
func (s *MemStorage) List(tenantID string) ([]Persona, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Persona, 0)
	for _, p := range s.data {
		if p.TenantID == tenantID {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// Update replaces the persona identified by (p.TenantID, p.ID). Returns ErrNotFound if
// no matching tenant-scoped record exists. CreatedAt is preserved from the existing row.
func (s *MemStorage) Update(p Persona) (Persona, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.data[p.ID]
	if !ok || existing.TenantID != p.TenantID {
		return Persona{}, ErrNotFound
	}
	p.CreatedAt = existing.CreatedAt
	p.UpdatedAt = time.Now().UTC()
	s.data[p.ID] = p
	return p, nil
}

// Delete removes the persona if it exists in tenantID. Returns ErrNotFound otherwise.
func (s *MemStorage) Delete(tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.data[id]
	if !ok || p.TenantID != tenantID {
		return ErrNotFound
	}
	delete(s.data, id)
	return nil
}
