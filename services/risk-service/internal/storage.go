package internal

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// ErrNotFound is returned when a tenant-scoped read misses.
var ErrNotFound = errors.New("not found")

// Storage is the risk-service persistence contract. Phase 1 provides an
// in-memory implementation; phase 2 will add Postgres-backed variants. Both
// evaluations and policies are tenant-scoped at the storage layer: a record
// written for tenant A is invisible (404) to tenant B even if the id is known.
//
// UserHasPriorEvaluation is the only "query" method and exists so the user
// scorer can detect "first high-value action". It is deliberately narrow
// rather than exposing a list endpoint for evaluations — phase 1 has no
// UX need to browse history.
type Storage interface {
	// Evaluations — write-once, read by id.
	PutEvaluation(e RiskEvaluation) error
	GetEvaluation(tenantID, id string) (RiskEvaluation, error)
	UserHasPriorEvaluation(tenantID, userID string) bool

	// Policies — standard CRUD.
	CreatePolicy(p Policy) (Policy, error)
	GetPolicy(tenantID, id string) (Policy, error)
	ListPolicies(tenantID string) ([]Policy, error)
	UpdatePolicy(p Policy) (Policy, error)
	DeletePolicy(tenantID, id string) error
}

// MemStorage is a thread-safe in-memory Storage implementation.
type MemStorage struct {
	mu          sync.RWMutex
	evaluations map[string]RiskEvaluation // keyed by evaluation id
	policies    map[string]Policy         // keyed by policy id
}

// NewMemStorage returns an initialised in-memory store.
func NewMemStorage() *MemStorage {
	return &MemStorage{
		evaluations: make(map[string]RiskEvaluation),
		policies:    make(map[string]Policy),
	}
}

// PutEvaluation inserts the evaluation. The caller fills ID, TenantID, and
// timestamps. Evaluations are immutable once stored.
func (s *MemStorage) PutEvaluation(e RiskEvaluation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evaluations[e.ID] = e
	return nil
}

// GetEvaluation returns the evaluation only if it exists *and* belongs to tenantID.
func (s *MemStorage) GetEvaluation(tenantID, id string) (RiskEvaluation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.evaluations[id]
	if !ok || e.TenantID != tenantID {
		return RiskEvaluation{}, ErrNotFound
	}
	return e, nil
}

// UserHasPriorEvaluation reports whether any evaluation exists for (tenantID, userID).
// Used by the user scorer to detect a first high-value action. Worst-case O(n)
// because phase 1 doesn't maintain a secondary index; acceptable given the
// in-memory scale.
func (s *MemStorage) UserHasPriorEvaluation(tenantID, userID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.evaluations {
		if e.TenantID == tenantID && e.UserID == userID {
			return true
		}
	}
	return false
}

// CreatePolicy inserts the policy.
func (s *MemStorage) CreatePolicy(p Policy) (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[p.ID] = p
	return p, nil
}

// GetPolicy returns the policy only if it exists *and* belongs to tenantID.
func (s *MemStorage) GetPolicy(tenantID, id string) (Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	if !ok || p.TenantID != tenantID {
		return Policy{}, ErrNotFound
	}
	return p, nil
}

// ListPolicies returns every policy belonging to tenantID, sorted by CreatedAt asc.
func (s *MemStorage) ListPolicies(tenantID string) ([]Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Policy, 0)
	for _, p := range s.policies {
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

// UpdatePolicy replaces the row identified by (p.TenantID, p.ID). CreatedAt is
// preserved from the existing row; UpdatedAt is stamped to now.
func (s *MemStorage) UpdatePolicy(p Policy) (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.policies[p.ID]
	if !ok || existing.TenantID != p.TenantID {
		return Policy{}, ErrNotFound
	}
	p.CreatedAt = existing.CreatedAt
	p.UpdatedAt = time.Now().UTC()
	s.policies[p.ID] = p
	return p, nil
}

// DeletePolicy removes the policy if it exists in tenantID.
func (s *MemStorage) DeletePolicy(tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[id]
	if !ok || p.TenantID != tenantID {
		return ErrNotFound
	}
	delete(s.policies, id)
	return nil
}
