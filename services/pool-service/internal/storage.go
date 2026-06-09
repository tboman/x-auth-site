package internal

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// Storage errors. Handlers translate these into HTTP status codes.
var (
	// ErrPoolNotFound — pool doesn't exist or belongs to another tenant.
	ErrPoolNotFound = errors.New("pool not found")
	// ErrIdentityNotFound — identity doesn't exist or is in another tenant.
	ErrIdentityNotFound = errors.New("identity not found")
	// ErrPoolFull — pool already holds Size identities.
	ErrPoolFull = errors.New("pool full")
	// ErrPersonaNotEligible — pool does not authorize the requested persona_id.
	ErrPersonaNotEligible = errors.New("persona not eligible for pool")
	// ErrNoAvailableIdentity — no free identity in the pool (all claimed/revoked).
	ErrNoAvailableIdentity = errors.New("no available identity in pool")
	// ErrIdentityRevoked — cannot release a permanently revoked identity.
	ErrIdentityRevoked = errors.New("identity revoked")
)

// Storage is the pool-service persistence contract. Phase 1 provides an in-memory
// implementation; phase 2 will add a Postgres-backed implementation. Tenant isolation
// is enforced inside the implementation — every call that reads/writes a Pool or
// Identity verifies the tenant_id.
type Storage interface {
	// Pool CRUD. ListPools returns up to `limit` pools ordered by CreatedAt desc
	// (id desc as tiebreaker); a non-zero `cursor` returns only pools strictly
	// older than the cursor (keyset pagination).
	CreatePool(p Pool) (Pool, error)
	GetPool(tenantID, id string) (Pool, error)
	ListPools(tenantID string, limit int, cursor time.Time) ([]Pool, error)
	DeletePool(tenantID, id string) error

	// Identity ops (all tenant-scoped via pool lookup). ListIdentities paginates
	// with the same keyset contract as ListPools.
	AddIdentity(tenantID, poolID string, ident Identity) (Identity, error)
	ListIdentities(tenantID, poolID string, limit int, cursor time.Time) ([]Identity, error)
	GetIdentity(tenantID, id string) (Identity, error)

	// ClaimIdentity atomically picks one available identity from a pool whose
	// persona_ids contains personaID, marks it claimed, and sets the install id.
	ClaimIdentity(tenantID, poolID, personaID, installID string) (Identity, error)

	// ReleaseIdentity marks an identity available and clears claimed_by_install_id.
	// Idempotent: calling on an already-available identity returns it unchanged.
	// Calling on a revoked identity returns ErrIdentityRevoked.
	ReleaseIdentity(tenantID, id string) (Identity, error)

	// RevokeIdentity marks an identity revoked. Terminal state.
	RevokeIdentity(tenantID, id string) error
}

// MemStorage is an in-memory, thread-safe Storage implementation.
//
// All operations take a single write lock so that the claim() flow — which
// must atomically pick-and-mutate — is correct by construction. Phase 2's
// Postgres impl will use a row-level lock or conditional update instead.
type MemStorage struct {
	mu         sync.Mutex
	pools      map[string]Pool     // pool_id -> Pool
	identities map[string]Identity // identity_id -> Identity
}

// NewMemStorage returns an initialised in-memory store.
func NewMemStorage() *MemStorage {
	return &MemStorage{
		pools:      make(map[string]Pool),
		identities: make(map[string]Identity),
	}
}

// ---------- Pool ops ----------

// CreatePool inserts the pool. Caller fills ID, TenantID, timestamps.
func (s *MemStorage) CreatePool(p Pool) (Pool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pools[p.ID] = p
	return p, nil
}

// GetPool returns the pool iff it exists and belongs to tenantID.
func (s *MemStorage) GetPool(tenantID, id string) (Pool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pools[id]
	if !ok || p.TenantID != tenantID {
		return Pool{}, ErrPoolNotFound
	}
	return p, nil
}

// ListPools returns up to `limit` pools owned by tenantID, ordered by CreatedAt desc
// (id desc as tiebreaker). If `cursor` is non-zero, only pools strictly older than the
// cursor are returned, providing stable keyset pagination without storing offsets.
func (s *MemStorage) ListPools(tenantID string, limit int, cursor time.Time) ([]Pool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Pool, 0)
	for _, p := range s.pools {
		if p.TenantID != tenantID {
			continue
		}
		if !cursor.IsZero() && !p.CreatedAt.Before(cursor) {
			continue
		}
		out = append(out, p)
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

// DeletePool removes the pool and all identities attached to it.
func (s *MemStorage) DeletePool(tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pools[id]
	if !ok || p.TenantID != tenantID {
		return ErrPoolNotFound
	}
	delete(s.pools, id)
	// Cascade: remove every identity that belonged to this pool.
	for idID, ident := range s.identities {
		if ident.PoolID == id {
			delete(s.identities, idID)
		}
	}
	return nil
}

// ---------- Identity ops ----------

// AddIdentity inserts an identity into a pool, rejecting if the pool is full.
// Caller fills ID, PoolID, SubjectID, Status, timestamps on ident.
func (s *MemStorage) AddIdentity(tenantID, poolID string, ident Identity) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pools[poolID]
	if !ok || p.TenantID != tenantID {
		return Identity{}, ErrPoolNotFound
	}
	if s.poolCountLocked(poolID) >= p.Size {
		return Identity{}, ErrPoolFull
	}
	s.identities[ident.ID] = ident
	return ident, nil
}

// ListIdentities returns up to `limit` identities in poolID (tenant-scoped), ordered by
// CreatedAt desc (id desc as tiebreaker). If `cursor` is non-zero, only identities
// strictly older than the cursor are returned (keyset pagination). Note: the claim
// path (ClaimIdentity) intentionally keeps its oldest-first ASC pick — only the list
// endpoint pages newest-first.
func (s *MemStorage) ListIdentities(tenantID, poolID string, limit int, cursor time.Time) ([]Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pools[poolID]
	if !ok || p.TenantID != tenantID {
		return nil, ErrPoolNotFound
	}
	out := make([]Identity, 0)
	for _, ident := range s.identities {
		if ident.PoolID != poolID {
			continue
		}
		if !cursor.IsZero() && !ident.CreatedAt.Before(cursor) {
			continue
		}
		out = append(out, ident)
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

// GetIdentity returns an identity by id, tenant-scoped via its pool.
func (s *MemStorage) GetIdentity(tenantID, id string) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ident, ok := s.identities[id]
	if !ok {
		return Identity{}, ErrIdentityNotFound
	}
	p, ok := s.pools[ident.PoolID]
	if !ok || p.TenantID != tenantID {
		return Identity{}, ErrIdentityNotFound
	}
	return ident, nil
}

// ClaimIdentity is the atomic claim path. One lock acquisition validates the pool,
// verifies persona eligibility, picks the first available identity (sorted by
// CreatedAt for determinism), mutates it to claimed, and returns it.
func (s *MemStorage) ClaimIdentity(tenantID, poolID, personaID, installID string) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pools[poolID]
	if !ok || p.TenantID != tenantID {
		return Identity{}, ErrPoolNotFound
	}
	if !containsString(p.PersonaIDs, personaID) {
		// Per requirements, 404 if pool doesn't list persona_id in persona_ids.
		return Identity{}, ErrPersonaNotEligible
	}

	// Collect available identities and pick the oldest for deterministic behaviour.
	var candidates []Identity
	for _, ident := range s.identities {
		if ident.PoolID == poolID && ident.Status == StatusAvailable {
			candidates = append(candidates, ident)
		}
	}
	if len(candidates) == 0 {
		return Identity{}, ErrNoAvailableIdentity
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].CreatedAt.Equal(candidates[j].CreatedAt) {
			return candidates[i].ID < candidates[j].ID
		}
		return candidates[i].CreatedAt.Before(candidates[j].CreatedAt)
	})

	picked := candidates[0]
	picked.Status = StatusClaimed
	install := installID
	picked.ClaimedByInstallID = &install
	picked.UpdatedAt = time.Now().UTC()
	s.identities[picked.ID] = picked
	return picked, nil
}

// ReleaseIdentity flips status -> available. Idempotent on already-available identities.
// Revoked identities cannot be released.
func (s *MemStorage) ReleaseIdentity(tenantID, id string) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ident, ok := s.identities[id]
	if !ok {
		return Identity{}, ErrIdentityNotFound
	}
	p, ok := s.pools[ident.PoolID]
	if !ok || p.TenantID != tenantID {
		return Identity{}, ErrIdentityNotFound
	}
	if ident.Status == StatusRevoked {
		return Identity{}, ErrIdentityRevoked
	}
	// Idempotent: release of an already-available identity is a no-op (but refresh UpdatedAt? no — stay pure).
	if ident.Status == StatusAvailable && ident.ClaimedByInstallID == nil {
		return ident, nil
	}
	ident.Status = StatusAvailable
	ident.ClaimedByInstallID = nil
	ident.UpdatedAt = time.Now().UTC()
	s.identities[id] = ident
	return ident, nil
}

// RevokeIdentity is terminal: once revoked, an identity stays revoked.
func (s *MemStorage) RevokeIdentity(tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ident, ok := s.identities[id]
	if !ok {
		return ErrIdentityNotFound
	}
	p, ok := s.pools[ident.PoolID]
	if !ok || p.TenantID != tenantID {
		return ErrIdentityNotFound
	}
	ident.Status = StatusRevoked
	ident.ClaimedByInstallID = nil
	ident.UpdatedAt = time.Now().UTC()
	s.identities[id] = ident
	return nil
}

// poolCountLocked returns the number of identities in poolID. Caller must hold s.mu.
func (s *MemStorage) poolCountLocked(poolID string) int {
	n := 0
	for _, ident := range s.identities {
		if ident.PoolID == poolID {
			n++
		}
	}
	return n
}

func containsString(xs []string, target string) bool {
	for _, x := range xs {
		if x == target {
			return true
		}
	}
	return false
}
