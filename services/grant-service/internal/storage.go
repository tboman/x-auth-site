package internal

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// ErrNotFound is returned when a grant does not exist in the requested tenant.
var ErrNotFound = errors.New("grant not found")

// GrantStore is the grant persistence contract. Phase 1 ships an in-memory
// implementation; phase 2 will add a Postgres-backed one.
type GrantStore interface {
	Create(g Grant) (Grant, error)
	Get(tenantID, id string) (Grant, error)
	Revoke(tenantID, id string, now time.Time) (Grant, bool, error)
	// ListByInstall returns all grants belonging to (tenantID, installID), active or not.
	// Used by /v1/installs/{install_id}/revoke-grants to cascade install revocation.
	ListByInstall(tenantID, installID string) ([]Grant, error)
	// FindByAccessTokenHash returns the grant whose access_token_hash matches, across
	// all tenants. Used by /v1/introspect, which by RFC 7662 cannot assume the caller
	// already knows the tenant that issued the token. Returns ErrNotFound if unknown.
	FindByAccessTokenHash(hash string) (Grant, error)
}

// AuditStore is the append-only audit log contract. There is deliberately no Update
// or Delete method: audit entries are immutable once written.
type AuditStore interface {
	Append(e AuditEvent) (AuditEvent, error)
	Query(tenantID string, f AuditFilter) ([]AuditEvent, error)
}

// AuditFilter narrows a Query call. Empty string / zero time fields are treated as "any".
type AuditFilter struct {
	InstallID string
	GrantID   string
	Type      string
	Since     time.Time
	Until     time.Time
	Limit     int
}

// MemGrantStore is an in-memory, thread-safe GrantStore. Tenant isolation is enforced
// at read time.
type MemGrantStore struct {
	mu   sync.RWMutex
	data map[string]Grant // keyed by grant id
}

// NewMemGrantStore returns an initialised in-memory grant store.
func NewMemGrantStore() *MemGrantStore {
	return &MemGrantStore{data: make(map[string]Grant)}
}

// Create inserts the grant. Caller fills ID, TenantID, timestamps, and hashes.
func (s *MemGrantStore) Create(g Grant) (Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[g.ID] = g
	return g, nil
}

// Get returns the grant if it exists *and* belongs to tenantID. Status is derived here.
func (s *MemGrantStore) Get(tenantID, id string) (Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.data[id]
	if !ok || g.TenantID != tenantID {
		return Grant{}, ErrNotFound
	}
	g.Status = DeriveStatus(g, time.Now().UTC())
	return g, nil
}

// Revoke marks the tenant-scoped grant revoked at `now`. Returns (grant, alreadyRevoked).
// Idempotent: a second revoke is a no-op and returns alreadyRevoked=true with the
// original revoked_at preserved.
func (s *MemGrantStore) Revoke(tenantID, id string, now time.Time) (Grant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.data[id]
	if !ok || g.TenantID != tenantID {
		return Grant{}, false, ErrNotFound
	}
	if g.RevokedAt != nil {
		g.Status = DeriveStatus(g, now)
		return g, true, nil
	}
	t := now
	g.RevokedAt = &t
	s.data[id] = g
	g.Status = DeriveStatus(g, now)
	return g, false, nil
}

// ListByInstall returns every grant bound to (tenantID, installID), sorted by IssuedAt
// ascending. Includes already-revoked / expired grants so the caller can derive an
// accurate before/after view of what this call revoked.
func (s *MemGrantStore) ListByInstall(tenantID, installID string) ([]Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now().UTC()
	out := make([]Grant, 0)
	for _, g := range s.data {
		if g.TenantID != tenantID || g.InstallID != installID {
			continue
		}
		g.Status = DeriveStatus(g, now)
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.Before(out[j].IssuedAt) })
	return out, nil
}

// FindByAccessTokenHash scans for a grant with the matching hash. Returns ErrNotFound
// if none exist. O(n) over the map is fine for phase 1; phase 2 adds a Postgres
// unique index on access_token_hash.
func (s *MemGrantStore) FindByAccessTokenHash(hash string) (Grant, error) {
	if hash == "" {
		return Grant{}, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, g := range s.data {
		if g.AccessTokenHash == hash {
			g.Status = DeriveStatus(g, time.Now().UTC())
			return g, nil
		}
	}
	return Grant{}, ErrNotFound
}

// DeriveStatus computes the Grant status from revoked_at + expires_at at time `now`.
// Revoked wins over expired — a grant that was revoked before it expired is reported
// as revoked, not expired.
func DeriveStatus(g Grant, now time.Time) string {
	if g.RevokedAt != nil {
		return StatusRevoked
	}
	if !g.ExpiresAt.IsZero() && !now.Before(g.ExpiresAt) {
		return StatusExpired
	}
	return StatusActive
}

// MemAuditStore is an append-only, thread-safe AuditStore.
//
// Appends take the write lock, queries take the read lock. There is no Delete or
// Update method by design: once an event is written, it is immutable for the process
// lifetime. Phase 2 will back this with a Postgres table with row-level security and
// no UPDATE/DELETE grant to the service role.
type MemAuditStore struct {
	mu     sync.RWMutex
	events []AuditEvent
}

// NewMemAuditStore returns an initialised in-memory audit log.
func NewMemAuditStore() *MemAuditStore {
	return &MemAuditStore{events: make([]AuditEvent, 0)}
}

// Append records the event. Caller fills ID, TenantID, and CreatedAt.
func (s *MemAuditStore) Append(e AuditEvent) (AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return e, nil
}

// Query returns tenant-scoped events matching the filter, sorted by CreatedAt descending
// (most recent first), limited by f.Limit (which must be >= 1; the handler clamps it).
func (s *MemAuditStore) Query(tenantID string, f AuditFilter) ([]AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEvent, 0)
	for _, e := range s.events {
		if e.TenantID != tenantID {
			continue
		}
		if f.InstallID != "" && e.InstallID != f.InstallID {
			continue
		}
		if f.GrantID != "" && e.GrantID != f.GrantID {
			continue
		}
		if f.Type != "" && e.Type != f.Type {
			continue
		}
		if !f.Since.IsZero() && e.CreatedAt.Before(f.Since) {
			continue
		}
		if !f.Until.IsZero() && !e.CreatedAt.Before(f.Until) {
			// Until is exclusive — events at exactly Until are NOT included. This matches
			// the common "[since, until)" convention for time-range queries.
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}
