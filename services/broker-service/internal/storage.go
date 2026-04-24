package internal

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// ErrNotFound is returned when an install, code, client, or token lookup misses.
var ErrNotFound = errors.New("not found")

// Storage is the broker-service persistence contract. Phase 1 has an in-memory
// implementation; phase 2 will introduce a Postgres-backed version.
//
// All install read/write operations are tenant-scoped — callers must supply the
// tenant id and the store refuses to return rows that belong to a different tenant.
// Auth codes, DCR clients, and token records are cross-tenant by nature (the code
// carries the tenant id it was issued for, and the token is the bearer's proof of
// tenancy), so they use key-only lookups.
type Storage interface {
	// Installs
	CreateInstall(i Install) (Install, error)
	GetInstall(tenantID, id string) (Install, error)
	UpdateInstall(i Install) (Install, error)
	ListInstalls(tenantID string) ([]Install, error)

	// DCR clients
	PutClient(c DCRClient) error
	GetClient(clientID string) (DCRClient, error)

	// Auth codes
	PutAuthCode(ac AuthCode) error
	ConsumeAuthCode(code string) (AuthCode, error) // read + delete

	// Token records
	PutToken(t TokenRecord) error
	GetToken(accessToken string) (TokenRecord, error)
	DeleteToken(accessToken string) error
}

// MemStorage is an in-memory, thread-safe Storage implementation.
type MemStorage struct {
	mu       sync.RWMutex
	installs map[string]Install     // keyed by install id
	clients  map[string]DCRClient   // keyed by client id
	codes    map[string]AuthCode    // keyed by authorization code
	tokens   map[string]TokenRecord // keyed by access token
}

// NewMemStorage returns an empty, initialised MemStorage.
func NewMemStorage() *MemStorage {
	return &MemStorage{
		installs: make(map[string]Install),
		clients:  make(map[string]DCRClient),
		codes:    make(map[string]AuthCode),
		tokens:   make(map[string]TokenRecord),
	}
}

// CreateInstall inserts the install. Caller fills ID, TenantID, and timestamps.
func (s *MemStorage) CreateInstall(i Install) (Install, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.installs[i.ID] = i
	return i, nil
}

// GetInstall returns the install if it exists *and* belongs to tenantID.
func (s *MemStorage) GetInstall(tenantID, id string) (Install, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i, ok := s.installs[id]
	if !ok || i.TenantID != tenantID {
		return Install{}, ErrNotFound
	}
	return i, nil
}

// UpdateInstall replaces the row identified by (i.TenantID, i.ID), preserving CreatedAt.
func (s *MemStorage) UpdateInstall(i Install) (Install, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.installs[i.ID]
	if !ok || existing.TenantID != i.TenantID {
		return Install{}, ErrNotFound
	}
	i.CreatedAt = existing.CreatedAt
	i.UpdatedAt = time.Now().UTC()
	s.installs[i.ID] = i
	return i, nil
}

// ListInstalls returns every install belonging to tenantID, sorted by CreatedAt asc.
func (s *MemStorage) ListInstalls(tenantID string) ([]Install, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Install, 0)
	for _, i := range s.installs {
		if i.TenantID == tenantID {
			out = append(out, i)
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

// PutClient upserts a DCR client.
func (s *MemStorage) PutClient(c DCRClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ClientID] = c
	return nil
}

// GetClient reads by client id.
func (s *MemStorage) GetClient(clientID string) (DCRClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[clientID]
	if !ok {
		return DCRClient{}, ErrNotFound
	}
	return c, nil
}

// PutAuthCode stores a pending authorization code. If CreatedAt is the zero
// value (direct-seed path in tests and admin tools that bypass /authorize) we
// stamp it to now so the TTL window in handleCodeGrant is meaningful.
func (s *MemStorage) PutAuthCode(ac AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ac.CreatedAt.IsZero() {
		ac.CreatedAt = time.Now().UTC()
	}
	s.codes[ac.Code] = ac
	return nil
}

// ConsumeAuthCode reads *and removes* the code in a single critical section.
// Authorization codes are one-shot by OAuth convention — once consumed, replay
// attempts must fail.
func (s *MemStorage) ConsumeAuthCode(code string) (AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.codes[code]
	if !ok {
		return AuthCode{}, ErrNotFound
	}
	delete(s.codes, code)
	return ac, nil
}

// PutToken stores an issued token record.
func (s *MemStorage) PutToken(t TokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[t.AccessToken] = t
	return nil
}

// GetToken reads by access token.
func (s *MemStorage) GetToken(accessToken string) (TokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[accessToken]
	if !ok {
		return TokenRecord{}, ErrNotFound
	}
	return t, nil
}

// DeleteToken removes a token (used by /revoke).
func (s *MemStorage) DeleteToken(accessToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tokens[accessToken]; !ok {
		return ErrNotFound
	}
	delete(s.tokens, accessToken)
	return nil
}
