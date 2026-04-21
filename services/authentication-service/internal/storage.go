package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"
)

// ErrNotFound is returned when any lookup misses. Handlers translate to 404.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a create would collide with an existing row
// (e.g. user email already taken within a tenant). Handlers translate to 409.
var ErrConflict = errors.New("conflict")

// Storage is the authentication-service persistence contract. Phase 1 has an
// in-memory implementation; phase 2 will introduce a Postgres-backed version.
//
// Users and sessions are tenant-scoped — every read requires the tenant id and
// returns ErrNotFound when the tenant does not match. Tokens, auth codes, and
// OIDC clients are cross-tenant by nature (the token is itself the bearer's
// proof of tenancy, and the client row is global), so they use key-only lookups.
type Storage interface {
	// Users (tenant-scoped)
	CreateUser(u User) (User, error)
	GetUser(tenantID, id string) (User, error)
	GetUserByEmail(tenantID, email string) (User, error)
	ListUsers(tenantID string) ([]User, error)
	UpdateUser(u User) (User, error)
	DeleteUser(tenantID, id string) error

	// Sessions (tenant-scoped)
	CreateSession(s Session) (Session, error)
	GetSession(tenantID, id string) (Session, error)
	UpdateSession(s Session) (Session, error)

	// Tokens (keyed by SHA-256 hash of the plaintext)
	PutToken(t Token) error
	GetTokenByHash(hash string) (Token, error)
	RevokeTokenByHash(hash string) error

	// Auth codes — one-shot
	PutAuthCode(ac AuthCode) error
	ConsumeAuthCode(code string) (AuthCode, error)

	// OIDC clients
	PutClient(c OIDCClient) error
	GetClient(clientID string) (OIDCClient, error)
}

// MemStorage is an in-memory, thread-safe Storage implementation.
type MemStorage struct {
	mu       sync.RWMutex
	users    map[string]User       // keyed by user id
	sessions map[string]Session    // keyed by session id
	tokens   map[string]Token      // keyed by token_hash
	codes    map[string]AuthCode   // keyed by authorization code
	clients  map[string]OIDCClient // keyed by client id
}

// NewMemStorage returns an empty, initialised MemStorage with the default dev
// OIDC client already seeded. Tests can overwrite or ignore it as needed.
func NewMemStorage() *MemStorage {
	s := &MemStorage{
		users:    make(map[string]User),
		sessions: make(map[string]Session),
		tokens:   make(map[string]Token),
		codes:    make(map[string]AuthCode),
		clients:  make(map[string]OIDCClient),
	}
	s.seedDefaultClient()
	return s
}

// seedDefaultClient writes a single dev OIDC client so cURL examples and local
// testing work without a DCR round-trip. TODO(phase-2): move DCR into this
// service (today it lives in broker-service for the agents product) and drop
// the static seed.
func (s *MemStorage) seedDefaultClient() {
	s.clients[DefaultClientID] = OIDCClient{
		ClientID:         DefaultClientID,
		ClientSecretHash: HashToken(DefaultClientSecret),
		RedirectURIs:     []string{"http://localhost:3000/callback"},
		CreatedAt:        time.Now().UTC(),
	}
}

// ---- Users ----

// CreateUser inserts a new user row. Returns ErrConflict if (tenant_id, email)
// is already taken.
func (s *MemStorage) CreateUser(u User) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.users {
		if existing.TenantID == u.TenantID && existing.Email == u.Email {
			return User{}, ErrConflict
		}
	}
	s.users[u.ID] = u
	return u, nil
}

// GetUser returns the user iff it exists and belongs to tenantID.
func (s *MemStorage) GetUser(tenantID, id string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok || u.TenantID != tenantID {
		return User{}, ErrNotFound
	}
	return u, nil
}

// GetUserByEmail is used by the social-login stub to upsert-by-email.
func (s *MemStorage) GetUserByEmail(tenantID, email string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.TenantID == tenantID && u.Email == email {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

// ListUsers returns every user for tenantID, sorted by CreatedAt asc, id tie-break.
func (s *MemStorage) ListUsers(tenantID string) ([]User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0)
	for _, u := range s.users {
		if u.TenantID == tenantID {
			out = append(out, u)
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

// UpdateUser replaces the row identified by (u.TenantID, u.ID), preserving
// CreatedAt and bumping UpdatedAt.
func (s *MemStorage) UpdateUser(u User) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.users[u.ID]
	if !ok || existing.TenantID != u.TenantID {
		return User{}, ErrNotFound
	}
	// Guard against email collision with a different user in the same tenant.
	if u.Email != existing.Email {
		for id, other := range s.users {
			if id == u.ID {
				continue
			}
			if other.TenantID == u.TenantID && other.Email == u.Email {
				return User{}, ErrConflict
			}
		}
	}
	u.CreatedAt = existing.CreatedAt
	u.UpdatedAt = time.Now().UTC()
	s.users[u.ID] = u
	return u, nil
}

// DeleteUser removes the user (tenant-scoped). Returns ErrNotFound if the user
// does not exist or belongs to a different tenant.
func (s *MemStorage) DeleteUser(tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.users[id]
	if !ok || existing.TenantID != tenantID {
		return ErrNotFound
	}
	delete(s.users, id)
	return nil
}

// ---- Sessions ----

// CreateSession inserts a new session row. Caller fills id, tenant id, timestamps.
func (s *MemStorage) CreateSession(sess Session) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
	return sess, nil
}

// GetSession returns the session iff it exists and belongs to tenantID.
func (s *MemStorage) GetSession(tenantID, id string) (Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok || sess.TenantID != tenantID {
		return Session{}, ErrNotFound
	}
	return sess, nil
}

// UpdateSession replaces the row identified by (s.TenantID, s.ID), preserving
// CreatedAt and bumping UpdatedAt.
func (s *MemStorage) UpdateSession(sess Session) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.sessions[sess.ID]
	if !ok || existing.TenantID != sess.TenantID {
		return Session{}, ErrNotFound
	}
	sess.CreatedAt = existing.CreatedAt
	sess.UpdatedAt = time.Now().UTC()
	s.sessions[sess.ID] = sess
	return sess, nil
}

// ---- Tokens ----

// PutToken stores a token record keyed by the already-hashed plaintext.
func (s *MemStorage) PutToken(t Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[t.TokenHash] = t
	return nil
}

// GetTokenByHash reads a token record by its SHA-256 hash.
func (s *MemStorage) GetTokenByHash(hash string) (Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[hash]
	if !ok {
		return Token{}, ErrNotFound
	}
	return t, nil
}

// RevokeTokenByHash stamps RevokedAt on the token row. Missing tokens are a
// soft-miss (ErrNotFound) so handlers can choose whether to surface 404 or the
// RFC 7009 "always 200" behaviour at their own discretion.
func (s *MemStorage) RevokeTokenByHash(hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[hash]
	if !ok {
		return ErrNotFound
	}
	now := time.Now().UTC()
	t.RevokedAt = &now
	s.tokens[hash] = t
	return nil
}

// ---- Auth codes ----

// PutAuthCode stores a pending authorization code.
func (s *MemStorage) PutAuthCode(ac AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[ac.Code] = ac
	return nil
}

// ConsumeAuthCode reads *and removes* the code in a single critical section.
// Authorization codes are one-shot per OAuth convention — replay must fail.
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

// ---- OIDC clients ----

// PutClient upserts an OIDC client row.
func (s *MemStorage) PutClient(c OIDCClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ClientID] = c
	return nil
}

// GetClient reads an OIDC client by client id.
func (s *MemStorage) GetClient(clientID string) (OIDCClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[clientID]
	if !ok {
		return OIDCClient{}, ErrNotFound
	}
	return c, nil
}

// HashToken returns the SHA-256 hex digest of s. Used as the storage key for
// token records — we never persist plaintext tokens. Also used for the seeded
// client secret to keep a single consistent "hashed at rest" story.
func HashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
