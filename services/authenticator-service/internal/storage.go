package internal

import (
	"errors"
	"sync"
	"time"
)

// ErrNotFound is returned when a lookup misses for the requesting tenant.
// Callers translate this to a 404.
var ErrNotFound = errors.New("not found")

// Storage is the authenticator-service persistence contract. Phase 1 provides
// the in-memory Store; phase 2 adds the Postgres-backed PGStorage (see
// docs/postgres.md). Both enforce tenant isolation on every read/write and
// return ErrNotFound for cross-tenant access.
//
// Phase 2.1 widened the method set: every operation that can fail now returns
// an error, so PGStorage propagates persistence failures instead of the old
// log-and-degrade behaviour (dropped put / empty list). Handlers translate
// non-ErrNotFound errors to 500 internal_error.
type Storage interface {
	Now() time.Time

	PutAuthenticator(a Authenticator) error
	GetAuthenticator(tenantID, id string) (Authenticator, error)
	ListAuthenticators(tenantID, userID string) ([]Authenticator, error)
	ListActiveAuthenticators(tenantID, userID string) ([]Authenticator, error)
	DisableAuthenticator(tenantID, id string) error

	PutChallenge(c Challenge) error
	GetChallenge(tenantID, id string) (Challenge, error)
	UpdateChallenge(tenantID, id string, mutator func(*Challenge)) (Challenge, error)

	// PurgeExpired deletes challenges that can never be verified again: rows
	// still `pending` whose expires_at is at or before now, plus rows already
	// lazily flipped to `expired`. It returns how many rows were removed.
	// Run periodically by the background sweeper in cmd/main.go.
	PurgeExpired(now time.Time) (int, error)
}

// Store is an in-memory, goroutine-safe repository for authenticators and
// challenges. Phase-1 Storage implementation — PGStorage is the phase-2
// PostgreSQL replacement; call sites pick one via the Storage interface.
type Store struct {
	mu             sync.RWMutex
	authenticators map[string]Authenticator // key: authenticator id
	challenges     map[string]Challenge     // key: challenge id
	now            func() time.Time
}

var _ Storage = (*Store)(nil)

// NewStore builds an empty Store. now is used for all timestamps; tests
// inject a fake clock. Pass nil for wall-clock time.
func NewStore(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		authenticators: make(map[string]Authenticator),
		challenges:     make(map[string]Challenge),
		now:            now,
	}
}

// Now returns the store's current time — used by handlers so tests can
// travel through time without poking into internals.
func (s *Store) Now() time.Time { return s.now() }

// -----------------------------------------------------------------------------
// Authenticator operations
// -----------------------------------------------------------------------------

// PutAuthenticator stores a (possibly new) authenticator. The caller is
// responsible for generating the id and stamping created/updated times.
// The in-memory implementation cannot fail; the error is always nil.
func (s *Store) PutAuthenticator(a Authenticator) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authenticators[a.ID] = a
	return nil
}

// GetAuthenticator fetches by id within a tenant. Cross-tenant reads return
// ErrNotFound — the record might exist, but not for this caller.
func (s *Store) GetAuthenticator(tenantID, id string) (Authenticator, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.authenticators[id]
	if !ok || a.TenantID != tenantID {
		return Authenticator{}, ErrNotFound
	}
	return a, nil
}

// ListAuthenticators returns every authenticator for a user within a tenant,
// including soft-deleted (`disabled`) ones so callers can audit history.
// Challenge method selection uses ListActiveAuthenticators instead.
func (s *Store) ListAuthenticators(tenantID, userID string) ([]Authenticator, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Authenticator, 0)
	for _, a := range s.authenticators {
		if a.TenantID == tenantID && a.UserID == userID {
			out = append(out, a)
		}
	}
	return out, nil
}

// ListActiveAuthenticators returns only `active` authenticators for a user.
func (s *Store) ListActiveAuthenticators(tenantID, userID string) ([]Authenticator, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Authenticator, 0)
	for _, a := range s.authenticators {
		if a.TenantID == tenantID && a.UserID == userID && a.Status == AuthenticatorStatusActive {
			out = append(out, a)
		}
	}
	return out, nil
}

// DisableAuthenticator soft-deletes by flipping status to `disabled`. Idempotent:
// disabling an already-disabled authenticator is a no-op (still returns nil).
func (s *Store) DisableAuthenticator(tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.authenticators[id]
	if !ok || a.TenantID != tenantID {
		return ErrNotFound
	}
	if a.Status != AuthenticatorStatusDisabled {
		a.Status = AuthenticatorStatusDisabled
		a.UpdatedAt = s.now()
		s.authenticators[id] = a
	}
	return nil
}

// -----------------------------------------------------------------------------
// Challenge operations
// -----------------------------------------------------------------------------

// PutChallenge stores a (possibly new) challenge. The in-memory
// implementation cannot fail; the error is always nil.
func (s *Store) PutChallenge(c Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[c.ID] = c
	return nil
}

// GetChallenge fetches by id within a tenant. Cross-tenant reads return
// ErrNotFound.
func (s *Store) GetChallenge(tenantID, id string) (Challenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.challenges[id]
	if !ok || c.TenantID != tenantID {
		return Challenge{}, ErrNotFound
	}
	return c, nil
}

// UpdateChallenge applies mutator under the store's write lock. Returns
// ErrNotFound if the challenge has been evicted or never existed. mutator
// may change any field except ID and TenantID (we refuse to persist if
// those differ, since that's a programmer bug).
func (s *Store) UpdateChallenge(tenantID, id string, mutator func(*Challenge)) (Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[id]
	if !ok || c.TenantID != tenantID {
		return Challenge{}, ErrNotFound
	}
	mutator(&c)
	if c.ID != id || c.TenantID != tenantID {
		// Programmer error — refuse silently corrupting state.
		return Challenge{}, errors.New("mutator changed immutable fields")
	}
	s.challenges[id] = c
	return c, nil
}

// PurgeExpired removes challenges that can never be verified again:
//
//   - `pending` rows whose expires_at is at or before now (same comparison the
//     verify handler uses for lazy expiry: !now.Before(expires_at)), and
//   - rows already lazily flipped to `expired` by a late verify call.
//
// Retention choice: `completed` and `failed` challenges are deliberately KEPT
// regardless of age — they double as the audit trail of step-up attempts (see
// migrations/000001_init.up.sql), and the migration's partial index only
// targets pending rows. Age-based retention for terminal audit rows is a
// separate compliance concern (GDPR erasure / retention policy), not this
// sweeper's job.
func (s *Store) PurgeExpired(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, c := range s.challenges {
		if c.Status == ChallengeStatusExpired ||
			(c.Status == ChallengeStatusPending && !now.Before(c.ExpiresAt)) {
			delete(s.challenges, id)
			n++
		}
	}
	return n, nil
}
