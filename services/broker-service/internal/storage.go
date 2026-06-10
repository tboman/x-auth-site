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
	// ListInstalls returns up to `limit` installs for tenantID ordered by
	// CreatedAt desc, id desc. A non-zero cursor restricts the result to rows
	// strictly older than the cursor (keyset pagination). limit <= 0 means no cap.
	ListInstalls(tenantID string, limit int, cursor time.Time) ([]Install, error)

	// DCR clients
	PutClient(c DCRClient) error
	GetClient(clientID string) (DCRClient, error)

	// Auth codes
	PutAuthCode(ac AuthCode) error
	ConsumeAuthCode(code string) (AuthCode, error) // read + delete

	// Token records. PutToken is an upsert keyed by access token — re-Putting an
	// existing record (e.g. with RotatedAt stamped) replaces it in place.
	// GetTokenByRefresh is the refresh-grant lookup; it returns ErrNotFound when
	// no record carries the given refresh token. DeleteTokensForInstall removes
	// every token record bound to an install (replay-revocation cleanup) and
	// returns the number of records removed.
	PutToken(t TokenRecord) error
	GetToken(accessToken string) (TokenRecord, error)
	GetTokenByRefresh(refreshToken string) (TokenRecord, error)
	DeleteToken(accessToken string) error
	DeleteTokensForInstall(installID string) (int, error)

	// Maintenance. PurgeExpired removes tokens and auth codes whose TTLs have
	// lapsed as of `now` and returns the total number of entries removed. The
	// predicates mirror read-time enforcement exactly (see implementations).
	PurgeExpired(now time.Time) (int, error)
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

// ListInstalls returns up to `limit` installs owned by tenantID, ordered by
// CreatedAt desc, id desc. If `cursor` is non-zero, only installs strictly older
// than the cursor are returned — stable keyset pagination without offsets, same
// contract as transaction-service's MemStorage.List.
func (s *MemStorage) ListInstalls(tenantID string, limit int, cursor time.Time) ([]Install, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Install, 0)
	for _, i := range s.installs {
		if i.TenantID != tenantID {
			continue
		}
		if !cursor.IsZero() && !i.CreatedAt.Before(cursor) {
			continue
		}
		out = append(out, i)
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

// GetTokenByRefresh reads by refresh token (linear scan — fine for the
// in-memory phase; PGStorage uses the idx_tokens_refresh index). An empty
// refresh token never matches: records issued without one must not be
// reachable via the refresh grant.
func (s *MemStorage) GetTokenByRefresh(refreshToken string) (TokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if refreshToken == "" {
		return TokenRecord{}, ErrNotFound
	}
	for _, t := range s.tokens {
		if t.RefreshToken == refreshToken {
			return t, nil
		}
	}
	return TokenRecord{}, ErrNotFound
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

// DeleteTokensForInstall removes every token record bound to installID and
// returns the number removed. Used by the refresh-grant replay revocation so a
// stolen-and-replayed refresh token kills the rotated-out descendants too.
// Deleting zero records is not an error — revocation is idempotent.
func (s *MemStorage) DeleteTokensForInstall(installID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for k, t := range s.tokens {
		if t.InstallID == installID {
			delete(s.tokens, k)
			removed++
		}
	}
	return removed, nil
}

// PurgeExpired sweeps the token and auth-code maps, removing entries whose TTLs
// have lapsed as of `now`. The predicates mirror read-time enforcement exactly:
//   - tokens: /userinfo rejects a bearer when now is after TokenRecord.ExpiresAt
//     (oidc.go), so any record with ExpiresAt before now is dead weight;
//   - auth codes: codes carry no stored expiry — /token rejects them when
//     time.Since(CreatedAt) exceeds AuthCodeTTLSeconds, so the purge cutoff is
//     CreatedAt older than now-AuthCodeTTLSeconds.
//
// Rotated records (RotatedAt != nil) need no extra predicate: rotation keeps
// the record's original ExpiresAt (the access-token expiry), so the same
// ExpiresAt sweep removes them once their access token dies — they cannot
// survive the purge indefinitely. Until then they MUST stay: the rotated
// marker is what powers refresh-replay detection.
//
// Returns the total number of entries removed across both maps.
func (s *MemStorage) PurgeExpired(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for k, t := range s.tokens {
		if now.After(t.ExpiresAt) {
			delete(s.tokens, k)
			removed++
		}
	}
	codeCutoff := now.Add(-time.Duration(AuthCodeTTLSeconds) * time.Second)
	for k, ac := range s.codes {
		if ac.CreatedAt.Before(codeCutoff) {
			delete(s.codes, k)
			removed++
		}
	}
	return removed, nil
}
