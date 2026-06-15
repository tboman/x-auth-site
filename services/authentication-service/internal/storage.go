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
	ListUsers(tenantID string, limit int, cursor time.Time) ([]User, error)
	UpdateUser(u User) (User, error)
	DeleteUser(tenantID, id string) error

	// Sessions (tenant-scoped)
	CreateSession(s Session) (Session, error)
	GetSession(tenantID, id string) (Session, error)
	UpdateSession(s Session) (Session, error)
	// ListSessions returns a tenant's sessions, newest first, capped at limit
	// (<=0 means a sensible default cap). Powers the session-management views.
	ListSessions(tenantID string, limit int) ([]Session, error)

	// Tokens (keyed by SHA-256 hash of the plaintext)
	PutToken(t Token) error
	GetTokenByHash(hash string) (Token, error)
	RevokeTokenByHash(hash string) error
	// RevokeTokenFamily stamps RevokedAt on every live token (access AND
	// refresh) carrying familyID — the §10.1 theft response when a rotated-out
	// refresh token is replayed. Returns the number of tokens revoked. An empty
	// familyID is a no-op (guards legacy rows migrated without a real family).
	RevokeTokenFamily(familyID string) (int, error)
	// RevokeTokenFamiliesBySession revokes every token family that has issued a
	// token against sessionID — used when a session is judged compromised (e.g.
	// device-fingerprint replay) so its outstanding refresh families die with
	// the session cookie. Returns the number of tokens revoked; an empty
	// sessionID is a no-op.
	RevokeTokenFamiliesBySession(tenantID, sessionID string) (int, error)

	// Auth codes — one-shot
	PutAuthCode(ac AuthCode) error
	ConsumeAuthCode(code string) (AuthCode, error)

	// OIDC clients
	PutClient(c OIDCClient) error
	GetClient(clientID string) (OIDCClient, error)
	// ListClients returns every registered client, newest first. Used by the
	// admin console's client-management view.
	ListClients() ([]OIDCClient, error)
	// DeleteClient removes a client by id. Returns ErrNotFound if absent.
	DeleteClient(clientID string) error

	// ListTenants derives the set of tenants from existing records by
	// aggregating distinct tenant_ids across users and sessions with per-tenant
	// counts, newest activity first. Used by the staff admin console — it
	// surfaces every tenant, including registry-less ones (ten_admin, …).
	ListTenants() ([]TenantSummary, error)

	// Tenant registry (self-service signup). A registry row carries the company
	// name and owner. CreateTenant returns ErrConflict if the slug is taken. An
	// owner email may own MORE THAN one workspace, so it is not unique:
	// ListTenantsByOwnerEmail returns every workspace an account owns (login picks
	// among them) and GetTenantByOwnerEmail returns any one (signup convenience).
	// UpdateTenantOwner reassigns a tenant's workspace owner (staff). The Get*
	// lookups return ErrNotFound on a miss.
	CreateTenant(t Tenant) (Tenant, error)
	GetTenant(id string) (Tenant, error)
	GetTenantBySlug(slug string) (Tenant, error)
	GetTenantByOwnerEmail(email string) (Tenant, error)
	ListTenantsByOwnerEmail(email string) ([]Tenant, error)
	UpdateTenantOwner(tenantID, email string) error

	// Identity anchors (tenant-scoped). CreateIdentityAnchor records an
	// additional way to identify a user — a phone number or a passkey credential
	// id (email stays canonical on users.email). Returns ErrConflict when the
	// (tenant_id, type, value) triple is already taken. ListIdentityAnchors
	// returns every anchor in a tenant, newest first — the master-admin
	// identities view groups them by user. Validation (verifying the anchor) is
	// not implemented yet, so created anchors carry a nil VerifiedAt.
	CreateIdentityAnchor(a IdentityAnchor) (IdentityAnchor, error)
	ListIdentityAnchors(tenantID string) ([]IdentityAnchor, error)
	// GetIdentityAnchorByValue resolves one anchor by (tenant, type, value) —
	// the lookup phone login uses to tell a known number from a new one. Returns
	// ErrNotFound on a miss.
	GetIdentityAnchorByValue(tenantID, anchorType, value string) (IdentityAnchor, error)

	// Device signals (append-only). RecordDeviceSignal logs one device
	// observation captured at a validation stage; ListDeviceSignals returns a
	// tenant's observations, newest first, capped at limit (<=0 = default cap).
	RecordDeviceSignal(ds DeviceSignal) error
	ListDeviceSignals(tenantID string, limit int) ([]DeviceSignal, error)
	// ListDeviceSignalsByUser returns one user's observations, newest first —
	// the history the device analyzer compares a fresh fingerprint against.
	ListDeviceSignalsByUser(tenantID, userID string, limit int) ([]DeviceSignal, error)

	// ProvisionTenant atomically creates a complete self-service workspace —
	// the tenant registry row, its owner user, the owner's initial session, and
	// the confidential OIDC client — in a single all-or-nothing unit. A failure
	// at any step must leave NO rows behind (the alternative orphans a tenant
	// with no client, blocking the owner's email from a clean retry). Returns
	// ErrConflict if the slug or owner email is already taken.
	ProvisionTenant(t Tenant, owner User, sess Session, client OIDCClient) error

	// Staff users
	PutStaffUser(u StaffUser) error
	GetStaffUserByEmail(email string) (StaffUser, error)
	GetStaffUserRoles(userID string) ([]string, error)
	AddStaffUserRole(userID, role string) error
	ListStaffUsers() ([]StaffUser, error)
	DeleteStaffUserRole(userID, role string) error

	// Transaction types (tenant-scoped). A tenant maps a named transaction type
	// to a protection-level ACR (owner dashboard); the /advice endpoint reads it.
	// CreateTransactionType returns ErrConflict on a duplicate (tenant_id, name);
	// Get/Delete return ErrNotFound on a miss. List is name-ordered.
	CreateTransactionType(tt TransactionType) error
	ListTransactionTypes(tenantID string) ([]TransactionType, error)
	GetTransactionType(tenantID, name string) (TransactionType, error)
	DeleteTransactionType(tenantID, name string) error

	// Advice calls (append-only). RecordAdviceCall logs one /v1/advice request;
	// ListAdviceCalls returns matching records newest-first for the staff history
	// view (filtered by tenant and/or user; empty filter fields match all).
	RecordAdviceCall(c AdviceCall) error
	ListAdviceCalls(filter AdviceCallFilter) ([]AdviceCall, error)
	// MarkAdviceCallCompleted stamps the advice row whose id == transactionID (and
	// tenant matches) as completed at the given auth context. A no-op (nil) if no
	// such row exists — the caller may pass a transaction_id we never issued.
	MarkAdviceCallCompleted(tenantID, transactionID, userID, acr string, at time.Time) error

	// Maintenance. PurgeExpired removes expired tokens, stale auth codes, and
	// long-expired sessions, returning the total number of entries removed.
	// Called periodically by the background sweeper in cmd/main.go.
	PurgeExpired(now time.Time) (int, error)
}

// MemStorage is an in-memory, thread-safe Storage implementation.
type MemStorage struct {
	mu        sync.RWMutex
	users     map[string]User            // keyed by user id
	sessions  map[string]Session         // keyed by session id
	tokens    map[string]Token           // keyed by token_hash
	codes     map[string]AuthCode        // keyed by authorization code
	clients   map[string]OIDCClient      // keyed by client id
	tenants   map[string]Tenant          // keyed by tenant id
	anchors   map[string]IdentityAnchor  // keyed by anchor id
	devSigs   []DeviceSignal             // append-only device-signal log
	adviceLog []AdviceCall               // append-only /v1/advice call log
	staffUsr  map[string]StaffUser       // keyed by user id
	staffRol  map[string][]string        // keyed by user id
	txnTypes  map[string]TransactionType // keyed by tenant_id\x00name
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
		tenants:  make(map[string]Tenant),
		anchors:  make(map[string]IdentityAnchor),
		staffUsr: make(map[string]StaffUser),
		staffRol: make(map[string][]string),
		txnTypes: make(map[string]TransactionType),
	}
	s.seedDefaultClient()
	return s
}

// seedDefaultClient writes a single dev OIDC client so cURL examples and local
// testing work without a DCR round-trip. TODO(phase-2): move DCR into this
// service (today it lives in broker-service for the agents product) and drop
// the static seed.
func (s *MemStorage) seedDefaultClient() {
	// Phase 1: the default dev client is treated as a public client (no secret),
	// so cURL examples and tests can exchange codes without client authentication.
	// The DefaultClientSecret constant is retained for the phase-2 switch to a
	// confidential client once real secrets per environment land.
	// TODO(phase-2): seed a confidential client with a random, hashed secret.
	_ = DefaultClientSecret
	s.clients[DefaultClientID] = OIDCClient{
		ClientID:         DefaultClientID,
		ClientSecretHash: "",
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
	// Uniqueness is on a PRESENT email only (migration 000008's partial index):
	// any number of phone-only users may have an empty/NULL email.
	if u.Email != "" {
		for _, existing := range s.users {
			if existing.TenantID == u.TenantID && existing.Email == u.Email {
				return User{}, ErrConflict
			}
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
	if email == "" {
		return User{}, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.TenantID == tenantID && u.Email == email {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

// ListUsers returns up to limit users for tenantID, newest first (CreatedAt
// desc, id desc tie-break). A non-zero cursor restricts results to users
// strictly older than the cursor — the keyset-pagination contract shared with
// transaction-service. limit <= 0 means "no limit".
func (s *MemStorage) ListUsers(tenantID string, limit int, cursor time.Time) ([]User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0)
	for _, u := range s.users {
		if u.TenantID != tenantID {
			continue
		}
		if !cursor.IsZero() && !u.CreatedAt.Before(cursor) {
			continue
		}
		out = append(out, u)
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

// DefaultSessionListCap bounds an unspecified ListSessions request.
const DefaultSessionListCap = 100

// ListSessions returns the tenant's sessions, newest first (CreatedAt desc, id
// desc tie-break), capped at limit.
func (s *MemStorage) ListSessions(tenantID string, limit int) ([]Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = DefaultSessionListCap
	}
	out := make([]Session, 0)
	for _, sess := range s.sessions {
		if sess.TenantID == tenantID {
			out = append(out, sess)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
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

// RevokeTokenFamily stamps RevokedAt on every live token in familyID. Already-
// revoked tokens are left untouched (their original revocation instant is the
// interesting forensic datum) and do not count toward the returned total.
func (s *MemStorage) RevokeTokenFamily(familyID string) (int, error) {
	if familyID == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	revoked := 0
	for hash, t := range s.tokens {
		if t.FamilyID != familyID || t.RevokedAt != nil {
			continue
		}
		t.RevokedAt = &now
		s.tokens[hash] = t
		revoked++
	}
	return revoked, nil
}

// RevokeTokenFamiliesBySession revokes every token family that has issued any
// token against sessionID. Two passes: collect the distinct families touched by
// the session, then stamp every live token in those families (covers tokens
// rotated onto the same family after the session moved on).
func (s *MemStorage) RevokeTokenFamiliesBySession(tenantID, sessionID string) (int, error) {
	if sessionID == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	families := map[string]struct{}{}
	for _, t := range s.tokens {
		if t.SessionID == sessionID && t.TenantID == tenantID && t.FamilyID != "" {
			families[t.FamilyID] = struct{}{}
		}
	}
	if len(families) == 0 {
		return 0, nil
	}
	now := time.Now().UTC()
	revoked := 0
	for hash, t := range s.tokens {
		if t.FamilyID == "" || t.RevokedAt != nil {
			continue
		}
		if _, ok := families[t.FamilyID]; !ok {
			continue
		}
		t.RevokedAt = &now
		s.tokens[hash] = t
		revoked++
	}
	return revoked, nil
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

// ListClients returns every registered client, newest first.
func (s *MemStorage) ListClients() ([]OIDCClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]OIDCClient, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ClientID < out[j].ClientID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// DeleteClient removes a client by id.
func (s *MemStorage) DeleteClient(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[clientID]; !ok {
		return ErrNotFound
	}
	delete(s.clients, clientID)
	return nil
}

// ---- Tenants (derived) ----

// ListTenants aggregates distinct tenant_ids across users and sessions with
// per-tenant counts and the most recent activity stamp, newest activity first.
func (s *MemStorage) ListTenants() ([]TenantSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	byID := make(map[string]*TenantSummary)
	touch := func(tenantID string, ts time.Time) *TenantSummary {
		sum, ok := byID[tenantID]
		if !ok {
			sum = &TenantSummary{TenantID: tenantID}
			byID[tenantID] = sum
		}
		if ts.After(sum.LastActivity) {
			sum.LastActivity = ts
		}
		return sum
	}
	for _, u := range s.users {
		touch(u.TenantID, u.CreatedAt).Users++
	}
	for _, sess := range s.sessions {
		touch(sess.TenantID, sess.UpdatedAt).Sessions++
	}

	out := make([]TenantSummary, 0, len(byID))
	for _, sum := range byID {
		out = append(out, *sum)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastActivity.Equal(out[j].LastActivity) {
			return out[i].TenantID < out[j].TenantID
		}
		return out[i].LastActivity.After(out[j].LastActivity)
	})
	return out, nil
}

// ---- Tenant registry ----

// CreateTenant inserts a registry row. Returns ErrConflict if the slug is taken
// (mirrors the PG unique constraint). An owner email is NOT unique — a user can
// own multiple workspaces.
func (s *MemStorage) CreateTenant(t Tenant) (Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.tenants {
		if existing.Slug == t.Slug {
			return Tenant{}, ErrConflict
		}
	}
	s.tenants[t.ID] = t
	return t, nil
}

// GetTenant returns the registry row for id, or ErrNotFound.
func (s *MemStorage) GetTenant(id string) (Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tenants[id]
	if !ok {
		return Tenant{}, ErrNotFound
	}
	return t, nil
}

// GetTenantBySlug returns the registry row whose slug matches, or ErrNotFound.
// Used for the "is this company name available?" check at signup.
func (s *MemStorage) GetTenantBySlug(slug string) (Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tenants {
		if t.Slug == slug {
			return t, nil
		}
	}
	return Tenant{}, ErrNotFound
}

// GetTenantByOwnerEmail returns any registry row owned by email, or ErrNotFound.
// A convenience for signup; login uses ListTenantsByOwnerEmail to see all.
func (s *MemStorage) GetTenantByOwnerEmail(email string) (Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tenants {
		if t.OwnerEmail == email {
			return t, nil
		}
	}
	return Tenant{}, ErrNotFound
}

// ListTenantsByOwnerEmail returns every workspace owned by email, slug-ordered.
func (s *MemStorage) ListTenantsByOwnerEmail(email string) ([]Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tenant, 0)
	for _, t := range s.tenants {
		if t.OwnerEmail == email {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

// UpdateTenantOwner reassigns a tenant's workspace owner. ErrNotFound if the
// tenant has no registry row.
func (s *MemStorage) UpdateTenantOwner(tenantID, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[tenantID]
	if !ok {
		return ErrNotFound
	}
	t.OwnerEmail = email
	s.tenants[tenantID] = t
	return nil
}

// ProvisionTenant writes the tenant, owner, session, and client under one lock.
// All conflict checks run before any write, so a rejected provision leaves the
// store untouched — the in-memory analogue of the PGStorage transaction.
func (s *MemStorage) ProvisionTenant(t Tenant, owner User, sess Session, client OIDCClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.tenants {
		if existing.Slug == t.Slug {
			return ErrConflict
		}
	}
	for _, u := range s.users {
		if u.TenantID == owner.TenantID && u.Email == owner.Email {
			return ErrConflict
		}
	}
	s.tenants[t.ID] = t
	s.users[owner.ID] = owner
	s.sessions[sess.ID] = sess
	s.clients[client.ClientID] = client
	return nil
}

// ---- Identity anchors ----

// CreateIdentityAnchor records an additional anchor for a user. Returns
// ErrConflict if the (tenant_id, type, value) triple is already taken (mirrors
// the uq_identity_anchor constraint in the PG schema).
func (s *MemStorage) CreateIdentityAnchor(a IdentityAnchor) (IdentityAnchor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.anchors {
		if existing.TenantID == a.TenantID && existing.Type == a.Type && existing.Value == a.Value {
			return IdentityAnchor{}, ErrConflict
		}
	}
	s.anchors[a.ID] = a
	return a, nil
}

// RecordDeviceSignal appends one device observation.
func (s *MemStorage) RecordDeviceSignal(ds DeviceSignal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devSigs = append(s.devSigs, ds)
	return nil
}

// ListDeviceSignals returns tenantID's observations, newest first, capped.
func (s *MemStorage) ListDeviceSignals(tenantID string, limit int) ([]DeviceSignal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = DefaultSessionListCap
	}
	out := make([]DeviceSignal, 0)
	// devSigs is append-ordered (oldest→newest); walk backwards for newest-first.
	for i := len(s.devSigs) - 1; i >= 0 && len(out) < limit; i-- {
		if s.devSigs[i].TenantID == tenantID {
			out = append(out, s.devSigs[i])
		}
	}
	return out, nil
}

// ListDeviceSignalsByUser returns tenantID/userID's observations, newest first.
func (s *MemStorage) ListDeviceSignalsByUser(tenantID, userID string, limit int) ([]DeviceSignal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = DefaultSessionListCap
	}
	out := make([]DeviceSignal, 0)
	for i := len(s.devSigs) - 1; i >= 0 && len(out) < limit; i-- {
		if s.devSigs[i].TenantID == tenantID && s.devSigs[i].UserID == userID {
			out = append(out, s.devSigs[i])
		}
	}
	return out, nil
}

// GetIdentityAnchorByValue resolves one anchor by (tenant, type, value). The
// triple is unique (mirrors the PG uq_identity_anchor constraint), so at most
// one matches. Returns ErrNotFound on a miss.
func (s *MemStorage) GetIdentityAnchorByValue(tenantID, anchorType, value string) (IdentityAnchor, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.anchors {
		if a.TenantID == tenantID && a.Type == anchorType && a.Value == value {
			return a, nil
		}
	}
	return IdentityAnchor{}, ErrNotFound
}

// ListIdentityAnchors returns every anchor in tenantID, newest first (CreatedAt
// desc, id desc tie-break) — the order the master-admin identities view groups
// by user.
func (s *MemStorage) ListIdentityAnchors(tenantID string) ([]IdentityAnchor, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]IdentityAnchor, 0)
	for _, a := range s.anchors {
		if a.TenantID == tenantID {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// ---- Maintenance ----

// PurgeExpired sweeps artefacts that read-time TTL checks would refuse anyway,
// so the maps (and, in PGStorage, the tables) don't grow unbounded. Predicates
// mirror the handlers' read-time expiry semantics exactly:
//
//   - tokens: removed when now.After(ExpiresAt) — the same check /userinfo and
//     the refresh grant apply before honouring a token, so a swept token only
//     changes the rejection detail ("unknown" instead of "expired"). Revoked
//     but unexpired tokens are KEPT: their RevokedAt state is still observable.
//   - auth codes: removed when CreatedAt is more than AuthCodeTTLSeconds ago —
//     handleCodeGrant rejects time.Since(CreatedAt) > TTL, so a swept code
//     would have been refused as expired on exchange.
//   - sessions: sessions carry ExpiresAt but NO handler rejects an expired
//     session at read time — GET /v1/sessions/{id} returns expired sessions
//     for inspection, and the refresh grant deliberately accepts an
//     expired-but-not-invalidated session while a live refresh token points at
//     it (extending ExpiresAt again). Expiry alone is therefore not safe to
//     purge. Instead a session is swept only once it has been expired for a
//     full RefreshTokenTTLSeconds: the newest refresh token bound to a session
//     expires at most RefreshTokenTTL−SessionTTL after the session's own
//     ExpiresAt (both stamps are set from the same instant on issue/rotation),
//     so past that grace window nothing can resurrect or rely on the session.
//
// Returns the total number of entries removed across all three stores.
func (s *MemStorage) PurgeExpired(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for hash, t := range s.tokens {
		if now.After(t.ExpiresAt) {
			delete(s.tokens, hash)
			removed++
		}
	}
	codeDeadline := now.Add(-time.Duration(AuthCodeTTLSeconds) * time.Second)
	for code, ac := range s.codes {
		if ac.CreatedAt.Before(codeDeadline) {
			delete(s.codes, code)
			removed++
		}
	}
	sessDeadline := now.Add(-time.Duration(RefreshTokenTTLSeconds) * time.Second)
	for id, sess := range s.sessions {
		if sess.ExpiresAt.Before(sessDeadline) {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed, nil
}

// HashToken returns the SHA-256 hex digest of s. Used as the storage key for
// token records — we never persist plaintext tokens. Also used for the seeded
// client secret to keep a single consistent "hashed at rest" story.
func HashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ---- Staff Users ----

func (s *MemStorage) PutStaffUser(u StaffUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.staffUsr[u.ID] = u
	return nil
}

func (s *MemStorage) GetStaffUserByEmail(email string) (StaffUser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.staffUsr {
		if u.Email == email {
			return u, nil
		}
	}
	return StaffUser{}, ErrNotFound
}

func (s *MemStorage) GetStaffUserRoles(userID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	roles, ok := s.staffRol[userID]
	if !ok {
		return []string{}, nil
	}
	// return a copy
	out := make([]string, len(roles))
	copy(out, roles)
	return out, nil
}

func (s *MemStorage) AddStaffUserRole(userID, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	roles := s.staffRol[userID]
	for _, r := range roles {
		if r == role {
			return nil
		}
	}
	s.staffRol[userID] = append(roles, role)
	return nil
}

func (s *MemStorage) ListStaffUsers() ([]StaffUser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]StaffUser, 0, len(s.staffUsr))
	for _, u := range s.staffUsr {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Email < out[j].Email
	})
	return out, nil
}

func (s *MemStorage) DeleteStaffUserRole(userID, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	roles := s.staffRol[userID]
	for i, r := range roles {
		if r == role {
			s.staffRol[userID] = append(roles[:i], roles[i+1:]...)
			return nil
		}
	}
	return nil
}

// ---- Transaction types ----

func ttKey(tenantID, name string) string { return tenantID + "\x00" + name }

func (s *MemStorage) CreateTransactionType(tt TransactionType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := ttKey(tt.TenantID, tt.Name)
	if _, exists := s.txnTypes[k]; exists {
		return ErrConflict
	}
	s.txnTypes[k] = tt
	return nil
}

func (s *MemStorage) ListTransactionTypes(tenantID string) ([]TransactionType, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TransactionType, 0)
	for _, tt := range s.txnTypes {
		if tt.TenantID == tenantID {
			out = append(out, tt)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *MemStorage) GetTransactionType(tenantID, name string) (TransactionType, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tt, ok := s.txnTypes[ttKey(tenantID, name)]
	if !ok {
		return TransactionType{}, ErrNotFound
	}
	return tt, nil
}

func (s *MemStorage) DeleteTransactionType(tenantID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := ttKey(tenantID, name)
	if _, ok := s.txnTypes[k]; !ok {
		return ErrNotFound
	}
	delete(s.txnTypes, k)
	return nil
}

// ---- Advice calls ----

func (s *MemStorage) RecordAdviceCall(c AdviceCall) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adviceLog = append(s.adviceLog, c)
	return nil
}

func (s *MemStorage) ListAdviceCalls(filter AdviceCallFilter) ([]AdviceCall, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	out := make([]AdviceCall, 0)
	// append-ordered (oldest→newest); walk backwards for newest-first.
	for i := len(s.adviceLog) - 1; i >= 0 && len(out) < limit; i-- {
		c := s.adviceLog[i]
		if filter.TenantID != "" && c.TenantID != filter.TenantID {
			continue
		}
		if filter.UserID != "" && c.UserID != filter.UserID {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *MemStorage) MarkAdviceCallCompleted(tenantID, transactionID, userID, acr string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.adviceLog {
		if s.adviceLog[i].ID == transactionID && s.adviceLog[i].TenantID == tenantID {
			t := at
			s.adviceLog[i].CompletedAt = &t
			s.adviceLog[i].CompletedUserID = userID
			s.adviceLog[i].CompletedACR = acr
			return nil
		}
	}
	return nil // unknown transaction_id — no-op
}
