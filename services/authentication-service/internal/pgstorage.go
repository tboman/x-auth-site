package internal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGStorage is the Postgres-backed Storage implementation. It preserves the same
// semantics as MemStorage — tenant isolation on every user/session read/write,
// ErrNotFound on misses, ErrConflict on (tenant_id, email) collisions — so the
// HTTP layer can swap implementations without behavioural drift.
//
// The schema lives in services/authentication-service/migrations/. The default
// dev OIDC client (cli_default) is seeded by the migration, mirroring
// MemStorage's seedDefaultClient.
type PGStorage struct {
	pool *pgxpool.Pool
}

// NewPGStorage returns a Storage backed by the given pgx pool. Callers retain
// ownership of the pool (e.g. close it on shutdown).
func NewPGStorage(pool *pgxpool.Pool) *PGStorage {
	return &PGStorage{pool: pool}
}

// bgCtx is the background context used for DB operations. The current Storage
// signatures don't accept context (matching MemStorage); we rely on pool-level
// defaults until the interface grows ctx support.
func bgCtx() context.Context { return context.Background() }

// ---- Users ----

// CreateUser inserts a new user row. Returns ErrConflict if (tenant_id, email)
// is already taken.
func (s *PGStorage) CreateUser(u User) (User, error) {
	const q = `
		INSERT INTO users (id, tenant_id, email, name, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := s.pool.Exec(bgCtx(), q,
		u.ID, u.TenantID, u.Email, nullable(u.Name),
		u.CreatedAt.UTC(), u.UpdatedAt.UTC(),
	)
	if isUniqueViolation(err) {
		return User{}, ErrConflict
	}
	if err != nil {
		return User{}, fmt.Errorf("pgstorage create_user: %w", err)
	}
	return u, nil
}

// GetUser returns the user iff it exists and belongs to tenantID.
func (s *PGStorage) GetUser(tenantID, id string) (User, error) {
	const q = `
		SELECT id, tenant_id, email, name, created_at, updated_at
		  FROM users
		 WHERE id = $1 AND tenant_id = $2
	`
	u, err := scanUser(s.pool.QueryRow(bgCtx(), q, id, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// GetUserByEmail is used by the social-login stub to upsert-by-email.
func (s *PGStorage) GetUserByEmail(tenantID, email string) (User, error) {
	const q = `
		SELECT id, tenant_id, email, name, created_at, updated_at
		  FROM users
		 WHERE tenant_id = $1 AND email = $2
	`
	u, err := scanUser(s.pool.QueryRow(bgCtx(), q, tenantID, email))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// ListUsers returns every user for tenantID, sorted by CreatedAt asc, id
// tie-break — the same ordering contract as MemStorage.
func (s *PGStorage) ListUsers(tenantID string) ([]User, error) {
	const q = `
		SELECT id, tenant_id, email, name, created_at, updated_at
		  FROM users
		 WHERE tenant_id = $1
		 ORDER BY created_at ASC, id ASC
	`
	rows, err := s.pool.Query(bgCtx(), q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_users: %w", err)
	}
	defer rows.Close()

	out := make([]User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list_users iter: %w", err)
	}
	return out, nil
}

// UpdateUser replaces the mutable columns. CreatedAt is preserved from the
// existing row and UpdatedAt is bumped server-side (same contract as
// MemStorage.UpdateUser). Returns ErrNotFound if no row matches both id and
// tenant_id, ErrConflict if the new email collides within the tenant.
func (s *PGStorage) UpdateUser(u User) (User, error) {
	const q = `
		UPDATE users SET
			email      = $3,
			name       = $4,
			updated_at = now()
		WHERE id = $1 AND tenant_id = $2
		RETURNING created_at, updated_at
	`
	var createdAt, updatedAt time.Time
	err := s.pool.QueryRow(bgCtx(), q,
		u.ID, u.TenantID, u.Email, nullable(u.Name),
	).Scan(&createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if isUniqueViolation(err) {
		return User{}, ErrConflict
	}
	if err != nil {
		return User{}, fmt.Errorf("pgstorage update_user: %w", err)
	}
	u.CreatedAt = createdAt.UTC()
	u.UpdatedAt = updatedAt.UTC()
	return u, nil
}

// DeleteUser removes the user (tenant-scoped). Returns ErrNotFound if the user
// does not exist or belongs to a different tenant.
func (s *PGStorage) DeleteUser(tenantID, id string) error {
	const q = `DELETE FROM users WHERE id = $1 AND tenant_id = $2`
	tag, err := s.pool.Exec(bgCtx(), q, id, tenantID)
	if err != nil {
		return fmt.Errorf("pgstorage delete_user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- Sessions ----

// CreateSession inserts a new session row. Caller fills id, tenant id, timestamps.
func (s *PGStorage) CreateSession(sess Session) (Session, error) {
	const q = `
		INSERT INTO sessions (
			id, tenant_id, user_id, risk_level, step_up_completed,
			created_at, updated_at, expires_at, invalidated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		sess.ID, sess.TenantID, sess.UserID, sess.RiskLevel, sess.StepUpCompleted,
		sess.CreatedAt.UTC(), sess.UpdatedAt.UTC(), sess.ExpiresAt.UTC(),
		nullableTime(sess.InvalidatedAt),
	); err != nil {
		return Session{}, fmt.Errorf("pgstorage create_session: %w", err)
	}
	return sess, nil
}

// GetSession returns the session iff it exists and belongs to tenantID.
func (s *PGStorage) GetSession(tenantID, id string) (Session, error) {
	const q = `
		SELECT id, tenant_id, user_id, risk_level, step_up_completed,
		       created_at, updated_at, expires_at, invalidated_at
		  FROM sessions
		 WHERE id = $1 AND tenant_id = $2
	`
	sess, err := scanSession(s.pool.QueryRow(bgCtx(), q, id, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return sess, err
}

// UpdateSession replaces the mutable columns. CreatedAt is preserved from the
// existing row and UpdatedAt is bumped server-side (same contract as
// MemStorage.UpdateSession). Returns ErrNotFound if no row matches both id and
// tenant_id.
func (s *PGStorage) UpdateSession(sess Session) (Session, error) {
	const q = `
		UPDATE sessions SET
			user_id           = $3,
			risk_level        = $4,
			step_up_completed = $5,
			expires_at        = $6,
			invalidated_at    = $7,
			updated_at        = now()
		WHERE id = $1 AND tenant_id = $2
		RETURNING created_at, updated_at
	`
	var createdAt, updatedAt time.Time
	err := s.pool.QueryRow(bgCtx(), q,
		sess.ID, sess.TenantID,
		sess.UserID, sess.RiskLevel, sess.StepUpCompleted,
		sess.ExpiresAt.UTC(), nullableTime(sess.InvalidatedAt),
	).Scan(&createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("pgstorage update_session: %w", err)
	}
	sess.CreatedAt = createdAt.UTC()
	sess.UpdatedAt = updatedAt.UTC()
	return sess, nil
}

// ---- Tokens ----

// PutToken stores a token record keyed by the already-hashed plaintext. Upsert
// semantics match MemStorage's map write — a re-put of the same hash replaces
// the record.
func (s *PGStorage) PutToken(t Token) error {
	const q = `
		INSERT INTO tokens (
			token_hash, session_id, user_id, tenant_id, token_type,
			scope, issued_at, expires_at, revoked_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (token_hash) DO UPDATE SET
			session_id = EXCLUDED.session_id,
			user_id    = EXCLUDED.user_id,
			tenant_id  = EXCLUDED.tenant_id,
			token_type = EXCLUDED.token_type,
			scope      = EXCLUDED.scope,
			issued_at  = EXCLUDED.issued_at,
			expires_at = EXCLUDED.expires_at,
			revoked_at = EXCLUDED.revoked_at
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		t.TokenHash, t.SessionID, t.UserID, t.TenantID, t.TokenType,
		nullable(t.Scope), t.IssuedAt.UTC(), t.ExpiresAt.UTC(),
		nullableTime(t.RevokedAt),
	); err != nil {
		return fmt.Errorf("pgstorage put_token: %w", err)
	}
	return nil
}

// GetTokenByHash reads a token record by its SHA-256 hash.
func (s *PGStorage) GetTokenByHash(hash string) (Token, error) {
	const q = `
		SELECT token_hash, session_id, user_id, tenant_id, token_type,
		       scope, issued_at, expires_at, revoked_at
		  FROM tokens
		 WHERE token_hash = $1
	`
	t, err := scanToken(s.pool.QueryRow(bgCtx(), q, hash))
	if errors.Is(err, pgx.ErrNoRows) {
		return Token{}, ErrNotFound
	}
	return t, err
}

// RevokeTokenByHash stamps RevokedAt on the token row. Missing tokens are a
// soft-miss (ErrNotFound) so handlers can choose whether to surface 404 or the
// RFC 7009 "always 200" behaviour at their own discretion.
func (s *PGStorage) RevokeTokenByHash(hash string) error {
	const q = `UPDATE tokens SET revoked_at = now() WHERE token_hash = $1`
	tag, err := s.pool.Exec(bgCtx(), q, hash)
	if err != nil {
		return fmt.Errorf("pgstorage revoke_token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- Auth codes ----

// PutAuthCode stores a pending authorization code.
func (s *PGStorage) PutAuthCode(ac AuthCode) error {
	const q = `
		INSERT INTO auth_codes (
			code, client_id, tenant_id, user_id, session_id,
			redirect_uri, scope, state, nonce, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (code) DO UPDATE SET
			client_id    = EXCLUDED.client_id,
			tenant_id    = EXCLUDED.tenant_id,
			user_id      = EXCLUDED.user_id,
			session_id   = EXCLUDED.session_id,
			redirect_uri = EXCLUDED.redirect_uri,
			scope        = EXCLUDED.scope,
			state        = EXCLUDED.state,
			nonce        = EXCLUDED.nonce,
			created_at   = EXCLUDED.created_at
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		ac.Code, ac.ClientID, ac.TenantID, ac.UserID, nullable(ac.SessionID),
		ac.RedirectURI, nullable(ac.Scope), nullable(ac.State), nullable(ac.Nonce),
		ac.CreatedAt.UTC(),
	); err != nil {
		return fmt.Errorf("pgstorage put_auth_code: %w", err)
	}
	return nil
}

// ConsumeAuthCode reads *and removes* the code in a single statement
// (DELETE ... RETURNING). Authorization codes are one-shot per OAuth
// convention — replay must fail, even under concurrent exchange attempts.
func (s *PGStorage) ConsumeAuthCode(code string) (AuthCode, error) {
	const q = `
		DELETE FROM auth_codes
		 WHERE code = $1
		RETURNING code, client_id, tenant_id, user_id, session_id,
		          redirect_uri, scope, state, nonce, created_at
	`
	var (
		ac                             AuthCode
		sessionID, scope, state, nonce *string
	)
	err := s.pool.QueryRow(bgCtx(), q, code).Scan(
		&ac.Code, &ac.ClientID, &ac.TenantID, &ac.UserID, &sessionID,
		&ac.RedirectURI, &scope, &state, &nonce, &ac.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthCode{}, ErrNotFound
	}
	if err != nil {
		return AuthCode{}, fmt.Errorf("pgstorage consume_auth_code: %w", err)
	}
	ac.SessionID = derefString(sessionID)
	ac.Scope = derefString(scope)
	ac.State = derefString(state)
	ac.Nonce = derefString(nonce)
	ac.CreatedAt = ac.CreatedAt.UTC()
	return ac, nil
}

// ---- OIDC clients ----

// PutClient upserts an OIDC client row. Full-record replace matches
// MemStorage's map write.
func (s *PGStorage) PutClient(c OIDCClient) error {
	const q = `
		INSERT INTO oidc_clients (client_id, client_secret_hash, redirect_uris, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (client_id) DO UPDATE SET
			client_secret_hash = EXCLUDED.client_secret_hash,
			redirect_uris      = EXCLUDED.redirect_uris,
			created_at         = EXCLUDED.created_at
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		c.ClientID, c.ClientSecretHash, c.RedirectURIs, c.CreatedAt.UTC(),
	); err != nil {
		return fmt.Errorf("pgstorage put_client: %w", err)
	}
	return nil
}

// GetClient reads an OIDC client by client id.
func (s *PGStorage) GetClient(clientID string) (OIDCClient, error) {
	const q = `
		SELECT client_id, client_secret_hash, redirect_uris, created_at
		  FROM oidc_clients
		 WHERE client_id = $1
	`
	var c OIDCClient
	err := s.pool.QueryRow(bgCtx(), q, clientID).Scan(
		&c.ClientID, &c.ClientSecretHash, &c.RedirectURIs, &c.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return OIDCClient{}, ErrNotFound
	}
	if err != nil {
		return OIDCClient{}, fmt.Errorf("pgstorage get_client: %w", err)
	}
	c.CreatedAt = c.CreatedAt.UTC()
	return c, nil
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// rowScanner is satisfied by both pgx.Row and pgx.Rows for shared scanning.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(r rowScanner) (User, error) {
	var (
		u    User
		name *string
	)
	if err := r.Scan(
		&u.ID, &u.TenantID, &u.Email, &name, &u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return User{}, err
	}
	u.Name = derefString(name)
	u.CreatedAt = u.CreatedAt.UTC()
	u.UpdatedAt = u.UpdatedAt.UTC()
	return u, nil
}

func scanSession(r rowScanner) (Session, error) {
	var (
		sess          Session
		invalidatedAt *time.Time
	)
	if err := r.Scan(
		&sess.ID, &sess.TenantID, &sess.UserID, &sess.RiskLevel, &sess.StepUpCompleted,
		&sess.CreatedAt, &sess.UpdatedAt, &sess.ExpiresAt, &invalidatedAt,
	); err != nil {
		return Session{}, err
	}
	if invalidatedAt != nil {
		ts := invalidatedAt.UTC()
		sess.InvalidatedAt = &ts
	}
	sess.CreatedAt = sess.CreatedAt.UTC()
	sess.UpdatedAt = sess.UpdatedAt.UTC()
	sess.ExpiresAt = sess.ExpiresAt.UTC()
	return sess, nil
}

func scanToken(r rowScanner) (Token, error) {
	var (
		t         Token
		scope     *string
		revokedAt *time.Time
	)
	if err := r.Scan(
		&t.TokenHash, &t.SessionID, &t.UserID, &t.TenantID, &t.TokenType,
		&scope, &t.IssuedAt, &t.ExpiresAt, &revokedAt,
	); err != nil {
		return Token{}, err
	}
	t.Scope = derefString(scope)
	if revokedAt != nil {
		ts := revokedAt.UTC()
		t.RevokedAt = &ts
	}
	t.IssuedAt = t.IssuedAt.UTC()
	t.ExpiresAt = t.ExpiresAt.UTC()
	return t, nil
}

// isUniqueViolation reports whether err is a Postgres unique_violation (23505),
// which the user paths translate to the service's ErrConflict.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC()
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
