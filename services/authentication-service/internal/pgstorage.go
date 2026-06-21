package internal

import (
	"context"
	"encoding/json"
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

// rowExecutor is the subset of *pgxpool.Pool and pgx.Tx that the insert helpers
// need. Sharing it lets the single-row writers (CreateUser, …) and the
// transactional ProvisionTenant reuse one INSERT definition per table, so the
// column lists — and the redirect_uris/web_origins nil-guard — can't drift
// between the two call paths.
type rowExecutor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func execInsertTenant(ctx context.Context, ex rowExecutor, t Tenant) error {
	const q = `
		INSERT INTO tenants (id, company_name, slug, owner_email, created_at)
		VALUES ($1, $2, $3, $4, $5)`
	_, err := ex.Exec(ctx, q, t.ID, t.CompanyName, t.Slug, t.OwnerEmail, t.CreatedAt.UTC())
	return err
}

func execInsertUser(ctx context.Context, ex rowExecutor, u User) error {
	const q = `
		INSERT INTO users (id, tenant_id, email, name, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)`
	// email is nullable (migration 000008): a phone-only account has no email
	// until a social login is linked. Empty → NULL so the partial unique index
	// (WHERE email IS NOT NULL) lets multiple emailless users coexist.
	_, err := ex.Exec(ctx, q, u.ID, u.TenantID, nullable(u.Email), nullable(u.Name),
		u.CreatedAt.UTC(), u.UpdatedAt.UTC())
	return err
}

func execInsertSession(ctx context.Context, ex rowExecutor, sess Session) error {
	const q = `
		INSERT INTO sessions (
			id, tenant_id, user_id, risk_level, step_up_completed,
			created_at, updated_at, expires_at, invalidated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := ex.Exec(ctx, q,
		sess.ID, sess.TenantID, sess.UserID, sess.RiskLevel, sess.StepUpCompleted,
		sess.CreatedAt.UTC(), sess.UpdatedAt.UTC(), sess.ExpiresAt.UTC(),
		nullableTime(sess.InvalidatedAt))
	return err
}

func execInsertClient(ctx context.Context, ex rowExecutor, c OIDCClient) error {
	const q = `
		INSERT INTO oidc_clients (client_id, client_secret_hash, tenant_id, redirect_uris, web_origins, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (client_id) DO UPDATE SET
			client_secret_hash = EXCLUDED.client_secret_hash,
			tenant_id          = EXCLUDED.tenant_id,
			redirect_uris      = EXCLUDED.redirect_uris,
			web_origins        = EXCLUDED.web_origins,
			created_at         = EXCLUDED.created_at`
	// Both array columns are TEXT[] NOT NULL: a nil slice encodes as SQL NULL
	// (the column DEFAULT only applies when the column is omitted, not when NULL
	// is passed explicitly), so coerce nil → empty array. A client registered
	// without a redirect URI (optional at self-service signup) hits this.
	redirects := c.RedirectURIs
	if redirects == nil {
		redirects = []string{}
	}
	origins := c.WebOrigins
	if origins == nil {
		origins = []string{}
	}
	_, err := ex.Exec(ctx, q,
		c.ClientID, c.ClientSecretHash, c.TenantID, redirects, origins, c.CreatedAt.UTC())
	return err
}

// ---- Users ----

// CreateUser inserts a new user row. Returns ErrConflict if (tenant_id, email)
// is already taken.
func (s *PGStorage) CreateUser(u User) (User, error) {
	err := execInsertUser(bgCtx(), s.pool, u)
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

// GetUserByEmail is used by the social-login stub to upsert-by-email. An empty
// email never matches a (possibly emailless) phone-only account.
func (s *PGStorage) GetUserByEmail(tenantID, email string) (User, error) {
	if email == "" {
		return User{}, ErrNotFound
	}
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

// ListUsers returns up to limit users for tenantID, newest first (created_at
// desc, id desc tie-break). A non-zero cursor restricts results to rows
// strictly older than the cursor (keyset pagination — same contract as
// transaction-service). limit <= 0 means "no limit".
//
// The keyset predicate + ordering is served by the existing
// idx_users_tenant_created (tenant_id, created_at, id) index via a backward
// index scan — equality on tenant_id, reversed order on (created_at, id) — so
// no additional index/migration is required.
func (s *PGStorage) ListUsers(tenantID string, limit int, cursor time.Time) ([]User, error) {
	base := `
		SELECT id, tenant_id, email, name, created_at, updated_at
		  FROM users
		 WHERE tenant_id = $1
	`
	args := []any{tenantID}
	if !cursor.IsZero() {
		base += ` AND created_at < $2`
		args = append(args, cursor.UTC())
	}
	base += ` ORDER BY created_at DESC, id DESC`
	if limit > 0 {
		base += fmt.Sprintf(` LIMIT $%d`, len(args)+1)
		args = append(args, limit)
	}

	rows, err := s.pool.Query(bgCtx(), base, args...)
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
		u.ID, u.TenantID, nullable(u.Email), nullable(u.Name),
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
	if err := execInsertSession(bgCtx(), s.pool, sess); err != nil {
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

// ListSessions returns the tenant's sessions, newest first, capped at limit.
func (s *PGStorage) ListSessions(tenantID string, limit int) ([]Session, error) {
	if limit <= 0 {
		limit = DefaultSessionListCap
	}
	const q = `
		SELECT id, tenant_id, user_id, risk_level, step_up_completed,
		       created_at, updated_at, expires_at, invalidated_at
		  FROM sessions
		 WHERE tenant_id = $1
		 ORDER BY created_at DESC, id DESC
		 LIMIT $2
	`
	rows, err := s.pool.Query(bgCtx(), q, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_sessions: %w", err)
	}
	defer rows.Close()

	out := make([]Session, 0)
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list_sessions rows: %w", err)
	}
	return out, nil
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
			token_hash, session_id, user_id, tenant_id, client_id, family_id,
			token_type, scope, issued_at, expires_at, revoked_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (token_hash) DO UPDATE SET
			session_id = EXCLUDED.session_id,
			user_id    = EXCLUDED.user_id,
			tenant_id  = EXCLUDED.tenant_id,
			client_id  = EXCLUDED.client_id,
			family_id  = EXCLUDED.family_id,
			token_type = EXCLUDED.token_type,
			scope      = EXCLUDED.scope,
			issued_at  = EXCLUDED.issued_at,
			expires_at = EXCLUDED.expires_at,
			revoked_at = EXCLUDED.revoked_at
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		t.TokenHash, t.SessionID, t.UserID, t.TenantID, t.ClientID, t.FamilyID,
		t.TokenType, nullable(t.Scope), t.IssuedAt.UTC(), t.ExpiresAt.UTC(),
		nullableTime(t.RevokedAt),
	); err != nil {
		return fmt.Errorf("pgstorage put_token: %w", err)
	}
	return nil
}

// GetTokenByHash reads a token record by its SHA-256 hash.
func (s *PGStorage) GetTokenByHash(hash string) (Token, error) {
	const q = `
		SELECT token_hash, session_id, user_id, tenant_id, client_id, family_id,
		       token_type, scope, issued_at, expires_at, revoked_at
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

// RevokeTokenFamily stamps revoked_at on every live token in familyID — the
// §10.1 theft response when a rotated-out refresh token is replayed. Already-
// revoked rows keep their original revocation instant. Empty familyID is a
// no-op guard for legacy rows backfilled by migration 000002.
func (s *PGStorage) RevokeTokenFamily(familyID string) (int, error) {
	if familyID == "" {
		return 0, nil
	}
	const q = `
		UPDATE tokens SET revoked_at = now()
		 WHERE family_id = $1 AND revoked_at IS NULL
	`
	tag, err := s.pool.Exec(bgCtx(), q, familyID)
	if err != nil {
		return 0, fmt.Errorf("pgstorage revoke_token_family: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// RevokeTokenFamiliesBySession revokes every live token whose family has issued
// at least one token against sessionID — the response when a session is judged
// compromised (device-fingerprint replay). Empty sessionID is a no-op.
func (s *PGStorage) RevokeTokenFamiliesBySession(tenantID, sessionID string) (int, error) {
	if sessionID == "" {
		return 0, nil
	}
	const q = `
		UPDATE tokens SET revoked_at = now()
		 WHERE revoked_at IS NULL
		   AND family_id <> ''
		   AND family_id IN (
		       SELECT DISTINCT family_id FROM tokens
		        WHERE session_id = $1 AND tenant_id = $2 AND family_id <> ''
		   )
	`
	tag, err := s.pool.Exec(bgCtx(), q, sessionID, tenantID)
	if err != nil {
		return 0, fmt.Errorf("pgstorage revoke_token_families_by_session: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ---- Transaction types ----

func (s *PGStorage) CreateTransactionType(tt TransactionType) error {
	const q = `INSERT INTO transaction_types (tenant_id, name, acr, created_at) VALUES ($1, $2, $3, $4)`
	_, err := s.pool.Exec(bgCtx(), q, tt.TenantID, tt.Name, tt.ACR, tt.CreatedAt.UTC())
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("pgstorage create_transaction_type: %w", err)
	}
	return nil
}

func (s *PGStorage) ListTransactionTypes(tenantID string) ([]TransactionType, error) {
	const q = `SELECT tenant_id, name, acr, created_at FROM transaction_types WHERE tenant_id = $1 ORDER BY name ASC`
	rows, err := s.pool.Query(bgCtx(), q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_transaction_types: %w", err)
	}
	defer rows.Close()
	out := make([]TransactionType, 0)
	for rows.Next() {
		var tt TransactionType
		if err := rows.Scan(&tt.TenantID, &tt.Name, &tt.ACR, &tt.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, tt)
	}
	return out, rows.Err()
}

func (s *PGStorage) GetTransactionType(tenantID, name string) (TransactionType, error) {
	const q = `SELECT tenant_id, name, acr, created_at FROM transaction_types WHERE tenant_id = $1 AND name = $2`
	var tt TransactionType
	err := s.pool.QueryRow(bgCtx(), q, tenantID, name).Scan(&tt.TenantID, &tt.Name, &tt.ACR, &tt.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TransactionType{}, ErrNotFound
	}
	if err != nil {
		return TransactionType{}, fmt.Errorf("pgstorage get_transaction_type: %w", err)
	}
	return tt, nil
}

func (s *PGStorage) DeleteTransactionType(tenantID, name string) error {
	const q = `DELETE FROM transaction_types WHERE tenant_id = $1 AND name = $2`
	tag, err := s.pool.Exec(bgCtx(), q, tenantID, name)
	if err != nil {
		return fmt.Errorf("pgstorage delete_transaction_type: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- Configurable flows ----

func (s *PGStorage) UpsertFlow(f FlowDefinition) error {
	stages, err := json.Marshal(f.Stages)
	if err != nil {
		return fmt.Errorf("pgstorage upsert_flow marshal: %w", err)
	}
	ctx := bgCtx()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pgstorage upsert_flow begin: %w", err)
	}
	defer tx.Rollback(ctx)

	// Enforce one enabled flow per (tenant, designation): demote the others first
	// so the partial unique index never rejects the upsert.
	if f.Enabled {
		const demote = `UPDATE flows SET enabled = false, updated_at = now()
			WHERE tenant_id = $1 AND designation = $2 AND id <> $3 AND enabled`
		if _, err := tx.Exec(ctx, demote, f.TenantID, f.Designation, f.ID); err != nil {
			return fmt.Errorf("pgstorage upsert_flow demote: %w", err)
		}
	}
	const q = `
		INSERT INTO flows (id, tenant_id, designation, slug, title, enabled, stages, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
		ON CONFLICT (id) DO UPDATE SET
			designation = EXCLUDED.designation,
			slug        = EXCLUDED.slug,
			title       = EXCLUDED.title,
			enabled     = EXCLUDED.enabled,
			stages      = EXCLUDED.stages,
			updated_at  = now()`
	if _, err := tx.Exec(ctx, q, f.ID, f.TenantID, f.Designation, f.Slug, f.Title, f.Enabled, stages); err != nil {
		return fmt.Errorf("pgstorage upsert_flow: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pgstorage upsert_flow commit: %w", err)
	}
	return nil
}

func scanFlow(row interface {
	Scan(dest ...any) error
}) (FlowDefinition, error) {
	var f FlowDefinition
	var stages []byte
	if err := row.Scan(&f.ID, &f.TenantID, &f.Designation, &f.Slug, &f.Title, &f.Enabled, &stages, &f.CreatedAt, &f.UpdatedAt); err != nil {
		return FlowDefinition{}, err
	}
	if len(stages) > 0 {
		if err := json.Unmarshal(stages, &f.Stages); err != nil {
			return FlowDefinition{}, fmt.Errorf("pgstorage scan_flow unmarshal: %w", err)
		}
	}
	return f, nil
}

const flowCols = `id, tenant_id, designation, slug, title, enabled, stages, created_at, updated_at`

func (s *PGStorage) ListFlows(tenantID string) ([]FlowDefinition, error) {
	q := `SELECT ` + flowCols + ` FROM flows WHERE tenant_id = $1 ORDER BY slug ASC`
	rows, err := s.pool.Query(bgCtx(), q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_flows: %w", err)
	}
	defer rows.Close()
	out := make([]FlowDefinition, 0)
	for rows.Next() {
		f, err := scanFlow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *PGStorage) GetFlow(tenantID, id string) (FlowDefinition, error) {
	q := `SELECT ` + flowCols + ` FROM flows WHERE tenant_id = $1 AND id = $2`
	f, err := scanFlow(s.pool.QueryRow(bgCtx(), q, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return FlowDefinition{}, ErrNotFound
	}
	if err != nil {
		return FlowDefinition{}, fmt.Errorf("pgstorage get_flow: %w", err)
	}
	return f, nil
}

func (s *PGStorage) GetEnabledFlow(tenantID, designation string) (FlowDefinition, error) {
	q := `SELECT ` + flowCols + ` FROM flows
		WHERE tenant_id = $1 AND designation = $2 AND enabled
		ORDER BY updated_at DESC LIMIT 1`
	f, err := scanFlow(s.pool.QueryRow(bgCtx(), q, tenantID, designation))
	if errors.Is(err, pgx.ErrNoRows) {
		return FlowDefinition{}, ErrNotFound
	}
	if err != nil {
		return FlowDefinition{}, fmt.Errorf("pgstorage get_enabled_flow: %w", err)
	}
	return f, nil
}

func (s *PGStorage) DeleteFlow(tenantID, id string) error {
	const q = `DELETE FROM flows WHERE tenant_id = $1 AND id = $2`
	tag, err := s.pool.Exec(bgCtx(), q, tenantID, id)
	if err != nil {
		return fmt.Errorf("pgstorage delete_flow: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- Advice calls ----

func (s *PGStorage) RecordAdviceCall(c AdviceCall) error {
	const q = `
		INSERT INTO advice_calls
			(id, tenant_id, client_id, user_id, session_id, device_id, transaction_type, acr, rank, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := s.pool.Exec(bgCtx(), q,
		c.ID, c.TenantID, nullable(c.ClientID), nullable(c.UserID), nullable(c.SessionID), nullable(c.DeviceID),
		c.TransactionType, c.ACR, c.Rank, c.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("pgstorage record_advice_call: %w", err)
	}
	return nil
}

func (s *PGStorage) ListAdviceCalls(filter AdviceCallFilter) ([]AdviceCall, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	q := `SELECT id, tenant_id, client_id, user_id, session_id, device_id, transaction_type, acr, rank, created_at,
	             completed_at, completed_user_id, completed_acr
	        FROM advice_calls WHERE 1=1`
	args := []any{}
	if filter.TenantID != "" {
		args = append(args, filter.TenantID)
		q += fmt.Sprintf(" AND tenant_id = $%d", len(args))
	}
	if filter.UserID != "" {
		args = append(args, filter.UserID)
		q += fmt.Sprintf(" AND user_id = $%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(bgCtx(), q, args...)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_advice_calls: %w", err)
	}
	defer rows.Close()
	out := make([]AdviceCall, 0)
	for rows.Next() {
		var c AdviceCall
		var clientID, userID, sessionID, deviceID, completedUserID, completedACR *string
		if err := rows.Scan(&c.ID, &c.TenantID, &clientID, &userID, &sessionID, &deviceID,
			&c.TransactionType, &c.ACR, &c.Rank, &c.CreatedAt,
			&c.CompletedAt, &completedUserID, &completedACR); err != nil {
			return nil, err
		}
		c.ClientID = derefString(clientID)
		c.UserID = derefString(userID)
		c.SessionID = derefString(sessionID)
		c.DeviceID = derefString(deviceID)
		c.CompletedUserID = derefString(completedUserID)
		c.CompletedACR = derefString(completedACR)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PGStorage) GetAdviceCall(tenantID, transactionID string) (AdviceCall, error) {
	const q = `SELECT id, tenant_id, client_id, user_id, session_id, device_id, transaction_type, acr, rank,
	                  created_at, completed_at, completed_user_id, completed_acr
	             FROM advice_calls WHERE id = $1 AND tenant_id = $2`
	var c AdviceCall
	var clientID, userID, sessionID, deviceID, completedUserID, completedACR *string
	err := s.pool.QueryRow(bgCtx(), q, transactionID, tenantID).Scan(
		&c.ID, &c.TenantID, &clientID, &userID, &sessionID, &deviceID,
		&c.TransactionType, &c.ACR, &c.Rank, &c.CreatedAt,
		&c.CompletedAt, &completedUserID, &completedACR)
	if errors.Is(err, pgx.ErrNoRows) {
		return AdviceCall{}, ErrNotFound
	}
	if err != nil {
		return AdviceCall{}, fmt.Errorf("pgstorage get_advice_call: %w", err)
	}
	c.ClientID = derefString(clientID)
	c.UserID = derefString(userID)
	c.SessionID = derefString(sessionID)
	c.DeviceID = derefString(deviceID)
	c.CompletedUserID = derefString(completedUserID)
	c.CompletedACR = derefString(completedACR)
	return c, nil
}

// MarkAdviceCallCompleted atomically transitions pending → completed. The
// `completed_at IS NULL` guard makes it single-use: a second call affects no
// rows, and a follow-up existence check distinguishes ErrConflict (already
// completed) from ErrNotFound (unknown id).
func (s *PGStorage) MarkAdviceCallCompleted(tenantID, transactionID, userID, acr string, at time.Time) error {
	const q = `
		UPDATE advice_calls
		   SET completed_at = $3, completed_user_id = $4, completed_acr = $5
		 WHERE id = $1 AND tenant_id = $2 AND completed_at IS NULL`
	tag, err := s.pool.Exec(bgCtx(), q, transactionID, tenantID, at.UTC(), nullable(userID), nullable(acr))
	if err != nil {
		return fmt.Errorf("pgstorage mark_advice_call_completed: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// No row updated: either it doesn't exist or it was already completed.
	var exists bool
	if err := s.pool.QueryRow(bgCtx(),
		`SELECT EXISTS(SELECT 1 FROM advice_calls WHERE id = $1 AND tenant_id = $2)`,
		transactionID, tenantID).Scan(&exists); err != nil {
		return fmt.Errorf("pgstorage mark_advice_call_completed exists: %w", err)
	}
	if exists {
		return ErrConflict
	}
	return ErrNotFound
}

// ---- Auth codes ----

// PutAuthCode stores a pending authorization code.
func (s *PGStorage) PutAuthCode(ac AuthCode) error {
	const q = `
		INSERT INTO auth_codes (
			code, client_id, tenant_id, user_id, session_id,
			redirect_uri, scope, state, nonce, code_challenge, created_at,
			acr, amr
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (code) DO UPDATE SET
			client_id      = EXCLUDED.client_id,
			tenant_id      = EXCLUDED.tenant_id,
			user_id        = EXCLUDED.user_id,
			session_id     = EXCLUDED.session_id,
			redirect_uri   = EXCLUDED.redirect_uri,
			scope          = EXCLUDED.scope,
			state          = EXCLUDED.state,
			nonce          = EXCLUDED.nonce,
			code_challenge = EXCLUDED.code_challenge,
			created_at     = EXCLUDED.created_at,
			acr            = EXCLUDED.acr,
			amr            = EXCLUDED.amr
	`
	amr := ac.AMR
	if amr == nil {
		amr = []string{}
	}
	if _, err := s.pool.Exec(bgCtx(), q,
		ac.Code, ac.ClientID, ac.TenantID, ac.UserID, nullable(ac.SessionID),
		ac.RedirectURI, nullable(ac.Scope), nullable(ac.State), nullable(ac.Nonce),
		nullable(ac.CodeChallenge), ac.CreatedAt.UTC(), ac.ACR, amr,
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
		          redirect_uri, scope, state, nonce, code_challenge, created_at,
		          acr, amr
	`
	var (
		ac                                            AuthCode
		sessionID, scope, state, nonce, codeChallenge *string
	)
	err := s.pool.QueryRow(bgCtx(), q, code).Scan(
		&ac.Code, &ac.ClientID, &ac.TenantID, &ac.UserID, &sessionID,
		&ac.RedirectURI, &scope, &state, &nonce, &codeChallenge, &ac.CreatedAt,
		&ac.ACR, &ac.AMR,
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
	ac.CodeChallenge = derefString(codeChallenge)
	ac.CreatedAt = ac.CreatedAt.UTC()
	return ac, nil
}

// ---- OIDC clients ----

// PutClient upserts an OIDC client row. Full-record replace matches
// MemStorage's map write.
func (s *PGStorage) PutClient(c OIDCClient) error {
	if err := execInsertClient(bgCtx(), s.pool, c); err != nil {
		return fmt.Errorf("pgstorage put_client: %w", err)
	}
	return nil
}

// GetClient reads an OIDC client by client id.
func (s *PGStorage) GetClient(clientID string) (OIDCClient, error) {
	const q = `
		SELECT client_id, client_secret_hash, tenant_id, redirect_uris, web_origins, created_at
		  FROM oidc_clients
		 WHERE client_id = $1
	`
	var c OIDCClient
	err := s.pool.QueryRow(bgCtx(), q, clientID).Scan(
		&c.ClientID, &c.ClientSecretHash, &c.TenantID, &c.RedirectURIs, &c.WebOrigins, &c.CreatedAt,
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

// ListClients returns every registered client, newest first.
func (s *PGStorage) ListClients() ([]OIDCClient, error) {
	const q = `
		SELECT client_id, client_secret_hash, tenant_id, redirect_uris, web_origins, created_at
		  FROM oidc_clients
		 ORDER BY created_at DESC, client_id ASC
	`
	rows, err := s.pool.Query(bgCtx(), q)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_clients: %w", err)
	}
	defer rows.Close()

	out := make([]OIDCClient, 0)
	for rows.Next() {
		var c OIDCClient
		if err := rows.Scan(&c.ClientID, &c.ClientSecretHash, &c.TenantID, &c.RedirectURIs, &c.WebOrigins, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("pgstorage list_clients scan: %w", err)
		}
		c.CreatedAt = c.CreatedAt.UTC()
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list_clients rows: %w", err)
	}
	return out, nil
}

// DeleteClient removes a client by id.
func (s *PGStorage) DeleteClient(clientID string) error {
	tag, err := s.pool.Exec(bgCtx(), `DELETE FROM oidc_clients WHERE client_id = $1`, clientID)
	if err != nil {
		return fmt.Errorf("pgstorage delete_client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- Tenants (derived) ----

// ListTenants aggregates distinct tenant_ids across users and sessions with
// per-tenant counts and the most recent activity stamp. A full-UNION group-by
// keeps users-only and sessions-only tenants both visible; ordered by newest
// activity first. Phase 1 has no tenant registry, so this is the only tenant
// enumeration available.
func (s *PGStorage) ListTenants() ([]TenantSummary, error) {
	const q = `
		SELECT tenant_id,
		       SUM(users)        AS users,
		       SUM(sessions)     AS sessions,
		       MAX(last_activity) AS last_activity
		  FROM (
		        SELECT tenant_id, COUNT(*) AS users, 0 AS sessions, MAX(created_at) AS last_activity
		          FROM users     GROUP BY tenant_id
		        UNION ALL
		        SELECT tenant_id, 0 AS users, COUNT(*) AS sessions, MAX(updated_at) AS last_activity
		          FROM sessions  GROUP BY tenant_id
		       ) t
		 GROUP BY tenant_id
		 ORDER BY last_activity DESC, tenant_id ASC
	`
	rows, err := s.pool.Query(bgCtx(), q)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_tenants: %w", err)
	}
	defer rows.Close()

	out := make([]TenantSummary, 0)
	for rows.Next() {
		var t TenantSummary
		if err := rows.Scan(&t.TenantID, &t.Users, &t.Sessions, &t.LastActivity); err != nil {
			return nil, fmt.Errorf("pgstorage list_tenants scan: %w", err)
		}
		t.LastActivity = t.LastActivity.UTC()
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list_tenants rows: %w", err)
	}
	return out, nil
}

// ---- Tenant registry ----

// CreateTenant inserts a registry row. The slug and owner_email unique
// constraints (migration 000006) back the ErrConflict contract: a 23505 on
// either becomes ErrConflict, exactly like the MemStorage in-memory check.
func (s *PGStorage) CreateTenant(t Tenant) (Tenant, error) {
	err := execInsertTenant(bgCtx(), s.pool, t)
	if isUniqueViolation(err) {
		return Tenant{}, ErrConflict
	}
	if err != nil {
		return Tenant{}, fmt.Errorf("pgstorage create_tenant: %w", err)
	}
	return t, nil
}

// ProvisionTenant writes the four signup rows in one transaction. Any error
// rolls the whole unit back (via the deferred Rollback, a no-op after Commit),
// so a failure at the client step can't leave an orphaned tenant + owner — the
// exact gap that the non-transactional sequence left when redirect_uris was nil.
func (s *PGStorage) ProvisionTenant(t Tenant, owner User, sess Session, client OIDCClient) error {
	ctx := bgCtx()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pgstorage provision begin: %w", err)
	}
	defer tx.Rollback(ctx)

	steps := []struct {
		name string
		run  func() error
	}{
		{"tenant", func() error { return execInsertTenant(ctx, tx, t) }},
		{"user", func() error { return execInsertUser(ctx, tx, owner) }},
		{"session", func() error { return execInsertSession(ctx, tx, sess) }},
		{"client", func() error { return execInsertClient(ctx, tx, client) }},
	}
	for _, step := range steps {
		if err := step.run(); err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return fmt.Errorf("pgstorage provision %s: %w", step.name, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pgstorage provision commit: %w", err)
	}
	return nil
}

// GetTenant returns the registry row for id, or ErrNotFound.
func (s *PGStorage) GetTenant(id string) (Tenant, error) {
	return s.getTenant(`WHERE id = $1`, id)
}

// GetTenantBySlug returns the registry row whose slug matches, or ErrNotFound.
func (s *PGStorage) GetTenantBySlug(slug string) (Tenant, error) {
	return s.getTenant(`WHERE slug = $1`, slug)
}

// GetTenantByOwnerEmail returns the registry row owned by email, or ErrNotFound.
func (s *PGStorage) GetTenantByOwnerEmail(email string) (Tenant, error) {
	return s.getTenant(`WHERE owner_email = $1`, email)
}

// getTenant runs the shared SELECT with a caller-supplied single-arg WHERE.
func (s *PGStorage) getTenant(where, arg string) (Tenant, error) {
	q := `SELECT id, company_name, slug, owner_email, created_at, phone_login_enabled, mdl_enroll_enabled FROM tenants ` + where
	var t Tenant
	err := s.pool.QueryRow(bgCtx(), q, arg).Scan(
		&t.ID, &t.CompanyName, &t.Slug, &t.OwnerEmail, &t.CreatedAt, &t.PhoneLoginEnabled, &t.MDLEnrollEnabled,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	if err != nil {
		return Tenant{}, fmt.Errorf("pgstorage get_tenant: %w", err)
	}
	t.CreatedAt = t.CreatedAt.UTC()
	return t, nil
}

// ListTenantsByOwnerEmail returns every workspace owned by email, slug-ordered.
// Owner email is no longer unique (a Google account may own several workspaces),
// so login uses this to drive the workspace picker.
func (s *PGStorage) ListTenantsByOwnerEmail(email string) ([]Tenant, error) {
	const q = `SELECT id, company_name, slug, owner_email, created_at, phone_login_enabled, mdl_enroll_enabled
		FROM tenants WHERE owner_email = $1 ORDER BY slug`
	rows, err := s.pool.Query(bgCtx(), q, email)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_tenants_by_owner: %w", err)
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.CompanyName, &t.Slug, &t.OwnerEmail, &t.CreatedAt, &t.PhoneLoginEnabled, &t.MDLEnrollEnabled); err != nil {
			return nil, fmt.Errorf("pgstorage list_tenants_by_owner scan: %w", err)
		}
		t.CreatedAt = t.CreatedAt.UTC()
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list_tenants_by_owner rows: %w", err)
	}
	return out, nil
}

// SetTenantOwner assigns a workspace owner, creating the registry row if absent.
// Staff use this to hand a tenant to a Google account — including a tenant that
// exists only via users/sessions (env-configured client, staging) and so has no
// registry row yet. UPSERT on the id PK: an existing row just gets its
// owner_email updated; a missing one is synthesized (see synthTenantIdentity).
func (s *PGStorage) SetTenantOwner(tenantID, email string) error {
	company, slug := synthTenantIdentity(tenantID)
	_, err := s.pool.Exec(bgCtx(), `
		INSERT INTO tenants (id, company_name, slug, owner_email, created_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (id) DO UPDATE SET owner_email = EXCLUDED.owner_email`,
		tenantID, company, slug, email)
	if err != nil {
		return fmt.Errorf("pgstorage set_tenant_owner: %w", err)
	}
	return nil
}

// SetTenantPhoneLogin toggles the tenant's SMS-OTP opt-in. ErrNotFound if the
// tenant has no registry row.
func (s *PGStorage) SetTenantPhoneLogin(tenantID string, enabled bool) error {
	tag, err := s.pool.Exec(bgCtx(),
		`UPDATE tenants SET phone_login_enabled = $2 WHERE id = $1`, tenantID, enabled)
	if err != nil {
		return fmt.Errorf("pgstorage set_tenant_phone_login: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetTenantMDLEnroll toggles the tenant's mDL-enrollment interstitial opt-in.
func (s *PGStorage) SetTenantMDLEnroll(tenantID string, enabled bool) error {
	tag, err := s.pool.Exec(bgCtx(),
		`UPDATE tenants SET mdl_enroll_enabled = $2 WHERE id = $1`, tenantID, enabled)
	if err != nil {
		return fmt.Errorf("pgstorage set_tenant_mdl_enroll: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- Identity anchors ----

// CreateIdentityAnchor inserts an additional anchor row. A 23505 on
// uq_identity_anchor (tenant_id, anchor_type, anchor_value) becomes ErrConflict,
// exactly like MemStorage's in-memory check.
func (s *PGStorage) CreateIdentityAnchor(a IdentityAnchor) (IdentityAnchor, error) {
	const q = `
		INSERT INTO identity_anchors (id, user_id, tenant_id, anchor_type, anchor_value, verified_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := s.pool.Exec(bgCtx(), q,
		a.ID, a.UserID, a.TenantID, a.Type, a.Value, nullableTime(a.VerifiedAt), a.CreatedAt.UTC())
	if isUniqueViolation(err) {
		return IdentityAnchor{}, ErrConflict
	}
	if err != nil {
		return IdentityAnchor{}, fmt.Errorf("pgstorage create_identity_anchor: %w", err)
	}
	return a, nil
}

// RecordDeviceSignal appends one device observation to the append-only log.
func (s *PGStorage) RecordDeviceSignal(ds DeviceSignal) error {
	const q = `
		INSERT INTO device_signals
			(id, tenant_id, user_id, session_id, stage, fingerprint, ip_address, user_agent, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := s.pool.Exec(bgCtx(), q,
		ds.ID, ds.TenantID, nullable(ds.UserID), nullable(ds.SessionID), ds.Stage,
		ds.Fingerprint, nullable(ds.IPAddress), nullable(ds.UserAgent), ds.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("pgstorage record_device_signal: %w", err)
	}
	return nil
}

// ListDeviceSignals returns tenantID's observations, newest first, capped.
func (s *PGStorage) ListDeviceSignals(tenantID string, limit int) ([]DeviceSignal, error) {
	if limit <= 0 {
		limit = DefaultSessionListCap
	}
	const q = `
		SELECT id, tenant_id, user_id, session_id, stage, fingerprint, ip_address, user_agent, created_at
		  FROM device_signals
		 WHERE tenant_id = $1
		 ORDER BY created_at DESC, id DESC
		 LIMIT $2
	`
	rows, err := s.pool.Query(bgCtx(), q, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_device_signals: %w", err)
	}
	defer rows.Close()

	out := make([]DeviceSignal, 0)
	for rows.Next() {
		ds, err := scanDeviceSignal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ds)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list_device_signals rows: %w", err)
	}
	return out, nil
}

// ListDeviceSignalsByUser returns tenantID/userID's observations, newest first.
func (s *PGStorage) ListDeviceSignalsByUser(tenantID, userID string, limit int) ([]DeviceSignal, error) {
	if limit <= 0 {
		limit = DefaultSessionListCap
	}
	const q = `
		SELECT id, tenant_id, user_id, session_id, stage, fingerprint, ip_address, user_agent, created_at
		  FROM device_signals
		 WHERE tenant_id = $1 AND user_id = $2
		 ORDER BY created_at DESC, id DESC
		 LIMIT $3
	`
	rows, err := s.pool.Query(bgCtx(), q, tenantID, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_device_signals_by_user: %w", err)
	}
	defer rows.Close()
	out := make([]DeviceSignal, 0)
	for rows.Next() {
		ds, err := scanDeviceSignal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ds)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list_device_signals_by_user rows: %w", err)
	}
	return out, nil
}

// GetIdentityAnchorByValue resolves a single anchor by its (tenant, type,
// value) — the lookup phone login uses to find whether a number is already
// known. Returns ErrNotFound on a miss. The uq_identity_anchor constraint makes
// the triple unique, so at most one row matches.
func (s *PGStorage) GetIdentityAnchorByValue(tenantID, anchorType, value string) (IdentityAnchor, error) {
	const q = `
		SELECT id, user_id, tenant_id, anchor_type, anchor_value, verified_at, created_at
		  FROM identity_anchors
		 WHERE tenant_id = $1 AND anchor_type = $2 AND anchor_value = $3
	`
	a, err := scanAnchor(s.pool.QueryRow(bgCtx(), q, tenantID, anchorType, value))
	if errors.Is(err, pgx.ErrNoRows) {
		return IdentityAnchor{}, ErrNotFound
	}
	return a, err
}

// DeleteIdentityAnchor removes one anchor by id, scoped to its tenant.
func (s *PGStorage) DeleteIdentityAnchor(tenantID, id string) error {
	tag, err := s.pool.Exec(bgCtx(),
		`DELETE FROM identity_anchors WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return fmt.Errorf("pgstorage delete_identity_anchor: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListIdentityAnchors returns every anchor in tenantID, newest first.
func (s *PGStorage) ListIdentityAnchors(tenantID string) ([]IdentityAnchor, error) {
	const q = `
		SELECT id, user_id, tenant_id, anchor_type, anchor_value, verified_at, created_at
		  FROM identity_anchors
		 WHERE tenant_id = $1
		 ORDER BY created_at DESC, id DESC
	`
	rows, err := s.pool.Query(bgCtx(), q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_identity_anchors: %w", err)
	}
	defer rows.Close()

	out := make([]IdentityAnchor, 0)
	for rows.Next() {
		a, err := scanAnchor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list_identity_anchors rows: %w", err)
	}
	return out, nil
}

// ---- Maintenance ----

// PurgeExpired runs the Postgres equivalent of MemStorage.PurgeExpired — see
// the predicate rationale documented there. In short:
//
//   - tokens:     expires_at < now            (read paths reject these anyway)
//   - auth_codes: created_at < now − AuthCodeTTL  (code grant rejects as expired)
//   - sessions:   expires_at < now − RefreshTokenTTL (grace window: an expired
//     session may still be legitimately referenced by a live refresh token,
//     which itself lives at most RefreshTokenTTL; only past that is it dead)
//
// Returns the total rows deleted across the three tables.
func (s *PGStorage) PurgeExpired(now time.Time) (int, error) {
	now = now.UTC()
	total := 0

	tag, err := s.pool.Exec(bgCtx(), `DELETE FROM tokens WHERE expires_at < $1`, now)
	if err != nil {
		return total, fmt.Errorf("pgstorage purge_expired tokens: %w", err)
	}
	total += int(tag.RowsAffected())

	codeDeadline := now.Add(-time.Duration(AuthCodeTTLSeconds) * time.Second)
	tag, err = s.pool.Exec(bgCtx(), `DELETE FROM auth_codes WHERE created_at < $1`, codeDeadline)
	if err != nil {
		return total, fmt.Errorf("pgstorage purge_expired auth_codes: %w", err)
	}
	total += int(tag.RowsAffected())

	sessDeadline := now.Add(-time.Duration(RefreshTokenTTLSeconds) * time.Second)
	tag, err = s.pool.Exec(bgCtx(), `DELETE FROM sessions WHERE expires_at < $1`, sessDeadline)
	if err != nil {
		return total, fmt.Errorf("pgstorage purge_expired sessions: %w", err)
	}
	total += int(tag.RowsAffected())

	return total, nil
}

// ---- Staff Users ----

func (s *PGStorage) PutStaffUser(u StaffUser) error {
	const q = `
		INSERT INTO staff_users (id, email, display_name, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
			email = EXCLUDED.email,
			display_name = EXCLUDED.display_name,
			active = EXCLUDED.active,
			updated_at = now()
	`
	_, err := s.pool.Exec(bgCtx(), q, u.ID, u.Email, nullable(u.DisplayName), u.Active, u.CreatedAt.UTC(), u.UpdatedAt.UTC())
	return err
}

func (s *PGStorage) GetStaffUserByEmail(email string) (StaffUser, error) {
	const q = `SELECT id, email, display_name, active, created_at, updated_at FROM staff_users WHERE email = $1`
	var u StaffUser
	var displayName *string
	err := s.pool.QueryRow(bgCtx(), q, email).Scan(&u.ID, &u.Email, &displayName, &u.Active, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return StaffUser{}, ErrNotFound
	}
	if err != nil {
		return StaffUser{}, err
	}
	u.DisplayName = derefString(displayName)
	return u, nil
}

func (s *PGStorage) GetStaffUserRoles(userID string) ([]string, error) {
	const q = `SELECT role FROM staff_user_roles WHERE staff_user_id = $1 ORDER BY created_at ASC`
	rows, err := s.pool.Query(bgCtx(), q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (s *PGStorage) AddStaffUserRole(userID, role string) error {
	const q = `
		INSERT INTO staff_user_roles (staff_user_id, role, created_at)
		VALUES ($1, $2, now())
		ON CONFLICT DO NOTHING
	`
	_, err := s.pool.Exec(bgCtx(), q, userID, role)
	return err
}

func (s *PGStorage) ListStaffUsers() ([]StaffUser, error) {
	const q = `SELECT id, email, display_name, active, created_at, updated_at FROM staff_users ORDER BY email ASC`
	rows, err := s.pool.Query(bgCtx(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StaffUser
	for rows.Next() {
		var u StaffUser
		var displayName *string
		if err := rows.Scan(&u.ID, &u.Email, &displayName, &u.Active, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		u.DisplayName = derefString(displayName)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *PGStorage) DeleteStaffUserRole(userID, role string) error {
	const q = `DELETE FROM staff_user_roles WHERE staff_user_id = $1 AND role = $2`
	_, err := s.pool.Exec(bgCtx(), q, userID, role)
	return err
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
		u           User
		email, name *string
	)
	if err := r.Scan(
		&u.ID, &u.TenantID, &email, &name, &u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return User{}, err
	}
	u.Email = derefString(email)
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
		&t.TokenHash, &t.SessionID, &t.UserID, &t.TenantID, &t.ClientID,
		&t.FamilyID, &t.TokenType, &scope, &t.IssuedAt, &t.ExpiresAt, &revokedAt,
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

func scanDeviceSignal(r rowScanner) (DeviceSignal, error) {
	var (
		ds                        DeviceSignal
		userID, sessionID, ip, ua *string
	)
	if err := r.Scan(
		&ds.ID, &ds.TenantID, &userID, &sessionID, &ds.Stage, &ds.Fingerprint, &ip, &ua, &ds.CreatedAt,
	); err != nil {
		return DeviceSignal{}, err
	}
	ds.UserID = derefString(userID)
	ds.SessionID = derefString(sessionID)
	ds.IPAddress = derefString(ip)
	ds.UserAgent = derefString(ua)
	ds.CreatedAt = ds.CreatedAt.UTC()
	return ds, nil
}

func scanAnchor(r rowScanner) (IdentityAnchor, error) {
	var (
		a          IdentityAnchor
		verifiedAt *time.Time
	)
	if err := r.Scan(
		&a.ID, &a.UserID, &a.TenantID, &a.Type, &a.Value, &verifiedAt, &a.CreatedAt,
	); err != nil {
		return IdentityAnchor{}, err
	}
	if verifiedAt != nil {
		ts := verifiedAt.UTC()
		a.VerifiedAt = &ts
	}
	a.CreatedAt = a.CreatedAt.UTC()
	return a, nil
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
