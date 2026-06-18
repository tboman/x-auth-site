package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGStorage is the Postgres-backed Storage implementation. It preserves the same
// semantics as the in-memory Store — tenant isolation enforced on every read/write,
// ErrNotFound when a (tenant_id, id) pair doesn't match, idempotent soft-delete,
// mutator-based challenge updates — so the HTTP layer can swap implementations
// without behavioural drift.
//
// Phase 2.1 widened the Storage signatures, so Put*/List* failures are now
// returned to the caller (handlers translate them to 500 internal_error)
// instead of the old log-and-degrade behaviour. The logger is retained for
// operational context on the storage side.
type PGStorage struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

var _ Storage = (*PGStorage)(nil)

// NewPGStorage returns a Storage backed by the given pgx pool. Callers retain
// ownership of the pool (e.g. close it on shutdown). log may be nil, in which
// case slog.Default() is used.
func NewPGStorage(pool *pgxpool.Pool, log *slog.Logger) *PGStorage {
	if log == nil {
		log = slog.Default()
	}
	return &PGStorage{pool: pool, log: log}
}

// bgCtx is the background context used for DB operations. The current Storage
// signatures don't accept context (matching the in-memory Store); we rely on
// pool-level defaults until the interface grows ctx support.
func bgCtx() context.Context { return context.Background() }

// Now returns the wall-clock time in UTC. The in-memory Store's injectable
// clock exists for handler tests, which keep running against Store; PGStorage
// always uses real time.
func (s *PGStorage) Now() time.Time { return time.Now().UTC() }

// -----------------------------------------------------------------------------
// Authenticator operations
// -----------------------------------------------------------------------------

// PutAuthenticator upserts the authenticator row, returning any persistence
// failure to the caller.
func (s *PGStorage) PutAuthenticator(a Authenticator) error {
	meta, err := encodeJSONMap(a.Metadata)
	if err != nil {
		return fmt.Errorf("pgstorage put_authenticator encode metadata: %w", err)
	}
	const q = `
		INSERT INTO authenticators (
			id, tenant_id, user_id, method, metadata, status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			tenant_id  = EXCLUDED.tenant_id,
			user_id    = EXCLUDED.user_id,
			method     = EXCLUDED.method,
			metadata   = EXCLUDED.metadata,
			status     = EXCLUDED.status,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		a.ID, a.TenantID, a.UserID, a.Method, meta, a.Status,
		a.CreatedAt.UTC(), a.UpdatedAt.UTC(),
	); err != nil {
		return fmt.Errorf("pgstorage put_authenticator: %w", err)
	}
	return nil
}

// GetAuthenticator fetches by id within a tenant. Cross-tenant reads return
// ErrNotFound — the record might exist, but not for this caller.
func (s *PGStorage) GetAuthenticator(tenantID, id string) (Authenticator, error) {
	const q = authenticatorCols + ` WHERE id = $1 AND tenant_id = $2`
	row := s.pool.QueryRow(bgCtx(), q, id, tenantID)
	a, err := scanAuthenticator(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Authenticator{}, ErrNotFound
	}
	if err != nil {
		return Authenticator{}, fmt.Errorf("pgstorage get_authenticator: %w", err)
	}
	return a, nil
}

// ListAuthenticators returns every authenticator for a user within a tenant,
// including soft-deleted (`disabled`) ones so callers can audit history.
// Rows come back ordered by (created_at DESC, id DESC) for determinism.
func (s *PGStorage) ListAuthenticators(tenantID, userID string) ([]Authenticator, error) {
	return s.listAuthenticators(tenantID, userID, false)
}

// ListActiveAuthenticators returns only `active` authenticators for a user.
func (s *PGStorage) ListActiveAuthenticators(tenantID, userID string) ([]Authenticator, error) {
	return s.listAuthenticators(tenantID, userID, true)
}

func (s *PGStorage) listAuthenticators(tenantID, userID string, activeOnly bool) ([]Authenticator, error) {
	q := authenticatorCols + ` WHERE tenant_id = $1 AND user_id = $2`
	args := []any{tenantID, userID}
	if activeOnly {
		q += ` AND status = $3`
		args = append(args, AuthenticatorStatusActive)
	}
	q += ` ORDER BY created_at DESC, id DESC`

	out := make([]Authenticator, 0)
	rows, err := s.pool.Query(bgCtx(), q, args...)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_authenticators: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		a, err := scanAuthenticator(rows)
		if err != nil {
			return nil, fmt.Errorf("pgstorage list_authenticators scan: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list_authenticators rows: %w", err)
	}
	return out, nil
}

// DisableAuthenticator soft-deletes by flipping status to `disabled`. Idempotent:
// disabling an already-disabled authenticator is a no-op (still returns nil) and
// leaves updated_at untouched — same contract as the in-memory Store.
func (s *PGStorage) DisableAuthenticator(tenantID, id string) error {
	const q = `
		UPDATE authenticators
		   SET status     = $3,
		       updated_at = CASE WHEN status = $3 THEN updated_at ELSE $4 END
		 WHERE id = $1 AND tenant_id = $2
	`
	tag, err := s.pool.Exec(bgCtx(), q, id, tenantID, AuthenticatorStatusDisabled, s.Now())
	if err != nil {
		return fmt.Errorf("pgstorage disable_authenticator: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// -----------------------------------------------------------------------------
// Challenge operations
// -----------------------------------------------------------------------------

// PutChallenge upserts the challenge row, returning any persistence failure
// to the caller.
func (s *PGStorage) PutChallenge(c Challenge) error {
	const q = `
		INSERT INTO challenges (
			id, tenant_id, user_id, method, authenticator_id,
			prompt, status, attempts, created_at, expires_at, completed_at,
			last_attempt_at, options_json, session_data
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (id) DO UPDATE SET
			tenant_id        = EXCLUDED.tenant_id,
			user_id          = EXCLUDED.user_id,
			method           = EXCLUDED.method,
			authenticator_id = EXCLUDED.authenticator_id,
			prompt           = EXCLUDED.prompt,
			status           = EXCLUDED.status,
			attempts         = EXCLUDED.attempts,
			created_at       = EXCLUDED.created_at,
			expires_at       = EXCLUDED.expires_at,
			completed_at     = EXCLUDED.completed_at,
			last_attempt_at  = EXCLUDED.last_attempt_at,
			options_json     = EXCLUDED.options_json,
			session_data     = EXCLUDED.session_data
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		c.ID, c.TenantID, c.UserID, c.Method, c.AuthenticatorID,
		nullable(c.Prompt), c.Status, c.Attempts,
		c.CreatedAt.UTC(), c.ExpiresAt.UTC(), nullableTime(c.CompletedAt),
		nullableTime(c.LastAttemptAt), nullable(c.OptionsJSON), nullableBytes(c.SessionData),
	); err != nil {
		return fmt.Errorf("pgstorage put_challenge: %w", err)
	}
	return nil
}

// GetChallenge fetches by id within a tenant. Cross-tenant reads return
// ErrNotFound.
func (s *PGStorage) GetChallenge(tenantID, id string) (Challenge, error) {
	const q = challengeCols + ` WHERE id = $1 AND tenant_id = $2`
	row := s.pool.QueryRow(bgCtx(), q, id, tenantID)
	c, err := scanChallenge(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Challenge{}, ErrNotFound
	}
	if err != nil {
		return Challenge{}, fmt.Errorf("pgstorage get_challenge: %w", err)
	}
	return c, nil
}

// UpdateChallenge applies mutator inside a transaction holding a row lock
// (SELECT ... FOR UPDATE), mirroring the in-memory Store's write-lock
// read-modify-write. Returns ErrNotFound if the (tenant, id) pair doesn't
// match, and refuses to persist if the mutator changed ID or TenantID.
func (s *PGStorage) UpdateChallenge(tenantID, id string, mutator func(*Challenge)) (Challenge, error) {
	ctx := bgCtx()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Challenge{}, fmt.Errorf("pgstorage update_challenge begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, challengeCols+` WHERE id = $1 AND tenant_id = $2 FOR UPDATE`, id, tenantID)
	c, err := scanChallenge(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Challenge{}, ErrNotFound
	}
	if err != nil {
		return Challenge{}, fmt.Errorf("pgstorage update_challenge select: %w", err)
	}

	mutator(&c)
	if c.ID != id || c.TenantID != tenantID {
		// Programmer error — refuse silently corrupting state.
		return Challenge{}, errors.New("mutator changed immutable fields")
	}

	const q = `
		UPDATE challenges SET
			user_id          = $3,
			method           = $4,
			authenticator_id = $5,
			prompt           = $6,
			status           = $7,
			attempts         = $8,
			created_at       = $9,
			expires_at       = $10,
			completed_at     = $11,
			last_attempt_at  = $12,
			options_json     = $13,
			session_data     = $14
		WHERE id = $1 AND tenant_id = $2
	`
	if _, err := tx.Exec(ctx, q,
		id, tenantID,
		c.UserID, c.Method, c.AuthenticatorID,
		nullable(c.Prompt), c.Status, c.Attempts,
		c.CreatedAt.UTC(), c.ExpiresAt.UTC(), nullableTime(c.CompletedAt),
		nullableTime(c.LastAttemptAt), nullable(c.OptionsJSON), nullableBytes(c.SessionData),
	); err != nil {
		return Challenge{}, fmt.Errorf("pgstorage update_challenge: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Challenge{}, fmt.Errorf("pgstorage update_challenge commit: %w", err)
	}
	return c, nil
}

// PurgeExpired deletes challenges that can never be verified again: `pending`
// rows past expires_at and rows already lazily flipped to `expired`. The
// pending arm is served by the partial index idx_challenge_pending_expiry the
// migration created for exactly this sweeper. Same retention choice as the
// in-memory Store: `completed` / `failed` rows are kept as the step-up audit
// trail — age-based retention for those is a separate compliance concern.
func (s *PGStorage) PurgeExpired(now time.Time) (int, error) {
	const q = `
		DELETE FROM challenges
		 WHERE (status = $1 AND expires_at <= $2)
		    OR status = $3
	`
	tag, err := s.pool.Exec(bgCtx(), q, ChallengeStatusPending, now.UTC(), ChallengeStatusExpired)
	if err != nil {
		return 0, fmt.Errorf("pgstorage purge_expired: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

const authenticatorCols = `
	SELECT id, tenant_id, user_id, method, metadata, status, created_at, updated_at
	  FROM authenticators`

const challengeCols = `
	SELECT id, tenant_id, user_id, method, authenticator_id,
	       prompt, status, attempts, created_at, expires_at, completed_at,
	       last_attempt_at, options_json, session_data
	  FROM challenges`

// rowScanner is satisfied by both pgx.Row and pgx.Rows for shared scanning.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAuthenticator(r rowScanner) (Authenticator, error) {
	var (
		a        Authenticator
		metadata []byte
	)
	if err := r.Scan(
		&a.ID, &a.TenantID, &a.UserID, &a.Method, &metadata, &a.Status,
		&a.CreatedAt, &a.UpdatedAt,
	); err != nil {
		return Authenticator{}, err
	}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &a.Metadata); err != nil {
			return Authenticator{}, fmt.Errorf("pgstorage decode metadata: %w", err)
		}
	}
	a.CreatedAt = a.CreatedAt.UTC()
	a.UpdatedAt = a.UpdatedAt.UTC()
	return a, nil
}

func scanChallenge(r rowScanner) (Challenge, error) {
	var (
		c             Challenge
		prompt        *string
		completedAt   *time.Time
		lastAttemptAt *time.Time
		optionsJSON   []byte
	)
	if err := r.Scan(
		&c.ID, &c.TenantID, &c.UserID, &c.Method, &c.AuthenticatorID,
		&prompt, &c.Status, &c.Attempts, &c.CreatedAt, &c.ExpiresAt, &completedAt,
		&lastAttemptAt, &optionsJSON, &c.SessionData,
	); err != nil {
		return Challenge{}, err
	}
	c.Prompt = derefString(prompt)
	c.OptionsJSON = string(optionsJSON)
	if completedAt != nil {
		t := completedAt.UTC()
		c.CompletedAt = &t
	}
	if lastAttemptAt != nil {
		t := lastAttemptAt.UTC()
		c.LastAttemptAt = &t
	}
	c.CreatedAt = c.CreatedAt.UTC()
	c.ExpiresAt = c.ExpiresAt.UTC()
	return c, nil
}

// encodeJSONMap marshals a metadata map for a JSONB column. A nil map becomes
// SQL NULL so it round-trips back as a nil map, matching the in-memory Store.
func encodeJSONMap(m map[string]any) (any, error) {
	if m == nil {
		return nil, nil
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return raw, nil
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

func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
