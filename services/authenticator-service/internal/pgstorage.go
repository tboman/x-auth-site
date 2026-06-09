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
// One deviation from the transaction-service reference: the phase-1 Storage
// interface has error-less Put*/List* signatures, so PGStorage carries a logger
// and reports failures there instead of returning them (dropped put / empty
// list). Widening those signatures is phase-2.1 work.
type PGStorage struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

var _ Storage = (*PGStorage)(nil)

// NewPGStorage returns a Storage backed by the given pgx pool. Callers retain
// ownership of the pool (e.g. close it on shutdown). log may be nil, in which
// case slog.Default() is used for the error-less Storage methods.
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

// PutAuthenticator upserts the authenticator row. The Storage signature cannot
// surface failures, so errors are logged and the put is dropped (same contract
// hazard the in-memory Store never trips).
func (s *PGStorage) PutAuthenticator(a Authenticator) {
	meta, err := encodeJSONMap(a.Metadata)
	if err != nil {
		s.log.Error("pgstorage_put_authenticator", "id", a.ID, "err", err)
		return
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
		s.log.Error("pgstorage_put_authenticator", "id", a.ID, "err", err)
	}
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
func (s *PGStorage) ListAuthenticators(tenantID, userID string) []Authenticator {
	return s.listAuthenticators(tenantID, userID, false)
}

// ListActiveAuthenticators returns only `active` authenticators for a user.
func (s *PGStorage) ListActiveAuthenticators(tenantID, userID string) []Authenticator {
	return s.listAuthenticators(tenantID, userID, true)
}

func (s *PGStorage) listAuthenticators(tenantID, userID string, activeOnly bool) []Authenticator {
	q := authenticatorCols + ` WHERE tenant_id = $1 AND user_id = $2`
	args := []any{tenantID, userID}
	if activeOnly {
		q += ` AND status = $3`
		args = append(args, AuthenticatorStatusActive)
	}
	q += ` ORDER BY created_at DESC, id DESC`

	// Errors can't be surfaced through the List* signatures; log and return the
	// same empty slice the in-memory Store would for an unknown user.
	out := make([]Authenticator, 0)
	rows, err := s.pool.Query(bgCtx(), q, args...)
	if err != nil {
		s.log.Error("pgstorage_list_authenticators", "tenant_id", tenantID, "user_id", userID, "err", err)
		return out
	}
	defer rows.Close()

	for rows.Next() {
		a, err := scanAuthenticator(rows)
		if err != nil {
			s.log.Error("pgstorage_list_authenticators", "tenant_id", tenantID, "user_id", userID, "err", err)
			return out
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		s.log.Error("pgstorage_list_authenticators", "tenant_id", tenantID, "user_id", userID, "err", err)
	}
	return out
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

// PutChallenge upserts the challenge row. Same error-less contract caveat as
// PutAuthenticator.
func (s *PGStorage) PutChallenge(c Challenge) {
	const q = `
		INSERT INTO challenges (
			id, tenant_id, user_id, method, authenticator_id,
			prompt, status, attempts, created_at, expires_at, completed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
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
			completed_at     = EXCLUDED.completed_at
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		c.ID, c.TenantID, c.UserID, c.Method, c.AuthenticatorID,
		nullable(c.Prompt), c.Status, c.Attempts,
		c.CreatedAt.UTC(), c.ExpiresAt.UTC(), nullableTime(c.CompletedAt),
	); err != nil {
		s.log.Error("pgstorage_put_challenge", "id", c.ID, "err", err)
	}
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
			completed_at     = $11
		WHERE id = $1 AND tenant_id = $2
	`
	if _, err := tx.Exec(ctx, q,
		id, tenantID,
		c.UserID, c.Method, c.AuthenticatorID,
		nullable(c.Prompt), c.Status, c.Attempts,
		c.CreatedAt.UTC(), c.ExpiresAt.UTC(), nullableTime(c.CompletedAt),
	); err != nil {
		return Challenge{}, fmt.Errorf("pgstorage update_challenge: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Challenge{}, fmt.Errorf("pgstorage update_challenge commit: %w", err)
	}
	return c, nil
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

const authenticatorCols = `
	SELECT id, tenant_id, user_id, method, metadata, status, created_at, updated_at
	  FROM authenticators`

const challengeCols = `
	SELECT id, tenant_id, user_id, method, authenticator_id,
	       prompt, status, attempts, created_at, expires_at, completed_at
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
		c           Challenge
		prompt      *string
		completedAt *time.Time
	)
	if err := r.Scan(
		&c.ID, &c.TenantID, &c.UserID, &c.Method, &c.AuthenticatorID,
		&prompt, &c.Status, &c.Attempts, &c.CreatedAt, &c.ExpiresAt, &completedAt,
	); err != nil {
		return Challenge{}, err
	}
	c.Prompt = derefString(prompt)
	if completedAt != nil {
		t := completedAt.UTC()
		c.CompletedAt = &t
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

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
