package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGStorage is the Postgres-backed Storage implementation. It preserves the same
// semantics as MemStorage — tenant isolation enforced on every read/write (identities
// are tenant-scoped via their pool), ErrPoolNotFound / ErrIdentityNotFound on
// cross-tenant access — so the HTTP layer can swap implementations without
// behavioural drift.
//
// Where MemStorage relies on a single mutex for the pick-and-mutate flows, PGStorage
// uses row-level locking instead: AddIdentity takes a FOR UPDATE lock on the pool row
// to serialise the capacity check, and ClaimIdentity picks its candidate with
// FOR UPDATE SKIP LOCKED so concurrent claims never hand out the same identity.
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

// ---------- Pool ops ----------

// CreatePool inserts the pool row. Caller fills ID, TenantID, timestamps.
func (s *PGStorage) CreatePool(p Pool) (Pool, error) {
	personaIDs, err := encodePersonaIDs(p.PersonaIDs)
	if err != nil {
		return Pool{}, err
	}
	const q = `
		INSERT INTO pools (id, tenant_id, name, size, persona_ids, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		p.ID, p.TenantID, p.Name, p.Size, personaIDs,
		p.CreatedAt.UTC(), p.UpdatedAt.UTC(),
	); err != nil {
		return Pool{}, fmt.Errorf("pgstorage create_pool: %w", err)
	}
	return p, nil
}

// GetPool returns the pool iff it exists and belongs to tenantID.
func (s *PGStorage) GetPool(tenantID, id string) (Pool, error) {
	const q = `
		SELECT id, tenant_id, name, size, persona_ids, created_at, updated_at
		  FROM pools
		 WHERE id = $1 AND tenant_id = $2
	`
	row := s.pool.QueryRow(bgCtx(), q, id, tenantID)
	p, err := scanPool(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Pool{}, ErrPoolNotFound
	}
	return p, err
}

// ListPools returns all pools owned by tenantID, ordered by created_at ASC, id ASC —
// the same deterministic order MemStorage produces.
func (s *PGStorage) ListPools(tenantID string) ([]Pool, error) {
	const q = `
		SELECT id, tenant_id, name, size, persona_ids, created_at, updated_at
		  FROM pools
		 WHERE tenant_id = $1
		 ORDER BY created_at ASC, id ASC
	`
	rows, err := s.pool.Query(bgCtx(), q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_pools: %w", err)
	}
	defer rows.Close()

	out := make([]Pool, 0)
	for rows.Next() {
		p, err := scanPool(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list_pools iter: %w", err)
	}
	return out, nil
}

// DeletePool removes the pool; identities cascade via the FK (ON DELETE CASCADE),
// matching MemStorage's explicit cascade.
func (s *PGStorage) DeletePool(tenantID, id string) error {
	const q = `DELETE FROM pools WHERE id = $1 AND tenant_id = $2`
	tag, err := s.pool.Exec(bgCtx(), q, id, tenantID)
	if err != nil {
		return fmt.Errorf("pgstorage delete_pool: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrPoolNotFound
	}
	return nil
}

// ---------- Identity ops ----------

// AddIdentity inserts an identity into a pool, rejecting if the pool is full. The
// pool row is locked FOR UPDATE for the duration of the capacity check so concurrent
// adds can't overshoot Size (the equivalent of MemStorage's single mutex).
func (s *PGStorage) AddIdentity(tenantID, poolID string, ident Identity) (Identity, error) {
	ctx := bgCtx()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Identity{}, fmt.Errorf("pgstorage add_identity begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op

	var size int
	err = tx.QueryRow(ctx,
		`SELECT size FROM pools WHERE id = $1 AND tenant_id = $2 FOR UPDATE`,
		poolID, tenantID,
	).Scan(&size)
	if errors.Is(err, pgx.ErrNoRows) {
		return Identity{}, ErrPoolNotFound
	}
	if err != nil {
		return Identity{}, fmt.Errorf("pgstorage add_identity pool: %w", err)
	}

	var count int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM identities WHERE pool_id = $1`, poolID,
	).Scan(&count); err != nil {
		return Identity{}, fmt.Errorf("pgstorage add_identity count: %w", err)
	}
	if count >= size {
		return Identity{}, ErrPoolFull
	}

	const q = `
		INSERT INTO identities (
			id, pool_id, subject_id, status, claimed_by_install_id, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	if _, err := tx.Exec(ctx, q,
		ident.ID, ident.PoolID, ident.SubjectID, string(ident.Status),
		ident.ClaimedByInstallID, ident.CreatedAt.UTC(), ident.UpdatedAt.UTC(),
	); err != nil {
		return Identity{}, fmt.Errorf("pgstorage add_identity insert: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Identity{}, fmt.Errorf("pgstorage add_identity commit: %w", err)
	}
	return ident, nil
}

// ListIdentities returns every identity in poolID (tenant-scoped), ordered by
// created_at ASC, id ASC.
func (s *PGStorage) ListIdentities(tenantID, poolID string) ([]Identity, error) {
	// Tenant-scope via the pool, and distinguish "pool missing" from "pool empty".
	if _, err := s.GetPool(tenantID, poolID); err != nil {
		return nil, err
	}
	const q = `
		SELECT id, pool_id, subject_id, status, claimed_by_install_id, created_at, updated_at
		  FROM identities
		 WHERE pool_id = $1
		 ORDER BY created_at ASC, id ASC
	`
	rows, err := s.pool.Query(bgCtx(), q, poolID)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_identities: %w", err)
	}
	defer rows.Close()

	out := make([]Identity, 0)
	for rows.Next() {
		ident, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ident)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list_identities iter: %w", err)
	}
	return out, nil
}

// GetIdentity returns an identity by id, tenant-scoped via its pool.
func (s *PGStorage) GetIdentity(tenantID, id string) (Identity, error) {
	const q = `
		SELECT i.id, i.pool_id, i.subject_id, i.status, i.claimed_by_install_id,
		       i.created_at, i.updated_at
		  FROM identities i
		  JOIN pools p ON p.id = i.pool_id
		 WHERE i.id = $1 AND p.tenant_id = $2
	`
	row := s.pool.QueryRow(bgCtx(), q, id, tenantID)
	ident, err := scanIdentity(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Identity{}, ErrIdentityNotFound
	}
	return ident, err
}

// ClaimIdentity is the atomic claim path. Pool existence and persona eligibility are
// validated first (same error precedence as MemStorage), then a single UPDATE picks
// the oldest available identity with FOR UPDATE SKIP LOCKED so concurrent claimers
// never receive the same row.
func (s *PGStorage) ClaimIdentity(tenantID, poolID, personaID, installID string) (Identity, error) {
	p, err := s.GetPool(tenantID, poolID)
	if err != nil {
		return Identity{}, err
	}
	if !containsString(p.PersonaIDs, personaID) {
		// Per requirements, 404 if pool doesn't list persona_id in persona_ids.
		return Identity{}, ErrPersonaNotEligible
	}

	const q = `
		UPDATE identities
		   SET status = 'claimed', claimed_by_install_id = $2, updated_at = now()
		 WHERE id = (
		         SELECT id FROM identities
		          WHERE pool_id = $1 AND status = 'available'
		          ORDER BY created_at ASC, id ASC
		          LIMIT 1
		            FOR UPDATE SKIP LOCKED
		       )
		RETURNING id, pool_id, subject_id, status, claimed_by_install_id, created_at, updated_at
	`
	row := s.pool.QueryRow(bgCtx(), q, poolID, installID)
	ident, err := scanIdentity(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Identity{}, ErrNoAvailableIdentity
	}
	if err != nil {
		return Identity{}, fmt.Errorf("pgstorage claim_identity: %w", err)
	}
	return ident, nil
}

// ReleaseIdentity flips status -> available and clears claimed_by_install_id.
// Idempotent on already-available identities (no write, row returned as-is).
// Revoked identities cannot be released.
func (s *PGStorage) ReleaseIdentity(tenantID, id string) (Identity, error) {
	const q = `
		UPDATE identities AS i
		   SET status = 'available', claimed_by_install_id = NULL, updated_at = now()
		  FROM pools p
		 WHERE i.id = $1 AND p.id = i.pool_id AND p.tenant_id = $2
		   AND i.status <> 'revoked'
		   AND NOT (i.status = 'available' AND i.claimed_by_install_id IS NULL)
		RETURNING i.id, i.pool_id, i.subject_id, i.status, i.claimed_by_install_id,
		          i.created_at, i.updated_at
	`
	row := s.pool.QueryRow(bgCtx(), q, id, tenantID)
	ident, err := scanIdentity(row)
	if err == nil {
		return ident, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Identity{}, fmt.Errorf("pgstorage release_identity: %w", err)
	}
	// No row was updated: either missing/cross-tenant, revoked, or already available
	// (idempotent no-op). Re-read to disambiguate — same precedence as MemStorage.
	ident, err = s.GetIdentity(tenantID, id)
	if err != nil {
		return Identity{}, err
	}
	if ident.Status == StatusRevoked {
		return Identity{}, ErrIdentityRevoked
	}
	return ident, nil
}

// RevokeIdentity is terminal: once revoked, an identity stays revoked.
func (s *PGStorage) RevokeIdentity(tenantID, id string) error {
	const q = `
		UPDATE identities AS i
		   SET status = 'revoked', claimed_by_install_id = NULL, updated_at = now()
		  FROM pools p
		 WHERE i.id = $1 AND p.id = i.pool_id AND p.tenant_id = $2
	`
	tag, err := s.pool.Exec(bgCtx(), q, id, tenantID)
	if err != nil {
		return fmt.Errorf("pgstorage revoke_identity: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrIdentityNotFound
	}
	return nil
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// rowScanner is satisfied by both pgx.Row and pgx.Rows for shared scanning.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanPool(r rowScanner) (Pool, error) {
	var (
		p          Pool
		personaIDs []byte
	)
	if err := r.Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Size, &personaIDs,
		&p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return Pool{}, err
	}
	ids, err := decodePersonaIDs(personaIDs)
	if err != nil {
		return Pool{}, err
	}
	p.PersonaIDs = ids
	p.CreatedAt = p.CreatedAt.UTC()
	p.UpdatedAt = p.UpdatedAt.UTC()
	return p, nil
}

func scanIdentity(r rowScanner) (Identity, error) {
	var (
		ident  Identity
		status string
	)
	if err := r.Scan(
		&ident.ID, &ident.PoolID, &ident.SubjectID, &status,
		&ident.ClaimedByInstallID, &ident.CreatedAt, &ident.UpdatedAt,
	); err != nil {
		return Identity{}, err
	}
	ident.Status = IdentityStatus(status)
	ident.CreatedAt = ident.CreatedAt.UTC()
	ident.UpdatedAt = ident.UpdatedAt.UTC()
	return ident, nil
}

// encodePersonaIDs marshals the persona-id list for the JSONB column. nil is stored
// as [] so the round-trip matches the handlers' non-nil contract.
func encodePersonaIDs(ids []string) ([]byte, error) {
	if ids == nil {
		ids = []string{}
	}
	out, err := json.Marshal(ids)
	if err != nil {
		return nil, fmt.Errorf("pgstorage encode persona_ids: %w", err)
	}
	return out, nil
}

func decodePersonaIDs(raw []byte) ([]string, error) {
	ids := []string{}
	if len(raw) == 0 {
		return ids, nil
	}
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil, fmt.Errorf("pgstorage decode persona_ids: %w", err)
	}
	if ids == nil {
		ids = []string{}
	}
	return ids, nil
}
