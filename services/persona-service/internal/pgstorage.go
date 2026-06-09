package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGStorage is the Postgres-backed Storage implementation. It preserves the same
// semantics as MemStorage — tenant isolation enforced on every read/write,
// ErrNotFound when a (tenant_id, id) pair doesn't match — so the HTTP layer can
// swap implementations without behavioural drift.
//
// Scopes ([]string) and Claims (free-form map) are stored as JSONB columns so the
// Go shapes round-trip without join tables; see migrations/000001_init.up.sql.
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

// Create inserts the persona row. Caller is expected to have filled ID, TenantID,
// and timestamps (same contract as MemStorage.Create).
func (s *PGStorage) Create(p Persona) (Persona, error) {
	scopes, claims, err := encodePersonaJSON(p)
	if err != nil {
		return Persona{}, err
	}
	const q = `
		INSERT INTO personas (
			id, tenant_id, name, scopes, claims,
			token_ttl_seconds, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8
		)
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		p.ID, p.TenantID, p.Name, scopes, claims,
		p.TokenTTLSeconds, p.CreatedAt.UTC(), p.UpdatedAt.UTC(),
	); err != nil {
		return Persona{}, fmt.Errorf("pgstorage create: %w", err)
	}
	return p, nil
}

// Get returns the persona if it exists and belongs to tenantID.
func (s *PGStorage) Get(tenantID, id string) (Persona, error) {
	const q = `
		SELECT id, tenant_id, name, scopes, claims,
		       token_ttl_seconds, created_at, updated_at
		  FROM personas
		 WHERE id = $1 AND tenant_id = $2
	`
	row := s.pool.QueryRow(bgCtx(), q, id, tenantID)
	p, err := scanPersona(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Persona{}, ErrNotFound
	}
	return p, err
}

// List returns all personas owned by tenantID, ordered by (created_at ASC, id ASC) —
// the same deterministic ordering MemStorage.List produces. The Storage contract has
// no pagination yet; when it grows limit/cursor parameters this becomes a keyset
// query like transaction-service's List.
func (s *PGStorage) List(tenantID string) ([]Persona, error) {
	const q = `
		SELECT id, tenant_id, name, scopes, claims,
		       token_ttl_seconds, created_at, updated_at
		  FROM personas
		 WHERE tenant_id = $1
		 ORDER BY created_at ASC, id ASC
	`
	rows, err := s.pool.Query(bgCtx(), q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list: %w", err)
	}
	defer rows.Close()

	out := make([]Persona, 0)
	for rows.Next() {
		p, err := scanPersona(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list iter: %w", err)
	}
	return out, nil
}

// Update replaces the mutable columns and stamps UpdatedAt. CreatedAt is preserved
// from the existing row (same contract as MemStorage.Update). Returns ErrNotFound
// if no row matches both id and tenant_id.
func (s *PGStorage) Update(p Persona) (Persona, error) {
	scopes, claims, err := encodePersonaJSON(p)
	if err != nil {
		return Persona{}, err
	}
	p.UpdatedAt = time.Now().UTC()
	const q = `
		UPDATE personas SET
			name              = $3,
			scopes            = $4,
			claims            = $5,
			token_ttl_seconds = $6,
			updated_at        = $7
		WHERE id = $1 AND tenant_id = $2
		RETURNING created_at
	`
	var createdAt time.Time
	err = s.pool.QueryRow(bgCtx(), q,
		p.ID, p.TenantID,
		p.Name, scopes, claims,
		p.TokenTTLSeconds, p.UpdatedAt,
	).Scan(&createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Persona{}, ErrNotFound
	}
	if err != nil {
		return Persona{}, fmt.Errorf("pgstorage update: %w", err)
	}
	p.CreatedAt = createdAt.UTC()
	return p, nil
}

// Delete removes the persona if it exists in tenantID. Returns ErrNotFound otherwise.
func (s *PGStorage) Delete(tenantID, id string) error {
	const q = `DELETE FROM personas WHERE id = $1 AND tenant_id = $2`
	tag, err := s.pool.Exec(bgCtx(), q, id, tenantID)
	if err != nil {
		return fmt.Errorf("pgstorage delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
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

func scanPersona(r rowScanner) (Persona, error) {
	var (
		p      Persona
		scopes []byte
		claims []byte
	)
	if err := r.Scan(
		&p.ID, &p.TenantID, &p.Name, &scopes, &claims,
		&p.TokenTTLSeconds, &p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return Persona{}, err
	}
	if len(scopes) > 0 {
		if err := json.Unmarshal(scopes, &p.Scopes); err != nil {
			return Persona{}, fmt.Errorf("pgstorage decode scopes: %w", err)
		}
	}
	if len(claims) > 0 {
		if err := json.Unmarshal(claims, &p.Claims); err != nil {
			return Persona{}, fmt.Errorf("pgstorage decode claims: %w", err)
		}
	}
	p.CreatedAt = p.CreatedAt.UTC()
	p.UpdatedAt = p.UpdatedAt.UTC()
	return p, nil
}

// encodePersonaJSON marshals the JSONB-backed fields. Scopes always serialise (a nil
// slice round-trips as JSON null); a nil Claims map becomes SQL NULL so the column
// stays empty rather than holding a JSON null literal.
func encodePersonaJSON(p Persona) (scopes []byte, claims any, err error) {
	scopes, err = json.Marshal(p.Scopes)
	if err != nil {
		return nil, nil, fmt.Errorf("pgstorage encode scopes: %w", err)
	}
	if p.Claims == nil {
		return scopes, nil, nil
	}
	raw, err := json.Marshal(p.Claims)
	if err != nil {
		return nil, nil, fmt.Errorf("pgstorage encode claims: %w", err)
	}
	return scopes, raw, nil
}
