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

// PGStorage is the Postgres-backed implementation of both GrantStore and AuditStore.
// It preserves the same semantics as the in-memory stores — tenant isolation enforced
// on every read/write, ErrNotFound when a (tenant_id, id) pair doesn't match, grant
// status derived at read time from revoked_at / expires_at — so the HTTP layer can
// swap implementations without behavioural drift.
//
// The audit log stays append-only: this type issues no UPDATE or DELETE against
// audit_events, matching the AuditStore contract (Append + Query only). GDPR erasure
// is handled via pseudonymization tooling, never row deletion.
type PGStorage struct {
	pool *pgxpool.Pool
}

// NewPGStorage returns a GrantStore + AuditStore backed by the given pgx pool. Callers
// retain ownership of the pool (e.g. close it on shutdown).
func NewPGStorage(pool *pgxpool.Pool) *PGStorage {
	return &PGStorage{pool: pool}
}

// Compile-time interface checks.
var (
	_ GrantStore = (*PGStorage)(nil)
	_ AuditStore = (*PGStorage)(nil)
)

// bgCtx is the background context used for DB operations. The current store
// signatures don't accept context (matching the mem stores); we rely on pool-level
// defaults until the interfaces grow ctx support.
func bgCtx() context.Context { return context.Background() }

// -----------------------------------------------------------------------------
// GrantStore
// -----------------------------------------------------------------------------

// Create inserts the grant row. Caller fills ID, TenantID, timestamps, and hashes.
func (s *PGStorage) Create(g Grant) (Grant, error) {
	const q = `
		INSERT INTO grants (
			id, tenant_id, install_id, identity_id, persona_id,
			access_token_hash, refresh_token_hash, issued_at, expires_at, revoked_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10
		)
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		g.ID, g.TenantID, g.InstallID, g.IdentityID, g.PersonaID,
		g.AccessTokenHash, nullable(g.RefreshTokenHash),
		g.IssuedAt.UTC(), g.ExpiresAt.UTC(), nullableTime(g.RevokedAt),
	); err != nil {
		return Grant{}, fmt.Errorf("pgstorage create grant: %w", err)
	}
	return g, nil
}

// Get returns the grant if it exists and belongs to tenantID. Status is derived here.
func (s *PGStorage) Get(tenantID, id string) (Grant, error) {
	const q = `
		SELECT id, tenant_id, install_id, identity_id, persona_id,
		       access_token_hash, refresh_token_hash, issued_at, expires_at, revoked_at
		  FROM grants
		 WHERE id = $1 AND tenant_id = $2
	`
	row := s.pool.QueryRow(bgCtx(), q, id, tenantID)
	g, err := scanGrant(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Grant{}, ErrNotFound
	}
	if err != nil {
		return Grant{}, fmt.Errorf("pgstorage get grant: %w", err)
	}
	g.Status = DeriveStatus(g, time.Now().UTC())
	return g, nil
}

// Revoke marks the tenant-scoped grant revoked at `now`. Idempotent: a second revoke
// is a no-op that returns alreadyRevoked=true with the original revoked_at preserved
// (COALESCE keeps the first value; the CTE captures the pre-update revoked_at so the
// caller can distinguish first revoke from retry). Returns ErrNotFound if no row
// matches both id and tenant_id.
func (s *PGStorage) Revoke(tenantID, id string, now time.Time) (Grant, bool, error) {
	const q = `
		WITH before AS (
			SELECT revoked_at FROM grants
			 WHERE id = $1 AND tenant_id = $2
			 FOR UPDATE
		)
		UPDATE grants g
		   SET revoked_at = COALESCE(g.revoked_at, $3)
		  FROM before
		 WHERE g.id = $1 AND g.tenant_id = $2
		RETURNING g.id, g.tenant_id, g.install_id, g.identity_id, g.persona_id,
		          g.access_token_hash, g.refresh_token_hash, g.issued_at, g.expires_at,
		          g.revoked_at, before.revoked_at
	`
	var (
		g            Grant
		refreshHash  *string
		revokedAt    *time.Time
		priorRevoked *time.Time
	)
	err := s.pool.QueryRow(bgCtx(), q, id, tenantID, now.UTC()).Scan(
		&g.ID, &g.TenantID, &g.InstallID, &g.IdentityID, &g.PersonaID,
		&g.AccessTokenHash, &refreshHash, &g.IssuedAt, &g.ExpiresAt,
		&revokedAt, &priorRevoked,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Grant{}, false, ErrNotFound
	}
	if err != nil {
		return Grant{}, false, fmt.Errorf("pgstorage revoke grant: %w", err)
	}
	g.RefreshTokenHash = derefString(refreshHash)
	if revokedAt != nil {
		t := revokedAt.UTC()
		g.RevokedAt = &t
	}
	g.IssuedAt = g.IssuedAt.UTC()
	g.ExpiresAt = g.ExpiresAt.UTC()
	g.Status = DeriveStatus(g, now)
	return g, priorRevoked != nil, nil
}

// ListByInstall returns every grant bound to (tenantID, installID), sorted by issued_at
// ascending (id as tiebreaker). Includes already-revoked / expired grants — same
// contract as MemGrantStore.
func (s *PGStorage) ListByInstall(tenantID, installID string) ([]Grant, error) {
	const q = `
		SELECT id, tenant_id, install_id, identity_id, persona_id,
		       access_token_hash, refresh_token_hash, issued_at, expires_at, revoked_at
		  FROM grants
		 WHERE tenant_id = $1 AND install_id = $2
		 ORDER BY issued_at ASC, id ASC
	`
	rows, err := s.pool.Query(bgCtx(), q, tenantID, installID)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_by_install: %w", err)
	}
	defer rows.Close()

	now := time.Now().UTC()
	out := make([]Grant, 0)
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("pgstorage list_by_install scan: %w", err)
		}
		g.Status = DeriveStatus(g, now)
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list_by_install iter: %w", err)
	}
	return out, nil
}

// FindByAccessTokenHash returns the grant whose access_token_hash matches, across all
// tenants (RFC 7662 introspection cannot assume the caller knows the issuing tenant;
// the handler enforces tenancy on the result). The empty hash never matches — it is
// the digest sentinel for "no token supplied".
func (s *PGStorage) FindByAccessTokenHash(hash string) (Grant, error) {
	if hash == "" {
		return Grant{}, ErrNotFound
	}
	const q = `
		SELECT id, tenant_id, install_id, identity_id, persona_id,
		       access_token_hash, refresh_token_hash, issued_at, expires_at, revoked_at
		  FROM grants
		 WHERE access_token_hash = $1
	`
	row := s.pool.QueryRow(bgCtx(), q, hash)
	g, err := scanGrant(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Grant{}, ErrNotFound
	}
	if err != nil {
		return Grant{}, fmt.Errorf("pgstorage find_by_access_token_hash: %w", err)
	}
	g.Status = DeriveStatus(g, time.Now().UTC())
	return g, nil
}

// -----------------------------------------------------------------------------
// AuditStore
// -----------------------------------------------------------------------------

// Append records the event. Caller fills ID, TenantID, and CreatedAt. INSERT only —
// audit_events has no update or delete path in this type, by design.
func (s *PGStorage) Append(e AuditEvent) (AuditEvent, error) {
	payload, err := encodePayload(e.Payload)
	if err != nil {
		return AuditEvent{}, fmt.Errorf("pgstorage audit append marshal: %w", err)
	}
	const q = `
		INSERT INTO audit_events (
			id, tenant_id, type, actor, install_id, grant_id, payload, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		)
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		e.ID, e.TenantID, e.Type, e.Actor,
		nullable(e.InstallID), nullable(e.GrantID),
		payload, e.CreatedAt.UTC(),
	); err != nil {
		return AuditEvent{}, fmt.Errorf("pgstorage audit append: %w", err)
	}
	return e, nil
}

// Query returns tenant-scoped events matching the filter, ordered by created_at DESC,
// id DESC (most recent first) — the same keyset-friendly ordering transaction-service
// uses. Since is inclusive, Until exclusive ("[since, until)"), matching MemAuditStore.
func (s *PGStorage) Query(tenantID string, f AuditFilter) ([]AuditEvent, error) {
	base := `
		SELECT id, tenant_id, type, actor, install_id, grant_id, payload, created_at
		  FROM audit_events
		 WHERE tenant_id = $1
	`
	args := []any{tenantID}
	if f.InstallID != "" {
		args = append(args, f.InstallID)
		base += fmt.Sprintf(` AND install_id = $%d`, len(args))
	}
	if f.GrantID != "" {
		args = append(args, f.GrantID)
		base += fmt.Sprintf(` AND grant_id = $%d`, len(args))
	}
	if f.Type != "" {
		args = append(args, f.Type)
		base += fmt.Sprintf(` AND type = $%d`, len(args))
	}
	if !f.Since.IsZero() {
		args = append(args, f.Since.UTC())
		base += fmt.Sprintf(` AND created_at >= $%d`, len(args))
	}
	if !f.Until.IsZero() {
		args = append(args, f.Until.UTC())
		base += fmt.Sprintf(` AND created_at < $%d`, len(args))
	}
	base += ` ORDER BY created_at DESC, id DESC`
	if f.Limit > 0 {
		args = append(args, f.Limit)
		base += fmt.Sprintf(` LIMIT $%d`, len(args))
	}

	rows, err := s.pool.Query(bgCtx(), base, args...)
	if err != nil {
		return nil, fmt.Errorf("pgstorage audit query: %w", err)
	}
	defer rows.Close()

	out := make([]AuditEvent, 0)
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("pgstorage audit query scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage audit query iter: %w", err)
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// rowScanner is satisfied by both pgx.Row and pgx.Rows for shared scanning.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanGrant(r rowScanner) (Grant, error) {
	var (
		g           Grant
		refreshHash *string
		revokedAt   *time.Time
	)
	if err := r.Scan(
		&g.ID, &g.TenantID, &g.InstallID, &g.IdentityID, &g.PersonaID,
		&g.AccessTokenHash, &refreshHash, &g.IssuedAt, &g.ExpiresAt, &revokedAt,
	); err != nil {
		return Grant{}, err
	}
	g.RefreshTokenHash = derefString(refreshHash)
	if revokedAt != nil {
		t := revokedAt.UTC()
		g.RevokedAt = &t
	}
	g.IssuedAt = g.IssuedAt.UTC()
	g.ExpiresAt = g.ExpiresAt.UTC()
	return g, nil
}

func scanAuditEvent(r rowScanner) (AuditEvent, error) {
	var (
		e                  AuditEvent
		installID, grantID *string
		payload            []byte
	)
	if err := r.Scan(
		&e.ID, &e.TenantID, &e.Type, &e.Actor,
		&installID, &grantID, &payload, &e.CreatedAt,
	); err != nil {
		return AuditEvent{}, err
	}
	e.InstallID = derefString(installID)
	e.GrantID = derefString(grantID)
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &e.Payload); err != nil {
			return AuditEvent{}, fmt.Errorf("pgstorage decode payload: %w", err)
		}
	}
	e.CreatedAt = e.CreatedAt.UTC()
	return e, nil
}

// encodePayload turns the free-form payload map into a JSONB value. A nil map is
// stored as SQL NULL so it round-trips back to nil rather than an empty object.
func encodePayload(p map[string]any) (any, error) {
	if p == nil {
		return nil, nil
	}
	return json.Marshal(p)
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
