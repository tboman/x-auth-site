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
// semantics as MemStorage — installs are tenant-scoped on every read/write and
// return ErrNotFound on a (tenant_id, id) miss; DCR clients, auth codes, and token
// records are key-only lookups (the row carries its own tenant id) — so the HTTP
// layer can swap implementations without behavioural drift.
//
// Phase-1 opaque UUID tokens are persisted as-is; JWT signing (and deferring token
// introspection to grant-service) is a later phase.
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

// -----------------------------------------------------------------------------
// Installs
// -----------------------------------------------------------------------------

// CreateInstall inserts the install row. Caller fills ID, TenantID, and timestamps.
func (s *PGStorage) CreateInstall(i Install) (Install, error) {
	const q = `
		INSERT INTO installs (
			id, tenant_id, runtime, persona_id, identity_id,
			client_id, status, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9
		)
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		i.ID, i.TenantID, i.Runtime, i.PersonaID, nullable(i.IdentityID),
		i.ClientID, i.Status, i.CreatedAt.UTC(), i.UpdatedAt.UTC(),
	); err != nil {
		return Install{}, fmt.Errorf("pgstorage create_install: %w", err)
	}
	return i, nil
}

// GetInstall returns the install if it exists *and* belongs to tenantID.
func (s *PGStorage) GetInstall(tenantID, id string) (Install, error) {
	const q = `
		SELECT id, tenant_id, runtime, persona_id, identity_id,
		       client_id, status, created_at, updated_at
		  FROM installs
		 WHERE id = $1 AND tenant_id = $2
	`
	row := s.pool.QueryRow(bgCtx(), q, id, tenantID)
	i, err := scanInstall(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Install{}, ErrNotFound
	}
	return i, err
}

// UpdateInstall replaces the mutable columns of the row identified by
// (i.TenantID, i.ID). CreatedAt is preserved from the existing row and UpdatedAt
// is stamped server-side — same contract as MemStorage.UpdateInstall. Returns
// ErrNotFound if no row matches both id and tenant_id.
func (s *PGStorage) UpdateInstall(i Install) (Install, error) {
	const q = `
		UPDATE installs SET
			runtime     = $3,
			persona_id  = $4,
			identity_id = $5,
			client_id   = $6,
			status      = $7,
			updated_at  = now()
		WHERE id = $1 AND tenant_id = $2
		RETURNING created_at, updated_at
	`
	var createdAt, updatedAt time.Time
	err := s.pool.QueryRow(bgCtx(), q,
		i.ID, i.TenantID,
		i.Runtime, i.PersonaID, nullable(i.IdentityID), i.ClientID, i.Status,
	).Scan(&createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Install{}, ErrNotFound
	}
	if err != nil {
		return Install{}, fmt.Errorf("pgstorage update_install: %w", err)
	}
	i.CreatedAt = createdAt.UTC()
	i.UpdatedAt = updatedAt.UTC()
	return i, nil
}

// ListInstalls returns up to `limit` installs for tenantID, ordered by
// created_at DESC, id DESC. If cursor is non-zero, only rows strictly older than
// the cursor are returned — same keyset-pagination contract as MemStorage and as
// transaction-service. The (tenant_id, created_at, id) index from 000001 serves
// this scan in both directions.
func (s *PGStorage) ListInstalls(tenantID string, limit int, cursor time.Time) ([]Install, error) {
	q := `
		SELECT id, tenant_id, runtime, persona_id, identity_id,
		       client_id, status, created_at, updated_at
		  FROM installs
		 WHERE tenant_id = $1
	`
	args := []any{tenantID}
	if !cursor.IsZero() {
		q += ` AND created_at < $2`
		args = append(args, cursor.UTC())
	}
	q += ` ORDER BY created_at DESC, id DESC`
	if limit > 0 {
		q += fmt.Sprintf(` LIMIT $%d`, len(args)+1)
		args = append(args, limit)
	}

	rows, err := s.pool.Query(bgCtx(), q, args...)
	if err != nil {
		return nil, fmt.Errorf("pgstorage list_installs: %w", err)
	}
	defer rows.Close()

	out := make([]Install, 0)
	for rows.Next() {
		i, err := scanInstall(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list_installs iter: %w", err)
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// DCR clients
// -----------------------------------------------------------------------------

// PutClient upserts a DCR client (MemStorage map-assignment semantics: the new
// record replaces every column, including created_at).
func (s *PGStorage) PutClient(c DCRClient) error {
	meta, err := encodeClientMetadata(c.ClientMetadata)
	if err != nil {
		return fmt.Errorf("pgstorage put_client marshal: %w", err)
	}
	const q = `
		INSERT INTO dcr_clients (client_id, client_secret, client_metadata, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (client_id) DO UPDATE SET
			client_secret   = EXCLUDED.client_secret,
			client_metadata = EXCLUDED.client_metadata,
			created_at      = EXCLUDED.created_at
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		c.ClientID, nullable(c.ClientSecret), meta, c.CreatedAt.UTC(),
	); err != nil {
		return fmt.Errorf("pgstorage put_client: %w", err)
	}
	return nil
}

// GetClient reads by client id.
func (s *PGStorage) GetClient(clientID string) (DCRClient, error) {
	const q = `
		SELECT client_id, client_secret, client_metadata, created_at
		  FROM dcr_clients
		 WHERE client_id = $1
	`
	var (
		c      DCRClient
		secret *string
		meta   []byte
	)
	err := s.pool.QueryRow(bgCtx(), q, clientID).Scan(&c.ClientID, &secret, &meta, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DCRClient{}, ErrNotFound
	}
	if err != nil {
		return DCRClient{}, fmt.Errorf("pgstorage get_client: %w", err)
	}
	c.ClientSecret = derefString(secret)
	if len(meta) > 0 {
		if err := json.Unmarshal(meta, &c.ClientMetadata); err != nil {
			return DCRClient{}, fmt.Errorf("pgstorage decode client_metadata: %w", err)
		}
	}
	c.CreatedAt = c.CreatedAt.UTC()
	return c, nil
}

// -----------------------------------------------------------------------------
// Auth codes
// -----------------------------------------------------------------------------

// PutAuthCode stores a pending authorization code. If CreatedAt is the zero value
// (direct-seed path in tests and admin tools that bypass /authorize) we stamp it
// to now so the TTL window in handleCodeGrant is meaningful — same contract as
// MemStorage.PutAuthCode.
func (s *PGStorage) PutAuthCode(ac AuthCode) error {
	if ac.CreatedAt.IsZero() {
		ac.CreatedAt = time.Now().UTC()
	}
	const q = `
		INSERT INTO auth_codes (
			code, tenant_id, runtime, persona_id, pool_id,
			client_id, redirect_uri, state, scope, code_challenge, created_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10, $11
		)
		ON CONFLICT (code) DO UPDATE SET
			tenant_id      = EXCLUDED.tenant_id,
			runtime        = EXCLUDED.runtime,
			persona_id     = EXCLUDED.persona_id,
			pool_id        = EXCLUDED.pool_id,
			client_id      = EXCLUDED.client_id,
			redirect_uri   = EXCLUDED.redirect_uri,
			state          = EXCLUDED.state,
			scope          = EXCLUDED.scope,
			code_challenge = EXCLUDED.code_challenge,
			created_at     = EXCLUDED.created_at
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		ac.Code, ac.TenantID, ac.Runtime, ac.PersonaID, nullable(ac.PoolID),
		ac.ClientID, nullable(ac.RedirectURI), nullable(ac.State), nullable(ac.Scope),
		nullable(ac.CodeChallenge), ac.CreatedAt.UTC(),
	); err != nil {
		return fmt.Errorf("pgstorage put_auth_code: %w", err)
	}
	return nil
}

// ConsumeAuthCode reads *and removes* the code in a single statement (DELETE …
// RETURNING). Authorization codes are one-shot by OAuth convention — once
// consumed, replay attempts must fail with ErrNotFound.
func (s *PGStorage) ConsumeAuthCode(code string) (AuthCode, error) {
	const q = `
		DELETE FROM auth_codes
		 WHERE code = $1
		RETURNING code, tenant_id, runtime, persona_id, pool_id,
		          client_id, redirect_uri, state, scope, code_challenge, created_at
	`
	var (
		ac                                        AuthCode
		poolID, redirectURI, state, sc, challenge *string
	)
	err := s.pool.QueryRow(bgCtx(), q, code).Scan(
		&ac.Code, &ac.TenantID, &ac.Runtime, &ac.PersonaID, &poolID,
		&ac.ClientID, &redirectURI, &state, &sc, &challenge, &ac.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthCode{}, ErrNotFound
	}
	if err != nil {
		return AuthCode{}, fmt.Errorf("pgstorage consume_auth_code: %w", err)
	}
	ac.PoolID = derefString(poolID)
	ac.RedirectURI = derefString(redirectURI)
	ac.State = derefString(state)
	ac.Scope = derefString(sc)
	ac.CodeChallenge = derefString(challenge)
	ac.CreatedAt = ac.CreatedAt.UTC()
	return ac, nil
}

// -----------------------------------------------------------------------------
// Token records
// -----------------------------------------------------------------------------

// PutToken stores an issued token record (upsert, mirroring MemStorage). The
// upsert writes rotated_at too, so re-Putting a record with RotatedAt stamped
// is how the refresh grant marks the old refresh token as rotated out.
func (s *PGStorage) PutToken(t TokenRecord) error {
	const q = `
		INSERT INTO tokens (
			access_token, refresh_token, install_id, persona_id, identity_id,
			subject, scope, tenant_id, expires_at, rotated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10
		)
		ON CONFLICT (access_token) DO UPDATE SET
			refresh_token = EXCLUDED.refresh_token,
			install_id    = EXCLUDED.install_id,
			persona_id    = EXCLUDED.persona_id,
			identity_id   = EXCLUDED.identity_id,
			subject       = EXCLUDED.subject,
			scope         = EXCLUDED.scope,
			tenant_id     = EXCLUDED.tenant_id,
			expires_at    = EXCLUDED.expires_at,
			rotated_at    = EXCLUDED.rotated_at
	`
	var rotatedAt any
	if t.RotatedAt != nil {
		rotatedAt = t.RotatedAt.UTC()
	}
	if _, err := s.pool.Exec(bgCtx(), q,
		t.AccessToken, nullable(t.RefreshToken), t.InstallID,
		nullable(t.PersonaID), nullable(t.IdentityID),
		nullable(t.Subject), nullable(t.Scope), t.TenantID, t.ExpiresAt.UTC(),
		rotatedAt,
	); err != nil {
		return fmt.Errorf("pgstorage put_token: %w", err)
	}
	return nil
}

// tokenColumns is the SELECT list scanToken expects, shared by GetToken and
// GetTokenByRefresh so the two lookups cannot drift.
const tokenColumns = `access_token, refresh_token, install_id, persona_id, identity_id,
	       subject, scope, tenant_id, expires_at, rotated_at`

// GetToken reads by access token.
func (s *PGStorage) GetToken(accessToken string) (TokenRecord, error) {
	q := `SELECT ` + tokenColumns + ` FROM tokens WHERE access_token = $1`
	t, err := scanToken(s.pool.QueryRow(bgCtx(), q, accessToken))
	if errors.Is(err, pgx.ErrNoRows) {
		return TokenRecord{}, ErrNotFound
	}
	if err != nil {
		return TokenRecord{}, fmt.Errorf("pgstorage get_token: %w", err)
	}
	return t, nil
}

// GetTokenByRefresh reads by refresh token (the refresh-grant lookup; served by
// idx_tokens_refresh from migration 000003). Refresh tokens are fresh UUIDs, so
// at most one row matches.
func (s *PGStorage) GetTokenByRefresh(refreshToken string) (TokenRecord, error) {
	if refreshToken == "" {
		// refresh_token is nullable; an empty presented token must never match.
		return TokenRecord{}, ErrNotFound
	}
	q := `SELECT ` + tokenColumns + ` FROM tokens WHERE refresh_token = $1`
	t, err := scanToken(s.pool.QueryRow(bgCtx(), q, refreshToken))
	if errors.Is(err, pgx.ErrNoRows) {
		return TokenRecord{}, ErrNotFound
	}
	if err != nil {
		return TokenRecord{}, fmt.Errorf("pgstorage get_token_by_refresh: %w", err)
	}
	return t, nil
}

// DeleteToken removes a token (used by /revoke). Returns ErrNotFound when the
// token does not exist, mirroring MemStorage.
func (s *PGStorage) DeleteToken(accessToken string) error {
	tag, err := s.pool.Exec(bgCtx(), `DELETE FROM tokens WHERE access_token = $1`, accessToken)
	if err != nil {
		return fmt.Errorf("pgstorage delete_token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteTokensForInstall removes every token record bound to installID and
// returns the number removed (idx_tokens_install serves the scan). Used by the
// refresh-grant replay revocation; zero rows is not an error — idempotent.
func (s *PGStorage) DeleteTokensForInstall(installID string) (int, error) {
	tag, err := s.pool.Exec(bgCtx(), `DELETE FROM tokens WHERE install_id = $1`, installID)
	if err != nil {
		return 0, fmt.Errorf("pgstorage delete_tokens_for_install: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// -----------------------------------------------------------------------------
// Maintenance
// -----------------------------------------------------------------------------

// PurgeExpired deletes expired token and auth-code rows, returning the total
// rows removed. The predicates mirror read-time enforcement exactly:
//   - tokens have a stored expiry (tokens.expires_at); /userinfo rejects a
//     bearer when now is after ExpiresAt, so `expires_at < now` rows are dead;
//   - auth_codes have no stored expiry — /token rejects a code when
//     time.Since(created_at) exceeds AuthCodeTTLSeconds, so the equivalent
//     delete predicate is `created_at < now - AuthCodeTTLSeconds`.
//
// Rotated rows (rotated_at IS NOT NULL) need no extra predicate: rotation keeps
// the row's original expires_at (the access-token expiry), so the expires_at
// sweep already removes them once their access token dies — they cannot survive
// indefinitely. Until then they must stay: the rotated marker powers
// refresh-replay detection.
func (s *PGStorage) PurgeExpired(now time.Time) (int, error) {
	total := 0
	tag, err := s.pool.Exec(bgCtx(),
		`DELETE FROM tokens WHERE expires_at < $1`, now.UTC())
	if err != nil {
		return total, fmt.Errorf("pgstorage purge_expired tokens: %w", err)
	}
	total += int(tag.RowsAffected())

	codeCutoff := now.UTC().Add(-time.Duration(AuthCodeTTLSeconds) * time.Second)
	tag, err = s.pool.Exec(bgCtx(),
		`DELETE FROM auth_codes WHERE created_at < $1`, codeCutoff)
	if err != nil {
		return total, fmt.Errorf("pgstorage purge_expired auth_codes: %w", err)
	}
	total += int(tag.RowsAffected())
	return total, nil
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// rowScanner is satisfied by both pgx.Row and pgx.Rows for shared scanning.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanInstall(r rowScanner) (Install, error) {
	var (
		i          Install
		identityID *string
	)
	if err := r.Scan(
		&i.ID, &i.TenantID, &i.Runtime, &i.PersonaID, &identityID,
		&i.ClientID, &i.Status, &i.CreatedAt, &i.UpdatedAt,
	); err != nil {
		return Install{}, err
	}
	i.IdentityID = derefString(identityID)
	i.CreatedAt = i.CreatedAt.UTC()
	i.UpdatedAt = i.UpdatedAt.UTC()
	return i, nil
}

// scanToken scans one tokens row (column order: tokenColumns) into a TokenRecord,
// normalising NULLs to "" / nil and timestamps to UTC.
func scanToken(r rowScanner) (TokenRecord, error) {
	var (
		t                                           TokenRecord
		refresh, personaID, identityID, subj, scope *string
		rotatedAt                                   *time.Time
	)
	if err := r.Scan(
		&t.AccessToken, &refresh, &t.InstallID, &personaID, &identityID,
		&subj, &scope, &t.TenantID, &t.ExpiresAt, &rotatedAt,
	); err != nil {
		return TokenRecord{}, err
	}
	t.RefreshToken = derefString(refresh)
	t.PersonaID = derefString(personaID)
	t.IdentityID = derefString(identityID)
	t.Subject = derefString(subj)
	t.Scope = derefString(scope)
	t.ExpiresAt = t.ExpiresAt.UTC()
	if rotatedAt != nil {
		utc := rotatedAt.UTC()
		t.RotatedAt = &utc
	}
	return t, nil
}

// encodeClientMetadata marshals the free-form RFC 7591 metadata object for the
// JSONB column. A nil map is stored as SQL NULL so it round-trips as nil.
func encodeClientMetadata(m map[string]any) (any, error) {
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

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
