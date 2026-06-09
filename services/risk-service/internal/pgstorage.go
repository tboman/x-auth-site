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
// The nested shapes (SignalsBreakdown, []string flags / matched policies, and
// the policy rule list) live in JSONB columns so the relational schema stays
// aligned with ARCHITECTURE.md §6.2 while round-tripping the in-memory contract.
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
// evaluations
// -----------------------------------------------------------------------------

// PutEvaluation inserts the evaluation row. Evaluations are immutable once
// stored, so this is insert-only — no upsert.
func (s *PGStorage) PutEvaluation(e RiskEvaluation) error {
	signals, err := json.Marshal(e.Signals)
	if err != nil {
		return fmt.Errorf("pgstorage put_evaluation marshal signals: %w", err)
	}
	flags, err := marshalStrings(e.Flags)
	if err != nil {
		return fmt.Errorf("pgstorage put_evaluation marshal flags: %w", err)
	}
	matched, err := marshalStrings(e.MatchedPolicies)
	if err != nil {
		return fmt.Errorf("pgstorage put_evaluation marshal matched_policies: %w", err)
	}
	const q = `
		INSERT INTO risk_evaluations (
			id, tenant_id, user_id, session_id, action,
			resource, resource_sensitivity, tier, score, signals,
			flags, policy_decision, matched_policies, created_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14
		)
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		e.ID, e.TenantID, e.UserID, nullable(e.SessionID), e.Action,
		nullable(e.Resource), e.ResourceSensitivity, e.Tier, e.Score, signals,
		flags, e.PolicyDecision, matched, e.CreatedAt.UTC(),
	); err != nil {
		return fmt.Errorf("pgstorage put_evaluation: %w", err)
	}
	return nil
}

// GetEvaluation returns the evaluation if it exists and belongs to tenantID.
func (s *PGStorage) GetEvaluation(tenantID, id string) (RiskEvaluation, error) {
	const q = `
		SELECT id, tenant_id, user_id, session_id, action,
		       resource, resource_sensitivity, tier, score, signals,
		       flags, policy_decision, matched_policies, created_at
		  FROM risk_evaluations
		 WHERE id = $1 AND tenant_id = $2
	`
	row := s.pool.QueryRow(bgCtx(), q, id, tenantID)
	e, err := scanEvaluation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return RiskEvaluation{}, ErrNotFound
	}
	return e, err
}

// UserHasPriorEvaluation reports whether any evaluation exists for
// (tenantID, userID). The interface has no error return; a query failure
// degrades to false, which makes the user scorer treat the action as a first
// high-value action — the conservative (higher-risk) direction.
func (s *PGStorage) UserHasPriorEvaluation(tenantID, userID string) bool {
	const q = `
		SELECT EXISTS (
			SELECT 1 FROM risk_evaluations
			 WHERE tenant_id = $1 AND user_id = $2
		)
	`
	var exists bool
	if err := s.pool.QueryRow(bgCtx(), q, tenantID, userID).Scan(&exists); err != nil {
		return false
	}
	return exists
}

// -----------------------------------------------------------------------------
// policies
// -----------------------------------------------------------------------------

// CreatePolicy inserts the policy row.
func (s *PGStorage) CreatePolicy(p Policy) (Policy, error) {
	rules, err := marshalRules(p.Rules)
	if err != nil {
		return Policy{}, fmt.Errorf("pgstorage create_policy marshal rules: %w", err)
	}
	const q = `
		INSERT INTO risk_policies (id, tenant_id, name, rules, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		p.ID, p.TenantID, p.Name, rules, p.CreatedAt.UTC(), p.UpdatedAt.UTC(),
	); err != nil {
		return Policy{}, fmt.Errorf("pgstorage create_policy: %w", err)
	}
	return p, nil
}

// GetPolicy returns the policy if it exists and belongs to tenantID.
func (s *PGStorage) GetPolicy(tenantID, id string) (Policy, error) {
	const q = `
		SELECT id, tenant_id, name, rules, created_at, updated_at
		  FROM risk_policies
		 WHERE id = $1 AND tenant_id = $2
	`
	row := s.pool.QueryRow(bgCtx(), q, id, tenantID)
	p, err := scanPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	return p, err
}

// ListPolicies returns up to `limit` policies belonging to tenantID, ordered
// created_at DESC, id DESC — same keyset contract as MemStorage.ListPolicies.
// A non-zero cursor returns only rows strictly older than it; limit <= 0
// disables the cap (the evaluation overlay loads every tenant policy this way).
// The existing idx_policy_tenant_created (tenant_id, created_at, id) btree
// serves this via a backward index scan — no DESC index needed.
func (s *PGStorage) ListPolicies(tenantID string, limit int, cursor time.Time) ([]Policy, error) {
	base := `
		SELECT id, tenant_id, name, rules, created_at, updated_at
		  FROM risk_policies
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
		return nil, fmt.Errorf("pgstorage list_policies: %w", err)
	}
	defer rows.Close()

	out := make([]Policy, 0)
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list_policies iter: %w", err)
	}
	return out, nil
}

// UpdatePolicy replaces the mutable columns (name, rules). CreatedAt is
// preserved from the existing row and UpdatedAt is stamped server-side — same
// contract as MemStorage.UpdatePolicy. Returns ErrNotFound if no row matches
// both id and tenant_id.
func (s *PGStorage) UpdatePolicy(p Policy) (Policy, error) {
	rules, err := marshalRules(p.Rules)
	if err != nil {
		return Policy{}, fmt.Errorf("pgstorage update_policy marshal rules: %w", err)
	}
	const q = `
		UPDATE risk_policies SET
			name       = $3,
			rules      = $4,
			updated_at = now()
		WHERE id = $1 AND tenant_id = $2
		RETURNING created_at, updated_at
	`
	var createdAt, updatedAt time.Time
	err = s.pool.QueryRow(bgCtx(), q, p.ID, p.TenantID, p.Name, rules).
		Scan(&createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("pgstorage update_policy: %w", err)
	}
	p.CreatedAt = createdAt.UTC()
	p.UpdatedAt = updatedAt.UTC()
	return p, nil
}

// DeletePolicy removes the policy if it exists in tenantID.
func (s *PGStorage) DeletePolicy(tenantID, id string) error {
	const q = `DELETE FROM risk_policies WHERE id = $1 AND tenant_id = $2`
	tag, err := s.pool.Exec(bgCtx(), q, id, tenantID)
	if err != nil {
		return fmt.Errorf("pgstorage delete_policy: %w", err)
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

func scanEvaluation(r rowScanner) (RiskEvaluation, error) {
	var (
		e                   RiskEvaluation
		sessionID, resource *string
		signals, flags      []byte
		matched             []byte
	)
	if err := r.Scan(
		&e.ID, &e.TenantID, &e.UserID, &sessionID, &e.Action,
		&resource, &e.ResourceSensitivity, &e.Tier, &e.Score, &signals,
		&flags, &e.PolicyDecision, &matched, &e.CreatedAt,
	); err != nil {
		return RiskEvaluation{}, err
	}
	e.SessionID = derefString(sessionID)
	e.Resource = derefString(resource)
	if len(signals) > 0 {
		if err := json.Unmarshal(signals, &e.Signals); err != nil {
			return RiskEvaluation{}, fmt.Errorf("pgstorage decode signals: %w", err)
		}
	}
	if len(flags) > 0 {
		if err := json.Unmarshal(flags, &e.Flags); err != nil {
			return RiskEvaluation{}, fmt.Errorf("pgstorage decode flags: %w", err)
		}
	}
	if len(matched) > 0 {
		if err := json.Unmarshal(matched, &e.MatchedPolicies); err != nil {
			return RiskEvaluation{}, fmt.Errorf("pgstorage decode matched_policies: %w", err)
		}
	}
	e.CreatedAt = e.CreatedAt.UTC()
	return e, nil
}

func scanPolicy(r rowScanner) (Policy, error) {
	var (
		p     Policy
		rules []byte
	)
	if err := r.Scan(
		&p.ID, &p.TenantID, &p.Name, &rules, &p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return Policy{}, err
	}
	if len(rules) > 0 {
		if err := json.Unmarshal(rules, &p.Rules); err != nil {
			return Policy{}, fmt.Errorf("pgstorage decode rules: %w", err)
		}
	}
	p.CreatedAt = p.CreatedAt.UTC()
	p.UpdatedAt = p.UpdatedAt.UTC()
	return p, nil
}

// marshalStrings encodes a []string as a JSONB array, mapping nil to '[]' so
// the NOT NULL DEFAULT '[]' columns never hold JSON null.
func marshalStrings(ss []string) ([]byte, error) {
	if ss == nil {
		ss = []string{}
	}
	return json.Marshal(ss)
}

// marshalRules is the same nil-to-empty-array mapping for the policy rule list.
func marshalRules(rules []PolicyRule) ([]byte, error) {
	if rules == nil {
		rules = []PolicyRule{}
	}
	return json.Marshal(rules)
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
