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
// History (the []HistoryEntry audit trail) is stored in the `metadata` JSONB column
// under the "history" key. That keeps the schema aligned with ARCHITECTURE.md §6.2
// (a single metadata JSONB) while still round-tripping the in-memory contract.
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

// Create inserts the transaction row.
func (s *PGStorage) Create(t Transaction) (Transaction, error) {
	meta, err := encodeMetadata(t)
	if err != nil {
		return Transaction{}, err
	}
	const q = `
		INSERT INTO transactions (
			id, tenant_id, user_id, session_id, risk_evaluation_id,
			risk_tier, risk_score, action, resource, resource_sensitivity,
			decision, step_up_used, step_up_method, challenge_id, policy_id,
			reason, metadata, created_at, decided_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15,
			$16, $17, $18, $19
		)
	`
	if _, err := s.pool.Exec(bgCtx(), q,
		t.ID, t.TenantID, t.UserID,
		nullable(t.SessionID), nullable(t.RiskEvaluationID),
		nullable(t.RiskTier), nullableFloat(t.RiskScore),
		t.Action, nullable(t.Resource), nullable(t.ResourceSensitivity),
		t.Decision, t.StepUpUsed, nullable(t.StepUpMethod),
		nullable(t.ChallengeID), nullable(t.PolicyID), nullable(t.Reason),
		meta, t.CreatedAt.UTC(), nullableTime(t.DecidedAt),
	); err != nil {
		return Transaction{}, fmt.Errorf("pgstorage create: %w", err)
	}
	return t, nil
}

// Update replaces the mutable columns. CreatedAt is preserved from the existing row
// (same contract as MemStorage.Update). Returns ErrNotFound if no row matches both
// id and tenant_id.
func (s *PGStorage) Update(t Transaction) (Transaction, error) {
	meta, err := encodeMetadata(t)
	if err != nil {
		return Transaction{}, err
	}
	const q = `
		UPDATE transactions SET
			user_id              = $3,
			session_id           = $4,
			risk_evaluation_id   = $5,
			risk_tier            = $6,
			risk_score           = $7,
			action               = $8,
			resource             = $9,
			resource_sensitivity = $10,
			decision             = $11,
			step_up_used         = $12,
			step_up_method       = $13,
			challenge_id         = $14,
			policy_id            = $15,
			reason               = $16,
			metadata             = $17,
			decided_at           = $18
		WHERE id = $1 AND tenant_id = $2
		RETURNING created_at
	`
	var createdAt time.Time
	err = s.pool.QueryRow(bgCtx(), q,
		t.ID, t.TenantID,
		t.UserID, nullable(t.SessionID), nullable(t.RiskEvaluationID),
		nullable(t.RiskTier), nullableFloat(t.RiskScore),
		t.Action, nullable(t.Resource), nullable(t.ResourceSensitivity),
		t.Decision, t.StepUpUsed, nullable(t.StepUpMethod),
		nullable(t.ChallengeID), nullable(t.PolicyID), nullable(t.Reason),
		meta, nullableTime(t.DecidedAt),
	).Scan(&createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Transaction{}, ErrNotFound
	}
	if err != nil {
		return Transaction{}, fmt.Errorf("pgstorage update: %w", err)
	}
	t.CreatedAt = createdAt.UTC()
	return t, nil
}

// Get returns the transaction if it exists and belongs to tenantID.
func (s *PGStorage) Get(tenantID, id string) (Transaction, error) {
	const q = `
		SELECT id, tenant_id, user_id, session_id, risk_evaluation_id,
		       risk_tier, risk_score, action, resource, resource_sensitivity,
		       decision, step_up_used, step_up_method, challenge_id, policy_id,
		       reason, metadata, created_at, decided_at
		  FROM transactions
		 WHERE id = $1 AND tenant_id = $2
	`
	row := s.pool.QueryRow(bgCtx(), q, id, tenantID)
	t, err := scanTransaction(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Transaction{}, ErrNotFound
	}
	return t, err
}

// List returns up to `limit` transactions for tenantID, ordered by created_at DESC,
// id DESC. If cursor is non-zero, only rows strictly older than the cursor are
// returned — same keyset-pagination contract as MemStorage.
func (s *PGStorage) List(tenantID string, limit int, cursor time.Time) ([]Transaction, error) {
	base := `
		SELECT id, tenant_id, user_id, session_id, risk_evaluation_id,
		       risk_tier, risk_score, action, resource, resource_sensitivity,
		       decision, step_up_used, step_up_method, challenge_id, policy_id,
		       reason, metadata, created_at, decided_at
		  FROM transactions
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
		return nil, fmt.Errorf("pgstorage list: %w", err)
	}
	defer rows.Close()

	out := make([]Transaction, 0)
	for rows.Next() {
		t, err := scanTransaction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstorage list iter: %w", err)
	}
	return out, nil
}

// AppendHistory atomically appends to metadata->'history'. Returns ErrNotFound if
// the (tenant, id) pair doesn't match.
func (s *PGStorage) AppendHistory(tenantID, id string, entry HistoryEntry) error {
	raw, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("pgstorage append_history marshal: %w", err)
	}
	const q = `
		UPDATE transactions
		   SET metadata = jsonb_set(
		           coalesce(metadata, '{}'::jsonb),
		           '{history}',
		           coalesce(metadata->'history', '[]'::jsonb) || $3::jsonb,
		           true
		       )
		 WHERE id = $1 AND tenant_id = $2
	`
	tag, err := s.pool.Exec(bgCtx(), q, id, tenantID, string(raw))
	if err != nil {
		return fmt.Errorf("pgstorage append_history: %w", err)
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

func scanTransaction(r rowScanner) (Transaction, error) {
	var (
		t Transaction
		sessionID, riskEvalID, riskTier, resource, sensitivity,
		stepUpMethod, challengeID, policyID, reason *string
		riskScore *float64
		metadata  []byte
		decidedAt *time.Time
	)
	if err := r.Scan(
		&t.ID, &t.TenantID, &t.UserID, &sessionID, &riskEvalID,
		&riskTier, &riskScore, &t.Action, &resource, &sensitivity,
		&t.Decision, &t.StepUpUsed, &stepUpMethod, &challengeID, &policyID,
		&reason, &metadata, &t.CreatedAt, &decidedAt,
	); err != nil {
		return Transaction{}, err
	}
	t.SessionID = derefString(sessionID)
	t.RiskEvaluationID = derefString(riskEvalID)
	t.RiskTier = derefString(riskTier)
	if riskScore != nil {
		t.RiskScore = *riskScore
	}
	t.Resource = derefString(resource)
	t.ResourceSensitivity = derefString(sensitivity)
	t.StepUpMethod = derefString(stepUpMethod)
	t.ChallengeID = derefString(challengeID)
	t.PolicyID = derefString(policyID)
	t.Reason = derefString(reason)
	if decidedAt != nil {
		d := decidedAt.UTC()
		t.DecidedAt = &d
	}
	if len(metadata) > 0 {
		var meta struct {
			History []HistoryEntry `json:"history"`
		}
		if err := json.Unmarshal(metadata, &meta); err != nil {
			return Transaction{}, fmt.Errorf("pgstorage decode metadata: %w", err)
		}
		t.History = meta.History
	}
	t.CreatedAt = t.CreatedAt.UTC()
	return t, nil
}

func encodeMetadata(t Transaction) ([]byte, error) {
	m := map[string]any{}
	if len(t.History) > 0 {
		m["history"] = t.History
	}
	return json.Marshal(m)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableFloat(f float64) any {
	if f == 0 {
		return nil
	}
	return f
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
