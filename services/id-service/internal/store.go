package internal

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a verification id/token is unknown.
var ErrNotFound = errors.New("verification not found")

// Storage persists verifications. Both implementations are interchangeable; the
// in-memory one keeps the service bootable in local dev / CI without a DB, the
// same pattern as the other services.
type Storage interface {
	Create(ctx context.Context, v *Verification) error
	Get(ctx context.Context, id string) (*Verification, error)
	GetByToken(ctx context.Context, token string) (*Verification, error)
	Update(ctx context.Context, v *Verification) error
	PurgeExpired(ctx context.Context, now time.Time) (int, error)
}

// ----------------------------------------------------------------------------
// In-memory store
// ----------------------------------------------------------------------------

type MemStorage struct {
	mu      sync.RWMutex
	byID    map[string]*Verification
	byToken map[string]string // token -> id
}

func NewMemStorage() *MemStorage {
	return &MemStorage{byID: map[string]*Verification{}, byToken: map[string]string{}}
}

func (m *MemStorage) Create(_ context.Context, v *Verification) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *v
	m.byID[v.ID] = &cp
	m.byToken[v.Token] = v.ID
	return nil
}

func (m *MemStorage) Get(_ context.Context, id string) (*Verification, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *v
	return &cp, nil
}

func (m *MemStorage) GetByToken(_ context.Context, token string) (*Verification, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byToken[token]
	if !ok {
		return nil, ErrNotFound
	}
	v := m.byID[id]
	cp := *v
	return &cp, nil
}

func (m *MemStorage) Update(_ context.Context, v *Verification) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[v.ID]; !ok {
		return ErrNotFound
	}
	cp := *v
	m.byID[v.ID] = &cp
	return nil
}

func (m *MemStorage) PurgeExpired(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, v := range m.byID {
		if v.Status == StatusPending && now.After(v.ExpiresAt) {
			delete(m.byID, id)
			delete(m.byToken, v.Token)
			n++
		}
	}
	return n, nil
}

// ----------------------------------------------------------------------------
// Postgres store (id_db)
// ----------------------------------------------------------------------------

type PGStorage struct {
	pool *pgxpool.Pool
}

func NewPGStorage(pool *pgxpool.Pool) *PGStorage { return &PGStorage{pool: pool} }

func (p *PGStorage) Create(ctx context.Context, v *Verification) error {
	claims, err := json.Marshal(v.Claims)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `
		INSERT INTO verifications
			(id, tenant_id, token, status, purpose, doctype, claims, channel,
			 nonce, client_id, response_uri, verify_url, result,
			 created_at, updated_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULL,$13,$14,$15)
	`, v.ID, v.TenantID, v.Token, v.Status, v.Purpose, v.DocType, claims, v.Channel,
		v.Nonce, v.ClientID, v.ResponseURI, v.VerifyURL,
		v.CreatedAt, v.UpdatedAt, v.ExpiresAt)
	return err
}

const verificationCols = `id, tenant_id, token, status, purpose, doctype, claims, channel,
	nonce, client_id, response_uri, verify_url, result, created_at, updated_at, expires_at`

func (p *PGStorage) scan(row interface {
	Scan(dest ...any) error
}) (*Verification, error) {
	var (
		v         Verification
		claimsRaw []byte
		resultRaw []byte
	)
	err := row.Scan(&v.ID, &v.TenantID, &v.Token, &v.Status, &v.Purpose, &v.DocType,
		&claimsRaw, &v.Channel, &v.Nonce, &v.ClientID, &v.ResponseURI, &v.VerifyURL,
		&resultRaw, &v.CreatedAt, &v.UpdatedAt, &v.ExpiresAt)
	if err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if len(claimsRaw) > 0 {
		_ = json.Unmarshal(claimsRaw, &v.Claims)
	}
	if len(resultRaw) > 0 {
		var res VerificationResult
		if err := json.Unmarshal(resultRaw, &res); err == nil {
			v.Result = &res
		}
	}
	return &v, nil
}

func (p *PGStorage) Get(ctx context.Context, id string) (*Verification, error) {
	return p.scan(p.pool.QueryRow(ctx, `SELECT `+verificationCols+` FROM verifications WHERE id=$1`, id))
}

func (p *PGStorage) GetByToken(ctx context.Context, token string) (*Verification, error) {
	return p.scan(p.pool.QueryRow(ctx, `SELECT `+verificationCols+` FROM verifications WHERE token=$1`, token))
}

func (p *PGStorage) Update(ctx context.Context, v *Verification) error {
	var resultRaw []byte
	if v.Result != nil {
		b, err := json.Marshal(v.Result)
		if err != nil {
			return err
		}
		resultRaw = b
	}
	ct, err := p.pool.Exec(ctx, `
		UPDATE verifications
		SET status=$2, result=$3, updated_at=$4
		WHERE id=$1
	`, v.ID, v.Status, resultRaw, v.UpdatedAt)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PGStorage) PurgeExpired(ctx context.Context, now time.Time) (int, error) {
	ct, err := p.pool.Exec(ctx, `
		DELETE FROM verifications WHERE status=$1 AND expires_at < $2
	`, StatusPending, now)
	if err != nil {
		return 0, err
	}
	return int(ct.RowsAffected()), nil
}
