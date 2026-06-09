package internal

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newPGStorage connects to the DSN in RISK_PG_DSN and returns a clean PGStorage.
// The test is skipped when the env var is unset so unit-test CI without a DB
// (and routine `go test ./...` runs on developer laptops) stays green. When it
// IS set, the test truncates both tables so it's safe to re-run.
//
// Recommended local setup:
//
//	docker run --rm -d --name xauth-pg -e POSTGRES_PASSWORD=postgres \
//	  -e POSTGRES_DB=risk_db -p 5432:5432 postgres:16
//	# then apply services/risk-service/migrations/000001_init.up.sql
//	RISK_PG_DSN="postgres://postgres:postgres@localhost:5432/risk_db?sslmode=disable" \
//	  go test ./services/risk-service/internal/ -run PG
func newPGStorage(t *testing.T) *PGStorage {
	t.Helper()
	dsn := os.Getenv("RISK_PG_DSN")
	if dsn == "" {
		t.Skip("RISK_PG_DSN not set; skipping PGStorage integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("pool.Ping: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE risk_evaluations, risk_policies"); err != nil {
		pool.Close()
		t.Fatalf("truncate: %v (is the migration applied?)", err)
	}
	t.Cleanup(func() { pool.Close() })
	return NewPGStorage(pool)
}

func TestPGStorageEvaluationRoundTrip(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := EvaluationIDPrefix + uuid.NewString()
	eval := RiskEvaluation{
		ID:                  id,
		TenantID:            "tenant-a",
		UserID:              "usr_1",
		SessionID:           "ses_1",
		Action:              "transfer.initiate",
		Resource:            "payments",
		ResourceSensitivity: SensitivityHigh,
		Tier:                TierHigh,
		Score:               0.85,
		Signals: SignalsBreakdown{
			Device:   ScorerResult{Score: 0.5, Flags: []string{"unknown_device"}},
			Behavior: ScorerResult{Score: 0.1, Flags: []string{}},
			Network:  ScorerResult{Score: 0.8, Flags: []string{"flagged_ip", "vpn_detected"}},
			User:     ScorerResult{Score: 0.5, Flags: []string{"first_high_value_action"}},
		},
		Flags:           []string{"unknown_device", "flagged_ip", "vpn_detected", "first_high_value_action"},
		PolicyDecision:  DecisionAllow,
		MatchedPolicies: []string{"pol_x"},
		CreatedAt:       now,
	}
	if err := s.PutEvaluation(eval); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.GetEvaluation("tenant-a", id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.UserID != "usr_1" || got.Tier != TierHigh || got.Score != 0.85 {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if got.Signals.Network.Score != 0.8 || len(got.Signals.Network.Flags) != 2 {
		t.Fatalf("signals lost: %+v", got.Signals)
	}
	if len(got.Flags) != 4 || got.Flags[0] != "unknown_device" {
		t.Fatalf("flags lost: %+v", got.Flags)
	}
	if len(got.MatchedPolicies) != 1 || got.MatchedPolicies[0] != "pol_x" {
		t.Fatalf("matched_policies lost: %+v", got.MatchedPolicies)
	}
	if !got.CreatedAt.Equal(now) {
		t.Fatalf("created_at mismatch: got %v want %v", got.CreatedAt, now)
	}

	// Tenant isolation: other tenant can't see it.
	if _, err := s.GetEvaluation("tenant-b", id); err != ErrNotFound {
		t.Fatalf("cross-tenant get should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageUserHasPriorEvaluation(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if s.UserHasPriorEvaluation("tenant-a", "usr_prior") {
		t.Fatal("empty table should report no prior evaluation")
	}
	if err := s.PutEvaluation(RiskEvaluation{
		ID: EvaluationIDPrefix + uuid.NewString(), TenantID: "tenant-a",
		UserID: "usr_prior", Action: "read.profile",
		ResourceSensitivity: SensitivityLow, Tier: TierLow, Score: 0.2,
		PolicyDecision: DecisionAllow, CreatedAt: now,
	}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if !s.UserHasPriorEvaluation("tenant-a", "usr_prior") {
		t.Fatal("expected prior evaluation for (tenant-a, usr_prior)")
	}
	// Tenant isolation: same user id under another tenant has no history.
	if s.UserHasPriorEvaluation("tenant-b", "usr_prior") {
		t.Fatal("cross-tenant prior evaluation must not leak")
	}
}

func TestPGStoragePolicyCRUD(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := PolicyIDPrefix + uuid.NewString()
	p := Policy{
		ID:       id,
		TenantID: "tenant-a",
		Name:     "high-value-transfers",
		Rules: []PolicyRule{
			{
				Condition: PolicyCondition{Field: "action", Op: "contains", Value: "transfer."},
				Action:    PolicyAction{TierFloor: TierHigh},
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if _, err := s.CreatePolicy(p); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetPolicy("tenant-a", id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "high-value-transfers" || len(got.Rules) != 1 {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if got.Rules[0].Condition.Field != "action" || got.Rules[0].Action.TierFloor != TierHigh {
		t.Fatalf("rules lost: %+v", got.Rules)
	}

	// Tenant isolation on read.
	if _, err := s.GetPolicy("tenant-b", id); err != ErrNotFound {
		t.Fatalf("cross-tenant get should be ErrNotFound, got %v", err)
	}

	// Delete: cross-tenant is ErrNotFound, same-tenant succeeds, second delete misses.
	if err := s.DeletePolicy("tenant-b", id); err != ErrNotFound {
		t.Fatalf("cross-tenant delete should be ErrNotFound, got %v", err)
	}
	if err := s.DeletePolicy("tenant-a", id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.DeletePolicy("tenant-a", id); err != ErrNotFound {
		t.Fatalf("double delete should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageUpdatePolicyPreservesCreatedAt(t *testing.T) {
	s := newPGStorage(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := PolicyIDPrefix + uuid.NewString()
	base := Policy{
		ID: id, TenantID: "tenant-a", Name: "before",
		Rules:     []PolicyRule{},
		CreatedAt: now, UpdatedAt: now,
	}
	if _, err := s.CreatePolicy(base); err != nil {
		t.Fatalf("create: %v", err)
	}
	updated := base
	updated.Name = "after"
	updated.Rules = []PolicyRule{{
		Condition: PolicyCondition{Field: "context.country", Op: "in", Value: []any{"KP"}},
		Action:    PolicyAction{Deny: true},
	}}
	// Caller may have mutated CreatedAt — the Update contract says it gets
	// restored from the persisted row, and UpdatedAt is stamped server-side.
	updated.CreatedAt = now.Add(time.Hour)
	out, err := s.UpdatePolicy(updated)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !out.CreatedAt.Equal(now) {
		t.Fatalf("update should preserve created_at: got %v want %v", out.CreatedAt, now)
	}
	if !out.UpdatedAt.After(out.CreatedAt) {
		t.Fatalf("updated_at should be stamped after created_at: %+v", out)
	}
	if out.Name != "after" || len(out.Rules) != 1 || !out.Rules[0].Action.Deny {
		t.Fatalf("update not applied: %+v", out)
	}

	// ErrNotFound for wrong tenant.
	wrong := updated
	wrong.TenantID = "tenant-b"
	if _, err := s.UpdatePolicy(wrong); err != ErrNotFound {
		t.Fatalf("cross-tenant update should be ErrNotFound, got %v", err)
	}
}

func TestPGStorageListPoliciesOrder(t *testing.T) {
	s := newPGStorage(t)
	base := time.Now().UTC().Truncate(time.Microsecond)
	want := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		id := PolicyIDPrefix + uuid.NewString()
		want = append(want, id)
		_, err := s.CreatePolicy(Policy{
			ID: id, TenantID: "tenant-a", Name: "p",
			CreatedAt: base.Add(time.Duration(i) * time.Second),
			UpdatedAt: base.Add(time.Duration(i) * time.Second),
		})
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	// A policy under another tenant must not appear in the list.
	if _, err := s.CreatePolicy(Policy{
		ID: PolicyIDPrefix + uuid.NewString(), TenantID: "tenant-b", Name: "other",
		CreatedAt: base, UpdatedAt: base,
	}); err != nil {
		t.Fatalf("seed other tenant: %v", err)
	}

	got, err := s.ListPolicies("tenant-a", 0, time.Time{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 policies, got %d", len(got))
	}
	// Newest first: the list is ordered created_at DESC, id DESC.
	for i, p := range got {
		if exp := want[len(want)-1-i]; p.ID != exp {
			t.Fatalf("order mismatch at %d: got %s want %s", i, p.ID, exp)
		}
	}
}

// TestPGStorageListPoliciesKeyset walks three keyset pages over five rows and
// checks the strictly-older-than-cursor contract end to end.
func TestPGStorageListPoliciesKeyset(t *testing.T) {
	s := newPGStorage(t)
	base := time.Now().UTC().Truncate(time.Microsecond)
	ids := make([]string, 5)
	for i := range ids {
		ids[i] = PolicyIDPrefix + uuid.NewString()
		if _, err := s.CreatePolicy(Policy{
			ID: ids[i], TenantID: "tenant-a", Name: "p",
			CreatedAt: base.Add(time.Duration(i) * time.Second),
			UpdatedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	// Page 1: zero cursor → the two newest rows.
	page1, err := s.ListPolicies("tenant-a", 2, time.Time{})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 2 || page1[0].ID != ids[4] || page1[1].ID != ids[3] {
		t.Fatalf("page1 mismatch: %+v", page1)
	}

	// Page 2: cursor = oldest CreatedAt of page 1 → strictly older rows only.
	page2, err := s.ListPolicies("tenant-a", 2, page1[1].CreatedAt)
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2) != 2 || page2[0].ID != ids[2] || page2[1].ID != ids[1] {
		t.Fatalf("page2 mismatch: %+v", page2)
	}

	// Page 3: one row left.
	page3, err := s.ListPolicies("tenant-a", 2, page2[1].CreatedAt)
	if err != nil {
		t.Fatalf("page3: %v", err)
	}
	if len(page3) != 1 || page3[0].ID != ids[0] {
		t.Fatalf("page3 mismatch: %+v", page3)
	}
}
