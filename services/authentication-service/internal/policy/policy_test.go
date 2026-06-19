package policy

import (
	"context"
	"strings"
	"testing"
)

func mustCompile(t *testing.T, code string) *Program {
	t.Helper()
	p, err := Compile(code)
	if err != nil {
		t.Fatalf("compile %q: %v", code, err)
	}
	return p
}

func TestNonBoolIsRejected(t *testing.T) {
	// With a dynamic map env the type checker can't prove the result type at
	// compile, so a non-bool expression is caught at evaluation instead.
	p, err := Compile(`risk.score + 1`)
	if err != nil {
		return // compile-time rejection is also acceptable
	}
	if _, err := p.Evaluate(context.Background(), Env{"risk": map[string]any{"score": 0.5}}); err == nil {
		t.Fatal("expected non-bool result to be rejected at evaluate")
	}
}

func TestCompileRejectsSyntaxError(t *testing.T) {
	if _, err := Compile(`risk.tier ===`); err == nil {
		t.Fatal("expected syntax error to fail compile")
	}
}

func TestCompileRejectsOverlong(t *testing.T) {
	if _, err := Compile(strings.Repeat("true || ", 400) + "true"); err == nil {
		t.Fatal("expected overlong expression to be rejected")
	}
}

func TestEvaluateRiskTier(t *testing.T) {
	p := mustCompile(t, `risk.tier == "low" && protection.achieved_rank >= protection.requested_rank`)

	got, err := p.Evaluate(context.Background(), Env{
		"risk":       map[string]any{"tier": "low"},
		"protection": map[string]any{"achieved_rank": 3, "requested_rank": 2},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !got {
		t.Fatal("low risk + satisfied protection should be true")
	}

	got, err = p.Evaluate(context.Background(), Env{
		"risk":       map[string]any{"tier": "high"},
		"protection": map[string]any{"achieved_rank": 3, "requested_rank": 2},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got {
		t.Fatal("high risk should be false")
	}
}

func TestEvaluateMissingKeyIsFalseNotError(t *testing.T) {
	// risk.* absent entirely — nested access reads nil, comparison is false,
	// and the policy degrades safely rather than erroring out auth.
	p := mustCompile(t, `risk.impossible_travel == true`)
	got, err := p.Evaluate(context.Background(), Env{"risk": map[string]any{}})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got {
		t.Fatal("missing impossible_travel should be false")
	}
}

func TestEvaluateFlagsMembership(t *testing.T) {
	p := mustCompile(t, `"tor_exit" in risk.flags`)
	got, err := p.Evaluate(context.Background(), Env{
		"risk": map[string]any{"flags": []string{"tor_exit", "new_device"}},
	})
	if err != nil || !got {
		t.Fatalf("membership: got=%v err=%v", got, err)
	}
}

func TestEvaluateClientAndScore(t *testing.T) {
	p := mustCompile(t, `risk.score >= 0.7 && request.client_id == "checkout"`)
	got, err := p.Evaluate(context.Background(), Env{
		"risk":    map[string]any{"score": 0.82},
		"request": map[string]any{"client_id": "checkout"},
	})
	if err != nil || !got {
		t.Fatalf("score+client: got=%v err=%v", got, err)
	}
}

func TestEvaluateInterruptsRunawayLoop(t *testing.T) {
	// The 50ms deadline (via WithContext) is a backstop against an author
	// shipping an accidental tight loop. A reduce over a large range is force-
	// iterated and must be cut off rather than blocking /authorize indefinitely.
	p := mustCompile(t, `reduce(1..50000000, #acc + #, 0) > 0`)
	if _, err := p.Evaluate(context.Background(), Env{}); err == nil {
		t.Fatal("expected runaway loop to be interrupted by the deadline")
	}
}
