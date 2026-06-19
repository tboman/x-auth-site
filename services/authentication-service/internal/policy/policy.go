// Package policy compiles and evaluates tenant-authored boolean expressions
// over an auth-journey context. It is the gate mechanism for the flow engine:
// stage-bound policies decide whether a stage runs, flow-bound policies decide
// whether a flow is selected. Risk signals (filled by a prior risk-evaluation
// stage) are first-class inputs — that is the differentiation over a fixed
// pipeline.
//
// Expressions are written in expr-lang (https://expr-lang.org), which is
// sandboxed (no I/O, no host calls) by construction. Each program is compiled
// once and evaluated under a hard deadline so a pathological expression cannot
// stall an /authorize request.
package policy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// maxExprLen caps source length so a binding can't ship a megabyte of source.
const maxExprLen = 2000

// evalTimeout bounds a single evaluation. Expressions are tiny; this is a
// backstop against an author writing an accidental tight loop (e.g. a huge range).
const evalTimeout = 50 * time.Millisecond

// ErrNotBool is returned when an expression evaluates to a non-boolean value.
var ErrNotBool = errors.New("policy expression did not evaluate to a bool")

// Env is the evaluation context exposed to expressions. A map (rather than a
// struct) keeps expression keys lowercase and idiomatic — risk.tier,
// request.client_id — and lets a missing nested key read as nil rather than a
// compile error, so policies degrade to false instead of breaking auth.
//
// Callers MUST populate every top-level key (see Keys) before Evaluate; the
// risk-evaluation stage fills risk.*.
type Env map[string]any

// Keys are the top-level names every Env carries. Documented for the admin UI
// and used to build the sample env handed to the compiler.
var Keys = []string{"user", "request", "risk", "protection", "time"}

// sampleEnv is the shape passed to the compiler so it can type-check top-level
// access. Field access on a map[string]any is dynamic, so this mainly fixes the
// set of root names; nested typos surface as nil at eval (→ false), never panics.
func sampleEnv() map[string]any {
	return map[string]any{
		"ctx":  context.Background(),
		"user": map[string]any{"id": ""},
		"request": map[string]any{
			"client_id": "", "ip": "",
			"geo": map[string]any{"country": ""},
		},
		"risk": map[string]any{
			"score": 0.0, "tier": "", "impossible_travel": false,
			"flags":  []string{},
			"device": 0.0, "behavior": 0.0, "network": 0.0, "user": 0.0,
		},
		"protection": map[string]any{"achieved_rank": 0, "requested_rank": 0},
		"time":       map[string]any{"hour": 0, "weekday": 0},
	}
}

// Program is a compiled, reusable policy expression.
type Program struct {
	src  string
	prog *vm.Program
}

// Source returns the original expression text (for admin display / audit).
func (p *Program) Source() string { return p.src }

// Compile parses and type-checks an expression, returning a reusable Program.
// The expression must yield a bool. Compilation is the lockout-prevention gate:
// the admin UI compiles every bound expression before a flow can be saved.
func Compile(code string) (*Program, error) {
	if l := len(code); l > maxExprLen {
		return nil, fmt.Errorf("policy expression too long (%d > %d bytes)", l, maxExprLen)
	}
	prog, err := expr.Compile(code,
		expr.Env(sampleEnv()),
		expr.AsBool(),
		expr.WithContext("ctx"), // VM checks ctx for cancellation between ops
	)
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	return &Program{src: code, prog: prog}, nil
}

// Evaluate runs the program against env under a bounded deadline. A runtime
// error, a deadline hit, or a non-bool result is returned as an error — the
// caller (the executor) decides fail-open vs fail-closed per binding semantics.
func (p *Program) Evaluate(ctx context.Context, env Env) (bool, error) {
	if env == nil {
		env = Env{}
	}
	cctx, cancel := context.WithTimeout(ctx, evalTimeout)
	defer cancel()
	env["ctx"] = cctx

	out, err := expr.Run(p.prog, map[string]any(env))
	if err != nil {
		return false, fmt.Errorf("evaluate policy: %w", err)
	}
	b, ok := out.(bool)
	if !ok {
		return false, fmt.Errorf("%w: got %T", ErrNotBool, out)
	}
	return b, nil
}
