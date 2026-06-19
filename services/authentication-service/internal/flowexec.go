package internal

// flowexec.go is the flow executor: the small state machine that drives a
// FlowExecution through a flow's stages. It generalizes the step-up interlude's
// storeFlow/peekFlow/dropFlow + AuthorizeVerify loop (otp.go) so that, in later
// phases, risk-evaluation and policy-gated stages can be inserted without
// touching each handler.
//
// Execution state lives in an in-process TTL map keyed by execution id — the
// same model (and the same single-replica caveat) the step-up flows use today.
// Persisting it (Redis/PG) is a later-phase item.

import (
	"net/http"
	"sync"
	"time"
)

// flowExecTTL bounds a parked execution. Matches the step-up flow TTL.
const flowExecTTL = otpFlowTTL

// execStore is the in-process registry of parked flow executions.
type execStore struct {
	mu    sync.Mutex
	execs map[string]*FlowExecution
}

func newExecStore() *execStore { return &execStore{execs: map[string]*FlowExecution{}} }

// put parks an execution, sweeping expired entries first (same as gcLocked in
// otp.go).
func (s *execStore) put(e *FlowExecution) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().UTC().Add(-flowExecTTL)
	for k, v := range s.execs {
		if v.CreatedAt.Before(cutoff) {
			delete(s.execs, k)
		}
	}
	s.execs[e.ID] = e
}

// get returns a live (non-expired) execution by id, or (nil,false).
func (s *execStore) get(id string) (*FlowExecution, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.execs[id]
	if !ok || time.Since(e.CreatedAt) > flowExecTTL {
		delete(s.execs, id)
		return nil, false
	}
	return e, true
}

// drop removes an execution (on completion/denial).
func (s *execStore) drop(id string) {
	s.mu.Lock()
	delete(s.execs, id)
	s.mu.Unlock()
}

// runFlow drives exec through stages starting at exec.Cursor. It advances on
// StageContinue, returns on StageRespond (the stage rendered/redirected and the
// caller has parked the execution), and returns on a terminal result
// (StageComplete/StageDeny). Reaching the end of the stage list is treated as
// completion. A stage error short-circuits as a deny so the caller can surface
// it; the stage itself decides whether to also render.
func runFlow(w http.ResponseWriter, r *http.Request, exec *FlowExecution, stages []Stage) (StageResult, error) {
	for exec.Cursor < len(stages) {
		res, err := stages[exec.Cursor].Execute(w, r, exec)
		if err != nil {
			return StageDeny, err
		}
		switch res {
		case StageContinue:
			exec.Cursor++
		case StageRespond, StageComplete, StageDeny:
			return res, nil
		default:
			exec.Cursor++
		}
	}
	return StageComplete, nil
}
