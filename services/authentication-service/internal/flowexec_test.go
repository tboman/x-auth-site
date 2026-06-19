package internal

import (
	"net/http"
	"testing"
	"time"
)

// fakeStage drives runFlow in tests without HTTP.
type fakeStage struct {
	typ string
	fn  func(exec *FlowExecution) (StageResult, error)
}

func (s fakeStage) Type() string { return s.typ }
func (s fakeStage) Execute(_ http.ResponseWriter, _ *http.Request, exec *FlowExecution) (StageResult, error) {
	return s.fn(exec)
}

// runFlow advances through Continue stages, pauses at a Respond stage (parking
// the cursor there), and on resume runs to Complete.
func TestRunFlowAdvancesPausesResumes(t *testing.T) {
	stages := []Stage{
		fakeStage{"risk", func(e *FlowExecution) (StageResult, error) { e.Context["risk"] = "low"; return StageContinue, nil }},
		fakeStage{"validate", func(e *FlowExecution) (StageResult, error) { return StageRespond, nil }},
		fakeStage{"issue", func(e *FlowExecution) (StageResult, error) { e.AchievedACR = "done"; return StageComplete, nil }},
	}
	exec := &FlowExecution{ID: "x", Context: map[string]any{}}

	res, err := runFlow(nil, nil, exec, stages)
	if err != nil || res != StageRespond {
		t.Fatalf("first run: want respond, got %v err=%v", res, err)
	}
	if exec.Cursor != 1 {
		t.Fatalf("should park at the validate stage (cursor 1), got %d", exec.Cursor)
	}
	if exec.Context["risk"] != "low" {
		t.Fatal("risk stage should have run before the pause")
	}

	// Resume: the responding stage's follow-up handler advances past it.
	exec.Cursor++
	res, err = runFlow(nil, nil, exec, stages)
	if err != nil || res != StageComplete {
		t.Fatalf("resume: want complete, got %v err=%v", res, err)
	}
	if exec.AchievedACR != "done" {
		t.Fatal("issue stage should have run on resume")
	}
}

// A stage error short-circuits as a deny.
func TestRunFlowErrorDenies(t *testing.T) {
	stages := []Stage{
		fakeStage{"boom", func(e *FlowExecution) (StageResult, error) { return StageContinue, errTestStage }},
	}
	res, err := runFlow(nil, nil, &FlowExecution{ID: "x", Context: map[string]any{}}, stages)
	if res != StageDeny || err != errTestStage {
		t.Fatalf("error should deny: res=%v err=%v", res, err)
	}
}

func TestExecStorePutGetDropExpiry(t *testing.T) {
	s := newExecStore()
	e := &FlowExecution{ID: "e1", CreatedAt: time.Now().UTC()}
	s.put(e)
	if got, ok := s.get("e1"); !ok || got != e {
		t.Fatal("get after put should return the execution")
	}
	s.drop("e1")
	if _, ok := s.get("e1"); ok {
		t.Fatal("get after drop should miss")
	}
	s.put(&FlowExecution{ID: "old", CreatedAt: time.Now().UTC().Add(-2 * flowExecTTL)})
	if _, ok := s.get("old"); ok {
		t.Fatal("expired execution should not be returned")
	}
}

func TestStageResultString(t *testing.T) {
	for r, want := range map[StageResult]string{
		StageContinue: "continue", StageRespond: "respond",
		StageComplete: "complete", StageDeny: "deny",
	} {
		if r.String() != want {
			t.Errorf("StageResult(%d).String() = %q, want %q", r, r.String(), want)
		}
	}
}

var errTestStage = &stageTestErr{}

type stageTestErr struct{}

func (*stageTestErr) Error() string { return "test stage error" }
