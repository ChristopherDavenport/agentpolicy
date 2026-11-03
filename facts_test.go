package agentpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/ChristopherDavenport/agenttool"
	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
)

// A claim is read once per call of a batch, and the hold and the
// call's own decision read the same claim, even when the sibling's
// reading was not kept because a hook failed for it. With claim reading
// off, nothing is asked.
func TestAClaimIsReadOncePerCallPerBatch(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		opts      []Option
		failOnce  bool
		wantAsks  map[string]int
		wantFirst agentturn.ToolAction
	}{
		{"read once", nil, false, map[string]int{"/a": 1, "/b": 1}, agentturn.Allow},
		{"a failed reading does not ask again", nil, true, map[string]int{"/a": 1, "/b": 1}, agentturn.Defer},
		{"claim reading off", []Option{WithoutFacts()}, false, map[string]int{}, agentturn.Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asks := map[string]int{}
			shell := agenttool.New("shell", "Runs a command", func(context.Context, agenttool.NoArgs) (string, error) { return "", nil },
				agenttool.WithFacts(func(_ context.Context, args json.RawMessage) (agenttool.Facts, error) {
					var a struct{ Path string }
					_ = json.Unmarshal(args, &a)
					asks[a.Path]++
					p, _ := json.Marshal(map[string]string{"path": a.Path})
					return agenttool.Facts{Calls: []agenttool.FactCall{{Args: p, Text: "cat " + a.Path}}}, nil
				}))
			failed := false
			flaky := func(_ context.Context, info agentturn.ToolCallInfo) (*agentturn.ToolDecision, error) {
				if tt.failOnce && !failed && info.Call.CallID == "c1" {
					failed = true
					return nil, errors.New("hook unavailable")
				}
				return nil, nil
			}
			opts := append([]Option{WithHooks(flaky), WithTools(func(string) (agenttool.Tool, bool) { return shell, true })}, tt.opts...)
			e, err := Build(Policy{Allow: rules(t, "shell"), Default: Ask()}, testMatchers, opts...)
			if err != nil {
				t.Fatal(err)
			}
			batch := []*openresponses.FunctionCall{
				{CallID: "c0", Name: "shell", Arguments: `{"path":"/a"}`},
				{CallID: "c1", Name: "shell", Arguments: `{"path":"/b"}`},
			}
			var ds []*agentturn.ToolDecision
			for i, c := range batch {
				d, err := e.Decide(ctx, agentturn.ToolCallInfo{RunID: "run_1", Turn: 1, Call: c, Tool: shell, Args: json.RawMessage(c.Arguments), Batch: batch, Index: i})
				if err != nil {
					t.Fatal(err)
				}
				ds = append(ds, d)
			}
			if len(asks) != len(tt.wantAsks) || asks["/a"] != tt.wantAsks["/a"] || asks["/b"] != tt.wantAsks["/b"] {
				t.Errorf("claims asked %v, want %v", asks, tt.wantAsks)
			}
			if ds[0].Action != tt.wantFirst || ds[1].Action != agentturn.Allow {
				t.Errorf("decisions %s, %s", actionName(ds[0].Action), actionName(ds[1].Action))
			}
		})
	}
}

// Runs that share an engine keep their batches apart: two runs whose
// batches are decided interleaved each read one claim and run each hook
// once per call, and a batch is dropped once its last call is decided.
func TestConcurrentBatchesKeepTheirReadings(t *testing.T) {
	ctx := context.Background()
	claims := map[string]int{}
	shell := agenttool.New("shell", "Runs a command", func(context.Context, agenttool.NoArgs) (string, error) { return "", nil },
		agenttool.WithFacts(func(_ context.Context, args json.RawMessage) (agenttool.Facts, error) {
			claims[string(args)]++
			return agenttool.Facts{}, nil
		}))
	hooks := map[string]int{}
	count := func(_ context.Context, info agentturn.ToolCallInfo) (*agentturn.ToolDecision, error) {
		hooks[info.RunID+"/"+info.Call.CallID]++
		return nil, nil
	}
	e, err := Build(Policy{Allow: rules(t, "shell"), Default: Ask()}, testMatchers, WithHooks(count), WithTools(func(string) (agenttool.Tool, bool) { return shell, true }))
	if err != nil {
		t.Fatal(err)
	}
	mk := func(run string) []agentturn.ToolCallInfo {
		batch := []*openresponses.FunctionCall{
			{CallID: "c0", Name: "shell", Arguments: `{"path":"/` + run + `/0"}`},
			{CallID: "c1", Name: "shell", Arguments: `{"path":"/` + run + `/1"}`},
		}
		out := make([]agentturn.ToolCallInfo, len(batch))
		for i, c := range batch {
			out[i] = agentturn.ToolCallInfo{RunID: run, Turn: 1, Call: c, Tool: shell, Args: json.RawMessage(c.Arguments), Batch: batch, Index: i}
		}
		return out
	}
	a, b := mk("run_a"), mk("run_b")
	for _, info := range []agentturn.ToolCallInfo{a[0], b[0], a[1], b[1]} {
		if d, err := e.Decide(ctx, info); err != nil || d.Action != agentturn.Allow {
			t.Fatalf("%s %s: %+v, %v", info.RunID, info.Call.CallID, d, err)
		}
	}
	for args, n := range claims {
		if n != 1 {
			t.Errorf("the claim for %s was read %d times", args, n)
		}
	}
	for call, n := range hooks {
		if n != 1 {
			t.Errorf("the hook ran %d times for %s", n, call)
		}
	}
	if len(claims) != 4 || len(hooks) != 4 {
		t.Errorf("claims %v, hooks %v", claims, hooks)
	}
	open := func() (live, done int) {
		e.mu.Lock()
		defer e.mu.Unlock()
		for _, b := range e.batches {
			if b.done {
				done++
			} else {
				live++
			}
		}
		return live, done
	}
	if live, done := open(); live != 0 || done != 2 {
		t.Errorf("%d batches open and %d done after every call was decided", live, done)
	}
	// A run forgotten drops its batch; a run's next batch drops its last.
	e.Forget("run_a")
	next := mk("run_b")
	for i := range next {
		next[i].Turn = 2
	}
	if _, err := e.Decide(ctx, next[0]); err != nil {
		t.Fatal(err)
	}
	if live, done := open(); live != 1 || done != 0 {
		t.Errorf("%d batches open and %d done after a Forget and a next batch", live, done)
	}
	// Done batches beyond the bound are dropped, oldest first.
	for i := range keptBatches + 10 {
		run := mk(fmt.Sprintf("run_%d", i))
		for _, info := range run {
			if _, err := e.Decide(ctx, info); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, done := open(); done != keptBatches {
		t.Errorf("%d done batches kept, want %d", done, keptBatches)
	}
}
