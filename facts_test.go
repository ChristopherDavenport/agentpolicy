package agentpolicy

import (
	"context"
	"encoding/json"
	"errors"
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
