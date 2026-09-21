package agentpolicy

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
)

// batch builds the hook's view of each call of a batch, one bash
// command per call, in the model's order.
func batch(runID string, commands ...string) []agentturn.ToolCallInfo {
	calls := make([]*openresponses.FunctionCall, len(commands))
	for i, c := range commands {
		args, _ := json.Marshal(map[string]string{"command": c})
		calls[i] = &openresponses.FunctionCall{CallID: "call_" + string(rune('a'+i)), Name: "bash", Arguments: string(args)}
	}
	infos := make([]agentturn.ToolCallInfo, len(calls))
	for i, c := range calls {
		infos[i] = agentturn.ToolCallInfo{RunID: runID, Turn: 1, Call: c, Args: json.RawMessage(c.Arguments), Batch: calls, Index: i}
	}
	return infos
}

func TestDecideHoldsTheBatchForAnAsk(t *testing.T) {
	ctx := context.Background()
	policy := Policy{
		Allow:   rules(t, "bash(git add:*) bash(git commit:*) bash(git status:*)"),
		Deny:    rules(t, "bash(rm:*)"),
		Ask:     rules(t, "bash(git push:*)"),
		Default: Ask(),
	}
	type want struct {
		action agentturn.ToolAction
		held   bool
		rule   string
		reason string
	}
	tests := []struct {
		name     string
		commands []string
		want     []want
	}{
		{name: "an ask holds the allowed calls before it", commands: []string{"git add -A", "git commit -m wip", "git push --force"}, want: []want{
			{agentturn.Defer, true, "bash(git add:*)", "held for approval: allowed by bash(git add:*)"},
			{agentturn.Defer, true, "bash(git commit:*)", "held for approval: allowed by bash(git commit:*)"},
			{agentturn.Defer, false, "bash(git push:*)", "approval required by bash(git push:*)"},
		}},
		{name: "and the allowed calls after it", commands: []string{"git push", "git status"}, want: []want{
			{agentturn.Defer, false, "bash(git push:*)", "approval required by bash(git push:*)"},
			{agentturn.Defer, true, "bash(git status:*)", "held for approval: allowed by bash(git status:*)"},
		}},
		{name: "a denied call stays denied", commands: []string{"git status", "rm -rf /", "git push"}, want: []want{
			{agentturn.Defer, true, "bash(git status:*)", "held for approval: allowed by bash(git status:*)"},
			{agentturn.Block, false, "bash(rm:*)", "denied by bash(rm:*)"},
			{agentturn.Defer, false, "bash(git push:*)", "approval required by bash(git push:*)"},
		}},
		{name: "the default asks and holds too", commands: []string{"git status", "npm test"}, want: []want{
			{agentturn.Defer, true, "bash(git status:*)", "held for approval: allowed by bash(git status:*)"},
			{agentturn.Defer, false, "", "no rule allows bash: approval required by default"},
		}},
		{name: "no ask, nothing held", commands: []string{"git add -A", "git status"}, want: []want{
			{agentturn.Allow, false, "bash(git add:*)", "allowed by bash(git add:*)"},
			{agentturn.Allow, false, "bash(git status:*)", "allowed by bash(git status:*)"},
		}},
		{name: "a batch of one", commands: []string{"git status"}, want: []want{
			{agentturn.Allow, false, "bash(git status:*)", "allowed by bash(git status:*)"},
		}},
	}
	for _, tc := range tests {
		j := &journal{}
		e, err := Build(policy, testMatchers, WithObserver(j.observe))
		if err != nil {
			t.Fatal(err)
		}
		infos := batch("run_1", tc.commands...)
		for i, info := range infos {
			d, err := e.Decide(ctx, info)
			if err != nil {
				t.Fatalf("%s[%d]: %v", tc.name, i, err)
			}
			w := tc.want[i]
			if d.Action != w.action || d.Reason != w.reason || d.By != "policy" {
				t.Errorf("%s[%d]: decision = %+v, want %+v", tc.name, i, d, w)
			}
			// The same call in the same batch decides the same.
			if d2, _ := e.Decide(ctx, info); !reflect.DeepEqual(d, d2) {
				t.Errorf("%s[%d]: decisions differ: %+v then %+v", tc.name, i, d, d2)
			}
		}
		vs := j.all()
		if len(vs) != 2*len(tc.want) {
			t.Fatalf("%s: %d verdicts, want %d", tc.name, len(vs), 2*len(tc.want))
		}
		for i, w := range tc.want {
			v := vs[2*i]
			rule := ""
			if v.Rule != nil {
				rule = v.Rule.String()
			}
			if v.Action != w.action || v.Held != w.held || rule != w.rule || v.Reason != w.reason || v.CallID != infos[i].Call.CallID || v.Tool != "bash" || v.RunID != "run_1" || v.Turn != 1 {
				t.Errorf("%s[%d]: verdict = %+v, want %+v", tc.name, i, v, w)
			}
			// Deferred returns what deferred a call, asked or held, and
			// nothing for one that was not.
			got, ok := e.Deferred(infos[i].Call.CallID)
			if ok != (w.action == agentturn.Defer) || (ok && !reflect.DeepEqual(got, v)) {
				t.Errorf("%s[%d]: Deferred = %+v, %v", tc.name, i, got, ok)
			}
		}
	}
}

func TestRelease(t *testing.T) {
	ctx := context.Background()
	policy := Policy{Allow: rules(t, "bash(git add:*) bash(git commit:*)"), Ask: rules(t, "bash(git push:*)"), Default: Deny()}
	setup := func(t *testing.T) (*Engine, *journal, *agentturn.RunEnd) {
		j := &journal{}
		e, err := Build(policy, testMatchers, WithObserver(j.observe))
		if err != nil {
			t.Fatal(err)
		}
		end := &agentturn.RunEnd{RunID: "run_1", Reason: agentturn.ReasonInputRequired}
		for _, info := range batch("run_1", "git add -A", "git commit -m wip", "git push") {
			if d, _ := e.Decide(ctx, info); d.Action != agentturn.Defer {
				t.Fatalf("%s: %+v", info.Call.CallID, d)
			}
			end.Pending = append(end.Pending, agentturn.PendingCall{Call: info.Call, Reason: agentturn.PendingDeferred})
		}
		j.verdicts = nil
		return e, j, end
	}
	reasons := func(j *journal) string {
		var out []string
		for _, v := range j.all() {
			if !v.Held {
				t.Errorf("release verdict without Held: %+v", v)
			}
			out = append(out, v.CallID+" "+v.Reason)
		}
		return strings.Join(out, "|")
	}

	// An approval of the ask releases the held calls, which run with
	// the batch.
	e, j, end := setup(t)
	got := e.Release(ctx, end, agentturn.Approve("call_c").WithNote("ok, once"))
	want := []agentturn.Answer{
		agentturn.Approve("call_a"),
		agentturn.Approve("call_b"),
		agentturn.Approve("call_c").WithNote("ok, once"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("released = %s\nwant %s", dump(got), dump(want))
	}
	if r := reasons(j); r != "call_a released: allowed by bash(git add:*)|call_b released: allowed by bash(git commit:*)" {
		t.Errorf("verdicts = %q", r)
	}
	for _, v := range j.all() {
		if v.Action != agentturn.Allow || v.Rule == nil || v.RunID != "run_1" || v.Turn != 1 || v.Tool != "bash" {
			t.Errorf("release verdict = %+v", v)
		}
	}

	// A refusal that lets the turn go on releases them too: the policy
	// allowed them, and the model sees the one refusal.
	e, j, end = setup(t)
	refusal := agentturn.Output(openresponses.NewFunctionCallOutput("call_c", "no"))
	if got := e.Release(ctx, end, refusal); !reflect.DeepEqual(got, []agentturn.Answer{agentturn.Approve("call_a"), agentturn.Approve("call_b"), refusal}) {
		t.Errorf("released after a refusal = %s", dump(got))
	}
	if r := reasons(j); r != "call_a released: allowed by bash(git add:*)|call_b released: allowed by bash(git commit:*)" {
		t.Errorf("verdicts = %q", r)
	}

	// A refusal that ends the turn refuses them with text the model
	// reads, and the turn ends with nothing of the batch run.
	e, j, end = setup(t)
	stop := agentturn.Refuse(openresponses.NewFunctionCallOutput("call_c", "no, stop"))
	got = e.Release(ctx, end, stop)
	want = []agentturn.Answer{
		agentturn.Output(openresponses.NewFunctionCallOutput("call_a", "The call was held for an approval and the turn was stopped; the call did not run.")),
		agentturn.Output(openresponses.NewFunctionCallOutput("call_b", "The call was held for an approval and the turn was stopped; the call did not run.")),
		stop,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("released after a stop = %s\nwant %s", dump(got), dump(want))
	}
	if r := reasons(j); r != "call_a not released: the turn was stopped|call_b not released: the turn was stopped" {
		t.Errorf("verdicts = %q", r)
	}
	for _, v := range j.all() {
		if v.Action != agentturn.Block || v.Rule != nil {
			t.Errorf("stop verdict = %+v", v)
		}
	}

	// A held call the front answered itself keeps the front's answer;
	// an answer for a call that is not pending is kept after the rest;
	// a call from a run the engine has forgotten is left alone; a nil
	// end returns the answers as they are.
	e, j, end = setup(t)
	own := agentturn.Output(openresponses.NewFunctionCallOutput("call_a", "I ran it myself"))
	stray := agentturn.Approve("call_z")
	if got := e.Release(ctx, end, stray, agentturn.Approve("call_c"), own); !reflect.DeepEqual(got, []agentturn.Answer{own, agentturn.Approve("call_b"), agentturn.Approve("call_c"), stray}) {
		t.Errorf("own answer kept = %s", dump(got))
	}
	if len(j.all()) != 1 {
		t.Errorf("verdicts = %+v", j.all())
	}
	other := call("other", "bash", `{"command":"git add x"}`)
	other.RunID = "run_2"
	e.Decide(ctx, other) // a new run forgets run_1
	if got := e.Release(ctx, end, agentturn.Approve("call_c")); len(got) != 1 {
		t.Errorf("forgotten run released %s", dump(got))
	}
	if got := e.Release(ctx, nil, agentturn.Approve("call_c")); len(got) != 1 {
		t.Errorf("nil end = %s", dump(got))
	}
}
