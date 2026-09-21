package agentpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
)

// released is [Engine.Release] as a front that answered every asked
// call sees it: the answers, and no error.
func released(ctx context.Context, t *testing.T, e *Engine, end *agentturn.RunEnd, answers ...agentturn.Answer) []agentturn.Answer {
	t.Helper()
	out, err := e.Release(ctx, end, answers...)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	return out
}

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
			got, ok := e.Deferred("run_1", infos[i].Call.CallID)
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
	got := released(ctx, t, e, end, agentturn.Approve("call_c").WithNote("ok, once"))
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
	if got := released(ctx, t, e, end, refusal); !reflect.DeepEqual(got, []agentturn.Answer{agentturn.Approve("call_a"), agentturn.Approve("call_b"), refusal}) {
		t.Errorf("released after a refusal = %s", dump(got))
	}
	if r := reasons(j); r != "call_a released: allowed by bash(git add:*)|call_b released: allowed by bash(git commit:*)" {
		t.Errorf("verdicts = %q", r)
	}

	// A refusal that ends the turn refuses them with text the model
	// reads, and the turn ends with nothing of the batch run.
	e, j, end = setup(t)
	stop := agentturn.Refuse(openresponses.NewFunctionCallOutput("call_c", "no, stop"))
	got = released(ctx, t, e, end, stop)
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

	// A held call the front answered itself keeps the front's answer,
	// and an answer for a call that is not pending is kept after the
	// rest.
	e, j, end = setup(t)
	own := agentturn.Output(openresponses.NewFunctionCallOutput("call_a", "I ran it myself"))
	stray := agentturn.Approve("call_z")
	if got := released(ctx, t, e, end, stray, agentturn.Approve("call_c"), own); !reflect.DeepEqual(got, []agentturn.Answer{own, agentturn.Approve("call_b"), agentturn.Approve("call_c"), stray}) {
		t.Errorf("own answer kept = %s", dump(got))
	}
	if len(j.all()) != 1 {
		t.Errorf("verdicts = %+v", j.all())
	}

	// The calls it answered are forgotten, so a second release of the
	// same end has nothing to answer them with and says which calls.
	got, err := e.Release(ctx, end, agentturn.Approve("call_c"))
	if !errors.Is(err, ErrUnanswered) || err.Error() != "agentpolicy: pending call has no answer: call_a (bash), call_b (bash)" {
		t.Errorf("second release: err = %v", err)
	}
	if !reflect.DeepEqual(got, []agentturn.Answer{agentturn.Approve("call_c")}) {
		t.Errorf("second release = %s", dump(got))
	}

	// A pending call the engine never deferred is named too, and a nil
	// end returns the answers as they are.
	e, _, end = setup(t)
	end.Pending = append(end.Pending, agentturn.PendingCall{Call: &openresponses.FunctionCall{CallID: "call_x", Name: "read"}, Reason: agentturn.PendingDeferred})
	if _, err := e.Release(ctx, end, agentturn.Approve("call_c")); !errors.Is(err, ErrUnanswered) || err.Error() != "agentpolicy: pending call has no answer: call_x (read)" {
		t.Errorf("a call the engine never deferred: err = %v", err)
	}
	if got, err := e.Release(ctx, nil, agentturn.Approve("call_c")); err != nil || len(got) != 1 {
		t.Errorf("nil end = %s, %v", dump(got), err)
	}
}

// One engine serves every agent of a product: what one run defers is
// not forgotten when another run decides. The scenario is the round 2
// codex-permissions study's, a main agent holding a batch of three
// while a sub-agent runs one allowed call on the same engine.
func TestEngineServesSeveralRuns(t *testing.T) {
	ctx := context.Background()
	e, err := Build(Policy{
		Allow:   rules(t, "bash(git add:*) bash(git commit:*)"),
		Ask:     rules(t, "bash(git push:*)"),
		Default: Ask(),
	}, testMatchers)
	if err != nil {
		t.Fatal(err)
	}
	end := &agentturn.RunEnd{RunID: "run_main", Reason: agentturn.ReasonInputRequired}
	for _, info := range batch("run_main", "git add -A", "git push --force", "git commit -m wip") {
		if d, _ := e.Decide(ctx, info); d.Action != agentturn.Defer {
			t.Fatalf("%s: %+v", info.Call.CallID, d)
		}
		end.Pending = append(end.Pending, agentturn.PendingCall{Call: info.Call, Reason: agentturn.PendingDeferred})
	}

	// A sub-agent decides one call on the same engine while the user is
	// being asked.
	sub := call("call_sub", "bash", `{"command":"git add docs"}`)
	sub.RunID = "run_sub"
	sub.Batch = []*openresponses.FunctionCall{sub.Call}
	if d, _ := e.Decide(ctx, sub); d.Action != agentturn.Allow {
		t.Fatalf("the sub-agent's call = %+v", d)
	}

	// The main agent's three calls are still the engine's, held and
	// asked as they were.
	for i, want := range []bool{true, false, true} {
		id := end.Pending[i].Call.CallID
		v, ok := e.Deferred("run_main", id)
		if !ok || v.Held != want {
			t.Errorf("Deferred(run_main, %s) = %+v, %v", id, v, ok)
		}
		if _, ok := e.Deferred("run_sub", id); ok {
			t.Errorf("%s is known to the sub-agent's run", id)
		}
	}
	answers, err := e.Release(ctx, end, agentturn.Approve(end.Pending[1].Call.CallID))
	if err != nil || len(answers) != 3 {
		t.Fatalf("Release built %d answers for 3 pending calls: %v", len(answers), err)
	}

	// A reviewer sees the asked call alone, not the held ones.
	e2, err := Build(Policy{Allow: rules(t, "bash(git add:*)"), Ask: rules(t, "bash(git push:*)"), Default: Ask()}, testMatchers)
	if err != nil {
		t.Fatal(err)
	}
	end2 := &agentturn.RunEnd{RunID: "run_main", Reason: agentturn.ReasonInputRequired}
	for _, info := range batch("run_main", "git add -A", "git push --force") {
		e2.Decide(ctx, info)
		end2.Pending = append(end2.Pending, agentturn.PendingCall{Call: info.Call, Reason: agentturn.PendingDeferred})
	}
	e2.Decide(ctx, sub)
	var reviewed []string
	answers, err = e2.Answers(ctx, ReviewerFunc(func(_ context.Context, info agentturn.ToolCallInfo, _ Verdict) (Review, error) {
		reviewed = append(reviewed, info.Call.CallID)
		return Review{Outcome: Approved}, nil
	}), end2)
	if err != nil || len(answers) != 2 || len(reviewed) != 1 || reviewed[0] != "call_b" {
		t.Errorf("Answers reviewed %v and built %d answers: %v", reviewed, len(answers), err)
	}

	// Forget drops what a run that ended another way left behind: the
	// release answered and forgot the main agent's calls, and the
	// sub-agent's own ask is still waiting.
	asked := call("call_sub_push", "bash", `{"command":"git push docs"}`)
	asked.RunID = "run_sub"
	e.Decide(ctx, asked)
	if got := e.Runs(); len(got) != 1 || got[0] != "run_sub" {
		t.Errorf("runs after the release = %v", got)
	}
	e.Forget("run_sub")
	if got := e.Runs(); len(got) != 0 {
		t.Errorf("runs after Forget = %v", got)
	}
}

// The hold decides a batch once, not once per pair: the loop hands
// the hook every call of the batch before any runs, and deciding the
// whole batch per call ran the product's splitter ninety extra times
// on a batch of ten.
func TestBatchIsDecidedOnce(t *testing.T) {
	ctx := context.Background()
	splits := 0
	matchers := map[string]ToolMatcher{"bash": {
		Match: PrefixMatcher("command"),
		Subjects: func(args json.RawMessage) ([]Subject, error) {
			splits++
			return shellSplit(args)
		},
	}}
	e, err := Build(Policy{Allow: rules(t, "bash(git:*)"), Ask: rules(t, "bash(git push:*)"), Default: Ask()}, matchers)
	if err != nil {
		t.Fatal(err)
	}
	commands := []string{"git status", "git diff", "git log", "git add -A", "git commit -m x"}
	infos := batch("run_1", commands...)
	for _, info := range infos {
		if d, _ := e.Decide(ctx, info); d.Action != agentturn.Allow {
			t.Fatalf("%s: %+v", info.Call.CallID, d)
		}
	}
	// One split for each call's own verdict, plus one pass over the
	// batch: linear, where it was one pass per call.
	if want := 2 * len(commands); splits > want {
		t.Errorf("the splitter ran %d times for %d calls, want at most %d", splits, len(commands), want)
	}

	// A policy that changes is a batch decided again, so a grant
	// mid-batch is not read from a stale count.
	splits = 0
	if err := e.Grant(ctx, Rule{Tool: "bash", Spec: "npm test:*"}); err != nil {
		t.Fatal(err)
	}
	if d, _ := e.Decide(ctx, infos[0]); d.Action != agentturn.Allow {
		t.Fatalf("after the grant: %+v", d)
	}
	if splits < 2 {
		t.Errorf("the batch was read from a stale count: %d splits", splits)
	}

	// An ask anywhere in the batch holds the rest, cache or no cache.
	e2, err := Build(Policy{Allow: rules(t, "bash(git:*)"), Ask: rules(t, "bash(git push:*)"), Default: Ask()}, matchers)
	if err != nil {
		t.Fatal(err)
	}
	held := batch("run_2", "git status", "git push --force", "git log")
	for i, info := range held {
		d, _ := e2.Decide(ctx, info)
		if d.Action != agentturn.Defer {
			t.Errorf("held[%d] = %+v", i, d)
		}
	}
}
