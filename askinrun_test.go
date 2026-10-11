package agentpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agenttool"
	"github.com/ChristopherDavenport/agentturn"
)

// askingCtx returns a context carrying an elicitor that answers every
// question with answer and counts them, as a front asking in the run.
func askingCtx(answer agenttool.Answer) (context.Context, *int) {
	asked := 0
	ctx := agenttool.ContextWithElicitor(context.Background(), func(context.Context, agenttool.Elicitation) (agenttool.Answer, error) {
		asked++
		return answer, nil
	})
	return ctx, &asked
}

// decideAll decides every call of a batch in the model's order, as the
// loop hands them to the hook.
func decideAll(t *testing.T, ctx context.Context, e *Engine, infos []agentturn.ToolCallInfo) []*agentturn.ToolDecision {
	t.Helper()
	out := make([]*agentturn.ToolDecision, len(infos))
	for i, info := range infos {
		d, err := e.Decide(ctx, info)
		if err != nil {
			t.Fatalf("%s: %v", info.Call.CallID, err)
		}
		out[i] = d
	}
	return out
}

func decisions(ds []*agentturn.ToolDecision) string {
	var out []string
	for _, d := range ds {
		out = append(out, fmt.Sprintf("%s %s", actionName(d.Action), d.Reason))
	}
	return strings.Join(out, "|")
}

// A grant made while a batch is decided, another conversation's or an
// "always allow", does not have the person asked again.
func TestAskInRunAsksOncePerBatchAcrossAGrant(t *testing.T) {
	e, err := Build(Policy{Allow: rules(t, "bash(git add:*)"), Ask: rules(t, "bash(git push:*)"), Default: Deny()}, testMatchers, WithAskInRun())
	if err != nil {
		t.Fatal(err)
	}
	ctx, asked := askingCtx(agenttool.Answer{Action: agenttool.ActionAccept})
	infos := batch("run_1", "git add -A", "git push")
	if _, err := e.Decide(ctx, infos[0]); err != nil {
		t.Fatal(err)
	}
	if err := e.Grant(context.Background(), rules(t, "bash(git status:*)")[0]); err != nil {
		t.Fatal(err)
	}
	d, err := e.Decide(ctx, infos[1])
	if err != nil || d.Action != agentturn.Allow || d.By != ByHuman {
		t.Fatalf("the push = %+v, %v", d, err)
	}
	if *asked != 1 {
		t.Errorf("asked %d times", *asked)
	}
}

// A person's answer for a call stands however the call's own decision
// reads it: here the call was asked about as a sibling, read without
// its tool, and its own decision, with its tool, allows it.
func TestAskInRunAnAnswerStandsForItsCall(t *testing.T) {
	tool := agenttool.New("bash", "A shell", func(context.Context, agenttool.NoArgs) (string, error) { return "", nil })
	asksWithoutTool := func(_ context.Context, info agentturn.ToolCallInfo) (*agentturn.ToolDecision, error) {
		if info.Tool == nil && strings.Contains(string(info.Args), "deploy") {
			return &agentturn.ToolDecision{Action: agentturn.Defer, Reason: "unknown tool"}, nil
		}
		return nil, nil
	}
	e, err := Build(Policy{Allow: rules(t, "bash(git:*) bash(make:*)"), Default: Deny()}, testMatchers, WithAskInRun(), WithHooks(asksWithoutTool))
	if err != nil {
		t.Fatal(err)
	}
	ctx, asked := askingCtx(agenttool.Answer{Action: agenttool.ActionDecline})
	infos := batch("run_1", "git status", "make deploy")
	for i := range infos {
		infos[i].Tool = tool
	}
	ds := decideAll(t, ctx, e, infos)
	if *asked != 1 || ds[1].Action != agentturn.Block || ds[1].By != ByHuman {
		t.Errorf("asked %d; decisions %s", *asked, decisions(ds))
	}
}

// The decline rule is the release's: a plain decline refuses its own
// call alone, and an answer that stops the turn refuses the calls held
// beside it, naming the call whose answer stopped it. A stop decides
// the held calls even while a sibling could not be read.
func TestAskInRunDeclineAndStop(t *testing.T) {
	stopping := func(_ context.Context, info agentturn.ToolCallInfo) (*agentturn.ToolDecision, error) {
		switch c := string(info.Args); {
		case strings.Contains(c, "broken"):
			return nil, errors.New("cannot read")
		case strings.Contains(c, "push"):
			return &agentturn.ToolDecision{Action: agentturn.Allow, Terminate: true}, nil
		}
		return nil, nil
	}
	build := func(t *testing.T, hooks ...func(context.Context, agentturn.ToolCallInfo) (*agentturn.ToolDecision, error)) *Engine {
		e, err := Build(Policy{Allow: rules(t, "bash(git add:*) bash(broken)"), Ask: rules(t, "bash(git push:*)"), Default: Deny()}, testMatchers, WithAskInRun(), WithHooks(hooks...))
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	decline := agenttool.Answer{Action: agenttool.ActionDecline}

	// A plain decline: the held add is released.
	ctx, _ := askingCtx(decline)
	ds := decideAll(t, ctx, build(t), batch("run_1", "git add -A", "git push"))
	if ds[0].Action != agentturn.Allow || ds[1].Action != agentturn.Block {
		t.Errorf("a plain decline: %s", decisions(ds))
	}

	// A decline that stops the turn: the held add is refused, naming the
	// push.
	ctx, _ = askingCtx(decline)
	ds = decideAll(t, ctx, build(t, stopping), batch("run_1", "git add -A", "git push"))
	if ds[0].Action != agentturn.Block || !strings.HasPrefix(ds[0].Reason, "not released: the turn was stopped by the answer to call_b (") {
		t.Errorf("a stop: %s", decisions(ds))
	}

	// A stop decides the held add although a sibling could not be read.
	ctx, _ = askingCtx(decline)
	e := build(t, stopping)
	infos := batch("run_1", "git add -A", "git push", "broken")
	d, err := e.Decide(ctx, infos[0])
	if err != nil || d.Action != agentturn.Block || !strings.Contains(d.Reason, "call_b") {
		t.Errorf("a stop beside an unreadable sibling: %+v, %v", d, err)
	}
	if _, ok := e.Deferred("run_1", "call_a"); ok {
		t.Error("the held add is remembered as deferred")
	}
}

// What was asked in a run is dropped when the run moves to its next
// batch and when the front forgets the run, even while the person is
// being asked, and never to make room.
func TestAskInRunDropsWhatARunAsked(t *testing.T) {
	e, err := Build(Policy{Allow: rules(t, "bash(git add:*)"), Ask: rules(t, "bash(git push:*)"), Default: Deny()}, testMatchers, WithAskInRun())
	if err != nil {
		t.Fatal(err)
	}
	ctx, _ := askingCtx(agenttool.Answer{Action: agenttool.ActionCancel})
	kept := func() int {
		e.mu.Lock()
		defer e.mu.Unlock()
		return len(e.asked)
	}
	first := batch("run_1", "git add -A", "git push")
	e.Decide(ctx, first[0])
	if kept() != 1 {
		t.Fatalf("kept %d after the first call", kept())
	}
	// The run's next turn: the batch before it is gone.
	next := batch("run_1", "git add docs", "git push origin")
	for i := range next {
		next[i].Turn = 2
	}
	e.Decide(ctx, next[0])
	if kept() != 1 {
		t.Errorf("kept %d after the run's next batch", kept())
	}
	e.Forget("run_1")
	if kept() != 0 {
		t.Errorf("kept %d after Forget", kept())
	}

	// A live batch is never dropped to make room: every run in flight
	// keeps its answers, however many there are.
	for i := range 65 {
		e.Decide(ctx, batch(fmt.Sprintf("run_%d", i), "git add -A", "git push")[0])
	}
	if kept() != 65 {
		t.Errorf("kept %d of 65 live batches", kept())
	}

	// A run forgotten while the person is being asked keeps nothing.
	var forgetting *Engine
	fctx := agenttool.ContextWithElicitor(context.Background(), func(context.Context, agenttool.Elicitation) (agenttool.Answer, error) {
		forgetting.Forget("run_f")
		return agenttool.Answer{Action: agenttool.ActionAccept}, nil
	})
	forgetting, err = Build(Policy{Allow: rules(t, "bash(git add:*)"), Ask: rules(t, "bash(git push:*)"), Default: Deny()}, testMatchers, WithAskInRun())
	if err != nil {
		t.Fatal(err)
	}
	if d, err := forgetting.Decide(fctx, batch("run_f", "git add -A", "git push")[0]); err != nil || d.Action != agentturn.Allow {
		t.Fatalf("the add = %+v, %v", d, err)
	}
	forgetting.mu.Lock()
	left := len(forgetting.asked)
	forgetting.mu.Unlock()
	if left != 0 {
		t.Errorf("a forgotten run kept %d batches", left)
	}
}

// A call decided in the run carries its subject and held mark, as a
// deferral does, and a person's answer names no rule.
func TestAskInRunDecisionsSayWhatTheyAreAbout(t *testing.T) {
	j := &journal{}
	e, err := Build(Policy{Allow: rules(t, "bash(git add:*) bash(git status:*) bash(git push:*)"), Ask: rules(t, "bash(git push:*)"), Default: Deny()}, testMatchers, WithAskInRun(), WithObserver(j.observe))
	if err != nil {
		t.Fatal(err)
	}
	// What the same batch's deferral says without asking in the run.
	plain, err := Build(Policy{Allow: rules(t, "bash(git add:*) bash(git status:*) bash(git push:*)"), Ask: rules(t, "bash(git push:*)"), Default: Deny()}, testMatchers)
	if err != nil {
		t.Fatal(err)
	}
	held, err := plain.Decide(context.Background(), batch("run_1", "git add -A && git status", "git push")[0])
	if err != nil || !held.Held {
		t.Fatalf("the plain hold = %+v, %v", held, err)
	}
	ctx, _ := askingCtx(agenttool.Answer{Action: agenttool.ActionDecline})
	ds := decideAll(t, ctx, e, batch("run_1", "git add -A && git status", "git push"))
	if !ds[0].Held || ds[0].Action != agentturn.Allow || ds[0].Subject != held.Subject {
		t.Errorf("the released add = %+v, the hold's subject %q", ds[0], held.Subject)
	}
	asked := 0
	for _, v := range j.all() {
		if v.By == ByHuman {
			asked++
		}
	}
	if asked != 1 {
		t.Errorf("%d verdicts by the person", asked)
	}
	for _, v := range j.all() {
		if v.By == ByHuman && v.Rule != nil {
			t.Errorf("a person's answer names rule %v", v.Rule)
		}
	}
}
