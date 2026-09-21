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
		agentturn.Approve("approve").WithNote("keep it read-only"),
		agentturn.ApproveWith("approve-args", json.RawMessage(`{"command":"git status --short"}`)),
		agentturn.Output(openresponses.NewFunctionCallOutput("refuse", "Denied by reviewer: exfiltrates a token. Do not pursue the same outcome through a workaround, indirect execution or policy circumvention.")).WithNote("use the vault instead"),
		agentturn.Output(openresponses.NewFunctionCallOutput("refuse-bare", "Denied by reviewer. Do not pursue the same outcome through a workaround, indirect execution or policy circumvention.")),
		agentturn.Output(openresponses.NewFunctionCallOutput("timeout", "The reviewer did not answer in time; the call did not run.")),
		agentturn.Output(openresponses.NewFunctionCallOutput("fail", "The reviewer could not evaluate the call; the call did not run.")),
		agentturn.Output(openresponses.NewFunctionCallOutput("zero", "Denied by reviewer. Do not pursue the same outcome through a workaround, indirect execution or policy circumvention.")),
	}
	if !reflect.DeepEqual(answers, want) {
		t.Errorf("answers = %s\nwant %s", dump(answers), dump(want))
	}
	// One verdict per answer, after the seven decisions.
	vs := j.all()[7:]
	wantReasons := []struct {
		action agentturn.ToolAction
		reason string
	}{
		{agentturn.Allow, "approved by reviewer: read-only"},
		{agentturn.Allow, "approved by reviewer"},
		{agentturn.Block, "denied by reviewer: exfiltrates a token."},
		{agentturn.Block, "denied by reviewer"},
		{agentturn.Block, "reviewer timed out"},
		{agentturn.Block, "reviewer failed: model unavailable"},
		{agentturn.Block, "denied by reviewer"},
	}
	if len(vs) != len(wantReasons) {
		t.Fatalf("verdicts = %d, want %d", len(vs), len(wantReasons))
	}
	for i, w := range wantReasons {
		v := vs[i]
		if v.Action != w.action || v.Reason != w.reason || v.CallID != calls[i].CallID || v.Tool != "bash" || v.RunID != "run_1" || v.Turn != 1 || v.Rule != nil {
			t.Errorf("verdict[%d] = %+v, want %v %q", i, v, w.action, w.reason)
		}
	}
}

func dump(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestAnswersRecallsOnlyTheRunInProgress(t *testing.T) {
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
	if _, err := e.Decide(ctx, agentturn.ToolCallInfo{RunID: "run_1", Turn: 3, Call: c, Args: json.RawMessage(c.Arguments)}); err != nil {
		t.Fatal(err)
	}
	// A decision for another run forgets run_1's deferred calls; the
	// reviewer then sees the call alone and an empty reason.
	other := call("c2", "read", `{}`)
	other.RunID = "run_2"
	if _, err := e.Decide(ctx, other); err != nil {
		t.Fatal(err)
	}
	answers, err := e.Answers(ctx, reviewer, pendingEnd("run_1", c))
	if err != nil || len(answers) != 1 || answers[0].CallID != "c1" {
		t.Fatalf("answers = %+v, %v", answers, err)
	}
	if want := (Verdict{RunID: "run_1", CallID: "c1", Tool: "bash", Action: agentturn.Defer}); len(seen) != 1 || !reflect.DeepEqual(seen[0], want) {
		t.Errorf("reviewer saw %+v, want %+v", seen, want)
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
		agentturn.Output(openresponses.NewFunctionCallOutput("aborted", "The call was cut off before it finished and may have run; it was not run again.")),
		agentturn.Approve("deferred"),
		agentturn.Output(openresponses.NewFunctionCallOutput("unknown", "The call was cut off before it finished and may have run; it was not run again.")),
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
	if err != nil || !reflect.DeepEqual(answers, []agentturn.Answer{agentturn.Approve("call_a"), agentturn.Approve("call_b")}) || strings.Join(reviewedIDs, ",") != "call_b" {
		t.Errorf("approved: %s, %v, reviewed %v", dump(answers), err, reviewedIDs)
	}
	// A refusal at the bound ends the run, so the held call is refused
	// with it.
	reviewedIDs = nil
	answers, err = e.Answers(ctx, reviewer(Refused), hold())
	want := []agentturn.Answer{
		agentturn.Output(openresponses.NewFunctionCallOutput("call_a", "The call was held for an approval and the turn was stopped; the call did not run.")),
		agentturn.Refuse(openresponses.NewFunctionCallOutput("call_b", "Denied by reviewer. Do not pursue the same outcome through a workaround, indirect execution or policy circumvention.")),
	}
	if !errors.Is(err, ErrDenialBound) || !reflect.DeepEqual(answers, want) || strings.Join(reviewedIDs, ",") != "call_b" {
		t.Errorf("refused: %s, %v, reviewed %v", dump(answers), err, reviewedIDs)
	}
}
