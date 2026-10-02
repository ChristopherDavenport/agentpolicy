package agentpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"github.com/ChristopherDavenport/agenttool"
	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
)

// Outcome is a reviewer's answer to a deferred call. The zero value is
// Refused, so a [Review] left unset refuses the call.
type Outcome int

const (
	// Refused answers the call with a refusal the model reads.
	Refused Outcome = iota
	// Approved runs the call, with Review.Args in place of the model's
	// arguments when set.
	Approved
	// TimedOut means the reviewer gave no answer in time. The call does
	// not run, and the record says why, distinct from a refusal.
	TimedOut
)

// String returns "refused", "approved" or "timed_out".
func (o Outcome) String() string {
	switch o {
	case Approved:
		return "approved"
	case TimedOut:
		return "timed_out"
	}
	return "refused"
}

// Review is a reviewer's answer.
type Review struct {
	Outcome Outcome
	// Reason is shown to the model on a refusal and recorded on every
	// outcome.
	Reason string
	// Args, for an approval, replaces the arguments the tool receives.
	// nil keeps the call's own.
	Args json.RawMessage
	// Note is what the reviewer tells the model with the result, on an
	// approval or a refusal: the loop appends it after the outputs as a
	// user message, so the model reads the result and the note
	// together, as a user's note on an approval reaches it.
	Note string
	// By names who answered, for the record: [ByAgent] for a model,
	// which is what the classify package's reviewer sets, [ByHuman]
	// for a person a reviewer asked on the front's behalf. Empty is
	// read as ByAgent, since a Reviewer answers where a human would.
	// [Engine.Answers] puts it on the verdict and on the answer, as
	// agentturn.Answer.By, which the session recorder writes as the
	// decision's decider; the engine's own fail-closed answers, a
	// timeout and a review that failed, are [ByPolicy].
	By string
}

// Reviewer answers a deferred call without a human: Codex's
// auto-review, a rule of the product's, a front that asks a person, or
// a test double. It receives the call as the hook saw it and the
// verdict that deferred it, and says who answered through Review.By. A
// model-backed one lives in the classify package; the engine never
// calls a model itself.
type Reviewer interface {
	Review(ctx context.Context, info agentturn.ToolCallInfo, v Verdict) (Review, error)
}

// ReviewerFunc adapts a function to [Reviewer].
type ReviewerFunc func(context.Context, agentturn.ToolCallInfo, Verdict) (Review, error)

// Review calls f.
func (f ReviewerFunc) Review(ctx context.Context, info agentturn.ToolCallInfo, v Verdict) (Review, error) {
	return f(ctx, info, v)
}

// DenialBound is when [Engine.Answers] stops answering: after
// Consecutive refusals in a row, or Total refusals within the last
// Window reviews. A zero field means no bound on that axis. Every
// answer that is not an approval counts as a refusal, a timeout and a
// failed review included.
type DenialBound struct {
	Consecutive int
	Total       int
	Window      int
}

// DefaultDenialBound is Codex's: three consecutive refusals, or ten
// within the last fifty reviews.
var DefaultDenialBound = DenialBound{Consecutive: 3, Total: 10, Window: 50}

// WithDenialBound replaces [DefaultDenialBound].
func WithDenialBound(b DenialBound) Option {
	return func(e *Engine) { e.bound = b }
}

// WithNeverStarted tells [Engine.Answers] which cut-off calls the
// session's record says never started: no dispatch and no output, in
// a file that records dispatches, agentsession's CallNeverStarted. The
// loop reports such a call from a seeded transcript as unknown, and
// without this Answers tells the model it may have run. fn is called
// with the run and the call and reports true only for a call the
// record shows never started. Such a call is refused as one that did
// not run, not approved for the loop to decide as a call pending as
// agentturn.PendingUndispatched is: the loop lists it as unknown and
// would hold an approval of it to the replay rule, and refuse it.
func WithNeverStarted(fn func(ctx context.Context, runID, callID string) bool) Option {
	return func(e *Engine) { e.neverStarted = fn }
}

// WithRan tells [Engine.Answers] which cut-off calls the session's record
// says ran to completion elsewhere, and what they returned: a call whose
// only dispatch is on a branch a rebase left, or in the session this one
// forks, which agentturn/session's ReplayAnswers answers with that output.
// fn is called with the run and the call and returns the output and where
// it ran, as the record says it ("ran on a branch the rebase left"), or
// nil for a call the record does not show completed; an empty where is
// recorded as "ran elsewhere". It is read for every call that may have
// run, a deferred call held after its dispatch included, before the
// reviewer and before the replay rule. The loop's PendingCall does not
// yet carry the output; once it does, as PendingCall.Ran and
// PendingCall.RanWhere, the loop's word is read first and fn second.
func WithRan(fn func(ctx context.Context, runID, callID string) (output *openresponses.FunctionCallOutput, where string)) Option {
	return func(e *Engine) { e.ran = fn }
}

// ErrDenialBound is returned by [Engine.Answers], with the answers,
// when the [DenialBound] was reached.
var ErrDenialBound = errors.New("agentpolicy: reviewer denial bound reached")

// reviewLog is the state behind the denial bound.
type reviewLog struct {
	// refused records the last Window reviews, true for a refusal.
	refused     []bool
	consecutive int
}

// What the model reads when a reviewer does not approve, and for a
// call no reviewer sees. A timeout and a failure say the call did not
// run; for a call that may have run, [notRun] gives way to cutOffText.
const (
	reviewerTimedOutText = "The reviewer did not answer in time"
	reviewerFailedText   = "The reviewer could not evaluate the call"
	didNotRunText        = "; the call did not run."
	cutOffText           = "The call was cut off before it finished and may have run; it was not run again."
	neverStartedText     = "The call was cut off before it started; it did not run."
	rejectedText         = "The call was refused before it ran; it did not run."
	noWorkaroundText     = "Do not pursue the same outcome through a workaround, indirect execution or policy circumvention."
)

// Reasons of the answers the engine makes on its own for a cut-off
// call, which the session recorder writes on the decision.
const (
	decidedOnResumeReason = "not started: decided on resume"
	neverStartedReason    = "not run: the call never started"
	rejectedReason        = "not run: the call was refused before it ran"
	// ranElsewhereReason stands in for the record's word on where a
	// call ran when WithRan gives none.
	ranElsewhereReason = "ran elsewhere"
)

// notRun is what the model reads when a reviewer's timeout or failure
// leaves a call unrun: text and that the call did not run, or, for a
// call that may have run, that it was cut off and was not run again.
func notRun(text string, mayHaveRun bool) string {
	if mayHaveRun {
		return cutOffText + " " + text + "."
	}
	return text + didNotRunText
}

// refusalText is what the model reads for a refusal: denied by policy
// when the reviewer says a rule answered, by reviewer otherwise.
func refusalText(reason, by string) string {
	who := "reviewer"
	if by == ByPolicy {
		who = "policy"
	}
	reason = strings.TrimSuffix(strings.TrimSpace(reason), ".")
	if reason == "" {
		return "Denied by " + who + ". " + noWorkaroundText
	}
	return "Denied by " + who + ": " + reason + ". " + noWorkaroundText
}

// Answers reviews the calls end left pending and returns one Answer
// per call for agentturn's Resume, in the order of end.Pending. An
// approval runs the call inside the loop, with the reviewer's
// arguments when it gave any, and carries the reviewer's note. A
// refusal, a timeout and a review that failed each answer the call
// with a refusal the model reads, and a refusal tells the model not to
// pursue the same outcome by another route; only a cancelled ctx
// returns an error instead of answers. Every answer is a Verdict
// through the observer: Allow for an approval, Block otherwise, with
// the reason and with Verdict.By naming who answered, the reviewer
// through Review.By or the policy for the answers the engine makes on
// its own. The answer names the same decider through
// agentturn.Answer.By, and a refusal, a timeout and a failed review
// carry the verdict's reason through agentturn.Answer.Reason, so the
// session's decision entry says who answered, and why, without the
// verdict beside it.
//
// The reviewer sees each deferred call as the hook saw it, with the
// verdict that deferred it, for the calls the engine asked about in
// that run; a call of a run it has forgotten is reviewed with the call
// alone and a verdict whose Action is Defer and whose Reason is empty.
// A call the engine held for an ask is not reviewed: the policy
// allowed it, and [Engine.Release] answers it from the asked calls'
// answers. A call an abort cut off or one found unanswered in a seeded
// transcript, whose tool may have run, is not reviewed either, and
// does not count toward the bound, unless the policy asks about
// running it again. When its tool says a second run is
// safe, agenttool.ReplaySafe, or safe under its first run's key,
// agenttool.ReplayKeyed, and the pending call carries that key, it is
// decided under the policy of the moment, as [Engine.Decide] decides
// it with its tool's confinement and the [WithHooks] fold but no hold:
// allowed, it is approved and runs again, with that key and any
// arguments a hook rewrote; asked about, it goes to the reviewer with
// that verdict, and counts toward the bound as any review does; and
// denied, it is refused with text that says it may have run and names
// the rule. A call a seeded transcript left may never have been
// decided, since it may have been waiting on the user when the product
// stopped, so a replay is never approved on the tool's word alone. The
// tool is the pending call's, or the one [WithTools] names for a call
// from a seeded transcript. A call the record shows ran to completion
// elsewhere, through [WithRan], is answered with that output before
// the replay rule, by policy, with the record's word on where it ran
// as the reason. When the call was never handed to its tool, pending
// as agentturn.PendingUndispatched, nothing has decided it, and
// agentturn's Resume puts an approval of it to BeforeToolCall as a
// run would: it is approved, by policy, with the reason "not started:
// decided on resume", for the policy to decide there, and that answer
// is no verdict, since the decision on resume is. A call the record
// says never started, through [WithNeverStarted], but that the loop
// lists under another reason is refused with text that says it did
// not run, since Resume would hold an approval of it to the replay
// rule and refuse it. A call pending as agentturn.PendingRejected was
// refused before it ran and is owed that refusal: it is answered, by
// policy, with text that says it was refused and did not run.
// Otherwise it is answered with a refusal that says it may have run,
// so the model decides whether to ask for it again, as is a call
// pending as agentturn.PendingAnswered, which is owed its output and
// cannot run again. A deferred call held after its dispatch is
// reviewed when it may run again, and refused as one that may have
// run when it may not.
//
// A reviewer's non-approval of a call that may have run, one the
// policy asked about running again, tells the model so: the text that
// says it was cut off and was not run again comes first, and a
// timeout and a failed review do not say the call did not run. An
// approval of such a call whose arguments differ from those it would
// otherwise run with, a hook's rewrite or those of the dispatch it
// repeats, is refused the same way, with the reason "not run again:
// the reviewer rewrote the arguments, and replay is X for the
// rewrite", unless its tool says the rewrite is agenttool.ReplaySafe,
// since Resume runs a keyed call again only with the arguments of the
// dispatch it repeats. That refusal is the engine's, not the
// reviewer's, and does not count toward the bound.
//
// When the [DenialBound] is reached, every refusal among the answers
// is built with agentturn.Refuse, so Resume appends the outputs and
// ends the run with StopRefused instead of calling the model, the
// held calls are refused with it, and the answers are returned with
// [ErrDenialBound] so the front can say why. The bound counts across
// calls to Answers until [Engine.ResetReviews].
//
// Answers completes with [Engine.Release], so a pending call it could
// not answer is [ErrUnanswered], returned with the answers and joined
// with [ErrDenialBound] when both hold.
func (e *Engine) Answers(ctx context.Context, r Reviewer, end *agentturn.RunEnd) ([]agentturn.Answer, error) {
	if end == nil || len(end.Pending) == 0 {
		return nil, nil
	}
	if r == nil {
		return nil, errors.New("agentpolicy: no reviewer")
	}
	if agentturn.RunIDFromContext(ctx) == "" {
		// The lookup WithToolsFor names answers for the ended run.
		ctx = agentturn.ContextWithRunID(ctx, end.RunID)
	}
	answers := make([]agentturn.Answer, 0, len(end.Pending))
	bounded := false
	for _, p := range end.Pending {
		call := p.Call
		if call == nil {
			continue
		}
		if p.Reason == agentturn.PendingUndispatched {
			// Nothing decided the call, and Resume puts an approval of
			// it to BeforeToolCall as a run would, so the policy decides
			// it there. That decision is the verdict; one here would say
			// allow for a call the policy may then block.
			answers = append(answers, agentturn.Approve(call.CallID).WithBy(ByPolicy).WithReason(decidedOnResumeReason))
			continue
		}
		if ans, v, ok := e.ranElsewhere(ctx, end.RunID, p); ok {
			answers = append(answers, ans)
			e.observe(ctx, v)
			continue
		}
		var (
			info agentturn.ToolCallInfo
			v    Verdict
			args json.RawMessage
		)
		if e.unreviewed(ctx, p) {
			ans, cv, ask := e.cutOff(ctx, end.RunID, p)
			if ask == nil {
				answers = append(answers, ans)
				e.observe(ctx, cv)
				continue
			}
			info, v, args = ask.info, cv, ask.args
		} else {
			info, v, args = e.recall(end.RunID, p)
			if v.Held {
				continue
			}
		}
		rev, err := r.Review(ctx, info, v)
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		if err == nil && rev.Outcome == Approved && rev.Args == nil {
			rev.Args = args
		}
		if err == nil && rev.Outcome == Approved && p.MayHaveRun() {
			// The reviewer approved a call that may have run with
			// arguments of its own. Resume runs a keyed call again only
			// with the arguments of the dispatch it repeats, so the
			// rewrite runs only when its tool says it is safe to; the
			// refusal is the engine's and does not count toward the
			// bound.
			if ans, verdict, ok := e.rewriteRefused(ctx, p, info, rev.Args, args); ok {
				answers = append(answers, ans)
				e.observe(ctx, verdict)
				continue
			}
		}
		ans, verdict := answer(call, info, rev, err, p.MayHaveRun())
		answers = append(answers, ans)
		if e.note(verdict.Action == agentturn.Allow) {
			bounded = true
		}
		e.observe(ctx, verdict)
	}
	if bounded {
		for i := range answers {
			if answers[i].Output != nil {
				answers[i].Terminate = true
			}
		}
	}
	answers, err := e.Release(ctx, end, answers...)
	switch {
	case bounded && err != nil:
		return answers, errors.Join(ErrDenialBound, err)
	case bounded:
		return answers, ErrDenialBound
	}
	return answers, err
}

// unreviewed reports whether a pending call is answered by cutOff
// rather than by the reviewer: one already answered or refused, and
// one that may have run, unless it was held after its dispatch and may
// run again, which is the reviewer's to approve. A call pending as
// undispatched is approved for the loop to decide before this is
// asked.
func (e *Engine) unreviewed(ctx context.Context, p agentturn.PendingCall) bool {
	switch {
	case p.Reason == agentturn.PendingAnswered, p.Reason == agentturn.PendingRejected:
		return true
	case p.Reason == agentturn.PendingDeferred && p.Dispatched:
		_, again := e.replay(ctx, p)
		return !again
	}
	return p.MayHaveRun()
}

// ranElsewhere answers a call that may have run, a deferred call held
// after its dispatch included, when the record shows it ran to
// completion elsewhere, on a branch a rebase left or in the session
// this one forks: it is owed that output and must not run again, nor
// be reviewed, so it is read before the replay rule and before the
// reviewer. The record is read through [WithRan] until agentturn's
// PendingCall carries the output, as PendingCall.Ran and
// PendingCall.RanWhere; then the loop's word is read first and the
// option second. It reports false for a call the record does not show
// completed.
func (e *Engine) ranElsewhere(ctx context.Context, runID string, p agentturn.PendingCall) (agentturn.Answer, Verdict, bool) {
	if e.ran == nil || !p.MayHaveRun() {
		return agentturn.Answer{}, Verdict{}, false
	}
	call := p.Call
	out, where := e.ran(ctx, runID, call.CallID)
	if out == nil {
		return agentturn.Answer{}, Verdict{}, false
	}
	if where == "" {
		where = ranElsewhereReason
	}
	v := Verdict{RunID: runID, CallID: call.CallID, Tool: call.Name, Action: agentturn.Allow, Reason: where, By: ByPolicy}
	ans := agentturn.Output(&openresponses.FunctionCallOutput{CallID: call.CallID, Status: out.Status, Output: out.Output})
	return ans.WithBy(ByPolicy).WithReason(where), v, true
}

// cutOff answers a call an abort cut off or a seeded transcript left
// unanswered, without a reviewer: refused as never run when the record
// says it never started, answered as refused when a decision refused
// it before it ran, and refused as one that may have run
// when its tool does not say a second run is safe, or keyed with the
// key of its first, or when it was already answered.
//
// A call that may run again is decided first under the policy of the
// moment, as [Engine.Decide] decides it without the hold, since a call
// a seeded transcript left may never have been decided at all: it runs
// again when the policy allows it, is refused as one that may have run
// when the policy denies it, and when the policy asks it is returned
// as a review, for the reviewer to answer with the verdict. A hook
// that fails reads as asking. Each answer carries the verdict's reason,
// which the session recorder writes on its decision.
func (e *Engine) cutOff(ctx context.Context, runID string, p agentturn.PendingCall) (agentturn.Answer, Verdict, *review) {
	call := p.Call
	v := Verdict{RunID: runID, CallID: call.CallID, Tool: call.Name, Action: agentturn.Block, By: ByPolicy}
	refuse := func(text string) (agentturn.Answer, Verdict, *review) {
		return agentturn.Output(openresponses.NewFunctionCallOutput(call.CallID, text)).WithBy(ByPolicy).WithReason(v.Reason), v, nil
	}
	if p.Reason != agentturn.PendingAnswered {
		if p.Reason != agentturn.PendingRejected && e.neverStarted != nil && e.neverStarted(ctx, runID, call.CallID) {
			v.Reason = neverStartedReason
			return refuse(neverStartedText)
		}
		if p.Reason == agentturn.PendingRejected {
			// The call is owed the refusal a decision made before it
			// ran. When agentturn's PendingCall carries that reject's
			// reason, the owed refusal will be written from it.
			v.Reason = rejectedReason
			return refuse(rejectedText)
		}
		if r, again := e.replay(ctx, p); again {
			tool := p.Tool
			if tool == nil {
				tool = e.sibling(ctx, call.Name)
			}
			// The policy decides the arguments the call would run with:
			// those of the dispatch it repeats, which a decision may
			// have rewritten, as Resume runs an approval with them.
			args := pendingArgs(p)
			info := agentturn.ToolCallInfo{RunID: runID, Call: call, Tool: tool, Args: args, Index: -1}
			out, err := e.judge(ctx, e.active(ctx), info, &v)
			if err != nil {
				v.Action, v.Rule, v.Subject, v.By = agentturn.Defer, nil, "", ByPolicy
				v.Reason = call.Name + " hook failed: " + err.Error()
			}
			if v.Action == agentturn.Block {
				text := cutOffText + " " + refusalText(v.Reason, ByPolicy)
				ans := agentturn.Output(openresponses.NewFunctionCallOutput(call.CallID, text)).WithBy(v.By).WithReason(v.Reason)
				return ans, v, nil
			}
			if out.Args != nil && !sameArgs(out.Args, args) {
				// A hook rewrote the arguments again. Resume runs a
				// keyed call again only with the arguments of the
				// dispatch it repeats, so the rewrite runs again only
				// when its tool says the rewrite is safe to.
				if rr := agenttool.ReplayOf(ctx, tool, out.Args); rr != agenttool.ReplaySafe {
					v.Action, v.Rule, v.Subject, v.By = agentturn.Block, nil, "", ByPolicy
					v.Reason = "not run again: a hook rewrote the arguments, and replay is " + rr.String() + " for the rewrite"
					return refuse(cutOffText)
				}
			}
			if out.Args != nil {
				// The verdict is about the rewrite, so a reviewer is
				// shown it, as Decide shows a deferred call's.
				info.Args = out.Args
			}
			if v.Action == agentturn.Defer {
				return agentturn.Answer{}, v, &review{info: info, args: out.Args}
			}
			v.Reason = "run again: replay " + r.String() + "; " + v.Reason
			ans := agentturn.Approve(call.CallID)
			if out.Args != nil {
				ans = agentturn.ApproveWith(call.CallID, out.Args)
			}
			return ans.WithNote(out.Note).WithBy(v.By).WithReason(v.Reason), v, nil
		}
	}
	v.Reason = "not reviewed: " + string(p.Reason)
	return refuse(cutOffText)
}

// review is a cut-off call the policy asks about, for the reviewer:
// the call as the policy decided it, and the arguments a hook
// rewrote, which an approval runs with unless the reviewer gives
// others.
type review struct {
	info agentturn.ToolCallInfo
	args json.RawMessage
}

// rewriteRefused refuses a reviewer's approval of a call that may have
// run when revArgs, the arguments the approval carries, differ both
// from the rewrite a hook gave the call, when one did, and from those
// of the dispatch it repeats, and the call's tool does not say running
// the rewrite is safe: Resume would refuse a keyed
// call run again with other arguments under its dispatch's key. It
// reports false when the approval stands.
func (e *Engine) rewriteRefused(ctx context.Context, p agentturn.PendingCall, info agentturn.ToolCallInfo, revArgs, rewrite json.RawMessage) (agentturn.Answer, Verdict, bool) {
	call := p.Call
	// The approval stands with the arguments a hook rewrote the call
	// to, and with those of the dispatch it repeats, which Resume runs
	// under the dispatch's key: a reviewer that puts a hook's rewrite
	// back rewrote nothing.
	if revArgs == nil || rewrite != nil && sameArgs(revArgs, rewrite) || sameArgs(revArgs, pendingArgs(p)) {
		return agentturn.Answer{}, Verdict{}, false
	}
	tool := p.Tool
	if tool == nil {
		tool = info.Tool
	}
	if tool == nil {
		tool = e.sibling(ctx, call.Name)
	}
	rr := agenttool.ReplayUnknown
	if tool != nil {
		rr = agenttool.ReplayOf(ctx, tool, revArgs)
	}
	if rr == agenttool.ReplaySafe {
		return agentturn.Answer{}, Verdict{}, false
	}
	v := Verdict{RunID: info.RunID, Turn: info.Turn, CallID: call.CallID, Tool: call.Name, Action: agentturn.Block, By: ByPolicy}
	v.Reason = "not run again: the reviewer rewrote the arguments, and replay is " + rr.String() + " for the rewrite"
	ans := agentturn.Output(openresponses.NewFunctionCallOutput(call.CallID, cutOffText)).WithBy(ByPolicy).WithReason(v.Reason)
	return ans, v, true
}

// replay returns what the call's tool says of running it again, the
// pending call's tool or the one WithTools names, and whether
// agentturn's Resume will run it: a safe replay, or a keyed one whose
// first key the loop carries.
func (e *Engine) replay(ctx context.Context, p agentturn.PendingCall) (agenttool.Replay, bool) {
	tool := p.Tool
	if tool == nil {
		tool = e.sibling(ctx, p.Call.Name)
	}
	if tool == nil {
		return agenttool.ReplayUnknown, false
	}
	r := agenttool.ReplayOf(ctx, tool, pendingArgs(p))
	return r, r == agenttool.ReplaySafe || r == agenttool.ReplayKeyed && p.IdempotencyKey != ""
}

// pendingArgs returns the arguments a pending call runs with when it
// is approved without arguments of its own: those of the dispatch it
// repeats, which a decision may have rewritten, else the model's.
func pendingArgs(p agentturn.PendingCall) json.RawMessage {
	if len(p.Args) == 0 {
		return callArgs(p.Call)
	}
	return p.Args
}

// sameArgs reports whether two argument objects are the same JSON
// value, whatever their spelling, as Resume compares them.
func sameArgs(a, b json.RawMessage) bool {
	x, errX := decodeNumbers(a)
	y, errY := decodeNumbers(b)
	if errX != nil || errY != nil {
		return bytes.Equal(a, b)
	}
	return reflect.DeepEqual(x, y)
}

// decodeNumbers decodes raw keeping numbers as written, so two integers
// past float64's precision are not taken for the same one.
func decodeNumbers(raw json.RawMessage) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// recall returns what the engine remembers of a deferred call of the
// run, or the call alone, and the arguments a hook rewrote it to, nil
// when none did. A call the engine does not remember, one deferred
// before a restart, carries the loop's own record of a rewrite on
// PendingCall.Args.
func (e *Engine) recall(runID string, p agentturn.PendingCall) (agentturn.ToolCallInfo, Verdict, json.RawMessage) {
	call := p.Call
	e.mu.Lock()
	defer e.mu.Unlock()
	if d, ok := e.deferred[runID][call.CallID]; ok {
		return d.info, d.verdict, d.args
	}
	args := callArgs(call)
	if p.Args != nil {
		args = p.Args
	}
	return agentturn.ToolCallInfo{RunID: runID, Call: call, Args: args},
		Verdict{RunID: runID, CallID: call.CallID, Tool: call.Name, Action: agentturn.Defer, By: ByPolicy},
		p.Args
}

// answer turns one review into the answer the loop takes and the
// verdict the observer records. mayHaveRun says the call was cut off
// and may have run, so a refusal, a timeout and a failed review tell
// the model so rather than that the call did not run. Each of those
// carries the verdict's reason, for the session's decision entry.
func answer(call *openresponses.FunctionCall, info agentturn.ToolCallInfo, rev Review, err error, mayHaveRun bool) (agentturn.Answer, Verdict) {
	v := Verdict{RunID: info.RunID, Turn: info.Turn, CallID: call.CallID, Tool: call.Name, Action: agentturn.Block, By: by(rev)}
	refuse := func(text string) agentturn.Answer {
		return agentturn.Output(openresponses.NewFunctionCallOutput(call.CallID, text)).WithBy(v.By).WithReason(v.Reason)
	}
	switch {
	case err != nil:
		v.Reason = "reviewer failed: " + err.Error()
		v.By = ByPolicy
		return refuse(notRun(reviewerFailedText, mayHaveRun)), v
	case rev.Outcome == Approved:
		v.Action = agentturn.Allow
		v.Reason = withReason("approved by reviewer", rev.Reason)
		if rev.Args != nil {
			return agentturn.ApproveWith(call.CallID, rev.Args).WithNote(rev.Note).WithBy(v.By), v
		}
		return agentturn.Approve(call.CallID).WithNote(rev.Note).WithBy(v.By), v
	case rev.Outcome == TimedOut:
		v.Reason = "reviewer timed out"
		v.By = ByPolicy
		return refuse(notRun(reviewerTimedOutText, mayHaveRun)), v
	}
	v.Reason = withReason("denied by reviewer", rev.Reason)
	text := refusalText(rev.Reason, v.By)
	if mayHaveRun {
		text = cutOffText + " " + text
	}
	return refuse(text).WithNote(rev.Note), v
}

// by names who a review came from: the reviewer's own word, or the
// agent, since a Reviewer answers where a human would. The verdict and
// the answer both carry it.
func by(rev Review) string {
	if rev.By == "" {
		return ByAgent
	}
	return rev.By
}

func withReason(text, reason string) string {
	if reason == "" {
		return text
	}
	return text + ": " + reason
}

// note records one review's outcome and reports whether the bound is
// reached.
func (e *Engine) note(approved bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	b := e.bound
	if approved {
		e.reviews.consecutive = 0
	} else {
		e.reviews.consecutive++
	}
	if b.Window > 0 {
		e.reviews.refused = append(e.reviews.refused, !approved)
		if len(e.reviews.refused) > b.Window {
			e.reviews.refused = e.reviews.refused[1:]
		}
	}
	if b.Consecutive > 0 && e.reviews.consecutive >= b.Consecutive {
		return true
	}
	if b.Total > 0 && b.Window > 0 {
		refused := 0
		for _, r := range e.reviews.refused {
			if r {
				refused++
			}
		}
		if refused >= b.Total {
			return true
		}
	}
	return false
}

// ResetReviews forgets the refusals the denial bound counts, as Codex
// does at each new user message. A front calls it before the prompt
// that starts a new turn.
func (e *Engine) ResetReviews() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reviews = reviewLog{}
}
