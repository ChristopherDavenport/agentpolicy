package agentpolicy

import (
	"context"
	"encoding/json"
	"errors"
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
// record shows never started.
func WithNeverStarted(fn func(ctx context.Context, runID, callID string) bool) Option {
	return func(e *Engine) { e.neverStarted = fn }
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
// call no reviewer sees.
const (
	reviewerTimedOutText = "The reviewer did not answer in time; the call did not run."
	reviewerFailedText   = "The reviewer could not evaluate the call; the call did not run."
	cutOffText           = "The call was cut off before it finished and may have run; it was not run again."
	neverStartedText     = "The call was cut off before it started; it did not run."
	noWorkaroundText     = "Do not pursue the same outcome through a workaround, indirect execution or policy circumvention."
)

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
// agentturn.Answer.By, so the session's decision entry says who
// answered without the verdict beside it.
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
// from a seeded transcript. When it was never handed to its tool,
// pending as agentturn.PendingUndispatched, or the record says it never started,
// through [WithNeverStarted], it is answered with a refusal that says
// it did not run. Otherwise it is answered with a refusal that says it
// may have run, so the model decides whether to ask for it again, as
// is a call pending as agentturn.PendingAnswered, which is owed its
// output and cannot run again. A deferred call held after its dispatch
// is reviewed when it may run again, and refused as one that may have
// run when it may not.
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
	answers := make([]agentturn.Answer, 0, len(end.Pending))
	bounded := false
	for _, p := range end.Pending {
		call := p.Call
		if call == nil {
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
			info, v = e.recall(end.RunID, call)
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
		ans, verdict := answer(call, info, rev, err)
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
// rather than by the reviewer: one that never started or was already
// answered, and one that may have run, unless it was held after its
// dispatch and may run again, which is the reviewer's to approve.
func (e *Engine) unreviewed(ctx context.Context, p agentturn.PendingCall) bool {
	switch {
	case p.Reason == agentturn.PendingUndispatched, p.Reason == agentturn.PendingAnswered:
		return true
	case p.Reason == agentturn.PendingDeferred && p.Dispatched:
		_, again := e.replay(ctx, p)
		return !again
	}
	return p.MayHaveRun()
}

// cutOff answers a call an abort cut off or a seeded transcript left
// unanswered, without a reviewer: refused as never run when it was not
// handed to its tool, and refused as one that may have run when its
// tool does not say a second run is safe, or keyed with the key of its
// first, or when it was already answered.
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
		if p.Reason == agentturn.PendingUndispatched || e.neverStarted != nil && e.neverStarted(ctx, runID, call.CallID) {
			v.Reason = "not run: the call never started"
			return refuse(neverStartedText)
		}
		if r, again := e.replay(ctx, p); again {
			tool := p.Tool
			if tool == nil {
				tool = e.sibling(call.Name)
			}
			info := agentturn.ToolCallInfo{RunID: runID, Call: call, Tool: tool, Args: callArgs(call), Index: -1}
			out, err := e.judge(ctx, e.active(), info, &v)
			if err != nil {
				v.Action, v.Rule, v.Subject, v.By = agentturn.Defer, nil, "", ByPolicy
				v.Reason = call.Name + " hook failed: " + err.Error()
			}
			switch v.Action {
			case agentturn.Block:
				text := cutOffText + " " + refusalText(v.Reason, ByPolicy)
				ans := agentturn.Output(openresponses.NewFunctionCallOutput(call.CallID, text)).WithBy(v.By).WithReason(v.Reason)
				return ans, v, nil
			case agentturn.Defer:
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

// replay returns what the call's tool says of running it again, the
// pending call's tool or the one WithTools names, and whether
// agentturn's Resume will run it: a safe replay, or a keyed one whose
// first key the loop carries.
func (e *Engine) replay(ctx context.Context, p agentturn.PendingCall) (agenttool.Replay, bool) {
	tool := p.Tool
	if tool == nil {
		tool = e.sibling(p.Call.Name)
	}
	if tool == nil {
		return agenttool.ReplayUnknown, false
	}
	r := agenttool.ReplayOf(ctx, tool, callArgs(p.Call))
	return r, r == agenttool.ReplaySafe || r == agenttool.ReplayKeyed && p.IdempotencyKey != ""
}

// recall returns what the engine remembers of a deferred call of the
// run, or the call alone.
func (e *Engine) recall(runID string, call *openresponses.FunctionCall) (agentturn.ToolCallInfo, Verdict) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if d, ok := e.deferred[runID][call.CallID]; ok {
		return d.info, d.verdict
	}
	return agentturn.ToolCallInfo{RunID: runID, Call: call, Args: callArgs(call)},
		Verdict{RunID: runID, CallID: call.CallID, Tool: call.Name, Action: agentturn.Defer, By: ByPolicy}
}

// answer turns one review into the answer the loop takes and the
// verdict the observer records.
func answer(call *openresponses.FunctionCall, info agentturn.ToolCallInfo, rev Review, err error) (agentturn.Answer, Verdict) {
	v := Verdict{RunID: info.RunID, Turn: info.Turn, CallID: call.CallID, Tool: call.Name, Action: agentturn.Block, By: by(rev)}
	refuse := func(text string) agentturn.Answer {
		return agentturn.Output(openresponses.NewFunctionCallOutput(call.CallID, text))
	}
	switch {
	case err != nil:
		v.Reason = "reviewer failed: " + err.Error()
		v.By = ByPolicy
		return refuse(reviewerFailedText).WithBy(ByPolicy), v
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
		return refuse(reviewerTimedOutText).WithBy(ByPolicy), v
	}
	v.Reason = withReason("denied by reviewer", rev.Reason)
	return refuse(refusalText(rev.Reason, v.By)).WithNote(rev.Note).WithBy(v.By), v
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
