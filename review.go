package agentpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

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
	// [Engine.Answers] puts it on the verdict, and it is what the
	// answer itself will carry once agentturn's Answer names a
	// decider; the engine's own fail-closed answers, a timeout and a
	// review that failed, are [ByPolicy].
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
	noWorkaroundText     = "Do not pursue the same outcome through a workaround, indirect execution or policy circumvention."
)

// refusalText is what the model reads for a refusal.
func refusalText(reason string) string {
	reason = strings.TrimSuffix(strings.TrimSpace(reason), ".")
	if reason == "" {
		return "Denied by reviewer. " + noWorkaroundText
	}
	return "Denied by reviewer: " + reason + ". " + noWorkaroundText
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
// its own.
//
// The reviewer sees each deferred call as the hook saw it, with the
// verdict that deferred it, for the calls the engine asked about in
// that run; a call of a run it has forgotten is reviewed with the call
// alone and a verdict whose Action is Defer and whose Reason is empty.
// A call the engine held for an ask is not reviewed: the policy
// allowed it, and [Engine.Release] answers it from the asked calls'
// answers. A call an abort cut off or one found
// unanswered in a seeded transcript, whose tool may have run, is not
// reviewed either: it is answered with a refusal that says so, and
// does not count toward the bound, so the model decides whether to
// ask for it again.
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
		if p.Reason == agentturn.PendingAborted || p.Reason == agentturn.PendingUnknown {
			answers = append(answers, agentturn.Output(openresponses.NewFunctionCallOutput(call.CallID, cutOffText)))
			e.observe(ctx, Verdict{RunID: end.RunID, CallID: call.CallID, Tool: call.Name, Action: agentturn.Block, Reason: "not reviewed: " + string(p.Reason), By: ByPolicy})
			continue
		}
		info, v := e.recall(end.RunID, call)
		if v.Held {
			continue
		}
		rev, err := r.Review(ctx, info, v)
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
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
		return refuse(reviewerFailedText), v
	case rev.Outcome == Approved:
		v.Action = agentturn.Allow
		v.Reason = withReason("approved by reviewer", rev.Reason)
		if rev.Args != nil {
			return agentturn.ApproveWith(call.CallID, rev.Args).WithNote(rev.Note), v
		}
		return agentturn.Approve(call.CallID).WithNote(rev.Note), v
	case rev.Outcome == TimedOut:
		v.Reason = "reviewer timed out"
		v.By = ByPolicy
		return refuse(reviewerTimedOutText), v
	}
	v.Reason = withReason("denied by reviewer", rev.Reason)
	return refuse(refusalText(rev.Reason)).WithNote(rev.Note), v
}

// by names who a review came from: the reviewer's own word, or the
// agent, since a Reviewer answers where a human would. It is what the
// answer will carry once agentturn's Answer names a decider; until
// then it reaches the session through the verdict.
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
