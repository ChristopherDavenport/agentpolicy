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
}

// Reviewer answers a deferred call without a human: Codex's
// auto-review, a rule of the product's, or a test double. It receives
// the call as the hook saw it and the verdict that deferred it. A
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

// What the model reads when a reviewer does not approve.
const (
	reviewerTimedOutText = "The reviewer did not answer in time; the call did not run."
	reviewerFailedText   = "The reviewer could not evaluate the call; the call did not run."
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
// per call, in the order of end.Pending, for agentturn's Resume. An
// approval runs the call inside the loop, with the reviewer's
// arguments when it gave any. A refusal, a timeout and a review that
// failed each answer the call with a refusal the model reads, and a
// refusal tells the model not to pursue the same outcome by another
// route; only a cancelled ctx returns an error instead of answers.
// Every answer is a Verdict through the observer: Allow for an
// approval, Block otherwise, with the reason.
//
// The reviewer sees each call as the hook saw it, with the verdict
// that deferred it, for the calls the engine deferred in the run in
// progress; a call it did not defer, one an abort cut off or one from
// a run it has forgotten, is reviewed with the call alone and a
// verdict whose Action is Defer and whose Reason is empty.
//
// When the [DenialBound] is reached the answers are returned with
// [ErrDenialBound], so the front can end the run instead of resuming
// it. The bound counts across calls to Answers until
// [Engine.ResetReviews].
func (e *Engine) Answers(ctx context.Context, r Reviewer, end *agentturn.RunEnd) ([]agentturn.Answer, error) {
	if end == nil || len(end.Pending) == 0 {
		return nil, nil
	}
	if r == nil {
		return nil, errors.New("agentpolicy: no reviewer")
	}
	answers := make([]agentturn.Answer, 0, len(end.Pending))
	bounded := false
	for _, call := range end.Pending {
		info, v := e.recall(end.RunID, call)
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
		return answers, ErrDenialBound
	}
	return answers, nil
}

// recall returns what the engine remembers of a deferred call, or the
// call alone.
func (e *Engine) recall(runID string, call *openresponses.FunctionCall) (agentturn.ToolCallInfo, Verdict) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if d, ok := e.deferred[call.CallID]; ok {
		return d.info, d.verdict
	}
	args := json.RawMessage(call.Arguments)
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	return agentturn.ToolCallInfo{RunID: runID, Call: call, Args: args},
		Verdict{RunID: runID, CallID: call.CallID, Tool: call.Name, Action: agentturn.Defer}
}

// answer turns one review into the answer the loop takes and the
// verdict the observer records.
func answer(call *openresponses.FunctionCall, info agentturn.ToolCallInfo, rev Review, err error) (agentturn.Answer, Verdict) {
	v := Verdict{RunID: info.RunID, Turn: info.Turn, CallID: call.CallID, Tool: call.Name, Action: agentturn.Block}
	refuse := func(text string) agentturn.Answer {
		return agentturn.Output(openresponses.NewFunctionCallOutput(call.CallID, text))
	}
	switch {
	case err != nil:
		v.Reason = "reviewer failed: " + err.Error()
		return refuse(reviewerFailedText), v
	case rev.Outcome == Approved:
		v.Action = agentturn.Allow
		v.Reason = withReason("approved by reviewer", rev.Reason)
		if rev.Args != nil {
			return agentturn.ApproveWith(call.CallID, rev.Args), v
		}
		return agentturn.Approve(call.CallID), v
	case rev.Outcome == TimedOut:
		v.Reason = "reviewer timed out"
		return refuse(reviewerTimedOutText), v
	}
	v.Reason = withReason("denied by reviewer", rev.Reason)
	return refuse(refusalText(rev.Reason)), v
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
