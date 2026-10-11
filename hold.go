package agentpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
)

// What the model reads for a held call that was not released.
const heldStoppedText = "The call was held for an approval and the turn was stopped; the call did not run."

// ErrUnanswered is returned by [Engine.Release], with the answers it
// built, when a call the run left pending has no answer: the caller
// did not answer it and the engine did not hold it, so resuming with
// the answers would fail. The error names every such call.
var ErrUnanswered = errors.New("agentpolicy: pending call has no answer")

// Deferred returns the verdict that deferred the call in the run,
// asked or held, so a front can show why a pending call waits and tell
// the calls it must answer, the asked ones, from the ones
// [Engine.Release] answers, the held ones. It reports false for a call
// the engine did not defer, one of another run, and one a resumed run
// has taken: [Engine.Resumed] forgets a call once the run that resumed
// it no longer lists it as pending, and a product that records a
// verdict does so from the observer.
func (e *Engine) Deferred(runID, callID string) (Verdict, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	d, ok := e.deferred[runID][callID]
	return d.verdict, ok
}

// Forget drops what the engine remembers of a run: the calls it
// deferred there and never answered, what [Engine.Answers] decided
// about them and no resumed run took, and what [WithAskInRun] asked in
// it. A front calls it when a run ends without its pending calls being
// answered, an abandoned conversation or a sub-agent that was
// cancelled, so the engine does not hold them for the life of the
// process. [Engine.Resumed] forgets the calls a resumed run took, so a
// run answered and resumed needs no Forget.
func (e *Engine) Forget(runID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.deferred, runID)
	delete(e.answering, runID)
	e.dropAsked(runID)
}

// Runs returns the runs the engine is holding deferred calls for, so a
// product can see what it has not answered.
func (e *Engine) Runs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.deferred))
	for id := range e.deferred {
		out = append(out, id)
	}
	return out
}

// remember records a call the engine deferred, under its own run.
func (e *Engine) remember(runID, callID string, d deferredCall) {
	e.mu.Lock()
	defer e.mu.Unlock()
	calls := e.deferred[runID]
	if calls == nil {
		calls = make(map[string]deferredCall)
		e.deferred[runID] = calls
	}
	calls[callID] = d
}

// answered forgets one call of a run, and the run when it was its
// last, so the engine's memory is bounded by the calls still waiting.
func (e *Engine) answered(runID, callID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	calls := e.deferred[runID]
	if calls == nil {
		return
	}
	delete(calls, callID)
	if len(calls) == 0 {
		delete(e.deferred, runID)
	}
}

// heldPrefix starts the reason of a held call's deferral; what follows
// it is the reason the policy allowed the call.
const heldPrefix = "held for approval: "

// Release answers the calls end left pending that the engine held for
// an ask, given the answers to the calls it asked about, and returns
// every answer for agentturn's Resume in the order of end.Pending, the
// model's order, which is the order a sequential batch runs in. The
// policy allowed a held call, so it is approved and runs with the
// batch, with the arguments a hook given to [WithHooks] rewrote it to,
// unless an answer ends the run, one built with
// agentturn.Refuse, in which case the held call is answered with a
// refusal the model reads, since the turn is over. A held call the
// given answers already cover keeps its answer, and an answer for a
// call that is not pending is returned after the rest.
// Every answer the engine builds names the policy as its decider,
// through agentturn.Answer.By, and carries the verdict's reason,
// "released: <why the policy allowed it>" or "not released: the turn
// was stopped by the answer to <call ID> (<subject or tool>)", naming
// the call whose answer ended the run, through agentturn.Answer.Reason,
// which the session recorder writes on the call's decision; the
// caller's answers are returned as given. A plain refusal, one that
// does not end the run, refuses its own call alone: the held calls are
// released beside it.
//
// A call is held when the deferral that left it pending says so:
// what the engine remembers of it in this process, or else
// agentturn.PendingCall.Decision with Held set, which the loop carries
// on the run's end and agentturn/session reads back from the record.
// So an end read back after a restart, or over a wire, is released
// as the one the engine saw, and the arguments a hook rewrote the
// call to travel as the pending call's Args, which Resume runs an
// approval with.
//
// Release changes nothing: it forgets no call and reports no verdict,
// so a Resume that then does not start leaves the engine as it was,
// and the front answers again and releases again. [Engine.Resumed]
// is the second phase: given the end the resumed run returned, it
// forgets the calls that run took and reports each release as a
// Verdict through the observer.
//
// A pending call neither the caller nor the engine answers is
// [ErrUnanswered], returned with the answers and naming the call,
// since Resume would otherwise fail with the loop's own error and
// nothing would say which call was missed. It is what a front sees
// when it answers the wrong run, when another hook deferred a call
// the engine never saw, or when it releases before every asked call is
// answered; the front answers the missing call and releases again.
func (e *Engine) Release(ctx context.Context, end *agentturn.RunEnd, answers ...agentturn.Answer) ([]agentturn.Answer, error) {
	if end == nil {
		return answers, nil
	}
	given := make(map[string]int, len(answers))
	stopped, stopper := false, ""
	for i, a := range answers {
		given[a.CallID] = i
		if a.Terminate && !stopped {
			stopped, stopper = true, a.CallID
		}
	}
	stopReason := ""
	if stopped {
		stopReason = stoppedReason(stopper, about(end, stopper))
	}
	out := make([]agentturn.Answer, 0, len(end.Pending))
	placed := make(map[string]bool, len(answers))
	var missed []string
	for _, p := range end.Pending {
		if p.Call == nil {
			continue
		}
		id := p.Call.CallID
		if i, ok := given[id]; ok {
			if !placed[id] {
				out = append(out, answers[i])
				placed[id] = true
			}
			continue
		}
		if placed[id] {
			// A call listed twice is answered once.
			continue
		}
		d, ok := e.heldCall(end.RunID, p)
		if !ok {
			missed = append(missed, id+" ("+p.Call.Name+")")
			continue
		}
		placed[id] = true
		if stopped {
			out = append(out, agentturn.Output(openresponses.NewFunctionCallOutput(id, heldStoppedText)).WithBy(ByPolicy).WithReason(stopReason))
			continue
		}
		ans := agentturn.Approve(id)
		if d.args != nil {
			ans = agentturn.ApproveWith(id, d.args)
		}
		// A hook's note on the call is the decision's, which the loop
		// says itself when the approval releases the call; on the
		// answer it would be said twice.
		out = append(out, ans.WithBy(ByPolicy).WithReason(releasedPrefix+d.allowed))
	}
	for _, a := range answers {
		if !placed[a.CallID] {
			out = append(out, a)
			placed[a.CallID] = true
		}
	}
	if len(missed) > 0 {
		return out, fmt.Errorf("%w: %s", ErrUnanswered, strings.Join(missed, ", "))
	}
	return out, nil
}

// The reasons of a release's verdicts and answers.
const (
	releasedPrefix    = "released: "
	notReleasedReason = "not released: the turn was stopped"
)

// stoppedReason is the reason a held call is not released: the turn was
// stopped by the answer to the call callID, which asked about about.
func stoppedReason(callID, about string) string {
	if callID == "" {
		return notReleasedReason
	}
	r := notReleasedReason + " by the answer to " + callID
	if about != "" {
		r += " (" + about + ")"
	}
	return r
}

// about is what the policy asked about the pending call callID of end:
// its decision's subject, or else its tool.
func about(end *agentturn.RunEnd, callID string) string {
	for _, p := range end.Pending {
		if p.Call == nil || p.Call.CallID != callID {
			continue
		}
		if p.Decision != nil && p.Decision.Subject != "" {
			return p.Decision.Subject
		}
		return p.Call.Name
	}
	return ""
}

// Resumed is the second phase of [Engine.Release] and [Engine.Answers]:
// a front calls it once Resume returns, given the end it resumed, the
// answers it resumed with and the end the resumed run returned, next.
// It settles every call of end the answers answer that next no longer
// lists as pending: it forgets the call, so an engine shared by several
// agents does not grow with the runs they finish, and reports what was
// decided about it through the observer: a release the answers carry,
// with Held set, Allow or Block when the turn was stopped, and the
// answer's reason; and the verdict [Engine.Answers] reached for it,
// counted toward the [DenialBound] only now. A release is an answer the
// engine built, one naming the policy as its decider, for a call the
// engine or the call's decision says was held; an answer the front
// gave a held call itself reports nothing, since the front's own
// decision is its record.
//
// A call next still lists as pending did not run: a Resume whose run
// failed before it took the answers returns an end with the calls
// still pending, and one whose hook deferred the call again leaves it
// waiting. Such a call is neither forgotten nor reported, so the front
// answers it again and releases again, and nothing is reported twice.
// A nil next, a Resume that returned no end, settles nothing.
func (e *Engine) Resumed(ctx context.Context, end *agentturn.RunEnd, answers []agentturn.Answer, next *agentturn.RunEnd) {
	if end == nil || next == nil {
		return
	}
	pending := make(map[string]agentturn.PendingCall, len(end.Pending))
	for _, p := range end.Pending {
		if p.Call != nil {
			pending[p.Call.CallID] = p
		}
	}
	still := make(map[string]bool, len(next.Pending))
	for _, p := range next.Pending {
		if p.Call != nil {
			still[p.Call.CallID] = true
		}
	}
	var (
		report   []Verdict
		reviewed []bool
		settled  []string
	)
	seen := make(map[string]bool, len(answers))
	for _, a := range answers {
		p, ok := pending[a.CallID]
		if !ok || seen[a.CallID] || still[a.CallID] {
			continue
		}
		seen[a.CallID] = true
		settled = append(settled, a.CallID)
		if r, ok := e.takeAnswered(end.RunID, a.CallID); ok {
			report = append(report, r.verdict)
			if r.reviewed {
				reviewed = append(reviewed, r.verdict.Action == agentturn.Allow)
			}
			continue
		}
		if a.By != ByPolicy {
			continue
		}
		d, held := e.heldCall(end.RunID, p)
		if !held {
			continue
		}
		v := Verdict{RunID: end.RunID, Turn: d.info.Turn, CallID: a.CallID, Tool: p.Call.Name, Action: agentturn.Allow, Held: true, By: ByPolicy, Subject: d.verdict.Subject, Confined: d.verdict.Confined, Reason: a.Reason}
		if a.Output != nil {
			v.Action = agentturn.Block
			if v.Reason == "" {
				v.Reason = notReleasedReason
			}
		} else {
			v.Rule = d.verdict.Rule
			if v.Reason == "" {
				v.Reason = releasedPrefix + d.allowed
			}
		}
		report = append(report, v)
	}
	for _, id := range settled {
		e.answered(end.RunID, id)
	}
	e.mu.Lock()
	e.dropAsked(end.RunID)
	e.mu.Unlock()
	for _, approved := range reviewed {
		e.note(approved)
	}
	for _, v := range report {
		e.observe(ctx, v)
	}
}

// heldCall returns what is known of a pending call held for an ask:
// what the engine remembers of it, or else what its decision carries.
// A call the engine remembers as asked is not held, whatever a
// decision says.
func (e *Engine) heldCall(runID string, p agentturn.PendingCall) (deferredCall, bool) {
	e.mu.Lock()
	d, known := e.deferred[runID][p.Call.CallID]
	e.mu.Unlock()
	if known {
		return d, d.verdict.Held
	}
	dec := p.Decision
	if dec == nil || !dec.Held || dec.Action != agentturn.Defer {
		return deferredCall{}, false
	}
	// What the recorded decision says, its reason, subject and decider,
	// is what is known of the verdict after a restart; the rule and the
	// confinement were the engine's and are not on the record.
	by := dec.By
	if by == "" {
		by = ByPolicy
	}
	return deferredCall{
		verdict: Verdict{Held: true, Action: agentturn.Defer, Reason: dec.Reason, Subject: dec.Subject, By: by},
		allowed: strings.TrimPrefix(dec.Reason, heldPrefix),
	}, true
}
