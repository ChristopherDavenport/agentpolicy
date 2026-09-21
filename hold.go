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
// the engine did not defer, one of another run, and one already
// answered: [Engine.Release] and [Engine.Answers] forget a call as
// they answer it, and a product that records a verdict does so from
// the observer.
func (e *Engine) Deferred(runID, callID string) (Verdict, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	d, ok := e.deferred[runID][callID]
	return d.verdict, ok
}

// Forget drops what the engine remembers of a run: the calls it
// deferred there and never answered. A front calls it when a run ends
// without its pending calls being answered, an abandoned conversation
// or a sub-agent that was cancelled, so the engine does not hold them
// for the life of the process. [Engine.Release] and [Engine.Answers]
// forget the calls they answer on their own, so a run answered through
// either needs no Forget.
func (e *Engine) Forget(runID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.deferred, runID)
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

// Release answers the calls end left pending that the engine held for
// an ask, given the answers to the calls it asked about, and returns
// every answer for agentturn's Resume in the order of end.Pending, the
// model's order, which is the order a sequential batch runs in. The
// policy allowed a held call, so it is approved and runs with the
// batch, unless an answer ends the run, one built with
// agentturn.Refuse, in which case the held call is answered with a
// refusal the model reads, since the turn is over. A held call the
// given answers already cover keeps its answer, and an answer for a
// call that is not pending is returned after the rest. Every release
// is a Verdict through the observer with Held set: Allow with the rule
// that allowed the call, or Block when the turn was stopped.
//
// A pending call neither the caller nor the engine answers is
// [ErrUnanswered], returned with the answers and naming the call,
// since Resume would otherwise fail with the loop's own error and
// nothing would say which call was missed. It is what a front sees
// when it answers the wrong run, or when another hook deferred a call
// the engine never saw.
//
// The calls it answers are forgotten: the run's entry is dropped as
// its last deferred call is answered, so an engine shared by several
// agents does not grow with the runs they finish.
func (e *Engine) Release(ctx context.Context, end *agentturn.RunEnd, answers ...agentturn.Answer) ([]agentturn.Answer, error) {
	if end == nil {
		return answers, nil
	}
	given := make(map[string]int, len(answers))
	stopped := false
	for i, a := range answers {
		given[a.CallID] = i
		stopped = stopped || a.Terminate
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
			out = append(out, answers[i])
			placed[id] = true
			e.answered(end.RunID, id)
			continue
		}
		d, ok := e.held(end.RunID, id)
		if !ok {
			missed = append(missed, id+" ("+p.Call.Name+")")
			continue
		}
		v := Verdict{RunID: d.info.RunID, Turn: d.info.Turn, CallID: id, Tool: p.Call.Name, Action: agentturn.Allow, Held: true, By: ByPolicy}
		if stopped {
			v.Action, v.Reason = agentturn.Block, "not released: the turn was stopped"
			out = append(out, agentturn.Output(openresponses.NewFunctionCallOutput(id, heldStoppedText)))
		} else {
			v.Rule, v.Reason = d.verdict.Rule, "released: "+d.allowed
			out = append(out, agentturn.Approve(id))
		}
		e.answered(end.RunID, id)
		e.observe(ctx, v)
	}
	for _, a := range answers {
		if !placed[a.CallID] {
			out = append(out, a)
		}
	}
	if len(missed) > 0 {
		return out, fmt.Errorf("%w: %s", ErrUnanswered, strings.Join(missed, ", "))
	}
	return out, nil
}

// held returns what the engine remembers of a held call of the run.
func (e *Engine) held(runID, callID string) (deferredCall, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	d, ok := e.deferred[runID][callID]
	if !ok || !d.verdict.Held {
		return deferredCall{}, false
	}
	return d, true
}
