package agentpolicy

import (
	"context"

	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
)

// What the model reads for a held call that was not released.
const heldStoppedText = "The call was held for an approval and the turn was stopped; the call did not run."

// Deferred returns the verdict that deferred the call in the run in
// progress, asked or held, so a front can show why a pending call
// waits and tell the calls it must answer, the asked ones, from the
// ones [Engine.Release] answers, the held ones. It reports false for
// a call the engine did not defer or has forgotten.
func (e *Engine) Deferred(callID string) (Verdict, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	d, ok := e.deferred[callID]
	return d.verdict, ok
}

// Release answers the calls end left pending that the engine held for
// an ask, given the answers to the calls it asked about, and returns
// every answer for agentturn's Resume in the order of end.Pending, the
// model's order, which is the order a sequential batch runs in. The
// policy allowed a held call, so it is approved and runs with the
// batch, unless an answer ends the run, one built with
// agentturn.Refuse, in which case the held call is answered with a
// refusal the model reads, since the turn is over. A held call the
// given answers already cover keeps its answer, and one from a run
// the engine has forgotten is left for the caller, as is an answer
// for a call that is not pending. Every release is a Verdict through
// the observer with Held set: Allow with the rule that allowed the
// call, or Block when the turn was stopped.
func (e *Engine) Release(ctx context.Context, end *agentturn.RunEnd, answers ...agentturn.Answer) []agentturn.Answer {
	if end == nil {
		return answers
	}
	given := make(map[string]int, len(answers))
	stopped := false
	for i, a := range answers {
		given[a.CallID] = i
		stopped = stopped || a.Terminate
	}
	out := make([]agentturn.Answer, 0, len(end.Pending))
	placed := make(map[string]bool, len(answers))
	for _, p := range end.Pending {
		if p.Call == nil {
			continue
		}
		id := p.Call.CallID
		if i, ok := given[id]; ok {
			out = append(out, answers[i])
			placed[id] = true
			continue
		}
		d, ok := e.held(end.RunID, id)
		if !ok {
			continue
		}
		v := Verdict{RunID: d.info.RunID, Turn: d.info.Turn, CallID: id, Tool: p.Call.Name, Held: true}
		if stopped {
			v.Action, v.Reason = agentturn.Block, "not released: the turn was stopped"
			out = append(out, agentturn.Output(openresponses.NewFunctionCallOutput(id, heldStoppedText)))
		} else {
			v.Action, v.Rule, v.Reason = agentturn.Allow, d.verdict.Rule, "released: "+d.allowed
			out = append(out, agentturn.Approve(id))
		}
		e.observe(ctx, v)
	}
	for _, a := range answers {
		if !placed[a.CallID] {
			out = append(out, a)
		}
	}
	return out
}

// held returns what the engine remembers of a held call of the run.
func (e *Engine) held(runID, callID string) (deferredCall, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	d, ok := e.deferred[callID]
	if !ok || !d.verdict.Held || e.runID != runID {
		return deferredCall{}, false
	}
	return d, true
}
