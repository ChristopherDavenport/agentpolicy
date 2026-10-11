package agentpolicy

import (
	"context"
	"encoding/json"

	"github.com/ChristopherDavenport/agenttool"
	"github.com/ChristopherDavenport/agentturn"
)

// WithAskInRun has [Engine.Decide] ask the person about a model's call
// while the run waits, rather than deferring it to the run's end: the
// way a product that approves every call in place, as Cline does,
// drives the engine. At the first call of a batch the hook is handed,
// Decide puts each call of the batch a rule asks about to
// agentturn.Ask, in the model's order, through the elicitor the loop
// places on the hook's context (agentturn.Config.ToolElicitor, or
// agentkit's question events), and keeps the answers for the rest of
// the batch. It then decides each call from them:
//
//   - a call a rule asked about is decided as the person answered,
//     by human: allowed, with what they said reaching the model after
//     the batch's outputs, or refused with the rule and what they said;
//   - a call the policy allowed and the ask held beside it is allowed
//     when every call of its batch that asked was accepted, reported as
//     a release, and refused with "not run: the user declined <tool>"
//     when one was declined, since nothing the model asked for in the
//     turn runs beside a call the person refused.
//
// Nothing is remembered for a call settled this way, so the run ends
// with no pending call for it and [Engine.Runs] does not grow. When
// the hook's context carries no elicitor, or a question is cancelled
// or cannot be asked, the call is deferred as without the option, and
// the calls held beside it wait for the run's end with it, for
// [Engine.Release]. A nested call is settled by the loop with the
// invoking tool's elicitor already, and is decided as without the
// option.
func WithAskInRun() Option {
	return func(e *Engine) { e.askInRun = true }
}

// askBatch is what was asked about one batch in the run: whether each
// call, by position, asks, the answer to each that was asked, nil when
// the question went unanswered, and the positions the hook has
// decided, so the batch is dropped when its last call is decided.
type askBatch struct {
	asks    map[int]bool
	answers map[int]asked
	decided map[int]bool
}

// asked is the answer to one question: the decision the answer made,
// nil when it went unanswered, and the tool of the call asked about.
type asked struct {
	decision *agentturn.ToolDecision
	tool     string
}

// maxAskBatches bounds the batches kept between their first call and
// their last: a batch whose run was cut before the hook was handed its
// every call is never dropped by its last decision.
const maxAskBatches = 64

// askedInRun decides a model's call from the answers the person gave
// in the run, as [WithAskInRun] describes, and reports false when the
// call is to be decided as without the option: no elicitor, a call the
// policy blocks or allows outright, or a question nobody answered. v is
// the call's verdict, out what the hooks gave it, and held whether the
// batch holds it; v is updated for a call it decides.
func (e *Engine) askedInRun(ctx context.Context, a active, info agentturn.ToolCallInfo, v *Verdict, out agentturn.ToolDecision, held bool) (*agentturn.ToolDecision, bool) {
	if _, ok := agenttool.ElicitorFrom(ctx); !ok || info.Call == nil {
		return nil, false
	}
	self := position(info)
	key := batchKey(info, a.gen, a.scope)
	ab := e.askBatchFor(ctx, a, info, key, self, *v, out)
	defer e.decidedInBatch(key, self, len(info.Batch))

	switch {
	case v.Action == agentturn.Defer:
		e.mu.Lock()
		ans, ok := ab.answers[self]
		e.mu.Unlock()
		if !ok {
			// The call was read otherwise when the batch was asked about,
			// with the tool WithTools names rather than its own: ask now.
			ans = askCall(ctx, info, *v, out)
			e.mu.Lock()
			ab.asks[self], ab.answers[self] = true, ans
			e.mu.Unlock()
		}
		if ans.decision == nil {
			return nil, false
		}
		decided := *ans.decision
		v.Action, v.By, v.Reason = decided.Action, decided.By, decided.Reason
		return &decided, true
	case v.Action == agentturn.Allow && held:
		e.mu.Lock()
		declined := ""
		for i := range len(info.Batch) {
			if i == self || !ab.asks[i] {
				continue
			}
			ans, ok := ab.answers[i]
			if !ok || ans.decision == nil {
				// A question is still open, or a sibling could not be
				// read: the call is held for the run's end.
				e.mu.Unlock()
				return nil, false
			}
			if ans.decision.Action == agentturn.Block && declined == "" {
				declined = ans.tool
			}
		}
		e.mu.Unlock()
		v.Held = true
		if declined != "" {
			v.Action, v.Rule, v.Reason = agentturn.Block, nil, "not run: the user declined "+declined
			return &agentturn.ToolDecision{Action: agentturn.Block, Reason: v.Reason, By: ByPolicy}, true
		}
		v.Reason = releasedPrefix + v.Reason
		decided := out
		decided.Action, decided.Reason, decided.By = agentturn.Allow, v.Reason, v.By
		return &decided, true
	}
	return nil, false
}

// askBatchFor returns what was asked about info's batch, asking the
// person about each call of it a rule asks about when the batch is new:
// in the model's order, the hook's own call read with the verdict the
// hook gave it and each other call as [Engine.Decide] would read it,
// with the tool [WithTools] names. A call that could not be read asks,
// as it holds its siblings, and is not asked about; its own decision
// will block it.
func (e *Engine) askBatchFor(ctx context.Context, a active, info agentturn.ToolCallInfo, key string, self int, own Verdict, ownOut agentturn.ToolDecision) *askBatch {
	e.mu.Lock()
	if ab, ok := e.asked[key]; ok {
		e.mu.Unlock()
		return ab
	}
	e.mu.Unlock()

	ab := &askBatch{asks: map[int]bool{}, answers: map[int]asked{}, decided: map[int]bool{}}
	for i, c := range info.Batch {
		if c == nil {
			continue
		}
		if i == self {
			if own.Action == agentturn.Defer {
				ab.asks[i], ab.answers[i] = true, askCall(ctx, info, own, ownOut)
			}
			continue
		}
		sib := agentturn.ToolCallInfo{RunID: info.RunID, Turn: info.Turn, Call: c, Tool: e.sibling(ctx, c.Name), Args: callArgs(c), Batch: info.Batch, Index: i}
		var v Verdict
		out, failed, err := e.evaluate(ctx, a, sib, &v)
		switch {
		case err != nil || failed:
			ab.asks[i] = true
		case v.Action == agentturn.Defer:
			ab.asks[i], ab.answers[i] = true, askCall(ctx, sib, v, out)
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if kept, ok := e.asked[key]; ok {
		return kept
	}
	if e.asked == nil {
		e.asked = make(map[string]*askBatch)
	}
	for k := range e.asked {
		if len(e.asked) < maxAskBatches {
			break
		}
		delete(e.asked, k)
	}
	e.asked[key] = ab
	return ab
}

// askCall puts one call to the person through agentturn.Ask, with the
// deferral its verdict makes, and returns the decision the answer
// made, nil when nobody answered.
func askCall(ctx context.Context, info agentturn.ToolCallInfo, v Verdict, out agentturn.ToolDecision) asked {
	args := info.Args
	if out.Args != nil {
		args = out.Args
	}
	deferral := &agentturn.ToolDecision{Action: agentturn.Defer, Reason: v.Reason, By: v.By, Subject: v.Subject, Args: out.Args, Note: out.Note, Terminate: out.Terminate}
	decided, ok := agentturn.Ask(ctx, agentturn.AskedCall{CallID: info.Call.CallID, Name: info.Call.Name, Args: json.RawMessage(args), Decision: deferral})
	if !ok {
		return asked{tool: info.Call.Name}
	}
	return asked{decision: decided, tool: info.Call.Name}
}

// decidedInBatch notes that the hook decided the call at position self
// of the batch key names, and drops the batch once every call of it
// has been decided.
func (e *Engine) decidedInBatch(key string, self, n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ab, ok := e.asked[key]
	if !ok {
		return
	}
	ab.decided[self] = true
	if len(ab.decided) >= n {
		delete(e.asked, key)
	}
}
