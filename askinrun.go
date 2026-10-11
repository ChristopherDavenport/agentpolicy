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
// drives the engine. At the first call of a batch the hook is handed
// that a rule asks about, or that the policy allows and an ask holds,
// Decide puts each call of the batch a rule asks about to
// agentturn.Ask, in the model's order, through the elicitor the loop
// places on the hook's context (agentturn.Config.ToolElicitor, or
// agentkit's question events), and keeps the answers for the rest of
// the batch. It then decides each call from them, by the rule a release
// at the run's end follows ([Engine.Release]):
//
//   - a call the person was asked about is decided as they answered,
//     by human: allowed, with what they said reaching the model after
//     the batch's outputs, or refused with the rule and what they said.
//     The answer stands for the call however its own decision reads it,
//     unless the policy denies the call, which no answer overrides;
//   - a call the policy allowed and the ask held beside it is released
//     once every call of its batch that asked is answered, accepted or
//     declined, since a plain decline refuses its own call alone; it is
//     refused, naming the call whose answer stopped the turn, when an
//     answer stops the turn (a refusal with Terminate set).
//
// Nothing is remembered for a call settled this way, and [Engine.Runs]
// does not grow for it. When the hook's context carries no elicitor,
// or a question is cancelled or cannot be asked, the call is deferred
// as without the option, and so is every call held beside it while no
// answer has stopped the turn: they wait for the run's end, for
// [Engine.Release]. A batch a call of which could not be read, its
// splitter or a hook having failed, holds its allowed calls the same
// way, so a run can still end on held calls. A nested call is settled
// by the loop with the invoking tool's elicitor already, and is
// decided as without the option.
func WithAskInRun() Option {
	return func(e *Engine) { e.askInRun = true }
}

// askBatch is what was asked about one batch in the run: whether each
// call, by position, asks, the answer to each that was asked, nil when
// the question went unanswered, and the positions the hook has
// decided, so the batch is dropped when its last call is decided. run
// names the run it belongs to, and seq the order it was asked in, for
// dropping the oldest first.
type askBatch struct {
	run     string
	seq     uint64
	asks    map[int]bool
	answers map[int]asked
	decided map[int]bool
}

// asked is the answer to one question: the decision the answer made,
// nil when it went unanswered, and the call asked about, by ID and by
// what the policy asked about it, its subject or else its tool.
type asked struct {
	decision *agentturn.ToolDecision
	callID   string
	about    string
}

// maxAskBatches bounds the batches kept between their first call and
// their last: one per run in flight, since a run decides one batch at
// a time.
const maxAskBatches = 64

// askKey names a batch by its run, its turn and its calls, and not by
// the rules of the moment: a grant made while the batch is decided,
// another conversation's or an "always allow" answer, must not have
// the person asked again.
func askKey(info agentturn.ToolCallInfo) string {
	return batchKey(info, 0, "")
}

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
	key := askKey(info)
	defer e.decidedInBatch(key, self, len(info.Batch))
	if v.Action == agentturn.Block {
		// A deny stands whatever the person said.
		return nil, false
	}
	if ans, ok := e.answerFor(key, self); ok {
		// The person answered for this call when the batch was asked
		// about, whatever its own decision reads now.
		return answered(v, ans), true
	}
	switch {
	case v.Action == agentturn.Defer:
		ab := e.askBatchFor(ctx, a, info, key, self, *v, out)
		e.mu.Lock()
		ans, wasAsked := ab.answers[self]
		e.mu.Unlock()
		if !wasAsked {
			// The call was read otherwise when the batch was asked about,
			// with the tool WithTools names rather than its own: ask now.
			ans = askCall(ctx, info, *v, out)
			e.setAnswer(key, self, ans)
		}
		if ans.decision == nil {
			// Nobody answered: the call waits for the run's end.
			return nil, false
		}
		return answered(v, ans), true
	case v.Action == agentturn.Allow && held:
		ab := e.askBatchFor(ctx, a, info, key, self, *v, out)
		e.mu.Lock()
		var stop *asked
		open := false
		for i := range len(info.Batch) {
			if i == self || !ab.asks[i] {
				continue
			}
			ans, ok := ab.answers[i]
			switch {
			case !ok || ans.decision == nil:
				// A question is still open, or a sibling could not be read.
				open = true
			case stop == nil && stops(ans.decision):
				stop = &ans
			}
		}
		e.mu.Unlock()
		v.Held = true
		if stop != nil {
			v.Action, v.Rule, v.Reason = agentturn.Block, nil, stoppedReason(stop.callID, stop.about)
			return &agentturn.ToolDecision{Action: agentturn.Block, Reason: v.Reason, By: ByPolicy}, true
		}
		if open {
			v.Held = false
			return nil, false
		}
		v.Reason = releasedPrefix + v.Reason
		decided := out
		decided.Action, decided.Reason, decided.By = agentturn.Allow, v.Reason, v.By
		return &decided, true
	}
	return nil, false
}

// answered is the decision an answer made for the call v is about,
// with v set to say so.
func answered(v *Verdict, ans asked) *agentturn.ToolDecision {
	decided := *ans.decision
	v.Action, v.By, v.Reason = decided.Action, decided.By, decided.Reason
	return &decided
}

// stops reports whether an answer stops the turn: a refusal that ends
// it, as agentturn.Refuse does at the run's end. A plain decline
// refuses its own call alone.
func stops(d *agentturn.ToolDecision) bool {
	return d.Action == agentturn.Block && d.Terminate
}

// answerFor returns the answer the person gave in the run for the call
// at position i of the batch key names.
func (e *Engine) answerFor(key string, i int) (asked, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ab, ok := e.asked[key]
	if !ok {
		return asked{}, false
	}
	ans, ok := ab.answers[i]
	if !ok || ans.decision == nil {
		return asked{}, false
	}
	return ans, true
}

// setAnswer keeps an answer for the call at position i of a batch.
func (e *Engine) setAnswer(key string, i int, ans asked) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ab, ok := e.asked[key]; ok {
		ab.asks[i], ab.answers[i] = true, ans
	}
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

	ab := &askBatch{run: info.RunID, asks: map[int]bool{}, answers: map[int]asked{}, decided: map[int]bool{}}
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
	// A run decides one batch at a time: a new batch of a run ends the
	// one before it, even one whose last call the hook was never handed.
	for k, old := range e.asked {
		if old.run == ab.run {
			delete(e.asked, k)
		}
	}
	for len(e.asked) >= maxAskBatches {
		oldest := ""
		for k, old := range e.asked {
			if oldest == "" || old.seq < e.asked[oldest].seq {
				oldest = k
			}
		}
		delete(e.asked, oldest)
	}
	e.askSeq++
	ab.seq = e.askSeq
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
	about := v.Subject
	if about == "" {
		about = info.Call.Name
	}
	got := asked{callID: info.Call.CallID, about: about}
	deferral := &agentturn.ToolDecision{Action: agentturn.Defer, Reason: v.Reason, By: v.By, Subject: v.Subject, Args: out.Args, Note: out.Note, Terminate: out.Terminate}
	decided, ok := agentturn.Ask(ctx, agentturn.AskedCall{CallID: info.Call.CallID, Name: info.Call.Name, Args: json.RawMessage(args), Decision: deferral})
	if ok {
		got.decision = decided
	}
	return got
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

// dropAsked drops what was asked in the run runID. The caller holds
// e.mu.
func (e *Engine) dropAsked(runID string) {
	for k, ab := range e.asked {
		if ab.run == runID {
			delete(e.asked, k)
		}
	}
}
