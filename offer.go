package agentpolicy

import (
	"context"

	"github.com/ChristopherDavenport/agenttool"
)

// Removes reports the deny rule that takes the tool out of the
// request, and whether one does. A deny rule with no specifier names
// the tool itself and so denies every call of it, which both
// references answer by never offering the tool: the model does not see
// it, plans nothing around it and spends no tokens being refused. A
// deny rule with a specifier denies some calls and leaves the tool
// offered.
//
// It is the engine's own tool-name test, so a front that lists what a
// policy withholds and the list the model is offered cannot disagree.
func (e *Engine) Removes(tool string) (Rule, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range e.policy.Deny {
		if r.Bare() && r.MatchesTool(tool) {
			return r, true
		}
	}
	return Rule{}, false
}

// Filter returns the tools of the list the policy does not remove, in
// order. It is the Offer the round 1 study asked for: a bare-name deny,
// or a deny whose tool-name glob matches, withholds the tool from the
// model rather than refusing its calls one at a time.
//
// The filtering is not journalled. It answers what the model is
// offered, once per turn, not what was decided about a call, and a
// front that shows the user what a policy withheld reads
// [Engine.Removes] for the rule.
func (e *Engine) Filter(tools []agenttool.Tool) []agenttool.Tool {
	out := make([]agenttool.Tool, 0, len(tools))
	for _, t := range tools {
		if t == nil {
			continue
		}
		if _, removed := e.Removes(t.Name()); !removed {
			out = append(out, t)
		}
	}
	return out
}

// ToolProvider returns the hook value for agentturn.Config.
// ToolProvider: base's tools with the ones the policy removes taken
// out. The loop consults it once per turn, before the model call, so a
// deny added by [Engine.SetPolicy] or a grant takes the tool away on
// the next turn and a tool a server announces mid-session is filtered
// as it appears.
//
// base is a provider rather than a list because the list is what
// changes; a product whose list is fixed passes one that returns it,
// or filters it once with [Engine.Filter] and sets Config.Tools.
func (e *Engine) ToolProvider(base func(context.Context) []agenttool.Tool) func(context.Context) []agenttool.Tool {
	return func(ctx context.Context) []agenttool.Tool {
		if base == nil {
			return nil
		}
		return e.Filter(base(ctx))
	}
}
