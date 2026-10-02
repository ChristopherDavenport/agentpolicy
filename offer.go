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
// offered, and so does a deny rule with none that a carve-out of the
// list reaches, since the carve-out lets some calls through.
//
// It reads the deny rules a decision under no grant scope reads: the
// policy's, and those of every rule set [Engine.GrantSet] activated
// under no scope, so a grant set's bare deny, a skill's
// disallowed-tools, removes the tool as the policy's does for as long
// as the set is active, and [Engine.Revoke] gives it back. It takes no
// context, so a set activated under a scope, see
// [ContextWithGrantScope], is not read here; [Engine.ToolProvider]
// reads the scope of the context the loop consults it with. It is the
// engine's own tool-name test, so a front that lists what a policy
// withholds and the list the model is offered cannot disagree.
func (e *Engine) Removes(tool string) (Rule, bool) {
	return removes(e.activeScope("").policy.Deny, tool)
}

// removes returns the first bare deny rule of list that names the tool
// and that no carve-out of the list reaches.
func removes(deny []Rule, tool string) (Rule, bool) {
	for _, r := range deny {
		if r.Bare() && r.MatchesTool(tool) && !reopened(deny, r) {
			return r, true
		}
	}
	return Rule{}, false
}

// reopened reports whether a carve-out of list may cancel the rule for
// some subject: one the decision would weigh against it, of its tool
// name and a source it does not rank below. Its pattern is matched only
// once a subject arrives, so any such carve-out counts.
func reopened(list []Rule, r Rule) bool {
	for _, c := range list {
		if _, carve := c.CarveOut(); carve && c.Tool == r.Tool && c.Source.Rank >= r.Source.Rank {
			return true
		}
	}
	return false
}

// Filter returns the tools of the list the policy does not remove, in
// order. It is the Offer the round 1 study asked for: a bare-name deny,
// or a deny whose tool-name glob matches, withholds the tool from the
// model rather than refusing its calls one at a time. The rules are
// read once for the list, as [Engine.Removes] reads them: the
// policy's and the unscoped grant sets', since it takes no context;
// [Engine.ToolProvider] reads a scope's sets too.
//
// The filtering is not journalled. It answers what the model is
// offered, once per turn, not what was decided about a call, and a
// front that shows the user what a policy withheld reads
// [Engine.Removes] for the rule.
func (e *Engine) Filter(tools []agenttool.Tool) []agenttool.Tool {
	return filter(e.activeScope("").policy.Deny, tools)
}

// filter returns the tools of the list no rule of deny removes.
func filter(deny []Rule, tools []agenttool.Tool) []agenttool.Tool {
	out := make([]agenttool.Tool, 0, len(tools))
	for _, t := range tools {
		if t == nil {
			continue
		}
		if _, removed := removes(deny, t.Name()); !removed {
			out = append(out, t)
		}
	}
	return out
}

// ToolProvider returns the hook value for agentturn.Config.
// ToolProvider: base's tools with the ones the policy removes taken
// out. The loop consults it once per turn, before the model call, so a
// deny added by [Engine.SetPolicy] or [Engine.GrantSet] takes the tool
// away on the next turn, [Engine.Revoke] gives it back on the next
// turn, and a tool a server announces mid-session is filtered as it
// appears.
//
// The deny rules read are those a decision under the context the loop
// consults it with reads: the policy's, the unscoped grant sets', and
// those of the sets activated under the grant scope that context
// carries, see [ContextWithGrantScope], so a scoped set's bare deny
// takes the tool out of the offer for the runs under its scope and no
// other. [Engine.Filter] and [Engine.Removes] take no context and read
// the unscoped sets alone.
//
// base is a provider rather than a list because the list is what
// changes; a product whose list is fixed passes one that returns it,
// or filters it once with [Engine.Filter] and sets Config.Tools.
func (e *Engine) ToolProvider(base func(context.Context) []agenttool.Tool) func(context.Context) []agenttool.Tool {
	return func(ctx context.Context) []agenttool.Tool {
		if base == nil {
			return nil
		}
		return filter(e.active(ctx).policy.Deny, base(ctx))
	}
}
