package agentpolicy

import (
	"context"
	"encoding/json"

	"github.com/ChristopherDavenport/agentturn"
)

// Refusal is one rule a grant could not activate, with the stable text
// that says why, so a front can show the user what a skill asked for
// and what it did not get, as it drops the "always allow" option when
// [Engine.GrantOver] refuses.
type Refusal struct {
	Rule   Rule
	Reason string
}

// grantScopeKey is the context key of a grant scope.
type grantScopeKey struct{}

// ContextWithGrantScope returns ctx carrying a grant scope: the key a
// host gives the conversation, agent or run whose calls a grant set
// should decide, a session ID say. [Engine.GrantSet] activates a set
// under the scope of its context, [Engine.Decide] consults the sets
// of its context's scope beside the unscoped ones, and [Engine.Revoke]
// removes the set of its context's scope. A context with no scope is
// the unscoped one, where a set decides every call the engine sees,
// as before.
//
// One engine serves every agent of a product, so without a scope a
// skill the main agent opened grants its tools to a sub-agent, or to
// another conversation, that never opened it. A host puts the scope on
// the context it runs each conversation under, the one the loop hands
// its hooks, and on the context it activates and revokes the skill's
// set with; [Engine.RevokeScope] takes every set of a scope back when
// the conversation ends.
func ContextWithGrantScope(ctx context.Context, scope string) context.Context {
	return context.WithValue(ctx, grantScopeKey{}, scope)
}

// GrantScopeFromContext returns the grant scope ctx carries, or "" for
// the unscoped one.
func GrantScopeFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	scope, _ := ctx.Value(grantScopeKey{}).(string)
	return scope
}

// grantKey is what a rule set is keyed by: the scope it was activated
// under and its source's name.
type grantKey struct {
	scope  string
	source string
}

// grant is one rule set in force, with the scope it decides under.
type grant struct {
	scope string
	set   RuleSet
}

func (g grant) key() grantKey { return grantKey{scope: g.scope, source: g.set.Source.Name} }

// rules is how many rules the set holds, which is what a revocation
// reports.
func (g grant) rules() int { return len(g.set.Allow) + len(g.set.Deny) + len(g.set.Ask) }

// GrantSet activates a rule set under its source, as a skill's
// allowed-tools grants the tools the skill was written to run. It is
// the grant a verdict cannot answer: there is no prompt yet, so
// [Engine.GrantOver] has nothing to grant over, and an appended allow
// rule loses to any ask rule naming the tool, which is why a team
// whose settings ask before every bash was prompted for every command
// of the commit skill they wrote to avoid it.
//
// A set's allow rules therefore shadow the ask rules they cover: while
// the grant is active, an ask rule from another source whose rank is
// at or below the set's is not consulted for a subject the set allows.
// A skill from a trusted source is a grant the user made by installing
// it; an untrusted source's allow rules are withheld, as [Merge]
// withholds them, and reported by [Engine.Withheld]. The set's deny
// and ask rules apply at once, trusted or not, since they only
// restrict. A grant never beats a deny.
//
// A rule is refused, and not activated, when it could never fire (no
// matcher, a carve-out, a tool-name glob in an allow list), when its
// source is untrusted, when a deny rule with no specifier names its
// tool, and when an ask rule with no specifier from a source that
// outranks the set names its tool, which is the rank check
// [Engine.GrantOver] makes. An ask rule with a specifier is left to
// the decision, where the rank test is made against the subject.
//
// Every rule is stamped with the set's source, as [Merge] stamps one,
// so the verdict that fires names where the permission came from.
//
// The set is keyed by the grant scope of ctx, see
// [ContextWithGrantScope], and its source name: activating a second
// set under the same name and scope replaces the first, and
// [Engine.Revoke] under the same scope removes it, which is what a
// product calls at the turn boundary for a grant that lasts one turn.
// A set activated under a scope decides only the calls whose context
// carries that scope; one activated under no scope decides every call
// the engine sees. Rules a name governs are expanded as [Build]
// expands them. Every grant and every refusal is a Verdict through the
// observer.
//
// A product with several skills activates each as its own source
// rather than merging them all into the policy before the run, so the
// tools of a skill the model never opened are never granted and
// [Merge] never has to be given two sources with one name.
func (e *Engine) GrantSet(ctx context.Context, set RuleSet) (granted []Rule, refused []Refusal) {
	set.Allow = stamp(e.expandList(set.Allow), set.Source)
	set.Deny = stamp(e.expandList(set.Deny), set.Source)
	set.Ask = stamp(e.expandList(set.Ask), set.Source)
	kept := grant{scope: GrantScopeFromContext(ctx), set: RuleSet{Source: set.Source}}
	refuse := func(r Rule, reason string) {
		refused = append(refused, Refusal{Rule: r, Reason: reason})
	}

	e.mu.Lock()
	p := e.policy
	e.mu.Unlock()

	for _, r := range set.Deny {
		if err := checkRule(r, e.matchers, "deny"); err != nil {
			refuse(r, err.Error())
			continue
		}
		kept.set.Deny = append(kept.set.Deny, r)
	}
	for _, r := range set.Ask {
		if err := checkRule(r, e.matchers, "ask"); err != nil {
			refuse(r, err.Error())
			continue
		}
		kept.set.Ask = append(kept.set.Ask, r)
	}
	for _, r := range set.Allow {
		switch {
		case checkGrant(r, e.matchers) != nil:
			refuse(r, checkGrant(r, e.matchers).Error())
		case !set.Source.Trusted:
			refuse(r, "withheld: the source "+sourceName(set.Source)+" is not trusted")
		default:
			if bad, why := blocks(p, r, set.Source); bad {
				refuse(r, why)
				continue
			}
			kept.set.Allow = append(kept.set.Allow, r)
			granted = append(granted, r)
		}
	}
	// An untrusted set keeps its allow rules where Engine.Withheld
	// reports them, and applies none of them.
	if !set.Source.Trusted {
		kept.set.Allow = nil
	}
	// The list is replaced rather than written through: a decision in
	// another agent's run may be reading the one it snapshotted.
	e.mu.Lock()
	grants := make([]grant, 0, len(e.grants)+1)
	replaced := false
	for _, g := range e.grants {
		if g.key() == kept.key() {
			grants, replaced = append(grants, kept), true
			continue
		}
		grants = append(grants, g)
	}
	if !replaced {
		grants = append(grants, kept)
	}
	e.grants = grants
	e.withheld[kept.key()] = withheldOf(set)
	e.gen++
	e.mu.Unlock()

	for i := range granted {
		g := granted[i]
		e.observe(ctx, Verdict{Tool: g.Tool, Action: agentturn.Allow, Rule: &g, Reason: "granted " + g.String() + " by " + sourceName(set.Source), By: ByPolicy})
	}
	for i := range refused {
		r := refused[i].Rule
		e.observe(ctx, Verdict{Tool: r.Tool, Action: agentturn.Block, Rule: &r, Reason: "not granted " + r.String() + ": " + refused[i].Reason, By: ByPolicy})
	}
	return granted, refused
}

// withheldOf returns the allow rules an untrusted set contributes.
func withheldOf(set RuleSet) []Rule {
	if set.Source.Trusted {
		return nil
	}
	return append([]Rule(nil), set.Allow...)
}

// sourceName names a source for a reason, "the product" for the zero
// source a product built by hand.
func sourceName(s Source) string {
	if s.Name == "" {
		return "the product"
	}
	return s.Name
}

// blocks reports whether a rule in force certainly keeps a grant from
// firing: a deny rule with no specifier for the tool, which no grant
// beats, or an ask rule with no specifier from a source that outranks
// the grant's, which is the rank check GrantOver makes. A rule with a
// specifier, or one a carve-out of its list reaches, is left to the
// decision, where the test is made against the subject.
func blocks(p Policy, r Rule, src Source) (bool, string) {
	for _, d := range p.Deny {
		if d.Bare() && d.MatchesTool(r.Tool) && !reopened(p.Deny, d) {
			return true, "denied by " + d.String() + ": a grant never beats a deny"
		}
	}
	for _, a := range p.Ask {
		if a.Bare() && a.MatchesTool(r.Tool) && a.Source.Rank > src.Rank && !reopened(p.Ask, a) {
			from := ""
			if a.Source.Name != "" {
				from = " from " + a.Source.Name
			}
			return true, a.String() + from + " outranks the grant"
		}
	}
	return false, ""
}

// Revoke removes the rules a source granted under the grant scope of
// ctx and returns how many rules it removed, so a product ends a
// turn-scoped grant at the turn boundary, as a skill's allowed-tools
// "clears when you send your next message". It touches neither the
// policy [Build] was given nor the rules [Engine.Grant] and
// [Engine.GrantOver] added, which are the always-allow journal and
// outlive a turn, nor the source's set under any other scope: an
// unscoped Revoke never removes a scoped set, and a scoped one never
// removes the unscoped set. The revocation is journaled as a Verdict,
// Block with "revoked the rules granted by N", when it removed a rule.
func (e *Engine) Revoke(ctx context.Context, source string) int {
	n := e.revoke(func(g grant) bool { return g.key() == grantKey{scope: GrantScopeFromContext(ctx), source: source} })
	if n > 0 {
		e.observe(ctx, Verdict{Action: agentturn.Block, Reason: "revoked the rules granted by " + source, By: ByPolicy})
	}
	return n
}

// RevokeScope removes every rule set activated under the grant scope
// of ctx, with the allow rules withheld from its untrusted ones, and
// returns how many rules it removed. A host calls it when a
// conversation ends, as it calls [Engine.Forget] for a run that ended
// another way, so nothing a conversation opened outlives it. Under a
// context with no scope it removes every unscoped set, and no scoped
// one. The revocation is journaled as a Verdict, Block with "revoked
// the rules granted under S", S the scope or "no scope", when it
// removed a rule.
func (e *Engine) RevokeScope(ctx context.Context) int {
	scope := GrantScopeFromContext(ctx)
	n := e.revoke(func(g grant) bool { return g.scope == scope })
	if n > 0 {
		under := scope
		if under == "" {
			under = "no scope"
		}
		e.observe(ctx, Verdict{Action: agentturn.Block, Reason: "revoked the rules granted under " + under, By: ByPolicy})
	}
	return n
}

// revoke removes the sets drop selects, and their withheld rules, and
// returns how many rules they held.
func (e *Engine) revoke(drop func(grant) bool) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	kept := make([]grant, 0, len(e.grants))
	for _, g := range e.grants {
		if !drop(g) {
			kept = append(kept, g)
			continue
		}
		n += g.rules()
		delete(e.withheld, g.key())
	}
	if len(kept) != len(e.grants) {
		// Replaced rather than filtered in place, since a decision in
		// another agent's run may be reading the list it snapshotted.
		e.grants = kept
		e.gen++
	}
	return n
}

// Grants returns the rule sets in force beside the policy under every
// grant scope, as [Engine.GrantSet] kept them: the unscoped sets
// first, then the scoped ones, each in the order they were activated.
// The rules it refused are not here, and an untrusted source's allow
// rules are on [Engine.Withheld] instead. A set's scope is not on the
// RuleSet; [Engine.GrantsFor] returns the sets one decision consults.
func (e *Engine) Grants() []RuleSet {
	e.mu.Lock()
	defer e.mu.Unlock()
	ordered := e.ordered()
	sets := make([]RuleSet, len(ordered))
	for i, g := range ordered {
		sets[i] = g.set
	}
	return cloneSets(sets)
}

// GrantsFor returns the rule sets a decision under ctx consults, in
// the order they are consulted: the unscoped sets, then the sets of
// the grant scope ctx carries, each in activation order. Under a
// context with no scope they are the unscoped sets alone.
func (e *Engine) GrantsFor(ctx context.Context) []RuleSet {
	return cloneSets(e.active(ctx).grants)
}

// ordered returns the grants in the order Grants reports them,
// unscoped first, as a view of the sets. The lock is held.
func (e *Engine) ordered() []grant {
	out := make([]grant, 0, len(e.grants))
	for _, g := range e.grants {
		if g.scope == "" {
			out = append(out, g)
		}
	}
	for _, g := range e.grants {
		if g.scope != "" {
			out = append(out, g)
		}
	}
	return out
}

// cloneSets copies rule sets so a caller cannot write into the lists
// a decision reads.
func cloneSets(sets []RuleSet) []RuleSet {
	out := make([]RuleSet, len(sets))
	for i, set := range sets {
		out[i] = RuleSet{
			Source: set.Source,
			Allow:  append([]Rule(nil), set.Allow...),
			Deny:   append([]Rule(nil), set.Deny...),
			Ask:    append([]Rule(nil), set.Ask...),
		}
	}
	return out
}

// active is what a decision is made against: the policy in force with
// the consulted grants' rules folded into its lists, and the grants
// themselves, whose allow rules shadow the ask rules they cover: the
// unscoped sets, then the sets of the decision's grant scope.
type active struct {
	policy Policy
	grants []RuleSet
	// scope is the grant scope the snapshot was taken for, and gen is
	// the engine's count of rule changes when it was taken; the batch
	// cache is keyed on both.
	scope string
	gen   uint64
}

// active snapshots the rules of the moment for a decision under ctx.
func (e *Engine) active(ctx context.Context) active {
	return e.activeScope(GrantScopeFromContext(ctx))
}

// activeScope snapshots the rules of the moment for a decision under
// scope: the policy, then the unscoped sets, then the scope's sets, in
// activation order.
func (e *Engine) activeScope(scope string) active {
	e.mu.Lock()
	defer e.mu.Unlock()
	a := active{policy: e.policy, scope: scope, gen: e.gen}
	if len(e.grants) == 0 {
		return a
	}
	for _, g := range e.grants {
		if g.scope == "" {
			a.grants = append(a.grants, g.set)
		}
	}
	if scope != "" {
		for _, g := range e.grants {
			if g.scope == scope {
				a.grants = append(a.grants, g.set)
			}
		}
	}
	for _, g := range a.grants {
		a.policy.Deny = concat(a.policy.Deny, g.Deny)
		a.policy.Ask = concat(a.policy.Ask, g.Ask)
		a.policy.Allow = concat(a.policy.Allow, g.Allow)
	}
	return a
}

// concat appends without writing into the base slice's own array.
func concat(base, more []Rule) []Rule {
	if len(more) == 0 {
		return base
	}
	out := make([]Rule, 0, len(base)+len(more))
	return append(append(out, base...), more...)
}

// shadowedBy returns the grant's allow rule that keeps an ask rule
// from firing for this subject: a rule of an active grant from another
// source, whose rank is at or above the ask rule's, that matches the
// subject. A grant from the ask rule's own source shadows nothing,
// since a set that both asks and allows for a subject means ask.
func (e *Engine) shadowedBy(a active, ask Rule, tool string, args json.RawMessage) (Rule, bool) {
	for _, g := range a.grants {
		if g.Source.Name == ask.Source.Name || g.Source.Rank < ask.Source.Rank {
			continue
		}
		if r, ok := e.match(g.Allow, tool, args); ok {
			return r, true
		}
	}
	return Rule{}, false
}
