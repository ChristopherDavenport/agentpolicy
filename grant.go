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
// The set is keyed by its source name: activating a second set under
// the same name replaces the first, and [Engine.Revoke] removes it,
// which is what a product calls at the turn boundary for a grant that
// lasts one turn. Rules a name governs are expanded as [Build] expands
// them. Every grant and every refusal is a Verdict through the
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
	kept := RuleSet{Source: set.Source}
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
		kept.Deny = append(kept.Deny, r)
	}
	for _, r := range set.Ask {
		if err := checkRule(r, e.matchers, "ask"); err != nil {
			refuse(r, err.Error())
			continue
		}
		kept.Ask = append(kept.Ask, r)
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
			kept.Allow = append(kept.Allow, r)
			granted = append(granted, r)
		}
	}
	// An untrusted set keeps its allow rules where Engine.Withheld
	// reports them, and applies none of them.
	if !set.Source.Trusted {
		kept.Allow = nil
	}
	e.mu.Lock()
	replaced := false
	for i, g := range e.grants {
		if g.Source.Name == set.Source.Name {
			e.grants[i], replaced = kept, true
			break
		}
	}
	if !replaced {
		e.grants = append(e.grants, kept)
	}
	e.withheld[set.Source.Name] = withheldOf(set)
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
// specifier is left to the decision, where the test is made against
// the subject.
func blocks(p Policy, r Rule, src Source) (bool, string) {
	for _, d := range p.Deny {
		if d.Bare() && d.MatchesTool(r.Tool) {
			return true, "denied by " + d.String() + ": a grant never beats a deny"
		}
	}
	for _, a := range p.Ask {
		if a.Bare() && a.MatchesTool(r.Tool) && a.Source.Rank > src.Rank {
			from := ""
			if a.Source.Name != "" {
				from = " from " + a.Source.Name
			}
			return true, a.String() + from + " outranks the grant"
		}
	}
	return false, ""
}

// Revoke removes the rules a source granted and returns how many rules
// it removed, so a product ends a turn-scoped grant at the turn
// boundary, as a skill's allowed-tools "clears when you send your next
// message". It touches neither the policy [Build] was given nor the
// rules [Engine.Grant] and [Engine.GrantOver] added, which are the
// always-allow journal and outlive a turn.
func (e *Engine) Revoke(ctx context.Context, source string) int {
	e.mu.Lock()
	n, kept := 0, e.grants[:0]
	for _, g := range e.grants {
		if g.Source.Name != source {
			kept = append(kept, g)
			continue
		}
		n += len(g.Allow) + len(g.Deny) + len(g.Ask)
	}
	for i := len(kept); i < len(e.grants); i++ {
		e.grants[i] = RuleSet{}
	}
	e.grants = kept
	delete(e.withheld, source)
	e.gen++
	e.mu.Unlock()
	if n > 0 {
		e.observe(ctx, Verdict{Action: agentturn.Block, Reason: "revoked the rules granted by " + source, By: ByPolicy})
	}
	return n
}

// Grants returns the rule sets in force beside the policy, in the
// order they were activated, as [Engine.GrantSet] kept them: the rules
// it refused are not here, and an untrusted source's allow rules are
// on [Engine.Withheld] instead.
func (e *Engine) Grants() []RuleSet {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]RuleSet, len(e.grants))
	for i, g := range e.grants {
		out[i] = RuleSet{
			Source: g.Source,
			Allow:  append([]Rule(nil), g.Allow...),
			Deny:   append([]Rule(nil), g.Deny...),
			Ask:    append([]Rule(nil), g.Ask...),
		}
	}
	return out
}

// active is what a decision is made against: the policy in force with
// the active grants' rules folded into its lists, and the grants
// themselves, whose allow rules shadow the ask rules they cover.
type active struct {
	policy Policy
	grants []RuleSet
	// gen is the engine's count of rule changes when the snapshot was
	// taken, which the batch cache is keyed on.
	gen uint64
}

// active snapshots the rules of the moment.
func (e *Engine) active() active {
	e.mu.Lock()
	defer e.mu.Unlock()
	a := active{policy: e.policy, gen: e.gen}
	if len(e.grants) == 0 {
		return a
	}
	a.grants = e.grants
	for _, g := range e.grants {
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
