package agentpolicy

import (
	"fmt"
	"sort"

	"github.com/ChristopherDavenport/agentturn"
)

// Default is what applies to a subject no rule matches. The zero value
// is unset, and [Build] refuses a policy whose default is unset, so a
// deny list written on its own never allows everything else by
// accident. Build one with [Allow], [Deny] or [Ask].
type Default struct {
	action agentturn.ToolAction
	set    bool
}

// Allow is the default that runs a call no rule mentions.
func Allow() Default { return Default{action: agentturn.Allow, set: true} }

// Deny is the default that blocks a call no rule mentions.
func Deny() Default { return Default{action: agentturn.Block, set: true} }

// Ask is the default that defers a call no rule mentions to the caller.
func Ask() Default { return Default{action: agentturn.Defer, set: true} }

// Action returns the action and whether the default was set.
func (d Default) Action() (agentturn.ToolAction, bool) { return d.action, d.set }

// String returns "allow", "deny", "ask" or "unset".
func (d Default) String() string {
	if !d.set {
		return "unset"
	}
	switch d.action {
	case agentturn.Block:
		return "deny"
	case agentturn.Defer:
		return "ask"
	}
	return "allow"
}

// Policy is the rule set: what is allowed, what is denied, what needs
// approval, and what happens otherwise. Precedence between the lists
// is fixed: deny, then ask, then allow, then Default.
type Policy struct {
	Allow []Rule
	Deny  []Rule
	Ask   []Rule
	// Default applies to a subject no rule matches. It must be set.
	Default Default
	// Sources lists where the rules came from, as [Merge] fills it,
	// so the session can name the policy in force. A policy built by
	// hand may leave it nil.
	Sources []Source
	// Withheld are the allow rules of the untrusted sources, stamped
	// with their source, in the order [Merge] saw them. They are not
	// evaluated: nothing in the engine reads this list, and a rebuild
	// of the policy with the source trusted is what applies them. A
	// front reads them to tell the user what trusting a folder would
	// allow, which is the reference's whole workflow around trust.
	Withheld []Rule
}

// RuleSet is the lists of one source, the input to [Merge].
type RuleSet struct {
	Source Source
	Allow  []Rule
	Deny   []Rule
	Ask    []Rule
}

// Merge unions the lists of several sources into one Policy, as the
// settings files of an organisation, a repository and a user combine.
// The sets are ordered by Rank, highest first, so the most
// authoritative rule is the one a verdict names; every rule is stamped
// with its set's Source, which is what scopes a carve-out; and the
// allow rules of an untrusted source are withheld, since they grant
// capability, while its deny and ask rules apply at once, since they
// only restrict. Precedence between the lists does not depend on the
// source. Default is left unset for the product to choose, and every
// source is listed on the policy, trusted or not.
//
// A withheld allow rule is kept on Policy.Withheld rather than
// dropped, so a front can tell the user what trusting a folder would
// allow. Nothing evaluates that list.
//
// Each source must be named, and no two may share a name.
func Merge(sets ...RuleSet) (Policy, error) {
	ordered := append([]RuleSet(nil), sets...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Source.Rank > ordered[j].Source.Rank })
	var p Policy
	seen := make(map[string]bool, len(ordered))
	for _, set := range ordered {
		if set.Source.Name == "" {
			return Policy{}, fmt.Errorf("agentpolicy: merge: a source has no name")
		}
		if seen[set.Source.Name] {
			return Policy{}, fmt.Errorf("agentpolicy: merge: duplicate source %q", set.Source.Name)
		}
		seen[set.Source.Name] = true
		p.Sources = append(p.Sources, set.Source)
		p.Deny = append(p.Deny, stamp(set.Deny, set.Source)...)
		p.Ask = append(p.Ask, stamp(set.Ask, set.Source)...)
		if set.Source.Trusted {
			p.Allow = append(p.Allow, stamp(set.Allow, set.Source)...)
		} else {
			p.Withheld = append(p.Withheld, stamp(set.Allow, set.Source)...)
		}
	}
	return p, nil
}

// stamp copies rules with their Source set to src.
func stamp(rules []Rule, src Source) []Rule {
	out := make([]Rule, len(rules))
	for i, r := range rules {
		r.Source = src
		out[i] = r
	}
	return out
}
