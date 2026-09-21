package agentpolicy

import (
	"reflect"
	"testing"

	"github.com/ChristopherDavenport/agentturn"
)

func TestDefault(t *testing.T) {
	tests := []struct {
		d      Default
		action agentturn.ToolAction
		set    bool
		str    string
	}{
		{Default{}, agentturn.Allow, false, "unset"},
		{Allow(), agentturn.Allow, true, "allow"},
		{Deny(), agentturn.Block, true, "deny"},
		{Ask(), agentturn.Defer, true, "ask"},
	}
	for _, tc := range tests {
		action, set := tc.d.Action()
		if action != tc.action || set != tc.set || tc.d.String() != tc.str {
			t.Errorf("%s: Action() = %v, %v; String() = %q", tc.str, action, set, tc.d.String())
		}
	}
}

func TestMerge(t *testing.T) {
	managed := Source{Name: "managed", Path: "/etc/dex.json", Hash: "m", Rank: 3, Trusted: true}
	project := Source{Name: "project", Path: ".dex/settings.json", Hash: "p", Rank: 2}
	user := Source{Name: "user", Path: "~/.dex/settings.json", Hash: "u", Rank: 1, Trusted: true}

	p, err := Merge(
		RuleSet{Source: user, Allow: rules(t, "read"), Ask: rules(t, "edit")},
		RuleSet{Source: project, Allow: rules(t, "bash(npm test:*)"), Deny: rules(t, "bash(rm:*)"), Ask: rules(t, "bash")},
		RuleSet{Source: managed, Deny: rules(t, "read(.env:*)")},
	)
	if err != nil {
		t.Fatal(err)
	}
	stamped := func(src Source, s string) []Rule {
		out := rules(t, s)
		for i := range out {
			out[i].Source = src
		}
		return out
	}
	// Lists are unioned in rank order, every rule stamped with its
	// source, and the untrusted project's allow rules withheld while
	// its deny and ask rules apply.
	want := Policy{
		Allow:    stamped(user, "read"),
		Deny:     append(stamped(managed, "read(.env:*)"), stamped(project, "bash(rm:*)")...),
		Ask:      append(stamped(project, "bash"), stamped(user, "edit")...),
		Sources:  []Source{managed, project, user},
		Withheld: stamped(project, "bash(npm test:*)"),
	}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("Merge = %+v\nwant %+v", p, want)
	}
	// A withheld rule is kept for a front to show and is never
	// evaluated: the engine reports it and decides without it.
	built := p
	built.Default = Ask()
	e, err := Build(built, testMatchers)
	if err != nil {
		t.Fatal(err)
	}
	if got := ruleText(e.Withheld()); got != "bash(npm test:*)" {
		t.Errorf("Withheld = %q", got)
	}
	if d, _ := e.Decide(t.Context(), call("call_1", "bash", `{"command":"npm test --watch"}`)); d.Action != agentturn.Defer || d.Reason != "approval required by bash" {
		t.Errorf("a withheld rule decided: %+v", d)
	}
	// Trusting the source is a merge again, and then it applies.
	project.Trusted = true
	p2, err := Merge(RuleSet{Source: project, Allow: rules(t, "bash(npm test:*)"), Deny: rules(t, "bash(rm:*)"), Ask: rules(t, "bash")})
	if err != nil || len(p2.Withheld) != 0 || !reflect.DeepEqual(p2.Allow, stamped(project, "bash(npm test:*)")) {
		t.Errorf("trusted merge = %+v, %v", p2, err)
	}
	// The default is the product's to choose.
	if _, set := p.Default.Action(); set {
		t.Error("Merge set a default")
	}
	if _, err := Build(p, testMatchers); err != ErrNoDefault {
		t.Errorf("Build of a merged policy without a default: %v", err)
	}

	// Errors.
	if _, err := Merge(RuleSet{Source: Source{Rank: 1}}); err == nil || err.Error() != "agentpolicy: merge: a source has no name" {
		t.Errorf("unnamed source: %v", err)
	}
	if _, err := Merge(RuleSet{Source: user}, RuleSet{Source: Source{Name: "user"}}); err == nil || err.Error() != `agentpolicy: merge: duplicate source "user"; give each source its own name, "user:<name>" for one skill of several` {
		t.Errorf("duplicate source: %v", err)
	}
	// Merging nothing is an empty policy.
	if p, err := Merge(); err != nil || !reflect.DeepEqual(p, Policy{}) {
		t.Errorf("Merge() = %+v, %v", p, err)
	}
	// The order among equal ranks is the order given.
	p, err = Merge(RuleSet{Source: Source{Name: "a"}, Deny: rules(t, "x")}, RuleSet{Source: Source{Name: "b"}, Deny: rules(t, "y")})
	if err != nil || p.Deny[0].Source.Name != "a" || p.Deny[1].Source.Name != "b" {
		t.Errorf("equal ranks: %+v, %v", p, err)
	}
}
