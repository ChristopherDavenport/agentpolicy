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
		Allow:   stamped(user, "read"),
		Deny:    append(stamped(managed, "read(.env:*)"), stamped(project, "bash(rm:*)")...),
		Ask:     append(stamped(project, "bash"), stamped(user, "edit")...),
		Sources: []Source{managed, project, user},
	}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("Merge = %+v\nwant %+v", p, want)
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
	if _, err := Merge(RuleSet{Source: user}, RuleSet{Source: Source{Name: "user"}}); err == nil || err.Error() != `agentpolicy: merge: duplicate source "user"` {
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
