package agentpolicy

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agentturn"
)

// The commit skill of the round 2 codex-permissions study: a team
// whose project settings ask before every bash is the team that wrote
// a commit skill, and at v0.0.2 the skill's allowed-tools granted
// nothing, because precedence is deny, ask, allow and GrantOver needs
// a verdict a skill does not have.
func TestGrantSetShadowsAnAskRule(t *testing.T) {
	ctx := context.Background()
	project := Source{Name: "project", Path: ".dex/settings.json", Rank: 2, Trusted: true}
	skill := func(rank int, trusted bool) RuleSet {
		return RuleSet{
			Source: Source{Name: "skill:commit", Path: ".dex/skills/commit.md", Rank: rank, Trusted: trusted},
			Allow:  rules(t, "Bash(git add:*) Bash(git commit:*) Bash(git status:*)"),
		}
	}
	build := func(t *testing.T) (*Engine, *journal) {
		t.Helper()
		j := &journal{}
		p, err := Merge(RuleSet{Source: project, Ask: rules(t, "bash")})
		if err != nil {
			t.Fatal(err)
		}
		p.Default = Ask()
		e, err := Build(p, testMatchers, WithObserver(j.observe), WithAliases(map[string][]string{"Bash": {"bash"}}))
		if err != nil {
			t.Fatal(err)
		}
		return e, j
	}
	decide := func(t *testing.T, e *Engine, command string) *agentturn.ToolDecision {
		t.Helper()
		d, err := e.Decide(ctx, call("call_1", "bash", `{"command":"`+command+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	// Without the grant the skill's own commands prompt, which is what
	// the skill was written to prevent.
	e, j := build(t)
	if d := decide(t, e, "git status --short"); d.Action != agentturn.Defer {
		t.Fatalf("before the grant: %+v", d)
	}

	// The grant shadows the project's ask rule for the subjects it
	// allows, and only those.
	granted, refused := e.GrantSet(ctx, skill(2, true))
	if got := ruleText(granted); got != "bash(git add:*) bash(git commit:*) bash(git status:*)" {
		t.Errorf("granted = %q", got)
	}
	if len(refused) != 0 {
		t.Errorf("refused = %+v", refused)
	}
	for _, tc := range []struct {
		command string
		want    agentturn.ToolAction
		reason  string
	}{
		{"git status --short", agentturn.Allow, "allowed by bash(git status:*)"},
		{"git commit -m wip", agentturn.Allow, "allowed by bash(git commit:*)"},
		{"git push --force", agentturn.Defer, "approval required by bash"},
		{"npm test", agentturn.Defer, "approval required by bash"},
	} {
		if d := decide(t, e, tc.command); d.Action != tc.want || d.Reason != tc.reason {
			t.Errorf("%q: decision = %+v, want %v %q", tc.command, d, tc.want, tc.reason)
		}
	}
	// The rule that fired is the skill's, with its source, so the
	// record says where the permission came from.
	from := ""
	for _, v := range j.all() {
		if v.Action == agentturn.Allow && v.Rule != nil && v.Rule.String() == "bash(git status:*)" {
			from = v.Rule.Source.Name
		}
	}
	if from != "skill:commit" {
		t.Errorf("the rule that allowed git status came from %q", from)
	}

	// The grant is the source's, and revoking it at the turn boundary
	// puts the ask rule back.
	if got := e.Grants(); len(got) != 1 || got[0].Source.Name != "skill:commit" || ruleText(got[0].Allow) != "bash(git add:*) bash(git commit:*) bash(git status:*)" {
		t.Errorf("Grants = %+v", got)
	}
	if n := e.Revoke(ctx, "skill:commit"); n != 3 {
		t.Errorf("Revoke removed %d rules", n)
	}
	if d := decide(t, e, "git status --short"); d.Action != agentturn.Defer {
		t.Errorf("after the revoke: %+v", d)
	}
	if got := e.Grants(); len(got) != 0 {
		t.Errorf("Grants after the revoke = %+v", got)
	}

	// The policy to persist is the one built: a scoped grant is not
	// part of it, and an engine rebuilt from it decides the same.
	e, _ = build(t)
	e.GrantSet(ctx, skill(2, true))
	if got := ruleText(e.Policy().Allow); got != "" {
		t.Errorf("Policy().Allow = %q", got)
	}
}

// The rank check GrantOver makes, made again for a rule set: a skill
// from a source that a bare ask rule outranks is refused and reported,
// so a front can show the user what the skill did not get, rather than
// a repository skill silently overruling the project's own settings.
func TestGrantSetRefusals(t *testing.T) {
	ctx := context.Background()
	managed := Source{Name: "managed", Rank: 3, Trusted: true}
	tests := []struct {
		name    string
		policy  Policy
		set     RuleSet
		granted string
		refused []Refusal
		action  agentturn.ToolAction
	}{
		{
			name:    "an ask rule that outranks the grant",
			policy:  Policy{Ask: []Rule{{Tool: "bash", Source: managed}}, Default: Ask()},
			set:     RuleSet{Source: Source{Name: "skill", Rank: 1, Trusted: true}, Allow: rules(t, "bash(git status:*)")},
			refused: []Refusal{{Rule: Rule{Tool: "bash", Spec: "git status:*", Source: Source{Name: "skill", Rank: 1, Trusted: true}}, Reason: "bash from managed outranks the grant"}},
			action:  agentturn.Defer,
		},
		{
			name:    "a deny rule, which no grant beats",
			policy:  Policy{Deny: []Rule{{Tool: "bash", Source: managed}}, Default: Allow()},
			set:     RuleSet{Source: Source{Name: "skill", Rank: 9, Trusted: true}, Allow: rules(t, "bash(git status:*)")},
			refused: []Refusal{{Rule: Rule{Tool: "bash", Spec: "git status:*", Source: Source{Name: "skill", Rank: 9, Trusted: true}}, Reason: "denied by bash: a grant never beats a deny"}},
			action:  agentturn.Block,
		},
		{
			name:    "an untrusted source",
			policy:  Policy{Ask: rules(t, "bash"), Default: Ask()},
			set:     RuleSet{Source: Source{Name: "skill", Rank: 9}, Allow: rules(t, "bash(git status:*)")},
			refused: []Refusal{{Rule: Rule{Tool: "bash", Spec: "git status:*", Source: Source{Name: "skill", Rank: 9}}, Reason: "withheld: the source skill is not trusted"}},
			action:  agentturn.Defer,
		},
		{
			name:    "a rule that could never fire",
			policy:  Policy{Default: Allow()},
			set:     RuleSet{Source: Source{Name: "skill", Trusted: true}, Allow: rules(t, "web(https://x:*)")},
			refused: []Refusal{{Rule: Rule{Tool: "web", Spec: "https://x:*", Source: Source{Name: "skill", Trusted: true}}, Reason: "agentpolicy: no matcher for the rule's tool: web(https://x:*)"}},
			action:  agentturn.Allow,
		},
		{
			name:    "an ask rule with a specifier is left to the decision",
			policy:  Policy{Ask: []Rule{{Tool: "bash", Spec: "git push:*", Source: managed}}, Default: Ask()},
			set:     RuleSet{Source: Source{Name: "skill", Rank: 1, Trusted: true}, Allow: rules(t, "bash(git status:*)")},
			granted: "bash(git status:*)",
			action:  agentturn.Allow,
		},
	}
	for _, tc := range tests {
		e, err := Build(tc.policy, testMatchers)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		granted, refused := e.GrantSet(ctx, tc.set)
		if got := ruleText(granted); got != tc.granted {
			t.Errorf("%s: granted = %q, want %q", tc.name, got, tc.granted)
		}
		if !reflect.DeepEqual(refused, tc.refused) {
			t.Errorf("%s: refused = %+v, want %+v", tc.name, refused, tc.refused)
		}
		d, err := e.Decide(ctx, call("call_1", "bash", `{"command":"git status --short"}`))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if d.Action != tc.action {
			t.Errorf("%s: decision = %+v, want %v", tc.name, d, tc.action)
		}
	}

	// An untrusted source's allow rules are reported rather than
	// dropped, and its deny and ask rules apply at once.
	e, err := Build(Policy{Default: Allow()}, testMatchers)
	if err != nil {
		t.Fatal(err)
	}
	e.GrantSet(ctx, RuleSet{
		Source: Source{Name: "skill"},
		Allow:  rules(t, "bash(git status:*)"),
		Deny:   rules(t, "bash(git push:*)"),
	})
	if got := ruleText(e.Withheld()); got != "bash(git status:*)" {
		t.Errorf("Withheld = %q", got)
	}
	if d, _ := e.Decide(ctx, call("call_1", "bash", `{"command":"git push --force"}`)); d.Action != agentturn.Block {
		t.Errorf("an untrusted source's deny rule: %+v", d)
	}
}

// Several skills are several sources, each activated and revoked on
// its own, so the tools of a skill the model never opened are never
// granted.
func TestGrantSetIsKeyedBySource(t *testing.T) {
	ctx := context.Background()
	e, err := Build(Policy{Ask: rules(t, "bash"), Default: Ask()}, testMatchers)
	if err != nil {
		t.Fatal(err)
	}
	commit := RuleSet{Source: Source{Name: "skill:commit", Trusted: true}, Allow: rules(t, "bash(git commit:*)")}
	review := RuleSet{Source: Source{Name: "skill:review", Trusted: true}, Allow: rules(t, "bash(git diff:*)")}
	e.GrantSet(ctx, commit)
	e.GrantSet(ctx, review)
	allowed := func(command string) bool {
		d, err := e.Decide(ctx, call("call_1", "bash", `{"command":"`+command+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		return d.Action == agentturn.Allow
	}
	if !allowed("git commit -m x") || !allowed("git diff HEAD") {
		t.Error("both skills' rules should be in force")
	}
	// Activating a source again replaces its rules rather than adding
	// to them.
	e.GrantSet(ctx, RuleSet{Source: commit.Source, Allow: rules(t, "bash(git add:*)")})
	if allowed("git commit -m x") || !allowed("git add -A") {
		t.Error("a second grant under one source should replace the first")
	}
	if got := len(e.Grants()); got != 2 {
		t.Errorf("%d grants, want 2", got)
	}
	// Revoking one leaves the other.
	e.Revoke(ctx, "skill:commit")
	if allowed("git add -A") || !allowed("git diff HEAD") {
		t.Error("revoking one source should leave the other")
	}
	if n := e.Revoke(ctx, "skill:none"); n != 0 {
		t.Errorf("revoking an unknown source removed %d rules", n)
	}
}

// A grant set's allow rule shadows an ask rule, and never a deny rule
// or an ask rule of its own source.
func TestGrantSetShadowLimits(t *testing.T) {
	ctx := context.Background()
	skill := Source{Name: "skill", Rank: 1, Trusted: true}
	e, err := Build(Policy{
		Deny:    []Rule{{Tool: "bash", Spec: "git push:*", Source: Source{Name: "managed", Rank: 3}}},
		Ask:     []Rule{{Tool: "bash", Spec: "git commit:*", Source: Source{Name: "project", Rank: 1}}},
		Default: Allow(),
	}, testMatchers)
	if err != nil {
		t.Fatal(err)
	}
	e.GrantSet(ctx, RuleSet{Source: skill, Allow: rules(t, "bash(git push:*) bash(git commit:*) bash(git status:*)"), Ask: rules(t, "bash(git status:*)")})
	for _, tc := range []struct {
		command string
		want    agentturn.ToolAction
		reason  string
	}{
		// A deny is never shadowed.
		{"git push --force", agentturn.Block, "denied by bash(git push:*)"},
		// An ask rule of equal rank from another source is.
		{"git commit -m x", agentturn.Allow, "allowed by bash(git commit:*)"},
		// The set's own ask rule is not: a set that both asks and
		// allows for a subject means ask.
		{"git status", agentturn.Defer, "approval required by bash(git status:*)"},
	} {
		d, err := e.Decide(ctx, call("call_1", "bash", `{"command":"`+tc.command+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		if d.Action != tc.want || d.Reason != tc.reason {
			t.Errorf("%q: decision = %+v, want %v %q", tc.command, d, tc.want, tc.reason)
		}
	}
}

// Every grant and every refusal reaches the observer.
func TestGrantSetJournal(t *testing.T) {
	ctx := context.Background()
	j := &journal{}
	e, err := Build(Policy{Ask: []Rule{{Tool: "bash", Source: Source{Name: "managed", Rank: 3}}}, Default: Ask()}, testMatchers, WithObserver(j.observe))
	if err != nil {
		t.Fatal(err)
	}
	e.GrantSet(ctx, RuleSet{
		Source: Source{Name: "skill:commit", Rank: 3, Trusted: true},
		Allow:  rules(t, "read(/repo:*) bash(git add:*)"),
	})
	e.Revoke(ctx, "skill:commit")
	var got []string
	for _, v := range j.all() {
		got = append(got, v.Reason)
	}
	want := []string{
		"granted read(/repo:*) by skill:commit",
		"granted bash(git add:*) by skill:commit",
		"revoked the rules granted by skill:commit",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("verdicts = %q\nwant %q", got, want)
	}
}
