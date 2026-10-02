package agentpolicy

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
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
		// A carve-out lets some calls past the bare rule, so the rule
		// does not certainly keep the grant from firing. (#60)
		{
			name:    "a deny rule a carve-out reaches is left to the decision",
			policy:  Policy{Deny: []Rule{{Tool: "bash", Source: managed}, {Tool: "bash", Spec: "!git status:*", Source: managed}}, Default: Allow()},
			set:     RuleSet{Source: Source{Name: "skill", Rank: 9, Trusted: true}, Allow: rules(t, "bash(git status:*)")},
			granted: "bash(git status:*)",
			action:  agentturn.Allow,
		},
		{
			name:    "an ask rule a carve-out reaches is left to the decision",
			policy:  Policy{Ask: []Rule{{Tool: "bash", Source: managed}, {Tool: "bash", Spec: "!git status:*", Source: managed}}, Default: Ask()},
			set:     RuleSet{Source: Source{Name: "skill", Rank: 1, Trusted: true}, Allow: rules(t, "bash(git status:*)")},
			granted: "bash(git status:*)",
			action:  agentturn.Allow,
		},
		{
			name:    "a carve-out from a lower source does not reach the deny",
			policy:  Policy{Deny: []Rule{{Tool: "bash", Source: managed}, {Tool: "bash", Spec: "!git status:*", Source: Source{Name: "project", Rank: 1, Trusted: true}}}, Default: Allow()},
			set:     RuleSet{Source: Source{Name: "skill", Rank: 9, Trusted: true}, Allow: rules(t, "bash(git status:*)")},
			refused: []Refusal{{Rule: Rule{Tool: "bash", Spec: "git status:*", Source: Source{Name: "skill", Rank: 9, Trusted: true}}, Reason: "denied by bash: a grant never beats a deny"}},
			action:  agentturn.Block,
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

// One engine serves every agent of a product, so its rules change
// under decisions being made in another agent's run. Under -race this
// fails if a mutator writes through a list a decision snapshotted.
func TestEngineIsSafeForConcurrentUse(t *testing.T) {
	ctx := context.Background()
	e, err := Build(Policy{Ask: rules(t, "bash"), Allow: rules(t, "read"), Default: Ask()}, testMatchers)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			run := fmt.Sprintf("run_%d", i)
			for n := range 50 {
				info := call(fmt.Sprintf("call_%d_%d", i, n), "bash", `{"command":"git status"}`)
				info.RunID = run
				if _, err := e.Decide(ctx, info); err != nil {
					t.Error(err)
					return
				}
			}
			e.Forget(run)
		}()
	}
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			src := Source{Name: fmt.Sprintf("skill_%d", i), Trusted: true}
			for range 50 {
				e.GrantSet(ctx, RuleSet{Source: src, Allow: rules(t, "bash(git status:*)")})
				e.Grants()
				e.Withheld()
				e.Revoke(ctx, src.Name)
			}
		}()
	}
	wg.Wait()
}

// One engine serves every agent of a product and remembers deferred
// calls per run, but a grant set had no run: a skill the main agent
// opened granted its tools to a sub-agent, or to another
// conversation, that never opened it, which agentkit v0.0.4 fails
// closed on. A grant scope on the context keeps a set to the
// conversation that activated it. (#18)
func TestGrantCrossesAgents(t *testing.T) {
	ctx := context.Background()
	a := ContextWithGrantScope(ctx, "A")
	b := ContextWithGrantScope(ctx, "B")
	if got := GrantScopeFromContext(a); got != "A" {
		t.Errorf("GrantScopeFromContext = %q", got)
	}
	if got := GrantScopeFromContext(ctx); got != "" {
		t.Errorf("GrantScopeFromContext of no scope = %q", got)
	}
	j := &journal{}
	e, err := Build(Policy{Ask: rules(t, "bash"), Default: Allow()}, testMatchers, WithObserver(j.observe))
	if err != nil {
		t.Fatal(err)
	}
	commit := RuleSet{Source: Source{Name: "skill:commit", Trusted: true}, Allow: rules(t, "bash(git commit:*)")}
	review := RuleSet{Source: Source{Name: "skill:review", Trusted: true}, Allow: rules(t, "bash(git diff:*)")}
	decide := func(t *testing.T, ctx context.Context, command string) *agentturn.ToolDecision {
		t.Helper()
		d, err := e.Decide(ctx, call("call_1", "bash", `{"command":"`+command+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	check := func(t *testing.T, name string, ctx context.Context, command string, want agentturn.ToolAction, reason string) {
		t.Helper()
		if d := decide(t, ctx, command); d.Action != want || d.Reason != reason {
			t.Errorf("%s: %q = %v %q, want %v %q", name, command, d.Action, d.Reason, want, reason)
		}
	}
	names := func(sets []RuleSet) string {
		var out []string
		for _, s := range sets {
			out = append(out, s.Source.Name)
		}
		return strings.Join(out, " ")
	}
	const (
		allowed = "allowed by bash(git commit:*)"
		asks    = "approval required by bash"
	)

	// The set the main agent's conversation activates decides its own
	// calls, and nobody else's.
	granted, refused := e.GrantSet(a, commit)
	if got := ruleText(granted); got != "bash(git commit:*)" || len(refused) != 0 {
		t.Fatalf("GrantSet under A = %q, %+v", got, refused)
	}
	check(t, "under A", a, "git commit -m wip", agentturn.Allow, allowed)
	check(t, "under B", b, "git commit -m wip", agentturn.Defer, asks)
	check(t, "under no scope", ctx, "git commit -m wip", agentturn.Defer, asks)
	if got := names(e.Grants()); got != "skill:commit" {
		t.Errorf("Grants = %q", got)
	}
	for name, c := range map[string]context.Context{"A": a, "B": b, "none": ctx} {
		want := ""
		if name == "A" {
			want = "skill:commit"
		}
		if got := names(e.GrantsFor(c)); got != want {
			t.Errorf("GrantsFor(%s) = %q, want %q", name, got, want)
		}
	}

	// A revoke under another scope, or under none, leaves A's set.
	if n := e.Revoke(b, "skill:commit"); n != 0 {
		t.Errorf("Revoke under B removed %d rules", n)
	}
	if n := e.Revoke(ctx, "skill:commit"); n != 0 {
		t.Errorf("Revoke under no scope removed %d rules", n)
	}
	check(t, "after the other revokes", a, "git commit -m wip", agentturn.Allow, allowed)
	if n := e.Revoke(a, "skill:commit"); n != 1 {
		t.Errorf("Revoke under A removed %d rules", n)
	}
	check(t, "after A's revoke", a, "git commit -m wip", agentturn.Defer, asks)
	if got := len(e.Grants()); got != 0 {
		t.Errorf("%d grants after the revoke", got)
	}

	// An unscoped set decides every call the engine sees, as before,
	// and a scoped revoke never removes it.
	e.GrantSet(ctx, commit)
	for name, c := range map[string]context.Context{"A": a, "B": b, "none": ctx} {
		check(t, "unscoped set under "+name, c, "git commit -m wip", agentturn.Allow, allowed)
	}
	if n := e.Revoke(a, "skill:commit"); n != 0 {
		t.Errorf("a scoped Revoke removed %d unscoped rules", n)
	}
	check(t, "unscoped set after a scoped revoke", a, "git commit -m wip", agentturn.Allow, allowed)

	// A decision consults the unscoped sets, then its scope's, and
	// Grants spans every scope, unscoped first; the same source under
	// two scopes is two sets.
	e.GrantSet(a, review)
	e.GrantSet(b, RuleSet{Source: review.Source, Allow: rules(t, "bash(git log:*)")})
	if got := names(e.Grants()); got != "skill:commit skill:review skill:review" {
		t.Errorf("Grants = %q", got)
	}
	if got := names(e.GrantsFor(a)); got != "skill:commit skill:review" {
		t.Errorf("GrantsFor(A) = %q", got)
	}
	if got := ruleText(e.GrantsFor(b)[1].Allow); got != "bash(git log:*)" {
		t.Errorf("GrantsFor(B)'s review set = %q", got)
	}
	if got := names(e.GrantsFor(ctx)); got != "skill:commit" {
		t.Errorf("GrantsFor(none) = %q", got)
	}
	check(t, "A's review set", a, "git diff HEAD", agentturn.Allow, "allowed by bash(git diff:*)")
	check(t, "B has no git diff", b, "git diff HEAD", agentturn.Defer, asks)
	check(t, "B's review set", b, "git log", agentturn.Allow, "allowed by bash(git log:*)")

	// RevokeScope takes every set of the conversation back when it
	// ends, and under no scope every unscoped set.
	if n := e.RevokeScope(a); n != 1 {
		t.Errorf("RevokeScope(A) removed %d rules", n)
	}
	if got := names(e.GrantsFor(a)); got != "skill:commit" {
		t.Errorf("GrantsFor(A) after RevokeScope = %q", got)
	}
	if n := e.RevokeScope(a); n != 0 {
		t.Errorf("a second RevokeScope(A) removed %d rules", n)
	}
	check(t, "B keeps its set", b, "git log", agentturn.Allow, "allowed by bash(git log:*)")
	if n := e.RevokeScope(ctx); n != 1 {
		t.Errorf("RevokeScope under no scope removed %d rules", n)
	}
	if got := names(e.Grants()); got != "skill:review" {
		t.Errorf("Grants after the unscoped RevokeScope = %q", got)
	}
	check(t, "B after the unscoped RevokeScope", b, "git commit -m wip", agentturn.Defer, asks)
	e.RevokeScope(b)
	if got := len(e.Grants()); got != 0 {
		t.Errorf("%d grants after every RevokeScope", got)
	}

	// The grant verdicts have no scope member and keep their text; a
	// RevokeScope that removed a rule is one verdict.
	var got []string
	for _, v := range j.all() {
		if v.CallID == "" {
			got = append(got, v.Reason)
		}
	}
	want := []string{
		"granted bash(git commit:*) by skill:commit",
		"revoked the rules granted by skill:commit",
		"granted bash(git commit:*) by skill:commit",
		"granted bash(git diff:*) by skill:review",
		"granted bash(git log:*) by skill:review",
		"revoked the rules granted under A",
		"revoked the rules granted without a scope",
		"revoked the rules granted under B",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("verdicts = %q\nwant %q", got, want)
	}
}

// Withheld spans every scope, and an untrusted set is keyed as a
// trusted one is: by its scope and its source.
func TestWithheldSpansEveryScope(t *testing.T) {
	ctx := context.Background()
	a := ContextWithGrantScope(ctx, "A")
	b := ContextWithGrantScope(ctx, "B")
	e, err := Build(Policy{Default: Allow()}, testMatchers)
	if err != nil {
		t.Fatal(err)
	}
	skill := Source{Name: "skill"}
	e.GrantSet(a, RuleSet{Source: skill, Allow: rules(t, "bash(git status:*)")})
	e.GrantSet(b, RuleSet{Source: skill, Allow: rules(t, "bash(git log:*)")})
	e.GrantSet(ctx, RuleSet{Source: skill, Allow: rules(t, "bash(git diff:*)")})
	if got := ruleText(e.Withheld()); got != "bash(git diff:*) bash(git status:*) bash(git log:*)" {
		t.Errorf("Withheld = %q", got)
	}
	e.Revoke(a, skill.Name)
	if got := ruleText(e.Withheld()); got != "bash(git diff:*) bash(git log:*)" {
		t.Errorf("Withheld after A's revoke = %q", got)
	}
	e.RevokeScope(ctx)
	if got := ruleText(e.Withheld()); got != "bash(git log:*)" {
		t.Errorf("Withheld after the unscoped RevokeScope = %q", got)
	}
}

// The batch hold reads the siblings under the decision's scope: a
// sibling a scoped set allows asks under every other scope, and the
// batch cache is never read across two scopes, even for one batch of
// one run decided under both.
func TestBatchHoldIsScoped(t *testing.T) {
	ctx := context.Background()
	a := ContextWithGrantScope(ctx, "A")
	b := ContextWithGrantScope(ctx, "B")
	e, err := Build(Policy{Ask: rules(t, "bash(git push:*)"), Default: Allow()}, testMatchers)
	if err != nil {
		t.Fatal(err)
	}
	e.GrantSet(a, RuleSet{Source: Source{Name: "skill:push", Trusted: true}, Allow: rules(t, "bash(git push:*)")})
	type want struct {
		action agentturn.ToolAction
		reason string
	}
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want []want
	}{
		{"under A nothing asks", a, []want{{agentturn.Allow, "allowed by default"}, {agentturn.Allow, "allowed by bash(git push:*)"}}},
		{"under B the sibling asks", b, []want{{agentturn.Defer, "held for approval: allowed by default"}, {agentturn.Defer, "approval required by bash(git push:*)"}}},
		{"under no scope the sibling asks", ctx, []want{{agentturn.Defer, "held for approval: allowed by default"}, {agentturn.Defer, "approval required by bash(git push:*)"}}},
	} {
		for i, info := range batch("run_1", "git status", "git push") {
			d, err := e.Decide(tc.ctx, info)
			if err != nil {
				t.Fatal(err)
			}
			if d.Action != tc.want[i].action || d.Reason != tc.want[i].reason {
				t.Errorf("%s[%d]: %v %q, want %v %q", tc.name, i, d.Action, d.Reason, tc.want[i].action, tc.want[i].reason)
			}
		}
		e.Forget("run_1")
	}
}
