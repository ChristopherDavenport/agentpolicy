package agentpolicy

import (
	"context"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agenttool"
	"github.com/ChristopherDavenport/agentturn"
)

func TestMatchesTool(t *testing.T) {
	tests := []struct {
		rule, tool string
		want       bool
	}{
		{"bash", "bash", true},
		{"bash", "Bash", false},
		{"bash", "bashful", false},
		{"mcp__*", "mcp__shell__exec", true},
		{"mcp__*", "mcp__", true},
		{"mcp__*", "bash", false},
		{"mcp__*__exec", "mcp__shell__exec", true},
		{"mcp__*__exec", "mcp__shell__list", false},
		{"*", "anything", true},
		{"ls *", "lsof", false},
		{"ls*", "lsof", true},
	}
	for _, tc := range tests {
		if got := (Rule{Tool: tc.rule}).MatchesTool(tc.tool); got != tc.want {
			t.Errorf("Rule{%q}.MatchesTool(%q) = %v, want %v", tc.rule, tc.tool, got, tc.want)
		}
	}
}

// A tool-name glob in the deny and ask lists fires, where at v0.0.2 it
// built, was reported by Engine.Policy, was shown by any front that
// lists the rules, and had no effect on any call.
func TestGlobRulesFire(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		policy Policy
		tool   string
		want   agentturn.ToolAction
		reason string
	}{
		{name: "a glob deny blocks every tool it names", policy: Policy{Deny: rules(t, "mcp__*"), Default: Allow()}, tool: "mcp__shell__exec", want: agentturn.Block, reason: "denied by mcp__*"},
		{name: "and leaves the others alone", policy: Policy{Deny: rules(t, "mcp__*"), Default: Allow()}, tool: "bash", want: agentturn.Allow, reason: "allowed by default"},
		{name: "a glob ask defers", policy: Policy{Ask: rules(t, "mcp__*"), Default: Allow()}, tool: "mcp__shell__exec", want: agentturn.Defer, reason: "approval required by mcp__*"},
		{name: "a deny glob beats an allow rule", policy: Policy{Deny: rules(t, "mcp__*"), Allow: rules(t, "mcp__shell__exec"), Default: Deny()}, tool: "mcp__shell__exec", want: agentturn.Block, reason: "denied by mcp__*"},
	}
	for _, tc := range tests {
		e, err := Build(tc.policy, testMatchers)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		d, err := e.Decide(ctx, call("call_1", tc.tool, `{"command":"rm -rf /"}`))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if d.Action != tc.want || d.Reason != tc.reason {
			t.Errorf("%s: decision = %+v, want %v %q", tc.name, d, tc.want, tc.reason)
		}
	}
}

// A bare-name deny removes the tool from the request, as the reference
// does: the model never sees it, rather than planning around a tool
// every call to which is refused.
func TestFilterRemovesDeniedTools(t *testing.T) {
	ctx := context.Background()
	tool := func(name string) agenttool.Tool {
		return agenttool.New(name, "a tool", func(context.Context, struct{}) (string, error) { return "", nil })
	}
	base := []agenttool.Tool{tool("read"), tool("bash"), tool("mcp__shell__exec"), tool("edit")}
	e, err := Build(Policy{
		Deny:    rules(t, "bash mcp__* edit(/etc:*)"),
		Default: Allow(),
	}, testMatchers)
	if err != nil {
		t.Fatal(err)
	}
	names := func(tools []agenttool.Tool) string {
		var out []string
		for _, t := range tools {
			out = append(out, t.Name())
		}
		return strings.Join(out, " ")
	}
	// A bare deny and a glob deny take the tool away; a deny with a
	// specifier denies some calls and leaves the tool offered.
	if got := names(e.Filter(base)); got != "read edit" {
		t.Errorf("Filter = %q, want %q", got, "read edit")
	}
	for _, tc := range []struct {
		tool string
		rule string
	}{{"bash", "bash"}, {"mcp__shell__exec", "mcp__*"}} {
		r, ok := e.Removes(tc.tool)
		if !ok || r.String() != tc.rule {
			t.Errorf("Removes(%q) = %v, %v", tc.tool, r, ok)
		}
	}
	for _, name := range []string{"read", "edit"} {
		if r, ok := e.Removes(name); ok {
			t.Errorf("Removes(%q) = %v", name, r)
		}
	}

	// The provider filters the list of the moment, so a tool a server
	// announces mid-session is filtered as it appears and a grant is
	// picked up on the next turn.
	offered := base
	provider := e.ToolProvider(func(context.Context) []agenttool.Tool { return offered })
	if got := names(provider(ctx)); got != "read edit" {
		t.Errorf("provider = %q", got)
	}
	offered = append(offered, tool("mcp__git__push"))
	if got := names(provider(ctx)); got != "read edit" {
		t.Errorf("provider after a late tool = %q", got)
	}
	if got := names(e.ToolProvider(nil)(ctx)); got != "" {
		t.Errorf("a nil base = %q", got)
	}

	// A grant set's bare deny, a skill's disallowed-tools, removes the
	// tool while the set is active, trusted or not, and a revoke gives
	// it back; its deny with a specifier leaves the tool offered.
	skill := Source{Name: "skill:review", Rank: 1}
	if granted, refused := e.GrantSet(ctx, RuleSet{Source: skill, Deny: rules(t, "read(/secrets:*)")}); len(granted)+len(refused) != 0 {
		t.Fatalf("GrantSet = %v, %v", granted, refused)
	}
	if got := names(provider(ctx)); got != "read edit" {
		t.Errorf("provider under a deny with a specifier = %q", got)
	}
	e.GrantSet(ctx, RuleSet{Source: skill, Deny: rules(t, "edit")})
	if got := names(provider(ctx)); got != "read" {
		t.Errorf("provider under the skill = %q", got)
	}
	if r, ok := e.Removes("edit"); !ok || r.String() != "edit" || r.Source != skill {
		t.Errorf("Removes(edit) under the skill = %+v, %v", r, ok)
	}
	if d, _ := e.Decide(ctx, call("call_1", "edit", `{"path":"x"}`)); d.Action != agentturn.Block || d.Reason != "denied by edit" {
		t.Errorf("Decide(edit) under the skill = %+v", d)
	}
	e.Revoke(ctx, skill.Name)
	if got := names(provider(ctx)); got != "read edit" {
		t.Errorf("provider after the revoke = %q", got)
	}
	if _, ok := e.Removes("edit"); ok {
		t.Error("Removes(edit) after the revoke")
	}
}

// The provider reads the grant scope of the context the loop consults
// it with, so a scoped set's bare deny takes the tool out of the offer
// for the runs under its scope and no other; Filter and Removes take
// no context and read the unscoped sets. (#18)
func TestToolProviderIsScoped(t *testing.T) {
	ctx := context.Background()
	a := ContextWithGrantScope(ctx, "A")
	b := ContextWithGrantScope(ctx, "B")
	tool := func(name string) agenttool.Tool {
		return agenttool.New(name, "a tool", func(context.Context, struct{}) (string, error) { return "", nil })
	}
	base := []agenttool.Tool{tool("read"), tool("bash"), tool("edit")}
	names := func(tools []agenttool.Tool) string {
		var out []string
		for _, t := range tools {
			out = append(out, t.Name())
		}
		return strings.Join(out, " ")
	}
	e, err := Build(Policy{Default: Allow()}, testMatchers)
	if err != nil {
		t.Fatal(err)
	}
	provider := e.ToolProvider(func(context.Context) []agenttool.Tool { return base })
	skill := Source{Name: "skill:review", Rank: 1}
	e.GrantSet(a, RuleSet{Source: skill, Deny: rules(t, "edit")})
	for name, tc := range map[string]struct {
		ctx  context.Context
		want string
	}{"A": {a, "read bash"}, "B": {b, "read bash edit"}, "none": {ctx, "read bash edit"}} {
		if got := names(provider(tc.ctx)); got != tc.want {
			t.Errorf("provider under %s = %q, want %q", name, got, tc.want)
		}
	}
	if got := names(e.Filter(base)); got != "read bash edit" {
		t.Errorf("Filter = %q", got)
	}
	if r, ok := e.Removes("edit"); ok {
		t.Errorf("Removes(edit) = %v under a scoped set", r)
	}

	// An unscoped set removes the tool for every scope, and Filter and
	// Removes read it.
	e.GrantSet(ctx, RuleSet{Source: Source{Name: "skill:safe", Rank: 1}, Deny: rules(t, "bash")})
	for name, tc := range map[string]struct {
		ctx  context.Context
		want string
	}{"A": {a, "read"}, "B": {b, "read edit"}, "none": {ctx, "read edit"}} {
		if got := names(provider(tc.ctx)); got != tc.want {
			t.Errorf("provider under %s with the unscoped set = %q, want %q", name, got, tc.want)
		}
	}
	if got := names(e.Filter(base)); got != "read edit" {
		t.Errorf("Filter with the unscoped set = %q", got)
	}
	if r, ok := e.Removes("bash"); !ok || r.String() != "bash" {
		t.Errorf("Removes(bash) = %v, %v", r, ok)
	}
	if n := e.RevokeScope(a); n != 1 {
		t.Errorf("RevokeScope(A) removed %d rules", n)
	}
	if got := names(provider(a)); got != "read edit" {
		t.Errorf("provider under A after RevokeScope = %q", got)
	}
}
