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
}
