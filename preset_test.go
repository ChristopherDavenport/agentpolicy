package agentpolicy

import (
	"context"
	"testing"

	"github.com/ChristopherDavenport/agentturn"
)

func TestPresets(t *testing.T) {
	tools := Tools{Read: []string{"read", "grep"}, Edit: []string{"edit", "write"}, Execute: []string{"bash"}}
	type want map[string]agentturn.ToolAction
	tests := []struct {
		name   string
		policy Policy
		want   want
	}{
		{"suggest", Suggest(tools), want{"read": agentturn.Allow, "grep": agentturn.Allow, "edit": agentturn.Defer, "write": agentturn.Defer, "bash": agentturn.Defer, "web_fetch": agentturn.Defer}},
		{"auto-edit", AutoEdit(tools), want{"read": agentturn.Allow, "grep": agentturn.Allow, "edit": agentturn.Allow, "write": agentturn.Allow, "bash": agentturn.Defer, "web_fetch": agentturn.Defer}},
		{"full-auto", FullAuto(tools), want{"read": agentturn.Allow, "grep": agentturn.Allow, "edit": agentturn.Allow, "write": agentturn.Allow, "bash": agentturn.Allow, "web_fetch": agentturn.Defer}},
	}
	for _, tc := range tests {
		e, err := Build(tc.policy, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for tool, action := range tc.want {
			d, err := e.Decide(context.Background(), call("c", tool, `{}`))
			if err != nil {
				t.Fatal(err)
			}
			if d.Action != action {
				t.Errorf("%s: %s = %v, want %v", tc.name, tool, d.Action, action)
			}
		}
	}
	// The presets over no tools still have a default.
	if _, err := Build(Suggest(Tools{}), nil); err != nil {
		t.Error(err)
	}
}
