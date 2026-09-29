package agentpolicy

import (
	"testing"

	"github.com/ChristopherDavenport/agentturn"
)

func TestVerdictRecord(t *testing.T) {
	project := Source{Name: "project", Path: ".agent/settings.json", Rank: 1}
	tests := []struct {
		name string
		v    Verdict
		want string
	}{
		{name: "a decision", v: Verdict{RunID: "run_1", Turn: 2, CallID: "call_1", Tool: "bash", Action: agentturn.Block, Rule: &Rule{Tool: "bash", Spec: "curl:*", Source: project, Note: "use fetch"}, Reason: "denied by bash(curl:*): use fetch", By: ByPolicy, Subject: "curl x", Confined: "landlock+seccomp"},
			want: `{"run_id":"run_1","turn":2,"call_id":"call_1","tool":"bash","action":"block","rule":"bash(curl:*)","source":"project","note":"use fetch","reason":"denied by bash(curl:*): use fetch","by":"policy","subject":"curl x","confined":"landlock+seccomp"}`},
		{name: "a held call", v: Verdict{RunID: "run_1", CallID: "call_2", Tool: "read", Action: agentturn.Defer, Held: true, Reason: "held for approval: allowed by default", By: ByPolicy},
			want: `{"run_id":"run_1","call_id":"call_2","tool":"read","action":"defer","reason":"held for approval: allowed by default","by":"policy","held":true}`},
		{name: "a guard's verdict", v: Verdict{RunID: "run_1", Guard: "secrets", Action: agentturn.Allow},
			want: `{"run_id":"run_1","guard":"secrets","action":"allow"}`},
		{name: "the zero verdict", want: `{"action":"allow"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, data := tt.v.Record()
			if ns != "agentpolicy:verdict" || string(data) != tt.want {
				t.Errorf("Record = %s %s\nwant %s", ns, data, tt.want)
			}
		})
	}
}
