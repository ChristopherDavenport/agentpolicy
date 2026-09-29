package agentpolicy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ChristopherDavenport/agentturn"
)

// The reference's documented Bash pattern table, which the round 1 to 3
// studies ran against PrefixMatcher; the last four rows are where it
// diverges. GlobMatcher agrees with every row.
var referenceTable = []struct {
	spec, cmd  string
	documented bool
	prefix     bool
}{
	{"npm run build", "npm run build", true, true},
	{"npm run:*", "npm run build", true, true},
	{"ls *", "lsof", false, false},
	{"git log * main", "git log --oneline main", true, false},
	{"* --version", "node --version", true, false},
	{"ls:*", "lsof", false, true},
	{"ls*", "lsof", true, false},
}

func TestGlobMatcherAgreesWithTheReference(t *testing.T) {
	glob, prefix := GlobMatcher("command"), PrefixMatcher("command")
	for _, tc := range referenceTable {
		args, _ := json.Marshal(map[string]string{"command": tc.cmd})
		if got := glob(tc.spec, args); got != tc.documented {
			t.Errorf("GlobMatcher(%q, %q) = %v, documented %v", tc.spec, tc.cmd, got, tc.documented)
		}
		// PrefixMatcher is unchanged, divergences and all.
		if got := prefix(tc.spec, args); got != tc.prefix {
			t.Errorf("PrefixMatcher(%q, %q) = %v, want %v", tc.spec, tc.cmd, got, tc.prefix)
		}
	}
}

func TestGlobMatcher(t *testing.T) {
	m := GlobMatcher("command")
	tests := []struct {
		spec, args string
		want       bool
	}{
		{"git:*", `{"command":"git"}`, true},
		{"git:*", `{"command":"git status"}`, true},
		{"git:*", `{"command":"gitk"}`, false},
		{"git status", `{"command":"git status"}`, true},
		{"git status", `{"command":"git status --short"}`, false},
		{"git status", `{"command":"Git status"}`, false},
		{"git push * main", `{"command":"git push --force origin main"}`, true},
		{"git push * main", `{"command":"git push origin main-backup"}`, false},
		{"git * main:*", `{"command":"git push origin main --force"}`, true},
		{"git * main:*", `{"command":"git push origin mainline"}`, false},
		{"*", `{"command":""}`, true},
		{":*", `{"command":"anything at all"}`, true},
		{"ls:*", `{"command":"ls\t-la"}`, false},
		{"ls *", `{"command":"ls"}`, false},
		{"ls *", `{"command":"ls -la"}`, true},
		{"*.env", `{"command":"cat .env"}`, true},
		{"git:*", `{"cmd":"git status"}`, false},
		{"git:*", `{"command":42}`, false},
		{"git:*", `not json`, false},
		{"git:*", ``, false},
	}
	for _, tc := range tests {
		if got := m(tc.spec, json.RawMessage(tc.args)); got != tc.want {
			t.Errorf("GlobMatcher(%q, %s) = %v, want %v", tc.spec, tc.args, got, tc.want)
		}
	}
}

// The failure the study named: a deny copied from the reference's
// documentation denies what it documents, and its carve-out reads the
// same grammar.
func TestGlobMatcherInTheEngine(t *testing.T) {
	e, err := Build(Policy{
		Deny:    rules(t, "bash(git push * main) bash(!git push --dry-run main)"),
		Default: Allow(),
	}, map[string]ToolMatcher{"bash": {Match: GlobMatcher("command")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cmd  string
		want agentturn.ToolAction
	}{
		{"git push --force origin main", agentturn.Block},
		{"git push --dry-run main", agentturn.Allow},
		{"git push origin feature", agentturn.Allow},
	} {
		args, _ := json.Marshal(map[string]string{"command": tc.cmd})
		if d, _ := e.Decide(context.Background(), call("call_1", "bash", string(args))); d.Action != tc.want {
			t.Errorf("%q: %+v, want %v", tc.cmd, d, tc.want)
		}
	}
}
