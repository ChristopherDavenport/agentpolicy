package agentpolicy

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRules(t *testing.T) {
	tests := []struct {
		in   string
		want []Rule
		err  string
	}{
		{in: "", want: nil},
		{in: "   \n\t ", want: nil},
		{in: "Bash", want: []Rule{{Tool: "Bash"}}},
		{in: "Bash Read", want: []Rule{{Tool: "Bash"}, {Tool: "Read"}}},
		{in: "Bash(git:*)", want: []Rule{{Tool: "Bash", Spec: "git:*"}}},
		{in: "Bash(git status:*) Bash(npm test:*)", want: []Rule{{Tool: "Bash", Spec: "git status:*"}, {Tool: "Bash", Spec: "npm test:*"}}},
		{in: "Bash(git add *) Bash(git commit *) Bash(git status *)", want: []Rule{{Tool: "Bash", Spec: "git add *"}, {Tool: "Bash", Spec: "git commit *"}, {Tool: "Bash", Spec: "git status *"}}},
		{in: "Edit(./Finance (2024)/**)", want: []Rule{{Tool: "Edit", Spec: "./Finance (2024)/**"}}},
		{in: "Read(!.env.example)", want: []Rule{{Tool: "Read", Spec: "!.env.example"}}},
		{in: "mcp__github__get_issue", want: []Rule{{Tool: "mcp__github__get_issue"}}},
		{in: "  Bash(a b)\n Read\t", want: []Rule{{Tool: "Bash", Spec: "a b"}, {Tool: "Read"}}},
		{in: "Bash(git", err: `agentpolicy: rule "Bash(git": unbalanced parentheses`},
		{in: "Bash(git status", err: `agentpolicy: rule "Bash(git status": unbalanced parentheses`},
		{in: "Bash git)", err: `agentpolicy: rule "git)": unbalanced parentheses`},
		{in: ")", err: `agentpolicy: rule ")": unbalanced parentheses`},
		{in: "(git:*)", err: `agentpolicy: rule "(git:*)": missing tool name`},
		{in: "Bash()", err: `agentpolicy: rule "Bash()": empty specifier`},
		{in: "Read(!)", err: `agentpolicy: rule "Read(!)": empty carve-out`},
		{in: "Bash(git)x", err: `agentpolicy: rule "Bash(git)x": text after the specifier`},
	}
	for _, tc := range tests {
		got, err := ParseRules(tc.in)
		if tc.err != "" {
			if err == nil || err.Error() != tc.err {
				t.Errorf("ParseRules(%q) err = %v, want %q", tc.in, err, tc.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRules(%q): %v", tc.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParseRules(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

func TestRuleString(t *testing.T) {
	// Every parsed rule renders back to its token, so a product can
	// write a granted rule into its settings as it was written.
	for _, in := range []string{"Bash", "Bash(git:*)", "Bash(git status *)", "Edit(./Finance (2024)/**)", "Read(!.env)"} {
		rules, err := ParseRules(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := rules[0].String(); got != in {
			t.Errorf("String() = %q, want %q", got, in)
		}
	}
	// The source is not rendered.
	r := Rule{Tool: "Bash", Spec: "git:*", Source: Source{Name: "project"}}
	if r.String() != "Bash(git:*)" {
		t.Errorf("String() = %q", r.String())
	}
}

func TestRuleCarveOut(t *testing.T) {
	tests := []struct {
		rule    Rule
		pattern string
		ok      bool
	}{
		{Rule{Tool: "Read"}, "", false},
		{Rule{Tool: "Read", Spec: ".env"}, "", false},
		{Rule{Tool: "Read", Spec: "!.env"}, ".env", true},
		{Rule{Tool: "Bash", Spec: "!git push:*"}, "git push:*", true},
	}
	for _, tc := range tests {
		pattern, ok := tc.rule.CarveOut()
		if pattern != tc.pattern || ok != tc.ok {
			t.Errorf("%s.CarveOut() = %q, %v; want %q, %v", tc.rule, pattern, ok, tc.pattern, tc.ok)
		}
		if tc.rule.Bare() != (tc.rule.Spec == "") {
			t.Errorf("%s.Bare() = %v", tc.rule, tc.rule.Bare())
		}
	}
}

func TestRuleErrorsArePrefixed(t *testing.T) {
	for _, in := range []string{"Bash(", "()", "Bash()"} {
		if _, err := ParseRules(in); err == nil || !strings.HasPrefix(err.Error(), "agentpolicy: ") {
			t.Errorf("ParseRules(%q) err = %v", in, err)
		}
	}
}
