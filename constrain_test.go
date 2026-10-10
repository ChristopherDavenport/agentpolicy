package agentpolicy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
)

type skillArgs struct {
	Name  string   `json:"name"`
	Files []string `json:"files"`
	// Only leaves the call itself out of the subjects, so the splitter
	// returns constraints alone.
	Only bool `json:"only"`
}

// skillSplit stands in for a skill tool whose file reads a product
// holds to the read tool's asks and denies: the call itself, then one
// constraint per file under read.
func skillSplit(_ context.Context, args json.RawMessage) ([]Subject, error) {
	var a skillArgs
	if err := json.Unmarshal(args, &a); err != nil {
		return nil, err
	}
	var out []Subject
	if !a.Only {
		out = append(out, Subject{Args: args})
	}
	for _, f := range a.Files {
		path, _ := json.Marshal(map[string]string{"path": f})
		out = append(out, Subject{Args: path, Tool: "read", Text: f, Constrain: true})
	}
	return out, nil
}

var constrainMatchers = map[string]ToolMatcher{
	"skill": {Match: PrefixMatcher("name"), Subjects: skillSplit},
	"read":  {Match: PrefixMatcher("path")},
}

// skillCall builds the hook's view of one skill call.
func skillCall(t *testing.T, id string, a skillArgs) agentturn.ToolCallInfo {
	t.Helper()
	args, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return call(id, "skill", string(args))
}

func TestConstraintSubject(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name               string
		allow, deny, ask   string
		def                Default
		call               skillArgs
		action             agentturn.ToolAction
		rule, reason, subj string
	}{
		{name: "a deny rule refuses it", allow: "skill", deny: "read(.env)", def: Allow(),
			call:   skillArgs{Name: "x", Files: []string{".env"}},
			action: agentturn.Block, rule: "read(.env)", reason: `denied by read(.env) on ".env"; nothing in this command ran`, subj: ".env"},
		{name: "an ask rule asks about it", allow: "skill", ask: "read(.env)", def: Allow(),
			call:   skillArgs{Name: "x", Files: []string{".env"}},
			action: agentturn.Defer, rule: "read(.env)", reason: "approval required by read(.env)", subj: ".env"},
		{name: "an allow rule for its tool does not allow the call", allow: "read(.env)", def: Ask(),
			call:   skillArgs{Name: "x", Files: []string{".env"}},
			action: agentturn.Defer, reason: "no rule allows skill: approval required by default"},
		{name: "a bare allow for its tool does not allow the call either", allow: "read", def: Deny(),
			call:   skillArgs{Name: "x", Files: []string{".env"}},
			action: agentturn.Block, reason: "no rule allows skill: denied by default"},
		{name: "the default does not apply to it", allow: "skill", def: Ask(),
			call:   skillArgs{Name: "x", Files: []string{".env"}},
			action: agentturn.Allow, rule: "skill", reason: "allowed by skill"},
		{name: "nor a deny default", allow: "skill", def: Deny(),
			call:   skillArgs{Name: "x", Files: []string{".env"}},
			action: agentturn.Allow, rule: "skill", reason: "allowed by skill"},
		{name: "a carve-out lifts an ask", allow: "skill", ask: "read(.env:*) read(!.env.example)", def: Allow(),
			call:   skillArgs{Name: "x", Files: []string{".env.example"}},
			action: agentturn.Allow, rule: "skill", reason: "allowed by skill"},
		{name: "and only what it carves out", allow: "skill", ask: "read(.env:*) read(!.env.example)", def: Allow(),
			call:   skillArgs{Name: "y", Files: []string{".env.local"}},
			action: agentturn.Defer, rule: "read(.env:*)", reason: "approval required by read(.env:*)", subj: ".env.local"},
		{name: "a carve-out lifts a deny", allow: "skill", deny: "read(.env:*) read(!.env.example)", def: Allow(),
			call:   skillArgs{Name: "x", Files: []string{".env.example"}},
			action: agentturn.Allow, rule: "skill", reason: "allowed by skill"},
		{name: "mixed with ordinary subjects the strictest stands", allow: "skill", deny: "read(secrets:*)", ask: "read(.env)", def: Allow(),
			call:   skillArgs{Name: "x", Files: []string{"README.md", ".env", "secrets/key"}},
			action: agentturn.Block, rule: "read(secrets:*)", reason: `denied by read(secrets:*) on "secrets/key"; nothing in this command ran, including "README.md" and ".env"`, subj: "secrets/key"},
		{name: "an ask stands over the call's allow", allow: "skill", ask: "read(.env)", def: Allow(),
			call:   skillArgs{Name: "x", Files: []string{"README.md", ".env"}},
			action: agentturn.Defer, rule: "read(.env)", reason: "approval required by read(.env)", subj: ".env"},
		{name: "the call's own block stands over a constraint's ask", ask: "read(.env)", def: Deny(),
			call:   skillArgs{Name: "x", Files: []string{".env"}},
			action: agentturn.Block, reason: "no rule allows skill: denied by default"},
		{name: "the call's own ask is the first of equals", ask: "read(.env)", def: Ask(),
			call:   skillArgs{Name: "x", Files: []string{".env"}},
			action: agentturn.Defer, reason: "no rule allows skill: approval required by default"},
		// Every subject a constraint: the call itself is decided first.
		{name: "constraints alone are decided with the call itself", allow: "skill", def: Ask(),
			call:   skillArgs{Name: "x", Files: []string{"README.md"}, Only: true},
			action: agentturn.Allow, rule: "skill", reason: "allowed by skill"},
		{name: "so constraints alone need the call's own allow", allow: "read", def: Ask(),
			call:   skillArgs{Name: "x", Files: []string{"README.md"}, Only: true},
			action: agentturn.Defer, reason: "no rule allows skill: approval required by default"},
		{name: "and still tighten it", allow: "skill", deny: "read(.env)", def: Allow(),
			call:   skillArgs{Name: "x", Files: []string{".env"}, Only: true},
			action: agentturn.Block, rule: "read(.env)", reason: `denied by read(.env) on ".env"; nothing in this command ran`, subj: ".env"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			j := &journal{}
			e, err := Build(Policy{Allow: rules(t, tc.allow), Deny: rules(t, tc.deny), Ask: rules(t, tc.ask), Default: tc.def}, constrainMatchers, WithObserver(j.observe))
			if err != nil {
				t.Fatal(err)
			}
			info := skillCall(t, "c", tc.call)
			w, err := e.Would(ctx, info)
			if err != nil {
				t.Fatal(err)
			}
			d, err := e.Decide(ctx, info)
			if err != nil {
				t.Fatal(err)
			}
			if d.Action != tc.action || d.Reason != tc.reason {
				t.Errorf("decision = %v %q, want %v %q", d.Action, d.Reason, tc.action, tc.reason)
			}
			v := j.all()[0]
			rule := ""
			if v.Rule != nil {
				rule = v.Rule.String()
			}
			if v.Action != tc.action || rule != tc.rule || v.Reason != tc.reason || v.Subject != tc.subj {
				t.Errorf("verdict = %v %q %q subject %q, want %v %q %q subject %q", v.Action, rule, v.Reason, v.Subject, tc.action, tc.rule, tc.reason, tc.subj)
			}
			// Would decides as Decide does before the hold.
			wrule := ""
			if w.Rule != nil {
				wrule = w.Rule.String()
			}
			if w.Action != v.Action || wrule != rule || w.Reason != v.Reason || w.Subject != v.Subject {
				t.Errorf("Would = %v %q %q subject %q, Decide's verdict %v %q %q subject %q", w.Action, wrule, w.Reason, w.Subject, v.Action, rule, v.Reason, v.Subject)
			}
		})
	}
}

func TestConstraintSubjectGrants(t *testing.T) {
	ctx := context.Background()
	asked := skillArgs{Name: "x", Files: []string{".env"}}

	// A grant of the constraint's tool allows nothing for it.
	e, err := Build(Policy{Ask: rules(t, "read(.env)"), Default: Ask()}, constrainMatchers)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Grant(ctx, Rule{Tool: "read", Spec: ".env"}); err != nil {
		t.Fatal(err)
	}
	v, err := e.Would(ctx, skillCall(t, "c1", asked))
	if err != nil {
		t.Fatal(err)
	}
	if v.Action != agentturn.Defer || v.Reason != "no rule allows skill: approval required by default" {
		t.Errorf("after a read grant: %v %q", v.Action, v.Reason)
	}

	// Answering the constraint's ask with "always allow" carves the
	// file out of the ask rule, which lifts the constraint, and the
	// call is decided by the skill tool's own rules.
	e, err = Build(Policy{Allow: rules(t, "skill"), Ask: rules(t, "read(.env)"), Default: Ask()}, constrainMatchers)
	if err != nil {
		t.Fatal(err)
	}
	v, err = e.Would(ctx, skillCall(t, "c2", asked))
	if err != nil {
		t.Fatal(err)
	}
	if v.Action != agentturn.Defer || v.Subject != ".env" {
		t.Fatalf("before the grant: %+v", v)
	}
	if ok, why := e.GrantOver(ctx, v, Rule{Tool: "read", Spec: ".env"}); !ok {
		t.Fatalf("GrantOver: %s", why)
	}
	v, err = e.Would(ctx, skillCall(t, "c3", asked))
	if err != nil {
		t.Fatal(err)
	}
	if v.Action != agentturn.Allow || v.Reason != "allowed by skill" {
		t.Errorf("after GrantOver: %v %q", v.Action, v.Reason)
	}

	// A grant set's allow rule passes over an ask rule for a
	// constraint as it does for any subject, and never over a deny.
	e, err = Build(Policy{Allow: rules(t, "skill"), Deny: rules(t, "read(secrets:*)"), Ask: rules(t, "read(.env)"), Default: Ask()}, constrainMatchers)
	if err != nil {
		t.Fatal(err)
	}
	e.GrantSet(ctx, RuleSet{Source: Source{Name: "skill:x", Trusted: true}, Allow: rules(t, "read")})
	v, err = e.Would(ctx, skillCall(t, "c4", asked))
	if err != nil {
		t.Fatal(err)
	}
	if v.Action != agentturn.Allow || v.Reason != "allowed by skill" {
		t.Errorf("under a grant set: %v %q", v.Action, v.Reason)
	}
	v, err = e.Would(ctx, skillCall(t, "c5", skillArgs{Name: "x", Files: []string{"secrets/key"}}))
	if err != nil {
		t.Fatal(err)
	}
	if v.Action != agentturn.Block || v.Subject != "secrets/key" {
		t.Errorf("a deny under a grant set: %v %q", v.Action, v.Reason)
	}
}

func TestConstraintSubjectInABatch(t *testing.T) {
	ctx := context.Background()
	matchers := map[string]ToolMatcher{
		"skill": constrainMatchers["skill"],
		"read":  constrainMatchers["read"],
		"bash":  {Match: PrefixMatcher("command")},
	}
	e, err := Build(Policy{Allow: rules(t, "skill bash(ls:*)"), Ask: rules(t, "read(.env)"), Default: Ask()}, matchers)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(skill skillArgs) []agentturn.ToolCallInfo {
		args, _ := json.Marshal(skill)
		calls := []*openresponses.FunctionCall{
			{CallID: "call_a", Name: "bash", Arguments: `{"command":"ls"}`},
			{CallID: "call_b", Name: "skill", Arguments: string(args)},
		}
		infos := make([]agentturn.ToolCallInfo, len(calls))
		for i, c := range calls {
			infos[i] = agentturn.ToolCallInfo{RunID: "run_" + skill.Name, Turn: 1, Call: c, Args: json.RawMessage(c.Arguments), Batch: calls, Index: i}
		}
		return infos
	}

	// A constraint that asks holds the rest of the batch.
	infos := mk(skillArgs{Name: "x", Files: []string{".env"}})
	d, err := e.Decide(ctx, infos[0])
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != agentturn.Defer || d.Reason != "held for approval: allowed by bash(ls:*)" {
		t.Errorf("beside an asking constraint: %v %q", d.Action, d.Reason)
	}
	if d, err = e.Decide(ctx, infos[1]); err != nil {
		t.Fatal(err)
	}
	if d.Action != agentturn.Defer || d.Reason != "approval required by read(.env)" {
		t.Errorf("the asking call: %v %q", d.Action, d.Reason)
	}

	// One no rule fires for holds nothing.
	infos = mk(skillArgs{Name: "y", Files: []string{"README.md"}})
	if d, err = e.Decide(ctx, infos[0]); err != nil {
		t.Fatal(err)
	}
	if d.Action != agentturn.Allow || d.Reason != "allowed by bash(ls:*)" {
		t.Errorf("beside a neutral constraint: %v %q", d.Action, d.Reason)
	}
}
