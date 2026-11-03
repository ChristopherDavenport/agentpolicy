package agentpolicy

import (
	"context"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agentturn"
)

// hookOn returns a hook that answers d for a call whose arguments
// contain match, and nothing for any other.
func hookOn(match string, d agentturn.ToolDecision) func(context.Context, agentturn.ToolCallInfo) (*agentturn.ToolDecision, error) {
	return func(_ context.Context, info agentturn.ToolCallInfo) (*agentturn.ToolDecision, error) {
		if !strings.Contains(string(info.Args), match) {
			return nil, nil
		}
		out := d
		return &out, nil
	}
}

// A hook's part of a decision is kept: one that makes the action
// stricter brings its subject, and one that defers a call the policy
// already defers adds its reason, and its subject when the policy's
// verdict has none, so the person asked reads why.
func TestHookFoldKeepsTheHooksPart(t *testing.T) {
	ctx := context.Background()
	workflow := hookOn(".github/workflows", agentturn.ToolDecision{Action: agentturn.Defer, Reason: "a workflow runs in CI", Subject: "writes .github/workflows/ci.yml"})
	remote := hookOn("git push", agentturn.ToolDecision{Action: agentturn.Defer, Reason: "git touches the remote", Subject: "git push"})
	again := hookOn("git push", agentturn.ToolDecision{Action: agentturn.Defer, Reason: "approval required by default"})
	tests := []struct {
		name    string
		policy  Policy
		hooks   []func(context.Context, agentturn.ToolCallInfo) (*agentturn.ToolDecision, error)
		call    agentturn.ToolCallInfo
		rule    string
		reason  string
		subject string
	}{
		{
			name:   "a stricter hook brings its subject",
			policy: Policy{Default: Allow()}, hooks: hookList(workflow),
			call:   call("c1", "edit", `{"path":".github/workflows/ci.yml"}`),
			reason: "a workflow runs in CI", subject: "writes .github/workflows/ci.yml",
		},
		{
			name:   "an equal defer takes the hook's subject when the verdict has none",
			policy: Policy{Ask: rules(t, "edit"), Default: Allow()}, hooks: hookList(workflow),
			call: call("c1", "edit", `{"path":".github/workflows/ci.yml"}`),
			rule: "edit", reason: "approval required by edit; a workflow runs in CI", subject: "writes .github/workflows/ci.yml",
		},
		{
			name:   "an equal defer adds its reason and keeps the verdict's subject",
			policy: Policy{Default: Ask()}, hooks: hookList(remote),
			call:   call("c1", "bash", `{"command":"git push origin"}`),
			reason: "no rule allows bash: approval required by default; git touches the remote", subject: "git push origin",
		},
		{
			name:   "a reason the verdict already holds is not repeated",
			policy: Policy{Default: Ask()}, hooks: hookList(again),
			call:   call("c1", "bash", `{"command":"git push origin"}`),
			reason: "no rule allows bash: approval required by default", subject: "git push origin",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []Verdict
			e, err := Build(tt.policy, testMatchers, WithHooks(tt.hooks...), WithObserver(func(_ context.Context, v Verdict) { got = append(got, v) }))
			if err != nil {
				t.Fatal(err)
			}
			d, err := e.Decide(ctx, tt.call)
			if err != nil {
				t.Fatal(err)
			}
			if d.Action != agentturn.Defer || d.Reason != tt.reason || d.Subject != tt.subject || d.By != ByPolicy {
				t.Errorf("decision = %s %q subject %q by %q, want defer %q subject %q by policy", actionName(d.Action), d.Reason, d.Subject, d.By, tt.reason, tt.subject)
			}
			if len(got) != 1 || ruleString(got[0].Rule) != tt.rule || got[0].Subject != tt.subject {
				t.Errorf("verdicts = %+v, want rule %q subject %q", got, tt.rule, tt.subject)
			}
		})
	}
}

func hookList(fns ...func(context.Context, agentturn.ToolCallInfo) (*agentturn.ToolDecision, error)) []func(context.Context, agentturn.ToolCallInfo) (*agentturn.ToolDecision, error) {
	return fns
}

func ruleString(r *Rule) string {
	if r == nil {
		return ""
	}
	return r.String()
}

// An answering hook's allow answers the policy's own ask, as a
// PreToolUse hook's allow skips the reference agent's prompt. It never
// lifts a deny, an ordinary hook's ask, or a hold.
func TestAnsweringHooksAnswerThePolicysAsk(t *testing.T) {
	ctx := context.Background()
	goSafe := hookOn(`"go `, agentturn.ToolDecision{Action: agentturn.Allow, Reason: "go is safe", By: ByAgent})
	rmToo := hookOn(`"rm `, agentturn.ToolDecision{Action: agentturn.Allow, Reason: "rm is fine"})
	meter := hookOn("metered", agentturn.ToolDecision{Action: agentturn.Defer, Reason: "fetches are metered"})
	policy := Policy{Deny: rules(t, "bash(rm:*)"), Ask: rules(t, "bash(git push:*)"), Default: Ask()}

	t.Run("one call", func(t *testing.T) {
		tests := []struct {
			name    string
			command string
			action  agentturn.ToolAction
			rule    string
			reason  string
			by      string
		}{
			{"the default's ask is answered", "go version", agentturn.Allow, "", "go is safe", ByAgent},
			{"a deny still blocks", "rm -rf /tmp/x", agentturn.Block, "bash(rm:*)", "denied by bash(rm:*)", ByPolicy},
			{"an ordinary hook's ask is not lifted", "go get metered", agentturn.Defer, "", "no rule allows bash: approval required by default; fetches are metered", ByPolicy},
			{"a call no answering hook allows stays asked", "git push", agentturn.Defer, "bash(git push:*)", "approval required by bash(git push:*)", ByPolicy},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var got []Verdict
				e, err := Build(policy, testMatchers, WithHooks(meter), WithAnsweringHooks(goSafe, rmToo),
					WithObserver(func(_ context.Context, v Verdict) { got = append(got, v) }))
				if err != nil {
					t.Fatal(err)
				}
				d, err := e.Decide(ctx, call("c1", "bash", `{"command":"`+tt.command+`"}`))
				if err != nil {
					t.Fatal(err)
				}
				if d.Action != tt.action || d.Reason != tt.reason || d.By != tt.by {
					t.Errorf("decision = %s %q by %q, want %s %q by %q", actionName(d.Action), d.Reason, d.By, actionName(tt.action), tt.reason, tt.by)
				}
				if len(got) != 1 || ruleString(got[0].Rule) != tt.rule || got[0].Subject != tt.command {
					t.Errorf("verdicts = %+v, want rule %q subject %q", got, tt.rule, tt.command)
				}
			})
		}
	})

	t.Run("a held call stays held", func(t *testing.T) {
		e, err := Build(policy, testMatchers, WithAnsweringHooks(goSafe))
		if err != nil {
			t.Fatal(err)
		}
		ds := decideAll(t, ctx, e, batch("run_1", "go version", "git push"))
		if !ds[0].Held || ds[0].Action != agentturn.Defer || ds[0].Reason != "held for approval: go is safe" {
			t.Errorf("go version = %+v, want it held for the push", ds[0])
		}
		if ds[1].Action != agentturn.Defer || ds[1].Held {
			t.Errorf("git push = %+v, want it asked", ds[1])
		}
	})
}

// An answering hook answers only the policy's own question: not an ask
// a constraint raised, such as ask tainted from a constraint source;
// not one of a source that outranks the host's own; and not a defer an
// ordinary hook raised. An ask rule of the host's own source it may
// answer.
func TestAnsweringHooksLiftOnlyThePolicysOwnAsk(t *testing.T) {
	ctx := context.Background()
	answer := hookOn(`"go `, agentturn.ToolDecision{Action: agentturn.Allow, Reason: "go is safe"})
	tainted := func(context.Context, agentturn.ToolCallInfo) ([]Subject, error) {
		return []Subject{{Tool: "tainted", Args: []byte(`{}`), Text: "untrusted content is in context"}}, nil
	}
	managed, err := Merge(RuleSet{Source: Source{Name: "managed", Rank: 3, Trusted: true}, Ask: rules(t, "bash(go:*)")})
	if err != nil {
		t.Fatal(err)
	}
	managed.Default = Allow()
	tests := []struct {
		name   string
		policy Policy
		opts   []Option
		action agentturn.ToolAction
		reason string
	}{
		{"an ask of the host's own source", Policy{Ask: rules(t, "bash(go:*)"), Default: Allow()}, nil, agentturn.Allow, "go is safe"},
		{"an ask a constraint raised", Policy{Ask: rules(t, "tainted"), Default: Allow()}, []Option{WithConstraints(tainted)}, agentturn.Defer, "approval required by tainted"},
		{"an ask of an outranking source", managed, nil, agentturn.Defer, "approval required by bash(go:*)"},
		{"a defer an ordinary hook raised", Policy{Default: Allow()}, []Option{WithHooks(hookOn(`"go `, agentturn.ToolDecision{Action: agentturn.Defer, Reason: "go fetches modules"}))}, agentturn.Defer, "go fetches modules"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := Build(tt.policy, testMatchers, append(tt.opts, WithAnsweringHooks(answer))...)
			if err != nil {
				t.Fatal(err)
			}
			d, err := e.Decide(ctx, call("c1", "bash", `{"command":"go version"}`))
			if err != nil {
				t.Fatal(err)
			}
			if d.Action != tt.action || d.Reason != tt.reason {
				t.Errorf("decision = %s %q, want %s %q", actionName(d.Action), d.Reason, actionName(tt.action), tt.reason)
			}
		})
	}
}
