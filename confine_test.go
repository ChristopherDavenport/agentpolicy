package agentpolicy

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ChristopherDavenport/agenttool"
	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
)

type sandboxArgs struct {
	Command string `json:"command"`
	Sandbox string `json:"sandbox"`
}

// sandboxedBash is a shell that runs every call under landlock and
// seccomp unless the call asks to leave, as the reference's escape
// hatch is an argument of its shell tool.
func sandboxedBash() agenttool.Tool {
	run := func(_ context.Context, a sandboxArgs) (string, error) { return "ran " + a.Command, nil }
	return agenttool.New("bash", "Run a command", run, agenttool.WithConfined(func(_ context.Context, args json.RawMessage) (bool, string) {
		var a sandboxArgs
		if json.Unmarshal(args, &a) != nil || a.Sandbox == "escalated" {
			return false, ""
		}
		return true, "landlock+seccomp"
	}))
}

// namelessSandbox says every call is confined and names nothing.
func namelessSandbox(name string) agenttool.Tool {
	run := func(_ context.Context, a sandboxArgs) (string, error) { return "", nil }
	return agenttool.New(name, "Run", run, agenttool.WithConfined(func(context.Context, json.RawMessage) (bool, string) { return true, "" }))
}

// localBash claims no sandbox.
func localBash() agenttool.Tool {
	return agenttool.New("bash", "Run a command", func(_ context.Context, a sandboxArgs) (string, error) { return "", nil })
}

func TestConfinedCallSkipsABareAsk(t *testing.T) {
	ctx := context.Background()
	bash := map[string]ToolMatcher{"bash": {Match: PrefixMatcher("command")}}
	tests := []struct {
		name     string
		policy   Policy
		matchers map[string]ToolMatcher
		opts     []Option
		tool     agenttool.Tool
		callTool string
		args     string
		action   agentturn.ToolAction
		rule     string
		reason   string
		confined string
	}{
		{name: "a bare ask is skipped for a confined call", policy: Policy{Ask: rules(t, "bash"), Default: Allow()}, tool: sandboxedBash(), args: `{"command":"ls"}`,
			action: agentturn.Allow, rule: "bash", reason: "confined by landlock+seccomp, so bash does not ask", confined: "landlock+seccomp"},
		{name: "and applies to a call that leaves the sandbox", policy: Policy{Ask: rules(t, "bash"), Default: Allow()}, tool: sandboxedBash(), args: `{"command":"ls","sandbox":"escalated"}`,
			action: agentturn.Defer, rule: "bash", reason: "approval required by bash"},
		{name: "a confined call under an Ask() default is allowed when a bare rule names it", policy: AutoEdit(Tools{Read: []string{"read"}, Execute: []string{"bash"}}), tool: sandboxedBash(), args: `{"command":"ls"}`,
			action: agentturn.Allow, rule: "bash", reason: "confined by landlock+seccomp, so bash does not ask", confined: "landlock+seccomp"},
		{name: "the default still asks for a confined call no rule names", policy: Policy{Default: Ask()}, tool: sandboxedBash(), args: `{"command":"ls"}`,
			action: agentturn.Defer, reason: "no rule allows bash: approval required by default", confined: "landlock+seccomp"},
		{name: "an ask rule with a specifier applies whatever the confinement", policy: Policy{Ask: rules(t, "bash bash(git push:*)"), Default: Allow()}, matchers: bash, tool: sandboxedBash(), args: `{"command":"git push origin main"}`,
			action: agentturn.Defer, rule: "bash(git push:*)", reason: "approval required by bash(git push:*)", confined: "landlock+seccomp"},
		{name: "the skipped rule is named when a specifier does not fire", policy: Policy{Ask: rules(t, "bash bash(git push:*)"), Default: Allow()}, matchers: bash, tool: sandboxedBash(), args: `{"command":"git status"}`,
			action: agentturn.Allow, rule: "bash", reason: "confined by landlock+seccomp, so bash does not ask", confined: "landlock+seccomp"},
		{name: "a deny rule applies whatever the confinement", policy: Policy{Deny: rules(t, "bash(rm:*)"), Ask: rules(t, "bash"), Default: Allow()}, matchers: bash, tool: sandboxedBash(), args: `{"command":"rm -rf /"}`,
			action: agentturn.Block, rule: "bash(rm:*)", reason: "denied by bash(rm:*)", confined: "landlock+seccomp"},
		{name: "a bare deny applies whatever the confinement", policy: Policy{Deny: rules(t, "bash"), Default: Allow()}, tool: sandboxedBash(), args: `{"command":"ls"}`,
			action: agentturn.Block, rule: "bash", reason: "denied by bash", confined: "landlock+seccomp"},
		{name: "a tool that claims no sandbox asks", policy: Policy{Ask: rules(t, "bash"), Default: Allow()}, tool: localBash(), args: `{"command":"ls"}`,
			action: agentturn.Defer, rule: "bash", reason: "approval required by bash"},
		{name: "a call with no tool asks", policy: Policy{Ask: rules(t, "bash"), Default: Allow()}, args: `{"command":"ls"}`,
			action: agentturn.Defer, rule: "bash", reason: "approval required by bash"},
		{name: "WithConfinement(nil) asks", policy: Policy{Ask: rules(t, "bash"), Default: Allow()}, opts: []Option{WithConfinement(nil)}, tool: sandboxedBash(), args: `{"command":"ls"}`,
			action: agentturn.Defer, rule: "bash", reason: "approval required by bash"},
		{name: "WithConfinement replaces the reading", policy: Policy{Ask: rules(t, "bash"), Default: Allow()}, tool: localBash(), args: `{"command":"ls"}`,
			opts: []Option{WithConfinement(func(context.Context, agenttool.Tool, json.RawMessage) (bool, string) {
				return true, "container:agent-sandbox"
			})},
			action: agentturn.Allow, rule: "bash", reason: "confined by container:agent-sandbox, so bash does not ask", confined: "container:agent-sandbox"},
		{name: "a bare glob ask is skipped too", policy: Policy{Ask: rules(t, "mcp__*"), Default: Allow()}, tool: namelessSandbox("mcp__box__run"), callTool: "mcp__box__run", args: `{}`,
			action: agentturn.Allow, rule: "mcp__*", reason: "confined, so mcp__* does not ask"},
		// A subject checked against another tool's rules is that tool's
		// question, not the shell's sandbox's.
		{name: "a subject of another tool is not skipped", policy: Policy{Ask: rules(t, "write"), Default: Allow()}, tool: sandboxedBash(), args: `{"command":"echo x > out.txt"}`,
			matchers: map[string]ToolMatcher{"bash": {Match: PrefixMatcher("command"), Subjects: func(args json.RawMessage) ([]Subject, error) {
				return []Subject{{Args: args, Text: "echo x"}, {Tool: "write", Args: json.RawMessage(`{"path":"out.txt"}`), Text: "> out.txt"}}, nil
			}}},
			action: agentturn.Defer, rule: "write", reason: "approval required by write", confined: "landlock+seccomp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var j journal
			e, err := Build(tt.policy, tt.matchers, append([]Option{WithObserver(j.observe)}, tt.opts...)...)
			if err != nil {
				t.Fatal(err)
			}
			name := tt.callTool
			if name == "" {
				name = "bash"
			}
			info := call("call_1", name, tt.args)
			info.Tool = tt.tool
			d, err := e.Decide(ctx, info)
			if err != nil {
				t.Fatal(err)
			}
			v := j.all()[0]
			rule := ""
			if v.Rule != nil {
				rule = v.Rule.String()
			}
			if d.Action != tt.action || d.Reason != tt.reason || rule != tt.rule || v.Confined != tt.confined {
				t.Errorf("got %v %q rule=%q confined=%q\nwant %v %q rule=%q confined=%q", d.Action, d.Reason, rule, v.Confined, tt.action, tt.reason, tt.rule, tt.confined)
			}
			// A call the engine allows is not remembered as deferred.
			if _, deferred := e.Deferred("run_1", "call_1"); deferred != (tt.action == agentturn.Defer) {
				t.Errorf("remembered = %v", deferred)
			}
		})
	}
}

// The hold reads the siblings' confinement: a confined command beside
// a read the policy allows holds nothing, and one that leaves the
// sandbox holds the read.
func TestConfinedSiblingHoldsNothing(t *testing.T) {
	ctx := context.Background()
	policy := AutoEdit(Tools{Read: []string{"read"}, Execute: []string{"bash"}})
	read := agenttool.New("read", "Read a file", func(_ context.Context, a struct {
		Path string `json:"path"`
	}) (string, error) {
		return "", nil
	})
	tools := agenttool.Set{sandboxedBash(), read}
	type step struct {
		action agentturn.ToolAction
		held   bool
	}
	tests := []struct {
		name  string
		opts  []Option
		calls [][2]string
		want  []step
	}{
		{name: "a confined command before the read", calls: [][2]string{{"bash", `{"command":"ls"}`}, {"read", `{"path":"go.mod"}`}},
			want: []step{{agentturn.Allow, false}, {agentturn.Allow, false}}},
		{name: "a confined command after the read, with the tools named", opts: []Option{WithTools(tools.Lookup)}, calls: [][2]string{{"read", `{"path":"go.mod"}`}, {"bash", `{"command":"ls"}`}},
			want: []step{{agentturn.Allow, false}, {agentturn.Allow, false}}},
		// Without the lookup a sibling the hook has not been handed reads
		// as unconfined, and the first reading is kept for the batch.
		{name: "a confined command after the read, with no tools named", calls: [][2]string{{"read", `{"path":"go.mod"}`}, {"bash", `{"command":"ls"}`}},
			want: []step{{agentturn.Defer, true}, {agentturn.Allow, false}}},
		{name: "a command that leaves the sandbox holds the read", opts: []Option{WithTools(tools.Lookup)}, calls: [][2]string{{"read", `{"path":"go.mod"}`}, {"bash", `{"command":"ls","sandbox":"escalated"}`}},
			want: []step{{agentturn.Defer, true}, {agentturn.Defer, false}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := Build(policy, nil, tt.opts...)
			if err != nil {
				t.Fatal(err)
			}
			batch := make([]*openresponses.FunctionCall, len(tt.calls))
			for i, c := range tt.calls {
				batch[i] = &openresponses.FunctionCall{CallID: "call_" + string(rune('a'+i)), Name: c[0], Arguments: c[1]}
			}
			for i, c := range batch {
				tool, _ := tools.Lookup(c.Name)
				info := agentturn.ToolCallInfo{RunID: "run_1", Turn: 1, Call: c, Tool: tool, Args: json.RawMessage(c.Arguments), Batch: batch, Index: i}
				// Twice: a call decided again in its batch is decided the same way.
				for range 2 {
					d, err := e.Decide(ctx, info)
					if err != nil {
						t.Fatal(err)
					}
					v, _ := e.Deferred("run_1", c.CallID)
					if d.Action != tt.want[i].action || v.Held != tt.want[i].held {
						t.Errorf("%s: %v held=%v %q, want %v held=%v", c.CallID, d.Action, v.Held, d.Reason, tt.want[i].action, tt.want[i].held)
					}
				}
			}
		})
	}
}

// Arguments a hook rewrites are decided again, their confinement read
// afresh, so the verdict describes the call that runs: a hook that
// takes a call out of its sandbox is asked about, and a path a hook
// resolves meets the deny rule for it. The stricter action stands.
// (#47)
func TestHookRewriteIsDecidedAgain(t *testing.T) {
	ctx := context.Background()
	rewrite := func(args string) func(context.Context, agentturn.ToolCallInfo) (*agentturn.ToolDecision, error) {
		return func(context.Context, agentturn.ToolCallInfo) (*agentturn.ToolDecision, error) {
			return &agentturn.ToolDecision{Args: json.RawMessage(args)}, nil
		}
	}
	matchers := map[string]ToolMatcher{"bash": {Match: PrefixMatcher("command")}, "read": {Match: PrefixMatcher("path")}}
	tests := []struct {
		name     string
		policy   Policy
		tool     agenttool.Tool
		callTool string
		args     string
		hook     string
		action   agentturn.ToolAction
		reason   string
		confined string
	}{
		{name: "a hook that leaves the sandbox is asked about", policy: Policy{Ask: rules(t, "bash"), Default: Allow()}, tool: sandboxedBash(),
			args: `{"command":"npm install left-pad"}`, hook: `{"command":"npm install left-pad","sandbox":"escalated"}`,
			action: agentturn.Defer, reason: "approval required by bash"},
		{name: "a hook that enters the sandbox is confined", policy: Policy{Ask: rules(t, "bash"), Default: Allow()}, tool: sandboxedBash(),
			args: `{"command":"ls","sandbox":"escalated"}`, hook: `{"command":"ls"}`,
			action: agentturn.Defer, reason: "approval required by bash", confined: "landlock+seccomp"},
		{name: "a resolved path meets its deny rule", policy: Policy{Deny: rules(t, "read(/etc:*)"), Default: Allow()}, callTool: "read",
			args: `{"path":"../../etc/shadow"}`, hook: `{"path":"/etc/shadow"}`,
			action: agentturn.Block, reason: "denied by read(/etc:*)"},
		{name: "an allowed rewrite is allowed by its own rule", policy: Policy{Allow: rules(t, "bash(git status:*) bash(git log:*)"), Default: Ask()},
			args: `{"command":"git status"}`, hook: `{"command":"git log"}`,
			action: agentturn.Allow, reason: "allowed by bash(git log:*)"},
		{name: "a rewrite the policy allows does not undo an ask", policy: Policy{Ask: rules(t, "bash(git push:*)"), Default: Allow()},
			args: `{"command":"git push"}`, hook: `{"command":"git status"}`,
			action: agentturn.Defer, reason: "approval required by bash(git push:*)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := &journal{}
			e, err := Build(tt.policy, matchers, WithObserver(j.observe), WithHooks(rewrite(tt.hook)))
			if err != nil {
				t.Fatal(err)
			}
			name := tt.callTool
			if name == "" {
				name = "bash"
			}
			info := call("c", name, tt.args)
			info.Tool = tt.tool
			d, err := e.Decide(ctx, info)
			if err != nil {
				t.Fatal(err)
			}
			if d.Action != tt.action || d.Reason != tt.reason || string(d.Args) != tt.hook {
				t.Errorf("decision = %v %q %s, want %v %q %s", d.Action, d.Reason, d.Args, tt.action, tt.reason, tt.hook)
			}
			if v := j.all()[0]; v.Confined != tt.confined || v.Reason != tt.reason {
				t.Errorf("verdict confined %q reason %q, want %q %q", v.Confined, v.Reason, tt.confined, tt.reason)
			}
		})
	}
}

// The lookup WithTools names takes a tool name alone, so one engine
// shared by runs whose tool lists differ read one list for all of
// them, and a batch hold could be defeated. WithToolsFor gives the
// lookup the decision's context, which carries the run's ID. (#43)
func TestWithToolsForAnswersPerRun(t *testing.T) {
	ctx := context.Background()
	policy := AutoEdit(Tools{Read: []string{"read"}, Execute: []string{"bash"}})
	// Run A's shell claims no sandbox; run B's runs every command
	// confined.
	lookup := func(ctx context.Context, name string) (agenttool.Tool, bool) {
		if name != "bash" {
			return nil, false
		}
		switch agentturn.RunIDFromContext(ctx) {
		case "run_A":
			return localBash(), true
		case "run_B":
			return sandboxedBash(), true
		}
		return nil, false
	}
	e, err := Build(policy, nil, WithToolsFor(lookup))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		run    string
		action agentturn.ToolAction
		held   bool
	}{{"run_A", agentturn.Defer, true}, {"run_B", agentturn.Allow, false}} {
		calls := []*openresponses.FunctionCall{
			{CallID: "call_a", Name: "read", Arguments: `{"path":"go.mod"}`},
			{CallID: "call_b", Name: "bash", Arguments: `{"command":"ls"}`},
		}
		// The read is decided before the hook has been handed the
		// command, so the sibling's tool is the lookup's.
		info := agentturn.ToolCallInfo{RunID: tc.run, Turn: 1, Call: calls[0], Args: json.RawMessage(calls[0].Arguments), Batch: calls, Index: 0}
		d, err := e.Decide(agentturn.ContextWithRunID(ctx, tc.run), info)
		if err != nil {
			t.Fatal(err)
		}
		v, _ := e.Deferred(tc.run, "call_a")
		if d.Action != tc.action || v.Held != tc.held {
			t.Errorf("%s: read = %v held=%v %q, want %v held=%v", tc.run, d.Action, v.Held, d.Reason, tc.action, tc.held)
		}
	}
}

// Answers looks a cut-off call's tool up with the ended run's ID on
// the context when the caller's carries none, and leaves a run ID the
// caller's context carries alone.
func TestAnswersLooksUpWithTheRunID(t *testing.T) {
	ctx := context.Background()
	read := agenttool.New("read", "A tool", func(context.Context, agenttool.NoArgs) (string, error) { return "", nil },
		agenttool.WithReplay(func(context.Context, json.RawMessage) agenttool.Replay { return agenttool.ReplaySafe }))
	var seen []string
	lookup := func(ctx context.Context, name string) (agenttool.Tool, bool) {
		run := agentturn.RunIDFromContext(ctx)
		seen = append(seen, run)
		if run == "r" && name == "read" {
			return read, true
		}
		return nil, false
	}
	e, err := Build(Policy{Default: Allow()}, nil, WithToolsFor(lookup))
	if err != nil {
		t.Fatal(err)
	}
	reviewer := ReviewerFunc(func(context.Context, agentturn.ToolCallInfo, Verdict) (Review, error) {
		t.Error("a cut-off call reached the reviewer")
		return Review{}, nil
	})
	end := func() *agentturn.RunEnd {
		return &agentturn.RunEnd{RunID: "r", Reason: agentturn.ReasonAborted, Pending: []agentturn.PendingCall{
			// A call from a seeded transcript names no tool; the lookup does.
			{Call: &openresponses.FunctionCall{CallID: "seeded", Name: "read", Arguments: `{}`}, Reason: agentturn.PendingUnknown},
		}}
	}
	const cut = "The call was cut off before it finished and may have run; it was not run again."
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want agentturn.Answer
	}{
		{"no run ID on the context", ctx, agentturn.Approve("seeded").WithBy(ByPolicy).WithReason("run again: replay safe; allowed by default")},
		{"another run's ID on the context", agentturn.ContextWithRunID(ctx, "other"), agentturn.Output(openresponses.NewFunctionCallOutput("seeded", cut)).WithBy(ByPolicy).WithReason("not reviewed: unknown")},
	} {
		seen = nil
		answers, err := e.Answers(tc.ctx, reviewer, end())
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(answers) != 1 || !reflect.DeepEqual(answers[0], tc.want) {
			t.Errorf("%s: answers = %+v, want %+v", tc.name, answers, tc.want)
		}
		if len(seen) == 0 {
			t.Fatalf("%s: the lookup was not consulted", tc.name)
		}
		want := agentturn.RunIDFromContext(tc.ctx)
		if want == "" {
			want = "r"
		}
		for _, run := range seen {
			if run != want {
				t.Errorf("%s: the lookup saw run %q, want %q", tc.name, run, want)
			}
		}
	}
}
