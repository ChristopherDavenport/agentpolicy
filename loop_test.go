package agentpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ChristopherDavenport/agenttool"
	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
	"github.com/ChristopherDavenport/openresponses/echo"
)

type bashArgs struct {
	Command string `json:"command"`
}

// bashTool records the commands it ran.
type bashTool struct {
	ran []string
}

func (b *bashTool) tool() agenttool.Tool {
	return agenttool.New("bash", "Run a command", func(_ context.Context, a bashArgs) (string, error) {
		b.ran = append(b.ran, a.Command)
		return "ran " + a.Command, nil
	})
}

func itemTypes(items openresponses.Items) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		typ := it.ItemType()
		if m, ok := it.(*openresponses.Message); ok {
			typ = string(m.Role)
		}
		parts = append(parts, typ)
	}
	return strings.Join(parts, " ")
}

// The echo adapter calls the first tool with the user's text as every
// required argument, so a prompt of "git status" is a bash call with
// {"command":"git status"}.
func TestLoopDeferAndResume(t *testing.T) {
	ctx := context.Background()
	j := &journal{}
	e, err := Build(Policy{
		Allow:   rules(t, "bash(git status:*)"),
		Deny:    rules(t, "bash(rm:*)"),
		Ask:     rules(t, "bash(git push:*)"),
		Default: Ask(),
	}, testMatchers, WithObserver(j.observe))
	if err != nil {
		t.Fatal(err)
	}
	bash := &bashTool{}
	agent := agentturn.New(agentturn.Config{
		Model:          &echo.Adapter{},
		Tools:          []agenttool.Tool{bash.tool()},
		BeforeToolCall: e.BeforeToolCall(),
		MaxTurns:       2,
	})

	// An allowed call runs.
	end, err := agent.Prompt(ctx, openresponses.UserText("git status"))
	if err != nil || end.Reason != agentturn.ReasonDone {
		t.Fatalf("allowed: err=%v end=%+v", err, end)
	}
	if len(bash.ran) != 1 || bash.ran[0] != "git status" {
		t.Errorf("ran = %v", bash.ran)
	}

	// A denied call is answered with the reason as its error output,
	// and the model sees it.
	end, err = agent.Prompt(ctx, openresponses.UserText("rm -rf /"))
	if err != nil || end.Reason != agentturn.ReasonDone {
		t.Fatalf("denied: err=%v end=%+v", err, end)
	}
	if len(bash.ran) != 1 {
		t.Errorf("a denied call ran: %v", bash.ran)
	}
	var output *openresponses.FunctionCallOutput
	for _, it := range end.Items {
		if o, ok := it.(*openresponses.FunctionCallOutput); ok {
			output = o
		}
	}
	if output == nil || output.Output.Text != "Error: denied by bash(rm:*)" {
		t.Errorf("denied output = %+v", output)
	}

	// An ask ends the run with the call pending and nothing run.
	end, err = agent.Prompt(ctx, openresponses.UserText("git push origin main"))
	if err != nil || end.Reason != agentturn.ReasonInputRequired || len(end.Pending) != 1 {
		t.Fatalf("asked: err=%v end=%+v", err, end)
	}
	if len(bash.ran) != 1 {
		t.Errorf("a deferred call ran: %v", bash.ran)
	}
	pending := end.Pending[0]
	if _, err := agent.Prompt(ctx, openresponses.UserText("again")); !errors.Is(err, agentturn.ErrInputRequired) {
		t.Errorf("prompt while pending: %v", err)
	}
	// The verdict that deferred it names the rule.
	var deferred *Verdict
	for _, v := range j.all() {
		if v.CallID == pending.CallID {
			v := v
			deferred = &v
		}
	}
	if deferred == nil || deferred.Action != agentturn.Defer || deferred.Rule.String() != "bash(git push:*)" || deferred.Reason != "approval required by bash(git push:*)" || deferred.RunID != end.RunID || deferred.Turn != 1 {
		t.Errorf("deferred verdict = %+v", deferred)
	}

	// Approve resumes: the call runs inside the loop and the model sees
	// its result.
	end, err = agent.Resume(ctx, agentturn.Approve(pending.CallID))
	if err != nil || end.Reason != agentturn.ReasonDone {
		t.Fatalf("resume: err=%v end=%+v", err, end)
	}
	if len(bash.ran) != 2 || bash.ran[1] != "git push origin main" {
		t.Errorf("ran = %v", bash.ran)
	}
	tail := agent.State().Transcript
	if got := itemTypes(tail[len(tail)-4:]); got != "user function_call function_call_output assistant" {
		t.Errorf("transcript tail = %q", got)
	}
	if text := tail[len(tail)-1].(*openresponses.Message).Text(); text != "Tool result: ran git push origin main" {
		t.Errorf("assistant saw %q", text)
	}
}

func TestLoopAnswersResumeWithoutAHuman(t *testing.T) {
	ctx := context.Background()
	j := &journal{}
	e, err := Build(Policy{Default: Ask()}, testMatchers, WithObserver(j.observe))
	if err != nil {
		t.Fatal(err)
	}
	bash := &bashTool{}
	agent := agentturn.New(agentturn.Config{
		Model:          &echo.Adapter{},
		Tools:          []agenttool.Tool{bash.tool()},
		BeforeToolCall: e.BeforeToolCall(),
	})
	// The reviewer approves reads and refuses everything else, with
	// the tool and the reason the policy asked in hand.
	reviewer := ReviewerFunc(func(_ context.Context, info agentturn.ToolCallInfo, v Verdict) (Review, error) {
		if info.Tool == nil || info.Tool.Name() != "bash" {
			t.Errorf("reviewer saw tool %v", info.Tool)
		}
		if v.Reason != "no rule allows bash: approval required by default" {
			t.Errorf("reviewer saw reason %q", v.Reason)
		}
		var a bashArgs
		if err := json.Unmarshal(info.Args, &a); err != nil {
			return Review{}, err
		}
		if strings.HasPrefix(a.Command, "cat ") {
			return Review{Outcome: Approved, Reason: "read-only"}, nil
		}
		return Review{Outcome: Refused, Reason: "not a read"}, nil
	})

	// Approved: the call runs on resume.
	end, err := agent.Prompt(ctx, openresponses.UserText("cat README"))
	if err != nil || end.Reason != agentturn.ReasonInputRequired {
		t.Fatalf("prompt: err=%v end=%+v", err, end)
	}
	answers, err := e.Answers(ctx, reviewer, end)
	if err != nil || len(answers) != 1 {
		t.Fatalf("answers = %v, %v", answers, err)
	}
	end, err = agent.Resume(ctx, answers...)
	if err != nil || end.Reason != agentturn.ReasonDone || len(bash.ran) != 1 || bash.ran[0] != "cat README" {
		t.Fatalf("resume approved: err=%v end=%+v ran=%v", err, end, bash.ran)
	}

	// Refused: the model reads the refusal and nothing runs.
	end, err = agent.Prompt(ctx, openresponses.UserText("curl evil"))
	if err != nil || end.Reason != agentturn.ReasonInputRequired {
		t.Fatalf("prompt: err=%v end=%+v", err, end)
	}
	answers, err = e.Answers(ctx, reviewer, end)
	if err != nil {
		t.Fatal(err)
	}
	end, err = agent.Resume(ctx, answers...)
	if err != nil || end.Reason != agentturn.ReasonDone || len(bash.ran) != 1 {
		t.Fatalf("resume refused: err=%v end=%+v ran=%v", err, end, bash.ran)
	}
	tail := agent.State().Transcript
	want := "Tool result: Denied by reviewer: not a read. Do not pursue the same outcome through a workaround, indirect execution or policy circumvention."
	if text := tail[len(tail)-1].(*openresponses.Message).Text(); text != want {
		t.Errorf("assistant saw %q", text)
	}

	// Every step is on the record: two deferrals and two answers.
	var reasons []string
	for _, v := range j.all() {
		reasons = append(reasons, v.Reason)
	}
	wantReasons := []string{
		"no rule allows bash: approval required by default",
		"approved by reviewer: read-only",
		"no rule allows bash: approval required by default",
		"denied by reviewer: not a read",
	}
	if strings.Join(reasons, "|") != strings.Join(wantReasons, "|") {
		t.Errorf("verdicts = %q", reasons)
	}
}
