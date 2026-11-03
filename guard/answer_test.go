package guard

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"testing"

	"github.com/ChristopherDavenport/agenttool"
	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
	"github.com/ChristopherDavenport/openresponses/echo"
)

const closingNote = "Case closed. Your reference is your SSN on file, 123-45-6789."

var ssn = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

// closing is a turn whose one call, close_case, ends the run with its
// output as the run's answer, as round 9's scenario 29 has it.
func closing(terminate bool) agentturn.TurnInfo {
	return agentturn.TurnInfo{
		RunID:       "run_1",
		Turn:        2,
		Response:    response(&openresponses.FunctionCall{CallID: "c1", Name: "close_case", Arguments: `{"reason":"refund done"}`}),
		ToolResults: []agenttool.Result{{Output: openresponses.FunctionCallOutputData{Text: closingNote}, Terminate: terminate}},
	}
}

// A turn a terminating result ends is final, and the result's output
// is the run's answer: the output subject carries the turn's results,
// and a guard over the answer judges that output.
func TestAnOutputCarriesTheAnswerATerminatingToolGives(t *testing.T) {
	ctx := context.Background()
	var seen []Output
	look := New("look", func(_ context.Context, subject any) (Verdict, error) {
		seen = append(seen, subject.(Output))
		return allow, nil
	})
	j := &journal{}
	hook := Chain{Guards: []Guard{look, Deny(ssn)}, Observer: j.observe}.ShouldStopAfterTurn()
	stop, err := hook(ctx, closing(true))
	var be *BlockedError
	if !stop || !errors.As(err, &be) || be.Guard != "deny" || be.Subject != "output" {
		t.Fatalf("a terminating answer with an SSN: stop = %v, %v", stop, err)
	}
	if len(seen) != 1 || !seen[0].Final || len(seen[0].Results) != 1 {
		t.Fatalf("the guard saw %+v", seen)
	}
	answer := seen[0].Answer()
	if len(answer) != 1 {
		t.Fatalf("Answer() = %+v", answer)
	}
	if out, ok := answer[0].(*openresponses.FunctionCallOutput); !ok || out.CallID != "c1" || out.Output.Text != closingNote {
		t.Errorf("Answer()[0] = %+v", answer[0])
	}

	// A result that does not end the run is not the answer: the turn is
	// not final, and the guards over the output read its items alone,
	// as before.
	seen = nil
	if stop, err := hook(ctx, closing(false)); stop || err != nil {
		t.Errorf("a turn the results do not end: stop = %v, %v", stop, err)
	}
	if len(seen) != 1 || seen[0].Final || len(seen[0].Results) != 1 || seen[0].Answer() != nil {
		t.Errorf("the guard saw %+v", seen)
	}
}

// Each reference guard judges the answer a terminating tool gives as
// it judges a final message.
func TestReferenceGuardsJudgeTheAnswer(t *testing.T) {
	ctx := context.Background()
	key := "AKIAIOSFODNN7EXAMPLE"
	answer := func(text string, terminate bool) Output {
		info := closing(terminate)
		info.ToolResults[0].Output.Text = text
		return Output{Response: info.Response, Results: info.ToolResults, Final: terminate}
	}
	tests := []struct {
		name    string
		g       Guard
		subject Output
		action  agentturn.ToolAction
		reason  string
	}{
		{"deny", Deny(ssn), answer(closingNote, true), agentturn.Block, `matched denied pattern "\b\d{3}-\d{2}-\d{4}\b"`},
		{"deny passes a result that is not the answer", Deny(ssn), answer(closingNote, false), agentturn.Allow, ""},
		{"secrets", Secrets(), answer("key "+key, true), agentturn.Block, "secret detected: aws_access_key"},
		{"redact blocks as secrets does", Redact(), answer("key "+key, true), agentturn.Block, "secret detected: aws_access_key"},
		{"limit", Limit(120), answer(closingNote, true), agentturn.Block, "output is 224 bytes, over the 120 byte limit"},
		{"limit passes a result that is not the answer", Limit(120), answer(closingNote, false), agentturn.Allow, ""},
	}
	for _, tc := range tests {
		v, err := tc.g.Check(ctx, tc.subject)
		if err != nil || v.Action != tc.action || v.Reason != tc.reason {
			t.Errorf("%s: %+v, %v", tc.name, v, err)
		}
	}
}

// In the loop, a guard over the answer stops a run a terminating tool
// would have answered, as a guard stop.
func TestTheAnswerIsGuardedInTheLoop(t *testing.T) {
	ctx := context.Background()
	closeCase := agenttool.NewFunc("close_case", "Closes the case", json.RawMessage(`{"type":"object"}`),
		func(context.Context, agenttool.Call) (agenttool.Result, error) {
			return agenttool.Result{Output: openresponses.FunctionCallOutputData{Text: closingNote}, Terminate: true}, nil
		})
	output := Chain{Guards: []Guard{Deny(ssn)}}
	agent := agentturn.New(agentturn.Config{
		Model:               &echo.Adapter{},
		Tools:               []agenttool.Tool{closeCase},
		ShouldStopAfterTurn: output.ShouldStopAfterTurn(),
	})
	end, err := agent.Prompt(ctx, openresponses.UserText("close my case"))
	var be *BlockedError
	if err != nil || end.Reason != agentturn.ReasonStopped || end.Cause != agentturn.StopGuard || !errors.As(end.Err, &be) || be.Guard != "deny" {
		t.Fatalf("end = %+v, %v", end, err)
	}
}
