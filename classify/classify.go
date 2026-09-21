// Package classify backs a guard and a reviewer with a model: the
// subject, content or a deferred tool call, is sent to the model with
// a rubric, and the model's structured answer becomes the verdict.
// Both take an openresponses.Streamer and a model name, so they work
// against any server, a local adapter or the echo adapter in a test.
//
//	rubric := "You review tool calls a coding agent wants to make. Allow " +
//		"reads and builds; refuse anything that sends data off the machine."
//	reviewer := classify.NewReviewer(client, "claude-sonnet-5", rubric, classify.WithTimeout(20*time.Second))
//	answers, err := eng.Answers(ctx, reviewer, end)
//
// The rubric is the product's. The answer shape is this package's, one
// JSON object, {"allow": true or false, "reason": "..."}, asked for
// through the request's text format and read leniently, so a model that
// wraps the object in prose still answers. A model failure or an answer
// that cannot be read is an error: the guard's hook then fails the
// call, and Engine.Answers turns the reviewer's error into a refusal,
// so both fail closed. A reviewer given a timeout reports TimedOut
// instead, which the record keeps apart from a refusal.
package classify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ChristopherDavenport/agentpolicy"
	"github.com/ChristopherDavenport/agentpolicy/guard"
	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
)

// Option configures a [Guard] or a [Reviewer].
type Option func(*options)

type options struct {
	name    string
	timeout time.Duration
	request openresponses.Request
}

// WithName sets the name the guard reports; the default is "classify".
func WithName(name string) Option {
	return func(o *options) { o.name = name }
}

// WithTimeout bounds each model call. A reviewer that runs out of time
// answers TimedOut; a guard that does returns the deadline error.
func WithTimeout(d time.Duration) Option {
	return func(o *options) { o.timeout = d }
}

// WithRequest sets the base of every request the model receives:
// reasoning, temperature, service tier and the rest are copied from
// it. Model, instructions, input, store and the text format are set by
// the package.
func WithRequest(base openresponses.Request) Option {
	return func(o *options) { o.request = base }
}

func build(opts []Option) options {
	o := options{name: "classify"}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// answerInstruction follows the rubric in the instructions.
const answerInstruction = `Answer with one JSON object and nothing else: {"allow": true or false, "reason": "one sentence"}.`

// answerSchema is the text format asked for.
var answerSchema = json.RawMessage(`{"type":"object","properties":{"allow":{"type":"boolean"},"reason":{"type":"string"}},"required":["allow","reason"],"additionalProperties":false}`)

// answer is the model's structured reply.
type answer struct {
	Allow  *bool  `json:"allow"`
	Reason string `json:"reason"`
}

// ask sends the subject to the model under the rubric and reads the
// answer.
func ask(ctx context.Context, model openresponses.Streamer, modelName, rubric, subject string, o options) (answer, error) {
	req := o.request
	req.Model = modelName
	req.Instructions = strings.TrimSpace(rubric) + "\n\n" + answerInstruction
	req.Input = openresponses.Items{openresponses.UserText(subject)}
	req.Text.Format = openresponses.JSONSchemaFormat("verdict", answerSchema, true)
	store := false
	req.Store = &store
	req.PreviousResponseID = ""
	resp, err := openresponses.CollectStream(ctx, model, req)
	if err != nil {
		return answer{}, fmt.Errorf("agentpolicy/classify: model: %w", err)
	}
	return parseAnswer(resp.OutputText())
}

// parseAnswer reads the first JSON object in text that carries an
// allow field, so an answer wrapped in prose or a code fence still
// reads.
func parseAnswer(text string) (answer, error) {
	for i := strings.IndexByte(text, '{'); i >= 0; {
		var a answer
		if err := json.NewDecoder(strings.NewReader(text[i:])).Decode(&a); err == nil && a.Allow != nil {
			return a, nil
		}
		next := strings.IndexByte(text[i+1:], '{')
		if next < 0 {
			break
		}
		i += 1 + next
	}
	return answer{}, fmt.Errorf("agentpolicy/classify: unreadable answer: %q", text)
}

// Guard classifies content with a model and blocks what the rubric
// refuses. It checks a guard.Input, a guard.Message or a guard.Output
// and passes anything else.
type Guard struct {
	model     openresponses.Streamer
	modelName string
	rubric    string
	o         options
}

var _ guard.Guard = (*Guard)(nil)

// New builds a guard over model.
func New(model openresponses.Streamer, modelName, rubric string, opts ...Option) *Guard {
	return &Guard{model: model, modelName: modelName, rubric: rubric, o: build(opts)}
}

// Name returns the guard's name.
func (g *Guard) Name() string { return g.o.name }

// Check renders the subject as text, one line per item, sends it under
// the rubric and returns Allow or Block with the model's reason. An
// empty subject passes without a model call.
func (g *Guard) Check(ctx context.Context, subject any) (guard.Verdict, error) {
	var items openresponses.Items
	kind := ""
	switch s := subject.(type) {
	case guard.Input:
		items, kind = s.Items, "input"
	case guard.Message:
		kind = "output"
		if s.Message != nil {
			items = openresponses.Items{s.Message}
		}
	case guard.Output:
		kind = "output"
		if s.Response != nil {
			items = s.Response.Output
		}
	default:
		return guard.Verdict{Action: agentturn.Allow}, nil
	}
	if len(items) == 0 {
		// Nothing to classify, and nothing to spend a model call on.
		return guard.Verdict{Action: agentturn.Allow}, nil
	}
	if g.o.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.o.timeout)
		defer cancel()
	}
	a, err := ask(ctx, g.model, g.modelName, g.rubric, kind+":\n"+render(items), g.o)
	if err != nil {
		return guard.Verdict{}, err
	}
	if *a.Allow {
		return guard.Verdict{Action: agentturn.Allow, Reason: a.Reason}, nil
	}
	return guard.Verdict{Action: agentturn.Block, Reason: a.Reason}, nil
}

// render writes the items as the model reads them: a message as its
// role and text, a call as its name and arguments, an output as its
// call ID and text, reasoning as its summary.
func render(items openresponses.Items) string {
	var b strings.Builder
	for _, item := range items {
		switch v := item.(type) {
		case *openresponses.Message:
			fmt.Fprintf(&b, "%s: %s\n", v.Role, v.Text())
		case *openresponses.FunctionCall:
			fmt.Fprintf(&b, "function_call %s: %s\n", v.Name, v.Arguments)
		case *openresponses.FunctionCallOutput:
			fmt.Fprintf(&b, "function_call_output %s: %s\n", v.CallID, v.Output.String())
		case *openresponses.ReasoningItem:
			if text := v.Summary.Text(); text != "" {
				fmt.Fprintf(&b, "reasoning: %s\n", text)
			}
		default:
			fmt.Fprintf(&b, "%s\n", item.ItemType())
		}
	}
	return b.String()
}

// Reviewer answers a deferred tool call with a model: Codex's
// auto-review on this stack. It is the front's answer source through
// Engine.Answers; the engine itself never calls a model.
type Reviewer struct {
	model     openresponses.Streamer
	modelName string
	rubric    string
	o         options
}

var _ agentpolicy.Reviewer = (*Reviewer)(nil)

// NewReviewer builds a reviewer over model.
func NewReviewer(model openresponses.Streamer, modelName, rubric string, opts ...Option) *Reviewer {
	return &Reviewer{model: model, modelName: modelName, rubric: rubric, o: build(opts)}
}

// Review renders the call, its tool's description when the tool is
// known, its arguments and the reason the policy deferred it, sends
// them under the rubric and returns Approved or Refused with the
// model's reason. When the reviewer's own timeout runs out it returns
// TimedOut and no error; a cancelled ctx, a model failure and an
// unreadable answer are errors, which Engine.Answers turns into
// refusals.
func (r *Reviewer) Review(ctx context.Context, info agentturn.ToolCallInfo, v agentpolicy.Verdict) (agentpolicy.Review, error) {
	parent := ctx
	if r.o.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.o.timeout)
		defer cancel()
	}
	a, err := ask(ctx, r.model, r.modelName, r.rubric, renderCall(info, v), r.o)
	if err != nil {
		if parent.Err() == nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return agentpolicy.Review{Outcome: agentpolicy.TimedOut, Reason: "no answer within " + r.o.timeout.String()}, nil
		}
		return agentpolicy.Review{}, err
	}
	if *a.Allow {
		return agentpolicy.Review{Outcome: agentpolicy.Approved, Reason: a.Reason}, nil
	}
	return agentpolicy.Review{Outcome: agentpolicy.Refused, Reason: a.Reason}, nil
}

// renderCall writes a deferred call as the model reads it.
func renderCall(info agentturn.ToolCallInfo, v agentpolicy.Verdict) string {
	var b strings.Builder
	name := v.Tool
	if info.Call != nil {
		name = info.Call.Name
	}
	fmt.Fprintf(&b, "tool: %s\n", name)
	if info.Tool != nil {
		if desc := info.Tool.Description(); desc != "" {
			fmt.Fprintf(&b, "description: %s\n", desc)
		}
	}
	args := string(info.Args)
	if args == "" && info.Call != nil {
		args = info.Call.Arguments
	}
	fmt.Fprintf(&b, "arguments: %s\n", args)
	if v.Reason != "" {
		fmt.Fprintf(&b, "policy: %s\n", v.Reason)
	}
	return b.String()
}
