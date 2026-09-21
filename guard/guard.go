// Package guard decides what may enter or leave an agent's window: a
// contract for a check over content, deterministic checks that ship
// here, and the hook values that run them, BeforeModelCall over the
// request's input, OutputGuard over each assistant message as the
// stream completes it and ShouldStopAfterTurn over a finished turn.
//
//	chain := guard.Chain{
//		Guards:   []guard.Guard{guard.Limit(1 << 20), guard.Redact(), guard.Deny(pattern)},
//		Observer: record,
//	}
//	cfg.BeforeModelCall = chain.BeforeModelCall()
//	cfg.OutputGuard = chain.OutputGuard()
//	cfg.ShouldStopAfterTurn = chain.ShouldStopAfterTurn()
//
// A guard returns the loop's own vocabulary: Allow passes the content,
// with a rewrite when it sets Items or Instructions, of the input
// before the call or of a message before the transcript keeps it; Block fails the model
// call when the subject is the input, withholds a message behind a
// placeholder when the subject is one, and stops the run as a guard
// stop, agentturn.ErrGuard on the run's end, when the subject is a
// finished turn, since the turn's items are already in the transcript.
// Defer has no meaning for content and is an error. Every verdict
// reaches the observer as an agentpolicy.Verdict whose Guard names the
// guard, so a product records it beside the engine's.
//
// Nothing here calls a model. The classify package has a guard that
// does.
package guard

import (
	"context"
	"fmt"

	"github.com/ChristopherDavenport/agentpolicy"
	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
)

// Input is the subject of a check before a model call: the request's
// input as the loop built it, filtered and transformed, and the
// request's instructions.
type Input struct {
	Items openresponses.Items
	// Instructions is the request's instructions field, the text the
	// model reads before the input. Most of what enters an agent's
	// window is here and not in the items: an AGENTS.md chain read out
	// of a checkout, a skill catalogue read out of a directory, a
	// memory block the model itself wrote. None of it is typed by the
	// person running the agent, so a guard that reads only the items
	// blocks an injection in a user message and passes the same
	// sentence in a repository's AGENTS.md.
	Instructions string
}

// Output is the subject of a check after a turn: the response the
// model produced, its output items in the transcript already.
type Output struct {
	Response *openresponses.Response
}

// Message is the subject of a check on one assistant message as the
// stream completes it, before the transcript, the record or the
// front's item_end keeps it. The message may still be rewritten or
// withheld; function calls and every other output item never come
// this way.
type Message struct {
	Message *openresponses.Message
}

// Verdict is a guard's answer.
type Verdict struct {
	// Action is Allow or Block. Defer is not valid for content.
	Action agentturn.ToolAction
	// Reason says why, in stable text the record keeps.
	Reason string
	// Items, for an Input, replaces the request's input for this call;
	// for a Message, its one item, a message, replaces the message.
	// nil keeps the subject. It is ignored for an Output and on a
	// Block.
	Items openresponses.Items
	// Instructions, for an Input, replaces the request's instructions
	// for this call, so a guard rewrites the text nobody typed as it
	// rewrites the items. nil keeps them, and "" sends none. It is
	// ignored for a Message, an Output and on a Block.
	Instructions *string
}

// Guard checks one subject, an [Input], a [Message] or an [Output]. A
// guard passes a subject it does not know with Allow.
type Guard interface {
	Name() string
	Check(ctx context.Context, subject any) (Verdict, error)
}

// New builds a Guard from a name and a function.
func New(name string, check func(ctx context.Context, subject any) (Verdict, error)) Guard {
	return &funcGuard{name: name, check: check}
}

type funcGuard struct {
	name  string
	check func(context.Context, any) (Verdict, error)
}

func (g *funcGuard) Name() string { return g.name }
func (g *funcGuard) Check(ctx context.Context, subject any) (Verdict, error) {
	return g.check(ctx, subject)
}

// BlockedError is the error a guard's Block becomes on the hooks that
// return one. From BeforeModelCall the loop ends the run with
// ReasonError after a ModelBlocked event; from ShouldStopAfterTurn it
// ends the run with ReasonStopped and StopGuard, the error on
// RunEnd.Err. It wraps agentturn.ErrGuard either way, so errors.Is
// tells a guard's refusal from a failure, and errors.As finds it.
type BlockedError struct {
	Guard string
	// Subject is "input" or "output".
	Subject string
	Reason  string
}

func (e *BlockedError) Error() string {
	return "agentpolicy/guard: " + e.Guard + " blocked the " + e.Subject + ": " + e.Reason
}

// Unwrap returns agentturn.ErrGuard.
func (e *BlockedError) Unwrap() error { return agentturn.ErrGuard }

// Chain runs guards in order and reports every verdict. Each guard
// sees the input, or the message, as the guard before it left it, so
// a rewrite feeds the next check. The observer, when set, receives
// every verdict as an agentpolicy.Verdict with Guard set, the same
// shape the engine reports, exactly once per guard per hook call.
type Chain struct {
	Guards   []Guard
	Observer func(context.Context, agentpolicy.Verdict)
	// Placeholder builds the message OutputGuard puts in place of one a
	// guard withheld. nil means [Withheld].
	Placeholder func(original *openresponses.Message, guard, reason string) *openresponses.Message
}

// BeforeModelCall returns the hook value for agentturn.Config. A Block
// fails the call with a [BlockedError]; a rewrite replaces the
// request's input, and its instructions when the verdict carries
// them, which the loop documents affects session verification as a
// Transform does; a guard that errs or defers fails the call with its
// error.
func (c Chain) BeforeModelCall() func(context.Context, *openresponses.Request) error {
	return func(ctx context.Context, req *openresponses.Request) error {
		runID := agentturn.RunIDFromContext(ctx)
		for _, g := range c.Guards {
			v, err := g.Check(ctx, Input{Items: req.Input, Instructions: req.Instructions})
			if err != nil {
				return fmt.Errorf("agentpolicy/guard: %s: %w", g.Name(), err)
			}
			c.observe(ctx, agentpolicy.Verdict{RunID: runID, Guard: g.Name(), Action: v.Action, Reason: v.Reason})
			switch v.Action {
			case agentturn.Allow:
				if v.Items != nil {
					req.Input = v.Items
				}
				if v.Instructions != nil {
					req.Instructions = *v.Instructions
				}
			case agentturn.Block:
				return &BlockedError{Guard: g.Name(), Subject: "input", Reason: v.Reason}
			default:
				return fmt.Errorf("agentpolicy/guard: %s: Defer is not valid for content", g.Name())
			}
		}
		return nil
	}
}

// OutputGuard returns the hook value for agentturn.Config. Each guard
// checks the message as a [Message]; a rewrite replaces it for the
// guards after and for the transcript, and a Block withholds it: the
// placeholder takes its place in the transcript, the record and the
// front's item_end, and the guards after the one that blocked are not
// consulted. The deltas of the original have already been delivered,
// so a front that must not show withheld text renders on item_end. A
// guard that errs or defers fails the run with its error. Withholding
// a message does not end the run; a chain that should also stop it is
// wired into ShouldStopAfterTurn as well, where it sees the turn's
// response as the model produced it.
func (c Chain) OutputGuard() func(context.Context, agentturn.OutputInfo) (*openresponses.Message, error) {
	return func(ctx context.Context, info agentturn.OutputInfo) (*openresponses.Message, error) {
		msg, replaced := info.Message, false
		for _, g := range c.Guards {
			v, err := g.Check(ctx, Message{Message: msg})
			if err != nil {
				return nil, fmt.Errorf("agentpolicy/guard: %s: %w", g.Name(), err)
			}
			c.observe(ctx, agentpolicy.Verdict{RunID: info.RunID, Turn: info.Turn, Guard: g.Name(), Action: v.Action, Reason: v.Reason})
			switch v.Action {
			case agentturn.Allow:
				if v.Items == nil {
					continue
				}
				m, ok := message(v.Items)
				if !ok {
					return nil, fmt.Errorf("agentpolicy/guard: %s: a rewrite of a message must be one message", g.Name())
				}
				msg, replaced = m, true
			case agentturn.Block:
				build := c.Placeholder
				if build == nil {
					build = Withheld
				}
				return build(info.Message, g.Name(), v.Reason), nil
			default:
				return nil, fmt.Errorf("agentpolicy/guard: %s: Defer is not valid for content", g.Name())
			}
		}
		if replaced {
			return msg, nil
		}
		return nil, nil
	}
}

// Withheld is the placeholder [Chain.OutputGuard] puts in place of a
// message a guard withheld when the chain sets none: an assistant
// message reading "Withheld by <guard>: <reason>", with the ID, status
// and phase of the original so the front's item_end matches its
// item_start.
func Withheld(original *openresponses.Message, guard, reason string) *openresponses.Message {
	m := openresponses.AssistantText("Withheld by " + guard + ": " + reason)
	if original != nil {
		m.ID, m.Status, m.Phase = original.ID, original.Status, original.Phase
	}
	return m
}

// ShouldStopAfterTurn returns the hook value for agentturn.Config. A
// Block stops the run after the turn as a guard stop, with a
// [BlockedError] wrapping agentturn.ErrGuard, so the run ends with
// ReasonStopped, StopGuard and the error on RunEnd.Err; the guards
// after the one that blocked are not consulted. A guard that errs or
// defers fails the run with its error.
func (c Chain) ShouldStopAfterTurn() func(context.Context, agentturn.TurnInfo) (bool, error) {
	return func(ctx context.Context, info agentturn.TurnInfo) (bool, error) {
		for _, g := range c.Guards {
			v, err := g.Check(ctx, Output{Response: info.Response})
			if err != nil {
				return false, fmt.Errorf("agentpolicy/guard: %s: %w", g.Name(), err)
			}
			c.observe(ctx, agentpolicy.Verdict{RunID: info.RunID, Turn: info.Turn, Guard: g.Name(), Action: v.Action, Reason: v.Reason})
			switch v.Action {
			case agentturn.Allow:
			case agentturn.Block:
				return true, &BlockedError{Guard: g.Name(), Subject: "output", Reason: v.Reason}
			default:
				return false, fmt.Errorf("agentpolicy/guard: %s: Defer is not valid for content", g.Name())
			}
		}
		return false, nil
	}
}

func (c Chain) observe(ctx context.Context, v agentpolicy.Verdict) {
	if c.Observer != nil {
		c.Observer(ctx, v)
	}
}

// BeforeModelCall runs guards over the input with no observer; see
// [Chain.BeforeModelCall].
func BeforeModelCall(guards ...Guard) func(context.Context, *openresponses.Request) error {
	return Chain{Guards: guards}.BeforeModelCall()
}

// OutputGuard runs guards over each assistant message with no
// observer; see [Chain.OutputGuard].
func OutputGuard(guards ...Guard) func(context.Context, agentturn.OutputInfo) (*openresponses.Message, error) {
	return Chain{Guards: guards}.OutputGuard()
}

// ShouldStopAfterTurn runs guards over a finished turn with no
// observer; see [Chain.ShouldStopAfterTurn].
func ShouldStopAfterTurn(guards ...Guard) func(context.Context, agentturn.TurnInfo) (bool, error) {
	return Chain{Guards: guards}.ShouldStopAfterTurn()
}

// allow is the verdict for a subject a guard passes.
var allow = Verdict{Action: agentturn.Allow}

// block builds a Block verdict.
func block(reason string) Verdict {
	return Verdict{Action: agentturn.Block, Reason: reason}
}

// items returns the items a subject carries: the input, the message,
// or the response's output.
func items(subject any) (openresponses.Items, bool) {
	switch s := subject.(type) {
	case Input:
		return s.Items, true
	case Message:
		if s.Message == nil {
			return nil, true
		}
		return openresponses.Items{s.Message}, true
	case Output:
		if s.Response == nil {
			return nil, true
		}
		return s.Response.Output, true
	}
	return nil, false
}

// message returns the one message a rewrite of a [Message] holds.
func message(items openresponses.Items) (*openresponses.Message, bool) {
	if len(items) != 1 {
		return nil, false
	}
	m, ok := items[0].(*openresponses.Message)
	return m, ok && m != nil
}

// instructions returns the instructions a subject carries: an Input's
// own, and none for a message or a finished turn, which are the
// model's words and not what was sent to it.
func instructions(subject any) string {
	if in, ok := subject.(Input); ok {
		return in.Instructions
	}
	return ""
}

// noun names the subject in a reason.
func noun(subject any) string {
	switch subject.(type) {
	case Output:
		return "output"
	case Message:
		return "message"
	}
	return "input"
}
