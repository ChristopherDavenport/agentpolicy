// Package guard decides what may enter or leave an agent's window: a
// contract for a check over content, deterministic checks that ship
// here, and the hook values that run them, BeforeModelCall over the
// request's input and ShouldStopAfterTurn over a finished turn.
//
//	chain := guard.Chain{
//		Guards:   []guard.Guard{guard.Limit(1 << 20), guard.Redact(), guard.Deny(pattern)},
//		Observer: record,
//	}
//	cfg.BeforeModelCall = chain.BeforeModelCall()
//	cfg.ShouldStopAfterTurn = chain.ShouldStopAfterTurn()
//
// A guard returns the loop's own vocabulary: Allow passes the content,
// with a rewrite of the input when it sets Items; Block fails the model
// call when the subject is the input, and stops the run when the
// subject is a finished turn, since the assistant's items are already
// in the transcript. Defer has no meaning for content and is an error.
// Every verdict reaches the observer as an agentpolicy.Verdict whose
// Guard names the guard, so a product records it beside the engine's.
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
// input as the loop built it, filtered and transformed.
type Input struct {
	Items openresponses.Items
}

// Output is the subject of a check after a turn: the response the
// model produced, its output items in the transcript already.
type Output struct {
	Response *openresponses.Response
}

// Verdict is a guard's answer.
type Verdict struct {
	// Action is Allow or Block. Defer is not valid for content.
	Action agentturn.ToolAction
	// Reason says why, in stable text the record keeps.
	Reason string
	// Items, for an Input, replaces the request's input for this call.
	// nil keeps it. It is ignored for an Output and on a Block.
	Items openresponses.Items
}

// Guard checks one subject, an [Input] or an [Output]. A guard passes a
// subject it does not know with Allow.
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

// BlockedError is the error the BeforeModelCall hook returns when a
// guard blocks the input. The loop wraps it and ends the run with
// ReasonError; errors.As finds it.
type BlockedError struct {
	Guard  string
	Reason string
}

func (e *BlockedError) Error() string {
	return "agentpolicy/guard: " + e.Guard + " blocked the input: " + e.Reason
}

// Chain runs guards in order and reports every verdict. Each guard
// sees the input as the guard before it left it, so a rewrite feeds
// the next check. The observer, when set, receives every verdict as
// an agentpolicy.Verdict with Guard set, the same shape the engine
// reports, exactly once per guard per hook call.
type Chain struct {
	Guards   []Guard
	Observer func(context.Context, agentpolicy.Verdict)
}

// BeforeModelCall returns the hook value for agentturn.Config. A Block
// fails the call with a [BlockedError]; a rewrite replaces the
// request's input, which the loop documents affects session
// verification as a Transform does; a guard that errs or defers fails
// the call with its error.
func (c Chain) BeforeModelCall() func(context.Context, *openresponses.Request) error {
	return func(ctx context.Context, req *openresponses.Request) error {
		runID := agentturn.RunIDFromContext(ctx)
		for _, g := range c.Guards {
			v, err := g.Check(ctx, Input{Items: req.Input})
			if err != nil {
				return fmt.Errorf("agentpolicy/guard: %s: %w", g.Name(), err)
			}
			c.observe(ctx, agentpolicy.Verdict{RunID: runID, Guard: g.Name(), Action: v.Action, Reason: v.Reason})
			switch v.Action {
			case agentturn.Allow:
				if v.Items != nil {
					req.Input = v.Items
				}
			case agentturn.Block:
				return &BlockedError{Guard: g.Name(), Reason: v.Reason}
			default:
				return fmt.Errorf("agentpolicy/guard: %s: Defer is not valid for content", g.Name())
			}
		}
		return nil
	}
}

// ShouldStopAfterTurn returns the hook value for agentturn.Config. A
// Block stops the run after the turn; the guards after the one that
// blocked are not consulted. A guard that errs or defers fails the
// run with its error.
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
				return true, nil
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

// items returns the items a subject carries: the input, or the
// response's output.
func items(subject any) (openresponses.Items, bool) {
	switch s := subject.(type) {
	case Input:
		return s.Items, true
	case Output:
		if s.Response == nil {
			return nil, true
		}
		return s.Response.Output, true
	}
	return nil, false
}

// noun names the subject in a reason.
func noun(subject any) string {
	if _, ok := subject.(Output); ok {
		return "output"
	}
	return "input"
}
