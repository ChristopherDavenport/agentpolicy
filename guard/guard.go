// Package guard decides what may enter or leave an agent's window: a
// contract for a check over content, deterministic checks that ship
// here, and the hook values that run them, BeforeModelCall over the
// request's input, OutputGuard over each assistant message as the
// stream completes it and ShouldStopAfterTurn over a finished turn.
//
//	input := guard.Chain{
//		Guards:   []guard.Guard{guard.Limit(1 << 20), guard.Redact(), guard.Deny(pattern)},
//		Observer: record,
//	}
//	output := guard.Chain{Guards: []guard.Guard{guard.Redact()}, Observer: record}
//	cfg.BeforeModelCall = input.BeforeModelCall()
//	cfg.OutputGuard = output.OutputGuard()
//
// A guard returns the loop's own vocabulary: Allow passes the content,
// with a rewrite when it sets Items or Instructions, of the input
// before the call or of a message before the transcript keeps it; Block
// stops the run as a guard stop, agentturn.ErrGuard on the run's end,
// when the subject is the input, before the model is called, or a
// finished turn, whose items are already in the transcript, and
// withholds a message behind a placeholder when the subject is one, or
// stops the run there too when the chain sets Stop. Defer has no
// meaning for content and is an error. A check that returns an error
// wrapping agentturn.ErrGuard stops the run as a guard stop, and is
// reported as that guard's Block. Every verdict
// reaches the observer as an agentpolicy.Verdict whose Guard names the
// guard, so a product records it beside the engine's.
//
// The two output hooks see the same words: OutputGuard sees each
// assistant message once, as it completes, and may rewrite or withhold
// it; ShouldStopAfterTurn sees the whole response afterwards, as the
// model produced it, and can only stop. A chain wired to both judges
// every message twice, so a product wires a rewriting chain to
// OutputGuard and keeps ShouldStopAfterTurn for a check over the
// finished turn that no rewrite answers, reading Output.Final to pass
// a turn that only called tools; see [Chain].
//
// Nothing here calls a model. The classify package has a guard that
// does.
package guard

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/ChristopherDavenport/agentpolicy"
	"github.com/ChristopherDavenport/agenttool"
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
// model produced, its output items in the transcript already. The
// response is the model's, not what the transcript kept: a message
// [Chain.OutputGuard] rewrote or withheld is here as the model said
// it, so a guard over what the user will read belongs on that hook,
// and a guard here reads what that hook never sees, a function call's
// arguments, a reasoning summary.
type Output struct {
	Response *openresponses.Response
	// Results are the turn's tool results in the model's order, as
	// agentturn.TurnInfo.ToolResults carries them; empty when the model
	// called no tools.
	Results []agenttool.Result
	// Final is set when the turn is the run's answer: the model called
	// no tools, as agentturn.TurnInfo.Final says, and the response is
	// the answer unless a queued follow-up keeps the run going; or one
	// of its results ends the run, its Terminate set, as the tool
	// answering for the model, and the outputs of the results that end
	// the run are the answer, [Output.Answer]. A guard over the answer
	// passes a turn that is not one rather than judging, and paying
	// for, a turn that produced nothing but tool calls.
	Final bool
}

// Answer returns the outputs of the results that end the run, each as
// a function call output with the call ID of the call it answers, the
// function calls of the response taken in order: the run's answer when
// a terminating tool answered for the model, which both fronts serve
// as the answer. It is nil for a turn no result ends. A guard over the
// answer judges these as it judges a final message, and the reference
// guards read them among the output's items.
func (o Output) Answer() openresponses.Items {
	var calls []*openresponses.FunctionCall
	if o.Response != nil {
		for _, item := range o.Response.Output {
			if c, ok := item.(*openresponses.FunctionCall); ok {
				calls = append(calls, c)
			}
		}
	}
	var out openresponses.Items
	for i, r := range o.Results {
		if !r.Terminate {
			continue
		}
		id := ""
		if i < len(calls) {
			id = calls[i].CallID
		}
		out = append(out, &openresponses.FunctionCallOutput{CallID: id, Output: r.Output})
	}
	return out
}

// terminates reports whether any of results ends the run.
func terminates(results []agenttool.Result) bool {
	for _, r := range results {
		if r.Terminate {
			return true
		}
	}
	return false
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
	// Quarantine, for an Input, names items of the input to quarantine
	// for the rest of the conversation, under agentturn.Quarantine:
	// every request from this one on leaves each out, or carries a
	// function call output as agentturn.QuarantinedOutput, and the
	// guards after this one see the input without them. It is an allow,
	// not a rewrite: the transcript and the record keep the items, and a
	// verdict that sets it with Items or Instructions fails the check.
	// Only items the loop built the request from can be named, as the
	// guard was handed them, by identity; one an earlier guard's rewrite
	// made fails the check closed. It is ignored for a Message, an
	// Output and on a Block.
	Quarantine openresponses.Items
}

// Guard checks one subject, an [Input], a [Message] or an [Output]. A
// guard passes a subject it does not know with Allow.
type Guard interface {
	Name() string
	Check(ctx context.Context, subject any) (Verdict, error)
}

// New builds a Guard from a name and a function. It says nothing of
// whether it rewrites its subject, so a parallel [Chain] checks it in
// sequence; [ReadOnly] marks one that never does.
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
// return one. From BeforeModelCall and from ShouldStopAfterTurn the
// loop ends the run with ReasonStopped and StopGuard, the error on
// RunEnd.Err, after a ModelBlocked event from the first. From
// OutputGuard, under [Chain.Stop], the loop withholds the message and
// ends the run with StopGuard and RunEnd.Withheld. It wraps
// agentturn.ErrGuard, so errors.Is tells a guard's refusal from a
// failure, and errors.As finds it.
type BlockedError struct {
	Guard string
	// Subject is "input", "message" or "output".
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
//
// One chain wired to both output hooks judges every assistant message
// twice: once as a [Message] on OutputGuard, as the stream completes
// it, and once inside an [Output] on ShouldStopAfterTurn, among the
// turn's other items, where the response is the one the model
// produced and not what the output guard's rewrites left in the
// transcript. The two hooks are for different checks. A guard that
// rewrites, or that judges what the user will read, belongs on
// OutputGuard alone; ShouldStopAfterTurn is for a check over the
// finished turn that no rewrite can answer, a secret in a function
// call's arguments or a reasoning summary, say, and a guard there
// reads Output.Final to pass a turn that only called tools. A product
// therefore wires one chain per hook rather than one chain to all
// three, as the package example does.
type Chain struct {
	Guards   []Guard
	Observer func(context.Context, agentpolicy.Verdict)
	// Placeholder builds the message OutputGuard puts in place of one a
	// guard withheld. It is handed the message as the guards before
	// the one that blocked left it, with their rewrites applied, and
	// not the message as the model produced it, so a placeholder that
	// keeps part of the message, or counts what it withheld, never
	// reads text a guard ahead of it already redacted. nil means
	// [Withheld].
	Placeholder func(left *openresponses.Message, guard, reason string) *openresponses.Message
	// Stop makes a Block of OutputGuard stop the run as a guard stop,
	// as a Block of the input does, rather than put a placeholder in
	// the message's place and go on. Neither the message nor the
	// guard's reason reaches the caller: the loop withholds the
	// message and the fronts report a content filter. Placeholder is
	// not used.
	Stop bool
	// Scope says which model calls BeforeModelCall checks: every one,
	// the default, or only the first of a run ([FirstTurn]). The output
	// hooks check every message and every turn whatever it says.
	Scope Scope
	// Parallel checks the guards that say they do not rewrite
	// ([Rewriting], [ReadOnly]) at the same time, each run of them
	// together, while every other guard is checked in sequence, over the
	// subject the guards before it left, as without it. The outcome and
	// the verdicts reported are those of checking in order: each guard's
	// verdict is reported in chain order, the first block in chain order
	// stands and the guards after it are not reported, and a guard still
	// running when an earlier one blocks or fails is cancelled through
	// its context. A guard checked beside others that rewrites anyway
	// fails the check. It is how two model-backed judges cost the
	// latency of one.
	Parallel bool
}

// Scope is which model calls a chain's BeforeModelCall checks.
type Scope int

const (
	// EveryCall checks the input of every model call.
	EveryCall Scope = iota
	// FirstTurn checks the input of the first model call of a run, the
	// turn agentturn.TurnFromContext gives being 1 (or 0, outside a
	// turn), and not in a run a handoff started, one whose
	// agentturn.TriggerFromContext is of kind "handoff": what the run
	// was started with is checked once, as the Agents SDK runs its
	// input guardrails on the starting agent's first turn. Later turns
	// add tool outputs and the model's own items, which a chain that
	// must judge them checks on every call.
	FirstTurn
)

// firstTurn reports whether ctx is a hook's on the first model call of
// a run no handoff started.
func firstTurn(ctx context.Context) bool {
	return agentturn.TurnFromContext(ctx) <= 1 && agentturn.TriggerFromContext(ctx).Kind != "handoff"
}

// Rewriting is implemented by a guard that says whether it may change
// its subject: rewrite an input's items or instructions or a message,
// or quarantine input items. A [Chain] that sets Parallel checks a
// guard that says it does not at the same time as its neighbours, and
// any other in sequence. The reference guards say what they do: Limit,
// Deny and Secrets do not rewrite, Redact does.
type Rewriting interface {
	Rewrites() bool
}

// ReadOnly returns g saying it never rewrites its subject, so a
// parallel [Chain] checks it beside the guards around it that say so
// too. A guard so marked that rewrites when checked beside others fails
// the check.
func ReadOnly(g Guard) Guard { return readOnly{g} }

type readOnly struct{ Guard }

func (readOnly) Rewrites() bool { return false }

// rewriter is a guard saying it may rewrite.
type rewriter struct{ Guard }

func (rewriter) Rewrites() bool { return true }

// alongside reports whether a parallel chain may check g beside other
// guards: it says it never rewrites.
func alongside(g Guard) bool {
	r, ok := g.(Rewriting)
	return ok && !r.Rewrites()
}

// changes reports whether a verdict changes its subject.
func changes(v Verdict) bool {
	return v.Action == agentturn.Allow && (v.Items != nil || v.Instructions != nil || len(v.Quarantine) > 0)
}

// quarantine quarantines the items v names, as [Verdict.Quarantine]
// says, when each is one of built, the items the loop built the
// request from, and v rewrites nothing; beside says the guard was
// checked beside others, where it may not. The error is the refusal's
// cause.
func quarantine(ctx context.Context, v Verdict, built openresponses.Items, beside bool) error {
	if beside {
		return errors.New("a guard checked beside others quarantined")
	}
	if v.Items != nil || v.Instructions != nil {
		return errors.New("a quarantine is not a rewrite")
	}
	for _, item := range v.Quarantine {
		if !slices.ContainsFunc(built, func(b openresponses.Item) bool { return sameItem(b, item) }) {
			return errors.New("an item the loop did not build the request from")
		}
	}
	return agentturn.Quarantine(ctx, v.Quarantine...)
}

// sameItem reports whether two items are one, by identity.
func sameItem(a, b openresponses.Item) bool {
	if a == nil || b == nil {
		return false
	}
	ta := reflect.TypeOf(a)
	return ta == reflect.TypeOf(b) && ta.Comparable() && a == b
}

// checked is one guard's answer.
type checked struct {
	v   Verdict
	err error
}

// checks checks the chain's guards and hands each answer to step in
// chain order, with whether the guard was checked beside others; step
// returns true to end the check, with what the hook returns. Each guard
// is given subject() as it starts. In sequence, a guard starts once
// step has taken the answer before it; under Parallel, a run of guards
// that say they do not rewrite starts together over one subject, and
// once step ends the check the rest of the run is cancelled.
func (c Chain) checks(ctx context.Context, subject func() any, step func(g Guard, a checked, beside bool) (bool, error)) error {
	for i := 0; i < len(c.Guards); {
		j := i + 1
		if c.Parallel && alongside(c.Guards[i]) {
			for j < len(c.Guards) && alongside(c.Guards[j]) {
				j++
			}
		}
		if j-i == 1 {
			v, err := c.Guards[i].Check(ctx, subject())
			if done, err := step(c.Guards[i], checked{v, err}, false); done {
				return err
			}
			i = j
			continue
		}
		run, cancel := context.WithCancel(ctx)
		s := subject()
		answers := make([]chan checked, j-i)
		for k := range answers {
			answers[k] = make(chan checked, 1)
			go func(g Guard, out chan<- checked) {
				v, err := g.Check(run, s)
				out <- checked{v, err}
			}(c.Guards[i+k], answers[k])
		}
		for k := range answers {
			a := <-answers[k]
			if done, err := step(c.Guards[i+k], a, true); done {
				cancel()
				return err
			}
		}
		cancel()
		i = j
	}
	return nil
}

// together is the error of a guard checked beside others that changed
// its subject.
func together(g Guard) error {
	return fmt.Errorf("agentpolicy/guard: %s: rewrote a subject it was checked on beside other guards", g.Name())
}

// BeforeModelCall returns the hook value for agentturn.Config. A Block
// returns a [BlockedError], which stops the run as a guard stop before
// the model is called; a rewrite replaces the
// request's input, and its instructions when the verdict carries
// them, which the loop documents affects session verification as a
// Transform does; a guard that errs or defers fails the call with its
// error.
func (c Chain) BeforeModelCall() func(context.Context, *openresponses.Request) error {
	return func(ctx context.Context, req *openresponses.Request) error {
		if c.Scope == FirstTurn && !firstTurn(ctx) {
			return nil
		}
		runID := agentturn.RunIDFromContext(ctx)
		// The items the loop built the request from, the only ones a
		// guard may quarantine.
		built := slices.Clone(req.Input)
		subject := func() any { return Input{Items: req.Input, Instructions: req.Instructions} }
		return c.checks(ctx, subject, func(g Guard, a checked, beside bool) (bool, error) {
			v, err := a.v, a.err
			if err != nil {
				return true, c.fail(ctx, agentpolicy.Verdict{RunID: runID, Guard: g.Name()}, err)
			}
			held := v.Action == agentturn.Allow && len(v.Quarantine) > 0
			if beside && changes(v) && !held {
				return true, together(g)
			}
			if held {
				if err := quarantine(ctx, v, built, beside); err != nil {
					// The refusal is the guard's verdict, a block, and
					// fails the run: the items it named reach the model
					// otherwise.
					reason := "quarantine refused: " + err.Error()
					c.observe(ctx, agentpolicy.Verdict{RunID: runID, Guard: g.Name(), Action: agentturn.Block, Reason: reason, Quarantined: slices.Clone(v.Quarantine)})
					return true, fmt.Errorf("agentpolicy/guard: %s: %s", g.Name(), reason)
				}
			}
			verdict := agentpolicy.Verdict{RunID: runID, Guard: g.Name(), Action: v.Action, Reason: v.Reason}
			if held {
				verdict.Quarantined = slices.Clone(v.Quarantine)
			}
			c.observe(ctx, verdict)
			switch v.Action {
			case agentturn.Allow:
				if v.Items != nil {
					req.Input = v.Items
				}
				if v.Instructions != nil {
					req.Instructions = *v.Instructions
				}
				if held {
					// The guards after see the input as the request will
					// carry it.
					req.Input = agentturn.QuarantineFromContext(ctx).Apply(req.Input)
				}
				return false, nil
			case agentturn.Block:
				return true, &BlockedError{Guard: g.Name(), Subject: "input", Reason: v.Reason}
			default:
				return true, fmt.Errorf("agentpolicy/guard: %s: Defer is not valid for content", g.Name())
			}
		})
	}
}

// OutputGuard returns the hook value for agentturn.Config. Each guard
// checks the message as a [Message]; a rewrite replaces it for the
// guards after and for the transcript, and a Block withholds it: the
// placeholder takes its place in the transcript, the record and the
// front's item_end, and the guards after the one that blocked are not
// consulted. The deltas of the original have already been delivered,
// so a front that must not show withheld text renders on item_end. A
// guard that errs or defers fails the run with its error, and one
// whose error wraps agentturn.ErrGuard stops it as a guard stop.
// Withholding a message does not end the run unless the chain sets
// [Chain.Stop]: a Block then returns a [BlockedError], and the loop
// withholds the message and ends the run as a guard stop, with no
// placeholder and no reason the caller reads.
func (c Chain) OutputGuard() func(context.Context, agentturn.OutputInfo) (*openresponses.Message, error) {
	return func(ctx context.Context, info agentturn.OutputInfo) (*openresponses.Message, error) {
		msg, replaced := info.Message, false
		var placeholder *openresponses.Message
		err := c.checks(ctx, func() any { return Message{Message: msg} }, func(g Guard, a checked, beside bool) (bool, error) {
			v, err := a.v, a.err
			if err != nil {
				return true, c.fail(ctx, agentpolicy.Verdict{RunID: info.RunID, Turn: info.Turn, Guard: g.Name()}, err)
			}
			if beside && changes(v) {
				return true, together(g)
			}
			c.observe(ctx, agentpolicy.Verdict{RunID: info.RunID, Turn: info.Turn, Guard: g.Name(), Action: v.Action, Reason: v.Reason})
			switch v.Action {
			case agentturn.Allow:
				if v.Items == nil {
					return false, nil
				}
				m, ok := message(v.Items)
				if !ok {
					return true, fmt.Errorf("agentpolicy/guard: %s: a rewrite of a message must be one message", g.Name())
				}
				msg, replaced = m, true
				return false, nil
			case agentturn.Block:
				if c.Stop {
					return true, &BlockedError{Guard: g.Name(), Subject: "message", Reason: v.Reason}
				}
				build := c.Placeholder
				if build == nil {
					build = Withheld
				}
				// The placeholder is built from the message as the chain
				// left it, not as the model produced it: a guard before
				// this one may have redacted what this one must not see.
				placeholder = build(msg, g.Name(), v.Reason)
				return true, nil
			default:
				return true, fmt.Errorf("agentpolicy/guard: %s: Defer is not valid for content", g.Name())
			}
		})
		switch {
		case err != nil:
			return nil, err
		case placeholder != nil:
			return placeholder, nil
		case replaced:
			return msg, nil
		}
		return nil, nil
	}
}

// Withheld is the placeholder [Chain.OutputGuard] puts in place of a
// message a guard withheld when the chain sets none: an assistant
// message reading "Withheld by <guard>: <reason>", with the ID, status
// and phase of the withheld message so the front's item_end matches
// its item_start. It reads nothing else of the message.
func Withheld(withheld *openresponses.Message, guard, reason string) *openresponses.Message {
	m := openresponses.AssistantText("Withheld by " + guard + ": " + reason)
	if withheld != nil {
		m.ID, m.Status, m.Phase = withheld.ID, withheld.Status, withheld.Phase
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
		out := Output{Response: info.Response, Results: info.ToolResults, Final: info.Final || terminates(info.ToolResults)}
		stop := false
		err := c.checks(ctx, func() any { return out }, func(g Guard, a checked, _ bool) (bool, error) {
			v, err := a.v, a.err
			if err != nil {
				return true, c.fail(ctx, agentpolicy.Verdict{RunID: info.RunID, Turn: info.Turn, Guard: g.Name()}, err)
			}
			c.observe(ctx, agentpolicy.Verdict{RunID: info.RunID, Turn: info.Turn, Guard: g.Name(), Action: v.Action, Reason: v.Reason})
			switch v.Action {
			case agentturn.Allow:
				return false, nil
			case agentturn.Block:
				stop = true
				return true, &BlockedError{Guard: g.Name(), Subject: "output", Reason: v.Reason}
			default:
				return true, fmt.Errorf("agentpolicy/guard: %s: Defer is not valid for content", g.Name())
			}
		})
		return stop, err
	}
}

// fail returns the error a guard's check failed with. One that wraps
// agentturn.ErrGuard stops the run as a guard stop, so it is the
// guard's Block and is reported as one, with the reason of a
// [BlockedError] or the error's text; any other fails the run, and is
// no verdict.
func (c Chain) fail(ctx context.Context, v agentpolicy.Verdict, err error) error {
	if errors.Is(err, agentturn.ErrGuard) {
		v.Action, v.Reason = agentturn.Block, err.Error()
		var b *BlockedError
		if errors.As(err, &b) {
			v.Reason = b.Reason
		}
		c.observe(ctx, v)
	}
	return fmt.Errorf("agentpolicy/guard: %s: %w", v.Guard, err)
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
// or the response's output followed by the answer a terminating tool
// gave, so a guard over the output reads the run's answer however the
// run gave it.
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
		var out openresponses.Items
		if s.Response != nil {
			out = s.Response.Output
		}
		if answer := s.Answer(); answer != nil {
			out = append(append(openresponses.Items(nil), out...), answer...)
		}
		return out, true
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
