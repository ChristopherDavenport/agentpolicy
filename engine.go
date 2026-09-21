package agentpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/ChristopherDavenport/agentturn"
	"github.com/ChristopherDavenport/openresponses"
)

// Errors returned by [Build] and the grants. Every error the package
// produces begins with "agentpolicy:".
var (
	// ErrNoDefault is returned when the policy's Default was left unset.
	ErrNoDefault = errors.New("agentpolicy: policy default is not set; use Allow(), Deny() or Ask()")
	// ErrNoMatcher is returned when a rule has a specifier and its tool
	// has no matcher, so the rule could never match. The error names
	// the rule.
	ErrNoMatcher = errors.New("agentpolicy: no matcher for the rule's tool")
)

// Verdict is what was decided and why, for recording: the engine's
// decision on a call, a hold and its release, a grant, a guard's
// verdict on content, or a reviewer's answer to a deferred call. The
// loop's recorder writes the decision the hook returned as the call's
// decision entry; the verdict carries what that entry cannot, the rule
// above all, and a product writes it beside the decision as a custom
// entry under agentpolicy.
type Verdict struct {
	RunID string
	Turn  int
	// CallID and Tool name the call decided. They are empty for a
	// content verdict; a grant names the rule's tool.
	CallID string
	Tool   string
	// Guard names the guard that decided content; empty otherwise.
	Guard string
	// Action is Allow, Block or Defer.
	Action agentturn.ToolAction
	// Rule is the rule that fired, or the rule granted. It is nil when
	// the default applied and for a guard's or a reviewer's verdict.
	Rule *Rule
	// Reason is the stable text behind the action, the same text the
	// model reads when the action blocks a call.
	Reason string
	// Held is set on a Defer for a call the policy allowed but holds
	// because another call of its batch asks, and on the verdict that
	// releases or refuses it once the ask is answered.
	Held bool
}

// Option configures an [Engine].
type Option func(*Engine)

// WithObserver registers fn to receive every verdict the engine
// produces: each decision, each grant and each reviewer answer, exactly
// once, outside the engine's lock. A hook cannot append to the
// transcript, so this is how a verdict reaches the session.
func WithObserver(fn func(context.Context, Verdict)) Option {
	return func(e *Engine) { e.observer = fn }
}

// Engine is the runtime form of a [Policy]: the policy in force, the
// matchers it is evaluated with, the grants made since it was built
// and the calls it has deferred. It is safe for concurrent use.
type Engine struct {
	matchers map[string]ToolMatcher
	observer func(context.Context, Verdict)
	bound    DenialBound

	mu     sync.Mutex
	policy Policy
	// deferred remembers the calls deferred in each run, asked and
	// held, keyed by run and then by call, so Answers can hand the
	// reviewer what the hook saw and Release can answer the held ones.
	// One engine serves as many runs as a product has agents: a
	// decision in one run never touches another's. A run's calls are
	// forgotten as they are answered, and [Engine.Forget] drops what a
	// run that ended another way left behind.
	deferred map[string]map[string]deferredCall
	reviews  reviewLog
}

type deferredCall struct {
	info    agentturn.ToolCallInfo
	verdict Verdict
	// allowed is the reason the policy allowed a held call, for the
	// verdict that releases it.
	allowed string
}

// byPolicy is what the engine's decisions name as their decider, the
// session format's word for a rule the harness evaluated on its own.
const byPolicy = "policy"

// Build validates the policy against the matchers and returns the
// runtime form. It fails with [ErrNoDefault] when the default is unset
// and with [ErrNoMatcher] when a rule has a specifier and its tool has
// no matcher, so a rule that could never match is refused here rather
// than ignored at the first call. The lists are copied; the caller's
// slices are not retained.
func Build(p Policy, matchers map[string]ToolMatcher, opts ...Option) (*Engine, error) {
	if _, ok := p.Default.Action(); !ok {
		return nil, ErrNoDefault
	}
	for _, list := range [][]Rule{p.Deny, p.Ask, p.Allow} {
		for _, r := range list {
			if err := checkRule(r, matchers); err != nil {
				return nil, err
			}
		}
	}
	e := &Engine{
		matchers: matchers,
		bound:    DefaultDenialBound,
		policy:   clonePolicy(p),
		deferred: make(map[string]map[string]deferredCall),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
}

// checkRule refuses a rule with no tool, and one with a specifier for
// a tool that has no matcher.
func checkRule(r Rule, matchers map[string]ToolMatcher) error {
	if r.Tool == "" {
		return fmt.Errorf("agentpolicy: rule %q: missing tool name", r.String())
	}
	if r.Spec == "" {
		return nil
	}
	if matchers[r.Tool].Match == nil {
		return fmt.Errorf("%w: %s", ErrNoMatcher, r)
	}
	return nil
}

// checkGrant refuses what checkRule refuses, and a carve-out, which
// grants nothing.
func checkGrant(r Rule, matchers map[string]ToolMatcher) error {
	if err := checkRule(r, matchers); err != nil {
		return err
	}
	if _, carve := r.CarveOut(); carve {
		return fmt.Errorf("agentpolicy: cannot grant a carve-out: %s", r)
	}
	return nil
}

func clonePolicy(p Policy) Policy {
	return Policy{
		Allow:   append([]Rule(nil), p.Allow...),
		Deny:    append([]Rule(nil), p.Deny...),
		Ask:     append([]Rule(nil), p.Ask...),
		Default: p.Default,
		Sources: append([]Source(nil), p.Sources...),
	}
}

// Policy returns a copy of the policy in force: the one built, with
// every grant since applied. A grant appends an allow rule; a grant
// over an ask rule also appends a carve-out beside that rule, or
// removes it, so what a product must persist is all here.
func (e *Engine) Policy() Policy {
	e.mu.Lock()
	defer e.mu.Unlock()
	return clonePolicy(e.policy)
}

// Sources returns the sources the policy was merged from, as
// [Merge] listed them, so the session can name the policy in force.
func (e *Engine) Sources() []Source {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Source(nil), e.policy.Sources...)
}

// BeforeToolCall returns the hook value for agentturn.Config.
func (e *Engine) BeforeToolCall() func(context.Context, agentturn.ToolCallInfo) (*agentturn.ToolDecision, error) {
	return e.Decide
}

// Decide is the verdict for one call. The call is split into its
// subjects by the tool's [Subjects], one subject when it has none, and
// each subject is decided with the fixed precedence: deny, then ask,
// then allow, then the default. The verdicts fold to the most
// restrictive: the call is blocked if any subject is denied, deferred
// if any subject asks, and allowed only when every subject is. A
// splitter that fails blocks the call with its error as the reason.
//
// A call the policy allows is held, deferred with Verdict.Held set,
// when another call of its batch asks, so nothing the model asked for
// in the same turn runs before the user has answered; the loop runs
// the hook for every call of the batch before any executes, so the
// engine sees the ask wherever it sits in the batch. [Engine.Release]
// answers the held calls once the asked ones are answered. A blocked
// call is blocked whatever its batch holds.
//
// The decision names the policy as its decider. The verdict reaches
// the observer before Decide returns, and the same policy and the same
// call in the same batch always give the same verdict.
//
// One engine serves every agent of a product. What it defers is
// remembered under the call's own run, so a decision in a sub-agent's
// run never forgets what the main agent is waiting on.
func (e *Engine) Decide(ctx context.Context, info agentturn.ToolCallInfo) (*agentturn.ToolDecision, error) {
	name, callID := "", ""
	if info.Call != nil {
		name, callID = info.Call.Name, info.Call.CallID
	}
	v := Verdict{RunID: info.RunID, Turn: info.Turn, CallID: callID, Tool: name}

	e.mu.Lock()
	p := e.policy
	e.mu.Unlock()

	v.Action, v.Rule, v.Reason = e.decide(p, name, info.Args)
	d := deferredCall{info: info}
	if v.Action == agentturn.Allow && e.batchAsks(p, info) {
		d.allowed = v.Reason
		v.Action, v.Held, v.Reason = agentturn.Defer, true, "held for approval: "+v.Reason
	}
	if v.Action == agentturn.Defer {
		d.verdict = v
		e.remember(info.RunID, callID, d)
	}
	e.observe(ctx, v)
	return &agentturn.ToolDecision{Action: v.Action, Reason: v.Reason, By: byPolicy}, nil
}

// decide evaluates one call as Decide does, without recording it.
func (e *Engine) decide(p Policy, name string, args json.RawMessage) (agentturn.ToolAction, *Rule, string) {
	subjects, err := e.split(name, args)
	if err != nil {
		return agentturn.Block, nil, name + " call could not be evaluated: " + err.Error()
	}
	return e.fold(p, name, subjects)
}

// batchAsks reports whether a call of info's batch other than info's
// own asks. The batch holds the loop's own pointers, so the call's is
// told by identity.
func (e *Engine) batchAsks(p Policy, info agentturn.ToolCallInfo) bool {
	for _, c := range info.Batch {
		if c == nil || c == info.Call {
			continue
		}
		if a, _, _ := e.decide(p, c.Name, callArgs(c)); a == agentturn.Defer {
			return true
		}
	}
	return false
}

// callArgs returns a call's arguments as the loop hands them to the
// hook: the empty object when the model gave none.
func callArgs(c *openresponses.FunctionCall) json.RawMessage {
	if c.Arguments == "" {
		return json.RawMessage("{}")
	}
	return json.RawMessage(c.Arguments)
}

// split returns the subjects of a call: the splitter's, or the call
// itself. A splitter that returns nothing is an error, since a call
// with no subjects would be allowed by every rule.
func (e *Engine) split(name string, args json.RawMessage) ([]Subject, error) {
	m := e.matchers[name]
	if m.Subjects == nil {
		return []Subject{{Args: args}}, nil
	}
	subjects, err := m.Subjects(args)
	if err != nil {
		return nil, err
	}
	if len(subjects) == 0 {
		return nil, errors.New("splitter returned no subjects")
	}
	return subjects, nil
}

// fold decides every subject and keeps the most restrictive verdict,
// the first of equals.
func (e *Engine) fold(p Policy, name string, subjects []Subject) (agentturn.ToolAction, *Rule, string) {
	var (
		action agentturn.ToolAction
		rule   *Rule
		reason string
	)
	for i, s := range subjects {
		tool := s.Tool
		if tool == "" {
			tool = name
		}
		a, r, why := e.decideSubject(p, tool, s.Args)
		if i == 0 || restrictiveness(a) > restrictiveness(action) {
			action, rule, reason = a, r, why
		}
	}
	return action, rule, reason
}

func restrictiveness(a agentturn.ToolAction) int {
	switch a {
	case agentturn.Block:
		return 2
	case agentturn.Defer:
		return 1
	}
	return 0
}

// decideSubject applies the precedence to one subject.
func (e *Engine) decideSubject(p Policy, tool string, args json.RawMessage) (agentturn.ToolAction, *Rule, string) {
	if r, ok := e.match(p.Deny, tool, args); ok {
		return agentturn.Block, &r, "denied by " + r.String()
	}
	if r, ok := e.match(p.Ask, tool, args); ok {
		return agentturn.Defer, &r, "approval required by " + r.String()
	}
	if r, ok := e.match(p.Allow, tool, args); ok {
		return agentturn.Allow, &r, "allowed by " + r.String()
	}
	action, _ := p.Default.Action()
	switch action {
	case agentturn.Block:
		return action, nil, "no rule allows " + tool + ": denied by default"
	case agentturn.Defer:
		return action, nil, "no rule allows " + tool + ": approval required by default"
	}
	return agentturn.Allow, nil, "allowed by default"
}

// match returns the first rule of list that matches the subject: the
// rule names the tool, is not a carve-out, is bare or its specifier
// matches, and no carve-out from the same source cancels it.
func (e *Engine) match(list []Rule, tool string, args json.RawMessage) (Rule, bool) {
	for _, r := range list {
		if r.Tool != tool {
			continue
		}
		if _, carve := r.CarveOut(); carve {
			continue
		}
		if !r.Bare() && !e.matches(r.Tool, r.Spec, args) {
			continue
		}
		if e.carvedOut(list, r, args) {
			continue
		}
		return r, true
	}
	return Rule{}, false
}

// matches runs the tool's matcher over one specifier.
func (e *Engine) matches(tool, spec string, args json.RawMessage) bool {
	m := e.matchers[tool].Match
	return m != nil && m(spec, args)
}

// carvedOut reports whether a carve-out in list, for the same tool and
// from the same source as r, matches the subject.
func (e *Engine) carvedOut(list []Rule, r Rule, args json.RawMessage) bool {
	for _, c := range list {
		if c.Tool != r.Tool || c.Source != r.Source {
			continue
		}
		if pattern, ok := c.CarveOut(); ok && e.matches(c.Tool, pattern, args) {
			return true
		}
	}
	return false
}

func (e *Engine) observe(ctx context.Context, v Verdict) {
	if e.observer != nil {
		e.observer(ctx, v)
	}
}

// Grant adds an allow rule for the rest of the process, as "always
// allow" does in an approval prompt that the default raised. The grant
// is journaled through the observer with a Verdict whose Action is
// Allow and whose Rule is the new rule. A rule with a specifier and no
// matcher is refused with [ErrNoMatcher]. A grant never beats a deny
// rule, and never outranks an ask rule; use [Engine.GrantOver] to
// answer a prompt an ask rule raised. A persisted grant is the
// product's: it writes the rule into its settings and rebuilds the
// engine at the next start.
func (e *Engine) Grant(ctx context.Context, r Rule) error {
	if err := checkGrant(r, e.matchers); err != nil {
		return err
	}
	e.mu.Lock()
	e.policy.Allow = append(e.policy.Allow, r)
	e.mu.Unlock()
	e.observe(ctx, Verdict{Tool: r.Tool, Action: agentturn.Allow, Rule: &r, Reason: "granted " + r.String()})
	return nil
}

// GrantOver answers the prompt behind v with "always allow". It adds r
// as an allow rule and, when an ask rule produced v, keeps that rule
// from firing for the calls r matches, since precedence alone would
// let it ask again: a grant with a specifier appends the carve-out
// "<tool>(!<spec>)" beside the ask rule, under the ask rule's own
// source, and a bare grant removes the ask rule. Both changes are in
// [Engine.Policy], so a product persists a grant by writing what the
// policy now holds. The grant is journaled as [Engine.Grant] journals
// one.
//
// It reports why it cannot, so a front drops the "always" option and
// offers a one-time approval instead: v did not defer the call, a deny
// rule produced it, the ask rule comes from a source that outranks r's,
// the ask rule is no longer in the policy, r does not name the ask
// rule's tool, r is a carve-out, or r has a specifier and no matcher.
// The reason is stable text a front can show.
func (e *Engine) GrantOver(ctx context.Context, v Verdict, r Rule) (granted bool, reason string) {
	if err := checkGrant(r, e.matchers); err != nil {
		return false, err.Error()
	}
	if v.Action != agentturn.Defer {
		if v.Action == agentturn.Block && v.Rule != nil {
			return false, "cannot grant over a deny rule: " + v.Rule.String()
		}
		return false, "nothing to grant over: the call was not deferred"
	}
	if v.Held {
		return false, "nothing to grant over: the call was held for another call's approval"
	}
	if v.Rule == nil {
		e.mu.Lock()
		e.policy.Allow = append(e.policy.Allow, r)
		e.mu.Unlock()
		reason = "granted " + r.String()
		e.observe(ctx, Verdict{Tool: r.Tool, Action: agentturn.Allow, Rule: &r, Reason: reason})
		return true, reason
	}
	ask := *v.Rule
	if r.Tool != ask.Tool {
		return false, "grant " + r.String() + " does not name the tool of " + ask.String()
	}
	if r.Source.Rank < ask.Source.Rank {
		from := ""
		if ask.Source.Name != "" {
			from = " from " + ask.Source.Name
		}
		return false, ask.String() + from + " outranks the grant"
	}
	e.mu.Lock()
	at := slices.Index(e.policy.Ask, ask)
	if at < 0 {
		e.mu.Unlock()
		return false, ask.String() + " is no longer in the ask list"
	}
	if r.Bare() {
		e.policy.Ask = slices.Delete(slices.Clone(e.policy.Ask), at, at+1)
	} else {
		e.policy.Ask = append(e.policy.Ask, Rule{Tool: ask.Tool, Spec: "!" + r.Spec, Source: ask.Source})
	}
	e.policy.Allow = append(e.policy.Allow, r)
	e.mu.Unlock()
	reason = "granted " + r.String() + " over " + ask.String()
	e.observe(ctx, Verdict{Tool: r.Tool, Action: agentturn.Allow, Rule: &r, Reason: reason})
	return true, reason
}
