package agentpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
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
	// ErrToolGlob is returned for a rule whose tool name is a glob that
	// the engine will not honour: one in the allow list, where the
	// reference refuses it too, and one with a specifier, which names
	// no matcher. The error names the rule.
	ErrToolGlob = errors.New("agentpolicy: tool-name glob")
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
	// Subject is the Text of the subject whose verdict the fold kept,
	// the half of a compound command that raised the question, as the
	// tool's Subjects splitter wrote it: a prompt says which part of a
	// command line it is asking about with it, and the reason names
	// the rule, the two read together. It is empty for a call no
	// splitter split, since the splitter is what writes the text, and
	// for a splitter that writes none.
	Subject string
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

// WithAliases names the tools a rule name governs, for the rules a
// product does not write itself: a settings file copied out of the
// reference's documentation, and a skill's allowed-tools, are spelled
// with the reference's tool names, "Bash", "Read", "Edit", and a
// product's tools are named whatever the product named them. The
// reference also has one rule name govern several tools, Read reaching
// its search tools as well as its file one, which nothing else here
// can express.
//
//	agentpolicy.WithAliases(map[string][]string{
//		"Bash": {"bash"},
//		"Read": {"read", "grep", "glob"},
//		"Edit": {"edit", "write"},
//	})
//
// [Build] expands a rule whose name has an entry into one rule per
// tool it names, keeping the specifier and the source, so the
// expansion happens once, where the matchers already are, and
// [Engine.Policy] reports the rules as they are evaluated. A name with
// no entry is a tool's own name and still fails closed: a rule with a
// specifier for a tool with no matcher does not build. Expansion is
// one level: a tool an alias names is not itself expanded. Nothing
// folds case, and an entry that names no tool does not build.
func WithAliases(aliases map[string][]string) Option {
	return func(e *Engine) { e.aliases = aliases }
}

// Engine is the runtime form of a [Policy]: the policy in force, the
// matchers it is evaluated with, the grants made since it was built
// and the calls it has deferred. It is safe for concurrent use.
type Engine struct {
	matchers map[string]ToolMatcher
	// aliases names the tools a rule name governs. It is set at Build
	// and never written after, so it is read without the lock.
	aliases  map[string][]string
	observer func(context.Context, Verdict)
	bound    DenialBound

	mu     sync.Mutex
	policy Policy
	// grants are the scoped rule sets in force beside the policy, in
	// activation order, one per source; withheld holds the allow rules
	// of the untrusted ones, which apply to nothing.
	grants   []RuleSet
	withheld map[string][]Rule
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
// runtime form. It fails with [ErrNoDefault] when the default is unset,
// with [ErrNoMatcher] when a rule has a specifier and its tool has no
// matcher, and with [ErrToolGlob] when a rule's tool name is a glob
// the engine will not honour, so a rule that could never match is
// refused here rather than ignored at the first call. The lists are
// copied; the caller's slices are not retained.
func Build(p Policy, matchers map[string]ToolMatcher, opts ...Option) (*Engine, error) {
	if _, ok := p.Default.Action(); !ok {
		return nil, ErrNoDefault
	}
	e := &Engine{
		matchers: matchers,
		bound:    DefaultDenialBound,
		deferred: make(map[string]map[string]deferredCall),
		withheld: make(map[string][]Rule),
	}
	for _, opt := range opts {
		opt(e)
	}
	if err := checkAliases(e.aliases); err != nil {
		return nil, err
	}
	p = e.expandPolicy(p)
	if err := checkPolicy(p, matchers); err != nil {
		return nil, err
	}
	e.policy = clonePolicy(p)
	return e, nil
}

// checkAliases refuses an alias table that would drop a rule or name a
// tool no call can have.
func checkAliases(aliases map[string][]string) error {
	for name, tools := range aliases {
		switch {
		case name == "":
			return fmt.Errorf("agentpolicy: alias: an entry has no rule name")
		case strings.Contains(name, "*"):
			return fmt.Errorf("agentpolicy: alias %q: a rule name with a glob names no tool", name)
		case len(tools) == 0:
			return fmt.Errorf("agentpolicy: alias %q: names no tool", name)
		}
		for _, tool := range tools {
			if tool == "" || strings.Contains(tool, "*") {
				return fmt.Errorf("agentpolicy: alias %q: %q is not a tool name", name, tool)
			}
		}
	}
	return nil
}

// expand returns the rules r stands for: one per tool its name is an
// alias for, keeping the specifier and the source, or r itself.
func (e *Engine) expand(r Rule) []Rule {
	tools, ok := e.aliases[r.Tool]
	if !ok {
		return []Rule{r}
	}
	out := make([]Rule, len(tools))
	for i, tool := range tools {
		out[i] = Rule{Tool: tool, Spec: r.Spec, Source: r.Source}
	}
	return out
}

// expandList expands every rule of a list, in order.
func (e *Engine) expandList(list []Rule) []Rule {
	if len(e.aliases) == 0 || len(list) == 0 {
		return list
	}
	out := make([]Rule, 0, len(list))
	for _, r := range list {
		out = append(out, e.expand(r)...)
	}
	return out
}

// expandPolicy expands every list of a policy.
func (e *Engine) expandPolicy(p Policy) Policy {
	if len(e.aliases) == 0 {
		return p
	}
	p.Allow, p.Deny, p.Ask = e.expandList(p.Allow), e.expandList(p.Deny), e.expandList(p.Ask)
	return p
}

// checkPolicy refuses every rule of a policy that could never fire.
func checkPolicy(p Policy, matchers map[string]ToolMatcher) error {
	for _, list := range []struct {
		name  string
		rules []Rule
	}{{"deny", p.Deny}, {"ask", p.Ask}, {"allow", p.Allow}} {
		for _, r := range list.rules {
			if err := checkRule(r, matchers, list.name); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkRule refuses a rule with no tool, one with a specifier for a
// tool that has no matcher, and a tool-name glob the engine will not
// honour: one in the allow list, and one with a specifier, since the
// glob names no matcher to read the specifier with. A rule that cannot
// work fails where every other unusable rule fails, at Build, rather
// than building and never firing.
func checkRule(r Rule, matchers map[string]ToolMatcher, list string) error {
	if r.Tool == "" {
		return fmt.Errorf("agentpolicy: rule %q: missing tool name", r.String())
	}
	if r.Glob() {
		switch {
		case list == "allow":
			return fmt.Errorf("%w: %s is not honoured in the allow list", ErrToolGlob, r)
		case r.Spec != "":
			return fmt.Errorf("%w: %s takes no specifier", ErrToolGlob, r)
		}
		return nil
	}
	if r.Spec == "" {
		return nil
	}
	if matchers[r.Tool].Match == nil {
		return fmt.Errorf("%w: %s%s", ErrNoMatcher, r, nearMiss(r.Tool, matchers))
	}
	return nil
}

// nearMiss names a matcher whose tool differs from the rule's only in
// case, since a rule copied out of the reference's documentation is
// spelled with the reference's tool names.
func nearMiss(tool string, matchers map[string]ToolMatcher) string {
	near := ""
	for name := range matchers {
		if name == tool || !strings.EqualFold(name, tool) {
			continue
		}
		if near == "" || name < near {
			near = name
		}
	}
	if near == "" {
		return ""
	}
	return "; did you mean " + near + "?"
}

// checkGrant refuses what checkRule refuses of an allow rule, and a
// carve-out, which grants nothing.
func checkGrant(r Rule, matchers map[string]ToolMatcher) error {
	if err := checkRule(r, matchers, "allow"); err != nil {
		return err
	}
	if _, carve := r.CarveOut(); carve {
		return fmt.Errorf("agentpolicy: cannot grant a carve-out: %s", r)
	}
	return nil
}

func clonePolicy(p Policy) Policy {
	return Policy{
		Allow:    append([]Rule(nil), p.Allow...),
		Deny:     append([]Rule(nil), p.Deny...),
		Ask:      append([]Rule(nil), p.Ask...),
		Default:  p.Default,
		Sources:  append([]Source(nil), p.Sources...),
		Withheld: append([]Rule(nil), p.Withheld...),
	}
}

// Policy returns a copy of the policy to persist: the one built, with
// every grant [Engine.Grant] and [Engine.GrantOver] made applied. A
// grant appends an allow rule; a grant over an ask rule also appends a
// carve-out beside that rule, or removes it, so what a product writes
// back into its settings is all here.
//
// The scoped rule sets [Engine.GrantSet] activated are not here, and
// [Engine.Grants] reports those: they last as long as the source that
// carries them, a skill in use rather than a settings file, and an
// engine rebuilt from this policy decides as this one does once they
// are revoked.
func (e *Engine) Policy() Policy {
	e.mu.Lock()
	defer e.mu.Unlock()
	return clonePolicy(e.policy)
}

// SetPolicy replaces the policy the engine decides with, validated as
// [Build] validates one and expanded through the same aliases. The
// matchers are not rebuilt, since they are the expensive half and they
// do not change, and the hook values the loop holds keep working, so a
// product re-derives its rules without replacing its config, which
// agentturn refuses while a run is active.
//
// It is what a tool list that changes needs. An engine is built from a
// snapshot of that list, so a tool an MCP server announces mid-session
// is a tool the policy never heard of: an Ask() default defers every
// call to it and an unattended run parks on an approval nobody will
// give. A product that cannot re-derive a policy writes rules that
// cover the tools it has not seen instead: a bare name, or a tool-name
// glob in the deny or ask list, "mcp__*", governs a tool that appears
// later, where an allow rule needs the tool's own name.
//
// The policy in force changes for the next call decided, not for the
// calls already decided: a run that ended on an ask is answered under
// the rules that deferred it, and a batch being decided as the policy
// changes can see both, so a product that must not straddle one
// replaces the policy between turns. The scoped grants
// [Engine.GrantSet] activated, the deferred calls and the review log
// are untouched. The replacement is not journalled; a product records
// it where it derives the policy.
func (e *Engine) SetPolicy(p Policy) error {
	if _, ok := p.Default.Action(); !ok {
		return ErrNoDefault
	}
	p = e.expandPolicy(p)
	if err := checkPolicy(p, e.matchers); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policy = clonePolicy(p)
	return nil
}

// PolicyOf returns the rules of one source, as a [RuleSet] carrying
// that source, which is what a product writes back into that source's
// settings file. The whole policy is not: it holds the rules of every
// file that was merged, so a product that persisted it would copy the
// managed and project files into its own local settings and freeze a
// snapshot of somebody else's.
//
// The rules are the ones in force, so a grant this source made is
// here, carve-out and all, and a rule another source contributed is
// not. A source with no rules gives an empty set whose Source is
// named from [Engine.Sources] when the merge listed it. The scoped
// sets [Engine.GrantSet] activated are not here: they are not a
// product's to persist.
func (e *Engine) PolicyOf(source string) RuleSet {
	e.mu.Lock()
	defer e.mu.Unlock()
	set := RuleSet{Source: Source{Name: source}}
	for _, s := range e.policy.Sources {
		if s.Name == source {
			set.Source = s
			break
		}
	}
	for _, from := range []struct {
		rules []Rule
		into  *[]Rule
	}{{e.policy.Allow, &set.Allow}, {e.policy.Deny, &set.Deny}, {e.policy.Ask, &set.Ask}} {
		for _, r := range from.rules {
			if r.Source.Name == source {
				*from.into = append(*from.into, r)
			}
		}
	}
	return set
}

// Sources returns the sources the policy was merged from, as
// [Merge] listed them, so the session can name the policy in force.
func (e *Engine) Sources() []Source {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Source(nil), e.policy.Sources...)
}

// Withheld returns the allow rules withheld from the untrusted
// sources: those the merge withheld, and those of the rule sets
// [Engine.GrantSet] activated from a source the user has not trusted.
// The engine never consults them: they are what a front shows when it
// asks whether to trust a folder or a skill, so the user reads what
// trusting it would allow rather than agreeing blind. Trusting a
// source means merging or granting again with Source.Trusted set.
func (e *Engine) Withheld() []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := append([]Rule(nil), e.policy.Withheld...)
	for _, g := range e.grants {
		out = append(out, e.withheld[g.Source.Name]...)
	}
	return out
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

	a := e.active()

	v.Action, v.Rule, v.Reason, v.Subject = e.decide(a, name, info.Args)
	d := deferredCall{info: info}
	if v.Action == agentturn.Allow && e.batchAsks(a, info) {
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
func (e *Engine) decide(a active, name string, args json.RawMessage) (agentturn.ToolAction, *Rule, string, string) {
	subjects, err := e.split(name, args)
	if err != nil {
		return agentturn.Block, nil, name + " call could not be evaluated: " + err.Error(), ""
	}
	return e.fold(a, name, subjects)
}

// batchAsks reports whether a call of info's batch other than info's
// own asks. The batch holds the loop's own pointers, so the call's is
// told by identity.
func (e *Engine) batchAsks(a active, info agentturn.ToolCallInfo) bool {
	for _, c := range info.Batch {
		if c == nil || c == info.Call {
			continue
		}
		if action, _, _, _ := e.decide(a, c.Name, callArgs(c)); action == agentturn.Defer {
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
func (e *Engine) fold(a active, name string, subjects []Subject) (agentturn.ToolAction, *Rule, string, string) {
	var (
		action  agentturn.ToolAction
		rule    *Rule
		reason  string
		subject string
	)
	for i, s := range subjects {
		tool := s.Tool
		if tool == "" {
			tool = name
		}
		act, r, why := e.decideSubject(a, tool, s.Args)
		if i == 0 || restrictiveness(act) > restrictiveness(action) {
			action, rule, reason, subject = act, r, why, s.Text
		}
	}
	return action, rule, reason, subject
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
func (e *Engine) decideSubject(a active, tool string, args json.RawMessage) (agentturn.ToolAction, *Rule, string) {
	p := a.policy
	if r, ok := e.match(p.Deny, tool, args); ok {
		return agentturn.Block, &r, "denied by " + r.String()
	}
	if r, ok := e.matchAsk(a, tool, args); ok {
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
// rule names the tool, itself or through a glob, is not a carve-out,
// is bare or its specifier matches, and no carve-out from the same
// source cancels it.
func (e *Engine) match(list []Rule, tool string, args json.RawMessage) (Rule, bool) {
	for _, r := range list {
		if e.fires(list, r, tool, args) {
			return r, true
		}
	}
	return Rule{}, false
}

// fires reports whether one rule of a list matches the subject.
func (e *Engine) fires(list []Rule, r Rule, tool string, args json.RawMessage) bool {
	if !r.MatchesTool(tool) {
		return false
	}
	if _, carve := r.CarveOut(); carve {
		return false
	}
	if !r.Bare() && !e.matches(r.Tool, r.Spec, args) {
		return false
	}
	return !e.carvedOut(list, r, args)
}

// matchAsk returns the first ask rule that matches the subject and
// that no active grant shadows. A grant's allow rule shadows an ask
// rule it covers, since precedence alone would let the rule ask again
// for the very calls the grant was made for; the allow list then
// carries the grant's own rule, so the subject is decided by it.
func (e *Engine) matchAsk(a active, tool string, args json.RawMessage) (Rule, bool) {
	for _, r := range a.policy.Ask {
		if !e.fires(a.policy.Ask, r, tool, args) {
			continue
		}
		if _, shadowed := e.shadowedBy(a, r, tool, args); shadowed {
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
// from a source that does not rank below r's, matches the subject.
// Rank rather than identity is the test, so a grant's carve-out lands
// in the file the grant came from and still cancels the rule it
// answers, while a repository's read(!.env.example) cannot open a
// read(.env:*) an administrator denied from a higher-ranked file.
func (e *Engine) carvedOut(list []Rule, r Rule, args json.RawMessage) bool {
	for _, c := range list {
		if c.Tool != r.Tool || c.Source.Rank < r.Source.Rank {
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
// matcher is refused with [ErrNoMatcher]. A rule whose name is an
// alias is expanded as [Build] expands one, so the grant adds a rule
// per tool the name governs and journals each. A grant never beats a
// deny rule, and never outranks an ask rule; use [Engine.GrantOver] to
// answer a prompt an ask rule raised. A persisted grant is the
// product's: it writes the rule into its settings and rebuilds the
// engine at the next start.
func (e *Engine) Grant(ctx context.Context, r Rule) error {
	granted := e.expand(r)
	for _, g := range granted {
		if err := checkGrant(g, e.matchers); err != nil {
			return err
		}
	}
	e.mu.Lock()
	e.policy.Allow = append(e.policy.Allow, granted...)
	e.mu.Unlock()
	for i := range granted {
		g := granted[i]
		e.observe(ctx, Verdict{Tool: g.Tool, Action: agentturn.Allow, Rule: &g, Reason: "granted " + g.String()})
	}
	return nil
}

// GrantOver answers the prompt behind v with "always allow". It adds r
// as an allow rule and, when an ask rule produced v, keeps that rule
// from firing for the calls r matches, since precedence alone would
// let it ask again: a grant with a specifier appends the carve-out
// "<tool>(!<spec>)" beside the ask rule, under the grant's own source,
// and a bare grant removes the ask rule. The carve-out is the grant's
// because the grant is, so a product that persists its own source's
// rules writes a personal "always allow" into its own settings and not
// into the file the team shares; a carve-out cancels a rule of any
// source that does not outrank it, which is what makes it reach the
// rule it answers. [Engine.PolicyOf] is what a product persists. The
// grant is journaled as [Engine.Grant] journals one.
//
// It reports why it cannot, so a front drops the "always" option and
// offers a one-time approval instead: v did not defer the call, a deny
// rule produced it, the ask rule comes from a source that outranks r's,
// the ask rule is no longer in the policy, r does not name the ask
// rule's tool, r is a carve-out, or r has a specifier and no matcher.
// The reason is stable text a front can show.
func (e *Engine) GrantOver(ctx context.Context, v Verdict, r Rule) (granted bool, reason string) {
	rules := e.expand(r)
	for _, g := range rules {
		if err := checkGrant(g, e.matchers); err != nil {
			return false, err.Error()
		}
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
		e.policy.Allow = append(e.policy.Allow, rules...)
		e.mu.Unlock()
		reason = "granted " + r.String()
		for i := range rules {
			g := rules[i]
			e.observe(ctx, Verdict{Tool: g.Tool, Action: agentturn.Allow, Rule: &g, Reason: "granted " + g.String()})
		}
		return true, reason
	}
	ask := *v.Rule
	// The rule that answers the ask is the expansion naming its tool;
	// the others are granted beside it.
	over := -1
	for i, g := range rules {
		if g.Tool == ask.Tool {
			over = i
			break
		}
	}
	if over < 0 {
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
	if g := rules[over]; g.Bare() {
		e.policy.Ask = slices.Delete(slices.Clone(e.policy.Ask), at, at+1)
	} else {
		e.policy.Ask = append(e.policy.Ask, Rule{Tool: ask.Tool, Spec: "!" + g.Spec, Source: g.Source})
	}
	e.policy.Allow = append(e.policy.Allow, rules...)
	e.mu.Unlock()
	reason = "granted " + r.String() + " over " + ask.String()
	for i := range rules {
		g := rules[i]
		e.observe(ctx, Verdict{Tool: g.Tool, Action: agentturn.Allow, Rule: &g, Reason: reason})
	}
	return true, reason
}
