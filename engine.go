package agentpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/ChristopherDavenport/agenttool"
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
	// Rule is the rule that fired, or the rule granted. On a call
	// allowed because it runs confined it is the ask rule the
	// confinement skipped. It is nil when the default applied and for a
	// guard's or a reviewer's verdict.
	Rule *Rule
	// Reason is the stable text behind the action, the same text the
	// model reads when the action blocks a call.
	Reason string
	// By names who decided, in the session format's words: [ByPolicy]
	// for a rule the engine evaluated on its own, [ByAgent] for a
	// reviewer that is a model, [ByHuman] for a person a front asked.
	// It is what a product writes as the decision's decider when it
	// records the verdict, and it is empty for a guard's verdict,
	// whose decider is the guard that Guard names.
	By string
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
	// Confined names what confines the call, as the tool's
	// agenttool.Confined reported it, "landlock+seccomp",
	// "container:agent-sandbox", when the tool says the call runs
	// confined, whatever the action: a prompt shows it beside the
	// question, and on an Allow it says why nobody was asked. It is
	// empty for a call that is not confined and for a tool that says it
	// is and names nothing.
	Confined string
}

// Option configures an [Engine].
type Option func(*Engine)

// WithObserver registers fn to receive every verdict the engine
// produces: each decision, each grant and each reviewer answer, exactly
// once, outside the engine's lock. A hook cannot append to the
// transcript, so this is how a verdict reaches the session.
//
// Each WithObserver adds an observer rather than replacing one, and
// the observers are called in the order they were given, each with
// every verdict. A kit that records verdicts and a product that passes
// an observer of its own therefore both see everything, whichever
// option comes last. A nil fn adds nothing.
func WithObserver(fn func(context.Context, Verdict)) Option {
	return func(e *Engine) {
		if fn != nil {
			e.observers = append(e.observers, fn)
		}
	}
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
// tool it names, keeping the specifier, the source and the note, so the
// expansion happens once, where the matchers already are, and
// [Engine.Policy] reports the rules as they are evaluated. A name with
// no entry is a tool's own name and still fails closed: a rule with a
// specifier for a tool with no matcher does not build. Expansion is
// one level: a tool an alias names is not itself expanded. Nothing
// folds case, and an entry that names no tool does not build.
func WithAliases(aliases map[string][]string) Option {
	return func(e *Engine) { e.aliases = aliases }
}

// WithConfinement replaces how the engine reads whether a call runs
// confined, which is agenttool.ConfinedBy over the call's tool and
// arguments by default. A call that runs confined is not asked about
// by an ask rule with no specifier that names the called tool, as both
// references skip a bare Bash ask for a sandboxed command: it is
// allowed, with a reason naming what confined it and the rule it
// skipped. A deny rule applies whatever the confinement, and so does
// an ask rule with a specifier, which is how a policy still asks about
// a call that leaves the sandbox, bash(sandbox:escalated) for a tool
// whose escape hatch is an argument. The default applies as it does to
// any call no rule names: a confined call to a tool no rule names
// still asks under an Ask() default.
//
// A tool that does not implement agenttool.Confined reads as
// unconfined, and so does a call whose tool the loop could not
// resolve, since the safe mistake is to ask. The annotations are never
// read this way: a server's hints are not the tool's own claim. nil
// turns the reading off, so every ask rule asks.
func WithConfinement(fn func(ctx context.Context, tool agenttool.Tool, args json.RawMessage) (bool, string)) Option {
	return func(e *Engine) { e.confine = fn }
}

// WithTools names the tools the engine reads confinement from for the
// other calls of a batch. The hook is handed its own call's tool, not
// its siblings', and whether a call is held depends on whether a
// sibling asks, which depends on whether the sibling runs confined.
// agenttool.Set's Lookup is the usual value.
//
// Without it the engine knows a sibling's tool once the loop has
// handed it that sibling's own call, which it does in the model's
// order: a sibling decided earlier in the batch is read as it was
// decided, and one later in the batch reads as unconfined, so a call
// before a confined command that a bare ask rule names is held for it,
// and [Engine.Release] with no answers releases it.
//
// The lookup must resolve a name to the tool the loop runs for it; a
// sibling read as confined through a tool the loop does not run is
// read as not asking until its own call is decided. [Engine.Answers]
// reads it too, for the tool of a cut-off call found in a seeded
// transcript, which the loop does not name, to ask whether the call
// may run again.
//
// The lookup is given the tool's name alone, so one engine shared by
// runs whose tool lists differ reads one list for all of them;
// [WithToolsFor] gives it the decision's context as well.
func WithTools(lookup func(name string) (agenttool.Tool, bool)) Option {
	return func(e *Engine) {
		if lookup == nil {
			e.lookup = nil
			return
		}
		e.lookup = func(_ context.Context, name string) (agenttool.Tool, bool) { return lookup(name) }
	}
}

// WithToolsFor is [WithTools] with the context of the decision, so a
// lookup answers for the run whose batch is decided: the context is
// the hook's for a sibling, which carries the run's ID
// (agentturn.RunIDFromContext), and [Engine.Answers]' for a cut-off
// call, carrying the ended run's ID when the caller's context carries
// none. An engine shared by concurrent runs whose tool lists differ
// answers per run through it; a lookup that ignores the context is
// WithTools.
func WithToolsFor(lookup func(ctx context.Context, name string) (agenttool.Tool, bool)) Option {
	return func(e *Engine) { e.lookup = lookup }
}

// WithHooks folds these hooks' decisions into the engine's, before the
// batch hold, so a hook's ask holds the rest of the batch as a rule's
// does, and a hook's block leaves nothing held for it. A product's own
// before-tool-call hooks belong here rather than chained after the
// engine with agentturn.ChainBeforeToolCall: a chained hook is outside
// the hold, so a call it defers lets its siblings run before anyone
// answers, and a call it blocks strands the siblings the engine held
// for it.
//
// The fold is agentturn.ChainBeforeToolCall's, with the engine's
// decision first: the strictest action wins, Block over Defer over
// Allow, a block ends the fold, and a hook that makes the action
// stricter brings its reason and its decider, By, with ByPolicy for an
// empty one; the verdict then has no Rule and no Subject. The first
// note stands, Terminate is set when any hook sets it, and arguments a
// hook rewrites are passed to the hooks after it and are what the call
// runs with, a held call's included when [Engine.Release] releases it.
// Rewritten arguments are decided again, their confinement read from
// them: the stricter of the two actions stands, a verdict the policy
// still owns takes the rewrite's rule and reason, and
// Verdict.Confined is the rewrite's, so a hook that takes a call out
// of its sandbox is asked about and the verdict does not say it ran
// confined.
// The first error fails the call's decision, and the turn with it.
//
// The engine reads a call's siblings to decide whether to hold it, so
// a hook is called for a sibling of the call being decided, before the
// loop hands the hook that sibling's own call, with the sibling's
// batch position and the tool [WithTools] names. A hook must therefore
// decide a call the same way however often it is asked, and one that
// fails for a sibling reads as asking, so the call is held, and is
// asked again for that sibling by the next call of the batch. Each
// WithHooks adds its hooks after those already given; a nil hook adds
// nothing.
func WithHooks(fns ...func(context.Context, agentturn.ToolCallInfo) (*agentturn.ToolDecision, error)) Option {
	return func(e *Engine) {
		for _, fn := range fns {
			if fn != nil {
				e.hooks = append(e.hooks, fn)
			}
		}
	}
}

// Engine is the runtime form of a [Policy]: the policy in force, the
// matchers it is evaluated with, the grants made since it was built
// and the calls it has deferred. It is safe for concurrent use.
type Engine struct {
	matchers map[string]ToolMatcher
	// aliases names the tools a rule name governs. It is set at Build
	// and never written after, so it is read without the lock.
	aliases map[string][]string
	// observers are called in order with every verdict. They are set
	// at Build and never written after, so they are read without the
	// lock.
	observers []func(context.Context, Verdict)
	bound     DenialBound
	confine   func(context.Context, agenttool.Tool, json.RawMessage) (bool, string)
	lookup    func(context.Context, string) (agenttool.Tool, bool)
	// hooks are folded into every decision after the policy's, and
	// neverStarted reads the record for a cut-off call. Both are set
	// at Build and never written after.
	hooks        []func(context.Context, agentturn.ToolCallInfo) (*agentturn.ToolDecision, error)
	neverStarted func(context.Context, string, string) bool

	mu     sync.Mutex
	policy Policy
	// grants are the rule sets in force beside the policy, in
	// activation order, one per grant scope and source; withheld holds
	// the allow rules of the untrusted ones, which apply to nothing,
	// under the same key. gen counts every change to the rules, so the
	// batch cache is never read across one.
	grants   []grant
	withheld map[grantKey][]Rule
	gen      uint64
	// batch is the last batch's verdicts, so the product's splitter
	// runs once per call of a batch rather than once per pair.
	batch batchCache
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
	// verdict that releases it; args and note are what the hooks
	// rewrote its arguments to and told the model, for its release.
	allowed string
	args    json.RawMessage
	note    string
}

// Who a decision names as its decider, in the session format's words.
const (
	// ByPolicy is a rule the harness evaluated on its own, which is
	// every decision the engine makes.
	ByPolicy = "policy"
	// ByAgent is another model: a [Reviewer] backed by one, as the
	// classify package's is.
	ByAgent = "agent"
	// ByHuman is a person the front asked, which is what a [Reviewer]
	// that prompts one sets on its [Review].
	ByHuman = "human"
)

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
		confine:  agenttool.ConfinedBy,
		deferred: make(map[string]map[string]deferredCall),
		withheld: make(map[grantKey][]Rule),
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
// alias for, keeping the specifier, the source and the note, or r
// itself.
func (e *Engine) expand(r Rule) []Rule {
	tools, ok := e.aliases[r.Tool]
	if !ok {
		return []Rule{r}
	}
	out := make([]Rule, len(tools))
	for i, tool := range tools {
		out[i] = Rule{Tool: tool, Spec: r.Spec, Source: r.Source, Note: r.Note}
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
	e.gen++
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
// [Engine.GrantSet] activated from a source the user has not trusted,
// under every grant scope, in the order [Engine.Grants] lists the
// sets. The engine never consults them: they are what a front shows
// when it asks whether to trust a folder or a skill, so the user reads
// what trusting it would allow rather than agreeing blind. Trusting a
// source means merging or granting again with Source.Trusted set.
func (e *Engine) Withheld() []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := append([]Rule(nil), e.policy.Withheld...)
	for _, g := range e.ordered() {
		out = append(out, e.withheld[g.key()]...)
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
// constraint subject, Subject.Constrain, is held to its tool's deny
// and ask rules alone and can only make the call stricter. A
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
// A call the tool says runs confined is not asked about by a bare ask
// rule naming its tool; [WithConfinement] says how that is read.
//
// The hold covers the hooks given with [WithHooks], whose decisions
// are folded into the policy's before it. A hook chained after Decide
// with agentturn.ChainBeforeToolCall is outside it: a call such a hook
// defers does not hold its siblings, and a call it blocks leaves the
// siblings Decide held waiting on a question nobody is asked.
//
// The decision names the policy as its decider, or the hook that made
// it stricter. The verdict reaches
// the observer before Decide returns, and the same policy and the same
// call in the same batch always give the same verdict.
//
// A nested call, one a tool made with agentturn.Invoke, has a Parent
// on its info. Its deferral is reported as a verdict, but nothing is
// remembered for it: the loop settles it inline, with the elicitor on
// the invoking tool's context or with a refusal, and it never ends the
// run pending, so no [Engine.Answers] or [Engine.Release] would
// forget it and [Engine.Deferred] would list it for as long as the
// run lives.
//
// One engine serves every agent of a product. What it defers is
// remembered under the call's own run, so a decision in a sub-agent's
// run never forgets what the main agent is waiting on. The rule sets
// consulted are the policy's, the unscoped sets [Engine.GrantSet]
// activated, and those of the grant scope ctx carries, see
// [ContextWithGrantScope], so a skill one conversation opened does not
// decide another's calls.
func (e *Engine) Decide(ctx context.Context, info agentturn.ToolCallInfo) (*agentturn.ToolDecision, error) {
	name, callID := "", ""
	if info.Call != nil {
		name, callID = info.Call.Name, info.Call.CallID
	}
	v := Verdict{RunID: info.RunID, Turn: info.Turn, CallID: callID, Tool: name, By: ByPolicy}

	a := e.active(ctx)

	out, err := e.judge(ctx, a, info, &v)
	if err != nil {
		return nil, err
	}
	d := deferredCall{info: info, args: out.Args, note: out.Note}
	if out.Args != nil {
		// The verdict is about the rewrite, so a reviewer is shown it.
		d.info.Args = out.Args
	}
	if e.batchAsks(ctx, a, info, v.Action) {
		d.allowed = v.Reason
		v.Action, v.Held, v.Reason = agentturn.Defer, true, "held for approval: "+v.Reason
	}
	if v.Action == agentturn.Defer && info.Parent == "" {
		d.verdict = v
		e.remember(info.RunID, callID, d)
	}
	e.observe(ctx, v)
	// Held and Subject travel on the decision, so a front that has only
	// the run's end tells a held call from the one asked about, and says
	// which part of the call a question is about, without the engine.
	out.Action, out.Reason, out.By, out.Held, out.Subject = v.Action, v.Reason, v.By, v.Held, v.Subject
	return &out, nil
}

// Would reports what [Engine.Decide] would decide for the call on its
// own, as a verdict, without deciding it: the policy of the moment and
// the grant sets ctx's scope consults, the call's confinement, and the
// [WithHooks] fold, but no batch hold, since the call's siblings are
// not read, and nothing remembered, so no deferral waits on an answer
// and nothing reaches the observer. It is the question a front asks to
// show which rule will match a call before the call is made, and a
// host asks to tell a call the policy allows on its own from one only
// a grant allowed, without reimplementing the precedence over
// [Engine.Policy] and [Engine.Grants]. The hooks are called as they
// are for a sibling, so a hook must decide a call the same way however
// often it is asked; a hook's error is returned as Decide returns it.
//
// The verdict is the one Decide would report before the hold, down to
// its rule, reason, subject and confinement; its Held is never set.
// What the hooks add to a decision besides its action, a rewrite of
// the arguments, a note and Terminate, is not returned, though a
// rewrite's rule, reason and confinement are the verdict's.
// Deciding the call afterwards may differ when the rules changed in
// between, or when another call of its batch asks.
func (e *Engine) Would(ctx context.Context, info agentturn.ToolCallInfo) (Verdict, error) {
	name, callID := "", ""
	if info.Call != nil {
		name, callID = info.Call.Name, info.Call.CallID
	}
	v := Verdict{RunID: info.RunID, Turn: info.Turn, CallID: callID, Tool: name, By: ByPolicy}
	if _, err := e.judge(ctx, e.active(ctx), info, &v); err != nil {
		return Verdict{}, err
	}
	return v, nil
}

// judge decides info's call as Decide does before the hold: the
// policy on its arguments, read with its tool's confinement, and then
// the hooks folded in. v carries the call's identity in and the
// verdict out.
func (e *Engine) judge(ctx context.Context, a active, info agentturn.ToolCallInfo, v *Verdict) (agentturn.ToolDecision, error) {
	out, _, err := e.evaluate(ctx, a, info, v)
	return out, err
}

// evaluate is judge, and reports too whether the verdict is a block
// because the call's subjects, or those of a hook's rewrite, could not
// be evaluated: its splitter failed, perhaps only for the moment, as
// when the decision's context is done or a remote executor did not
// answer.
func (e *Engine) evaluate(ctx context.Context, a active, info agentturn.ToolCallInfo, v *Verdict) (agentturn.ToolDecision, bool, error) {
	name := ""
	if info.Call != nil {
		name = info.Call.Name
	}
	c := e.confinement(ctx, info.Tool, info.Args)
	var failed bool
	v.Action, v.Rule, v.Reason, v.Subject, failed = e.decide(ctx, a, name, c, info.Args)
	v.Confined = c.by
	out, rewriteFailed, err := e.foldHooks(ctx, a, name, info, v)
	return out, failed || rewriteFailed, err
}

// foldHooks folds the hooks' decisions into v, the policy's, as
// [WithHooks] describes, and returns what the hooks add to the
// decision besides its action: the note, Terminate and the rewritten
// arguments. Arguments a hook rewrites are decided again, their
// confinement read afresh: the stricter action stands, and a verdict
// still the policy's takes the rewrite's rule and reason, so it
// describes the arguments the call runs with. failed reports that the
// verdict is the block of a rewrite whose subjects could not be
// evaluated.
func (e *Engine) foldHooks(ctx context.Context, a active, name string, info agentturn.ToolCallInfo, v *Verdict) (out agentturn.ToolDecision, failed bool, err error) {
	policy := true
	for _, fn := range e.hooks {
		if v.Action == agentturn.Block {
			break
		}
		d, err := fn(ctx, info)
		if err != nil {
			return agentturn.ToolDecision{}, false, err
		}
		if d == nil {
			continue
		}
		if restrictiveness(d.Action) > restrictiveness(v.Action) {
			v.Action, v.Reason, v.Rule, v.Subject, v.By = d.Action, d.Reason, nil, "", d.By
			if v.By == "" {
				v.By = ByPolicy
			}
			policy = false
		}
		if out.Note == "" {
			out.Note = d.Note
		}
		out.Terminate = out.Terminate || d.Terminate
		if d.Args != nil {
			out.Args, info.Args = d.Args, d.Args
			c := e.confinement(ctx, info.Tool, d.Args)
			act, rule, reason, subject, bad := e.decide(ctx, a, name, c, d.Args)
			if r, cur := restrictiveness(act), restrictiveness(v.Action); r > cur || policy && r == cur {
				v.Action, v.Rule, v.Reason, v.Subject, v.By = act, rule, reason, subject, ByPolicy
				policy, failed = true, bad
			}
			v.Confined = c.by
		}
	}
	return out, failed, nil
}

// confinement is what a call's tool says of where it runs.
type confinement struct {
	ok bool
	by string
}

// confinement reads whether a call of tool with args runs confined.
func (e *Engine) confinement(ctx context.Context, tool agenttool.Tool, args json.RawMessage) confinement {
	if e.confine == nil || tool == nil {
		return confinement{}
	}
	ok, by := e.confine(ctx, tool, args)
	if !ok {
		return confinement{}
	}
	return confinement{ok: true, by: by}
}

// decide evaluates one call as Decide does, without recording it. ctx
// is the decision's, handed to the tool's splitter. failed reports a
// block because the splitter failed, rather than one a rule made.
func (e *Engine) decide(ctx context.Context, a active, name string, c confinement, args json.RawMessage) (act agentturn.ToolAction, rule *Rule, reason, subject string, failed bool) {
	subjects, err := e.split(ctx, name, args)
	if err != nil {
		return agentturn.Block, nil, name + " call could not be evaluated: " + err.Error(), "", true
	}
	act, rule, reason, subject = e.fold(a, name, c, subjects)
	return act, rule, reason, subject, false
}

// batchCache is whether each call of one batch asks, by its position
// in the batch, kept for the rest of that batch's decisions. key names
// the batch, its run and turn, every call's ID, name and arguments,
// and the rules it was decided under, the grant scope included, so a
// batch is never read against another's calls, even one whose provider
// numbers its calls the same way, against a policy that has changed
// since, or against another scope's grants.
type batchCache struct {
	key  string
	asks map[int]bool
}

// batchAsks reports whether a call the policy allowed is held: whether
// a call of its batch other than its own asks. own is what the policy
// made of info's own call, which is kept for its siblings whatever it
// is; the siblings are read only for a call the policy allows.
//
// Each call of the batch is decided once for the batch and kept: the
// loop hands the hook every call of the batch before any executes, so
// deciding the whole batch per call ran the product's splitter once
// per pair, ninety times over on a batch of ten. A call the hook has
// been handed is kept as it was decided, with its own tool; a sibling
// it has not is decided with the tool [WithTools] names, or none. A
// reading only ever moves toward asking: a call whose own decision
// asks is kept as asking whatever it was first read as, and one first
// read as asking stays so, so a call decided twice is held at least as
// often as the first time and never runs beside an ask. A sibling that
// could not be read, its hook or its splitter having failed, holds the
// call and is not kept: the failure may pass, as a cancelled context or
// a remote executor that did not answer does, so the next call of the
// batch reads it again.
func (e *Engine) batchAsks(ctx context.Context, a active, info agentturn.ToolCallInfo, own agentturn.ToolAction) bool {
	if len(info.Batch) < 2 || info.Call == nil {
		return false
	}
	self := position(info)
	key := batchKey(info, a.gen, a.scope)
	e.mu.Lock()
	if e.batch.key != key {
		e.batch = batchCache{key: key, asks: make(map[int]bool, len(info.Batch))}
	}
	if self >= 0 {
		e.batch.asks[self] = e.batch.asks[self] || own == agentturn.Defer
	}
	if own != agentturn.Allow {
		e.mu.Unlock()
		return false
	}
	known := maps.Clone(e.batch.asks)
	e.mu.Unlock()

	asks, decided := false, map[int]bool{}
	for i, c := range info.Batch {
		if c == nil || i == self {
			continue
		}
		ask, ok := known[i]
		if !ok {
			var keep bool
			ask, keep = e.siblingAsks(ctx, a, info, i)
			if keep {
				decided[i] = ask
			}
		}
		asks = asks || ask
	}
	if len(decided) > 0 {
		e.mu.Lock()
		if e.batch.key == key {
			for i, ask := range decided {
				e.batch.asks[i] = e.batch.asks[i] || ask
			}
		}
		e.mu.Unlock()
	}
	return asks
}

// siblingAsks reports whether the call at position i of info's batch
// asks, decided as Decide would decide it, the hooks included, with the
// tool [WithTools] names. A sibling that could not be read, a hook
// having failed or its subjects not evaluated, reads as asking, and
// keep is false so the reading is not kept for the batch. A sibling a
// rule blocks does not ask, and is kept.
func (e *Engine) siblingAsks(ctx context.Context, a active, info agentturn.ToolCallInfo, i int) (ask, keep bool) {
	c := info.Batch[i]
	args := callArgs(c)
	sib := agentturn.ToolCallInfo{RunID: info.RunID, Turn: info.Turn, Call: c, Tool: e.sibling(ctx, c.Name), Args: args, Batch: info.Batch, Index: i}
	v := Verdict{}
	_, failed, err := e.evaluate(ctx, a, sib, &v)
	if err != nil || failed {
		return true, false
	}
	return v.Action == agentturn.Defer, true
}

// position returns the index of info's own call in its batch: Index
// when it names the call, else the call found by identity, else -1, in
// which case every call of the batch is read as a sibling.
func position(info agentturn.ToolCallInfo) int {
	if i := info.Index; i >= 0 && i < len(info.Batch) && info.Batch[i] == info.Call {
		return i
	}
	return slices.Index(info.Batch, info.Call)
}

// sibling returns the tool [WithTools] or [WithToolsFor] names for the
// decision ctx belongs to, or nil.
func (e *Engine) sibling(ctx context.Context, name string) agenttool.Tool {
	if e.lookup == nil {
		return nil
	}
	t, ok := e.lookup(ctx, name)
	if !ok {
		return nil
	}
	return t
}

// batchKey names a batch by its run, its turn, its calls and the rules
// of the moment, the grant scope they were read under included.
func batchKey(info agentturn.ToolCallInfo, gen uint64, scope string) string {
	var b strings.Builder
	b.WriteString(strconv.FormatUint(gen, 10))
	b.WriteByte(0)
	b.WriteString(strconv.Quote(scope))
	b.WriteByte(0)
	b.WriteString(info.RunID)
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(info.Turn))
	for _, c := range info.Batch {
		b.WriteByte(0)
		if c != nil {
			b.WriteString(strconv.Quote(c.CallID))
			b.WriteString(strconv.Quote(c.Name))
			b.WriteString(strconv.Quote(c.Arguments))
		}
	}
	return b.String()
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
// itself, the splitter called with ctx. A splitter that returns nothing
// is an error, since a call with no subjects would be allowed by every
// rule. A splitter that returns only constraints has the call itself
// put before them, since constraints never allow and the call needs a
// subject that can.
func (e *Engine) split(ctx context.Context, name string, args json.RawMessage) ([]Subject, error) {
	m := e.matchers[name]
	if m.Subjects == nil {
		return []Subject{{Args: args}}, nil
	}
	subjects, err := m.Subjects(ctx, args)
	if err != nil {
		return nil, err
	}
	if len(subjects) == 0 {
		return nil, errors.New("splitter returned no subjects")
	}
	if !slices.ContainsFunc(subjects, func(s Subject) bool { return !s.Constrain }) {
		subjects = append([]Subject{{Args: args}}, subjects...)
	}
	return subjects, nil
}

// fold decides every subject and keeps the most restrictive verdict,
// the first of equals. A constraint no deny or ask rule fires for has
// no verdict and is passed over; split guarantees an ordinary subject,
// which always has one. A block of a call split into several subjects
// names the subject it was for, says nothing in the command ran and
// names the other subjects, so the model does not report the other
// half as having succeeded.
func (e *Engine) fold(a active, name string, c confinement, subjects []Subject) (agentturn.ToolAction, *Rule, string, string) {
	var (
		action  agentturn.ToolAction
		rule    *Rule
		reason  string
		subject string
		at      = -1
	)
	for i, s := range subjects {
		tool := s.Tool
		if tool == "" {
			tool = name
		}
		// The call's confinement is its tool's: a subject checked
		// against another tool's rules is not skipped for it.
		sc := c
		if tool != name {
			sc = confinement{}
		}
		act, r, why, ok := e.decideSubject(a, tool, sc, s.Args, s.Constrain)
		if !ok {
			continue
		}
		if at < 0 || restrictiveness(act) > restrictiveness(action) {
			action, rule, reason, subject, at = act, r, why, s.Text, i
		}
	}
	if action == agentturn.Block && len(subjects) > 1 && subject != "" {
		reason += " on " + strconv.Quote(subject) + "; nothing in this command ran"
		var rest []string
		for i, s := range subjects {
			if i != at && s.Text != "" && s.Text != subject && !slices.Contains(rest, strconv.Quote(s.Text)) {
				rest = append(rest, strconv.Quote(s.Text))
			}
		}
		if len(rest) > 0 {
			reason += ", including " + series(rest)
		}
	}
	return action, rule, reason, subject
}

// series joins items as prose: "a", "a and b", "a, b and c".
func series(items []string) string {
	if len(items) < 2 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
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

// decideSubject applies the precedence to one subject. A bare ask rule
// the confinement skips allows the subject, since the rule was what
// would have asked. A constraint stops after the ask rules: one no
// deny or ask rule fires for has no verdict, and ok is false.
func (e *Engine) decideSubject(a active, tool string, c confinement, args json.RawMessage, constrain bool) (act agentturn.ToolAction, rule *Rule, reason string, ok bool) {
	p := a.policy
	if r, ok := e.match(p.Deny, tool, args); ok {
		return agentturn.Block, &r, "denied by " + r.cite(), true
	}
	r, skipped, asked := e.matchAsk(a, tool, args, c.ok)
	if asked {
		return agentturn.Defer, &r, "approval required by " + r.cite(), true
	}
	if constrain {
		return agentturn.Allow, nil, "", false
	}
	if skipped {
		return agentturn.Allow, &r, confinedReason(c.by, r), true
	}
	if r, ok := e.match(p.Allow, tool, args); ok {
		return agentturn.Allow, &r, "allowed by " + r.cite(), true
	}
	action, _ := p.Default.Action()
	switch action {
	case agentturn.Block:
		return action, nil, "no rule allows " + tool + ": denied by default", true
	case agentturn.Defer:
		return action, nil, "no rule allows " + tool + ": approval required by default", true
	}
	return agentturn.Allow, nil, "allowed by default", true
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
//
// For a confined subject a bare rule is skipped rather than fired, and
// when no rule with a specifier fires the first skipped one is
// returned with skipped set, so the verdict names it.
func (e *Engine) matchAsk(a active, tool string, args json.RawMessage, confined bool) (r Rule, skipped, ok bool) {
	for _, rule := range a.policy.Ask {
		if !e.fires(a.policy.Ask, rule, tool, args) {
			continue
		}
		if _, shadowed := e.shadowedBy(a, rule, tool, args); shadowed {
			continue
		}
		if confined && rule.Bare() {
			if !skipped {
				r, skipped = rule, true
			}
			continue
		}
		return rule, false, true
	}
	return r, skipped, false
}

// confinedReason is the reason a confined call was allowed.
func confinedReason(by string, r Rule) string {
	if by == "" {
		return "confined, so " + r.String() + " does not ask"
	}
	return "confined by " + by + ", so " + r.String() + " does not ask"
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
	for _, fn := range e.observers {
		fn(ctx, v)
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
	e.gen++
	e.mu.Unlock()
	for i := range granted {
		g := granted[i]
		e.observe(ctx, Verdict{Tool: g.Tool, Action: agentturn.Allow, Rule: &g, Reason: "granted " + g.String(), By: ByPolicy})
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
		e.gen++
		e.mu.Unlock()
		reason = "granted " + r.String()
		for i := range rules {
			g := rules[i]
			e.observe(ctx, Verdict{Tool: g.Tool, Action: agentturn.Allow, Rule: &g, Reason: "granted " + g.String(), By: ByPolicy})
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
	at := slices.IndexFunc(e.policy.Ask, ask.same)
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
	e.gen++
	e.mu.Unlock()
	reason = "granted " + r.String() + " over " + ask.String()
	for i := range rules {
		g := rules[i]
		e.observe(ctx, Verdict{Tool: g.Tool, Action: agentturn.Allow, Rule: &g, Reason: reason, By: ByPolicy})
	}
	return true, reason
}
