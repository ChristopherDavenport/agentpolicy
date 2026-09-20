# Plan: policy layer

Decisions about what an agent may do and what may enter or leave its
window. The loop makes permissions a non-goal and gives the seams:
`BeforeToolCall` for calls, `BeforeModelCall` and `ShouldStopAfterTurn`
for content. Every product then writes the same rule grammar, the same
matcher and the same approval flow, and `agentskill` already parses an
`allowed-tools` grammar nothing enforces. This module is that grammar,
that matcher and those hook values, once.

Permissions and guardrails are one module because they are one shape:
a rule over a subject, a verdict from the loop's vocabulary, a reason,
and a record. A permission's subject is a tool call; a guardrail's is
content. Two modules would mean two grammars and two ways to record a
verdict.

The reference shapes are Claude Code's permission rules
(`Bash(git:*)`, allow and deny lists, ask by default) and Codex CLI's
approval modes (suggest, auto-edit, full-auto) and its reviewer
subagent. The study builds both on this module and wires them into
dex. The findings of that study are in `../feedback.md`; this plan has
them applied, and each place it changed says which finding changed it.

## Goals

- One rule grammar, `Tool` or `Tool(spec)`, with allow, deny and ask
  lists and a fixed precedence.
- A policy that becomes a `BeforeToolCall` value and returns the
  loop's own `ToolDecision`: Allow, Block with a reason, or Defer for
  approval.
- Guards over input and output that become `BeforeModelCall` and
  `ShouldStopAfterTurn` values.
- Every verdict observable, so a product records it beside the
  session.
- A mutable policy for "always allow this", with its own journal.
- An answer source for a deferred call that is not a human, so a run
  nobody is watching still gets a fail-closed decision and a record.
- The root is deterministic: no model, no network. A model-backed
  guard or reviewer is a package that takes an `openresponses.Streamer`.

## Non-goals

- Knowing what a tool does. The meaning of a spec such as `git:*`
  belongs to the tool; the product registers a matcher for it, and a
  splitter when one call is several subjects.
- Sandboxing. An OS sandbox is the product's; this module decides,
  it does not confine.
- The approval user interface. Defer ends the run with the pending
  calls; a front asks and resumes.
- Content classification models. `classify` wires one in; training
  or choosing it is the product's.

## Module and packages

Separate module, `github.com/ChristopherDavenport/agentpolicy`.

```
agentpolicy/                 Rule, Source, Policy, Merge, Matcher registry, Engine, Verdict, Reviewer, Answers, presets
agentpolicy/guard            Guard contract, deterministic guards, hook constructors
agentpolicy/classify         a Guard and a Reviewer backed by a model through openresponses.Streamer
```

The root module depends on `openresponses`, `agenttool`, `agentturn`
and the standard library. It sits above the loop, as `tools/agent`
does, because it produces the loop's hook values.

## Core types

```go
// Rule is one token of the grammar: a tool name, or a name with a
// specifier, "Bash(git:*)". The same grammar as a skill's
// allowed-tools, so agentskill.ToolRule maps onto it field for field
// without either module importing the other.
type Rule struct {
    Tool   string
    Spec   string // "" for a bare name
    Source Source // where the rule came from; zero for the product's own
}

// Source is where a set of rules came from. Name scopes a carve-out
// and identifies the source in the merge; Path and Hash let a session
// name the policy in force; Trusted false withholds the source's allow
// rules; Rank orders sources by authority for GrantOver and never
// affects precedence between lists. (Finding 3.)
type Source struct {
    Name, Path, Hash string
    Trusted          bool
    Rank             int
}

// ParseRules splits on whitespace outside parentheses, so a specifier
// may contain spaces and literal parentheses: "Bash(git status:*)".
func ParseRules(s string) ([]Rule, error)

// Matcher decides whether a spec matches one subject's arguments. A
// product registers one per tool that takes specs; a rule with a spec
// for a tool without a matcher is an error at Policy build time, not
// a silent non-match.
type Matcher func(spec string, args json.RawMessage) bool

// PrefixMatcher is the common case: the spec is "<prefix>:*" or an
// exact value, compared against one string field of the arguments.
func PrefixMatcher(field string) Matcher

// Subject is one thing a policy is evaluated against. A call is one
// subject unless the tool's Subjects splits it. Tool, when set,
// evaluates the subject against another tool's rules, as a shell
// redirect target is checked against the file rules. (Finding 1.)
type Subject struct {
    Args json.RawMessage
    Tool string
    Text string
}

// Subjects splits one call into its subjects. A shell tool splits on
// operators; most tools have none and are one subject. The splitter
// is the product's; the root package holds no shell parser.
type Subjects func(args json.RawMessage) ([]Subject, error)

type ToolMatcher struct {
    Match    Matcher
    Subjects Subjects // nil means one subject, the call
}

// Default is what applies when no rule matches. It cannot be left
// unset: Build refuses a Policy whose Default is the zero value, so a
// deny list alone never allows everything by accident. (Finding 5.)
type Default struct{ /* unexported */ }

func Allow() Default
func Deny() Default
func Ask() Default

type Policy struct {
    Allow   []Rule
    Deny    []Rule
    Ask     []Rule
    Default Default
    // Sources lists where the rules came from, as Merge fills it.
    Sources []Source
}

// RuleSet is one source's lists. Merge unions the lists of several
// sources into one Policy, orders them by Rank, stamps every rule
// with its Source, withholds the allow rules of an untrusted source,
// and leaves Default unset for the product to choose. (Finding 3.)
type RuleSet struct {
    Source           Source
    Allow, Deny, Ask []Rule
}

func Merge(sets ...RuleSet) (Policy, error)

// Build validates the policy against the matchers and returns the
// runtime form.
func Build(p Policy, matchers map[string]ToolMatcher, opts ...Option) (*Engine, error)

func (e *Engine) Decide(ctx context.Context, info agentturn.ToolCallInfo) (*agentturn.ToolDecision, error)
func (e *Engine) BeforeToolCall() func(context.Context, agentturn.ToolCallInfo) (*agentturn.ToolDecision, error)
func (e *Engine) Policy() Policy
func (e *Engine) Sources() []Source
```

Precedence is fixed: deny, then ask, then allow, then the default.
A deny is a Block whose reason names the rule. An ask is a Defer. The
reason strings are stable, because the model reads them and a test
asserts them.

`Decide` evaluates the policy against every subject of the call and
folds the verdicts with the rule both references share: deny if any
subject is denied, ask if any subject asks, allow only if every
subject is allowed. With that, `git status && rm -rf /` under
`Allow: [bash(git status:*)]`, `Deny: [bash(rm:*)]` is denied, where
one subject per call would have allowed it. A splitter that cannot
parse its call fails closed: the call is blocked with the splitter's
error as the reason, so an allow-by-default policy never runs what it
could not read. (Finding 1.)

A specifier that begins with `!` is a carve-out: it never matches on
its own, and a match of another rule in the same list, for the same
tool, from the same source, is cancelled when the carve-out's pattern
matches the subject. The pattern after the `!` is the tool's, as any
spec is. The carve-out reaches only its own source's rules, so a
`Read(!.env.example)` in a repository's settings cannot open a
`Read(.env*)` an administrator denied. That is the whole reason a
rule carries a source. (Finding 3.)

### Verdict observer

```go
// Verdict is what was decided and why, for recording: a rule
// decision, a grant, a guard's verdict on content, or a reviewer's
// answer to a deferred call.
type Verdict struct {
    RunID  string
    Turn   int
    CallID string // the call decided; empty for content and grants
    Tool   string
    Guard  string // the guard that decided content; empty otherwise
    Action agentturn.ToolAction
    Rule   *Rule  // the rule that fired, nil for the default
    Reason string
}

func WithObserver(fn func(context.Context, Verdict)) Option
```

A hook cannot append to the transcript, so a verdict reaches the
session through the observer. A verdict on a call is what the
product's recorder writes as the session format's `decision` entry on
that call: Block is `reject` carrying the reason, Defer is `hold`, and
Allow is `proceed`, which the format has a writer record only when it
answers a hold or rewrote the arguments, since the call's `dispatch`
is otherwise the record. `by` is `policy` for the engine's decision
and `agent` for a reviewer's answer; the rule that fired is a member
the format does not define, which readers preserve. A guard's verdict
on content and a grant are not a call's fate, so the recorder writes
those as `custom` entries under `agentpolicy`.

### Runtime changes

```go
// Grant adds an allow rule for the rest of the process, as "always
// allow" does in an approval prompt from the default. Every grant is
// journaled through the observer with a Verdict whose Action is Allow
// and whose Rule is the new rule, so the record shows when the policy
// changed. A rule with a spec and no matcher is refused.
func (e *Engine) Grant(ctx context.Context, r Rule) error

// GrantOver answers the prompt behind v: it adds r as an allow rule
// and, when an ask rule produced v, keeps that rule from firing for
// the calls r matches, since precedence alone would let it ask again.
// It reports when it cannot, so a front drops the "always" option:
// over a deny rule, over an ask rule from a source that outranks r's,
// or for a rule that does not name the ask rule's tool. (Finding 2.)
func (e *Engine) GrantOver(ctx context.Context, v Verdict, r Rule) (granted bool, reason string)
```

The way an ask rule is kept from firing is written into the policy,
not held in the engine: a grant with a specifier appends the
carve-out `<tool>(!<spec>)` beside the ask rule, under the ask rule's
own source, and a bare grant removes the ask rule. `Engine.Policy`
therefore holds the whole policy in force, an engine rebuilt from it
decides the same, and a persisted grant is the product's: it writes
what the policy now holds into its settings and rebuilds the engine
at the next start. A grant never beats a deny rule, and a grant from
a lower-ranked source never touches an ask rule from a higher-ranked
one.

### The reviewer

Codex's unattended mode answers the prompts a human would with a
reviewer subagent. On this stack that reviewer is the front's answer
source, above the loop: on `ReasonInputRequired` the front asks it
for each pending call and hands the answers to `Resume`. The engine
keeps the fail-closed rule and the denial bound in one place, so no
front rediscovers them. (Finding 4.)

```go
// Review is a reviewer's answer. The zero Outcome is Refused, so an
// unset answer refuses. TimedOut is neither an approval nor a
// refusal: the call did not run, and the record says why.
type Outcome int // Refused, Approved, TimedOut

type Review struct {
    Outcome Outcome
    Reason  string
    Args    json.RawMessage // for an approval, rewritten arguments
}

type Reviewer interface {
    Review(context.Context, agentturn.ToolCallInfo, Verdict) (Review, error)
}

// Answers reviews the calls end left pending and returns one Answer
// per call for Agent.Resume. A refusal, a timeout and a reviewer
// failure each answer the call with a refusal the model reads, and
// the refusal tells it not to pursue the same outcome by another
// route. Every answer is a Verdict through the observer. After three
// consecutive refusals, or ten within the last fifty reviews, the
// answers are returned with ErrDenialBound so the front can stop the
// run instead of resuming it.
func (e *Engine) Answers(ctx context.Context, r Reviewer, end *agentturn.RunEnd) ([]agentturn.Answer, error)
```

The engine remembers what it deferred in the run in progress, the
hook's `ToolCallInfo` and the verdict, so the reviewer sees the tool
and the reason the policy asked. `Decide` never calls a model; the
reviewer the front passes in may.

### Presets

`Suggest`, `AutoEdit` and `FullAuto` return a `Policy` over a given
set of tool names, split into read, edit and execute by the product,
matching Codex's three modes. They are examples of the grammar, kept
in the package so two products do not diverge. Each sets `Default` to
`Ask()`, so a tool the split does not name prompts.

### `guard`

```go
// Subject is what a guard looks at.
type Input struct{ Items openresponses.Items }      // the request's input before a model call
type Output struct{ Response *openresponses.Response } // a finished turn

type Verdict struct {
    Action agentturn.ToolAction // Allow passes; Block stops; Defer is not valid for content
    Reason string
    Items  openresponses.Items  // for Input, a rewrite; nil keeps the input
}

type Guard interface {
    Name() string
    Check(ctx context.Context, subject any) (Verdict, error)
}

// Chain runs guards in order and reports every verdict through the
// same observer the engine uses, as an agentpolicy.Verdict whose
// Guard names the guard.
type Chain struct {
    Guards   []Guard
    Observer func(context.Context, agentpolicy.Verdict)
}

func (c Chain) BeforeModelCall() func(context.Context, *openresponses.Request) error
func (c Chain) ShouldStopAfterTurn() func(context.Context, agentturn.TurnInfo) (bool, error)

func BeforeModelCall(guards ...Guard) func(context.Context, *openresponses.Request) error
func ShouldStopAfterTurn(guards ...Guard) func(context.Context, agentturn.TurnInfo) (bool, error)
```

An input guard may block, which fails the model call with the reason,
or rewrite, which replaces the request's input for that call; the loop
already documents that a changed input affects session verification
like a `Transform` does. An output guard can only stop the run, since
the assistant's items are already in the transcript; a product that
wants to re-prompt appends a message and continues. Deterministic
guards ship here: a byte size limit, a regex deny list, a secret
pattern scanner that blocks, and one that redacts. Every verdict goes
to the same observer.

### `classify`

One guard that sends the subject to a model with a rubric and reads a
structured answer, and one reviewer that does the same for a deferred
call. Both take an `openresponses.Streamer` and a model name, so they
work against any server or an echo adapter in tests. The rubric is the
product's; the answer shape, `{"allow": bool, "reason": string}`, is
this package's. The reviewer takes a timeout and reports it as
`TimedOut`; a model failure or an unreadable answer is an error, which
`Answers` turns into a refusal.

## Conventions shared with the siblings

1. One decision vocabulary: the loop's Allow, Block and Defer. This
   module returns `agentturn.ToolDecision` and reuses `ToolAction` for
   content; it defines no second set.
2. Sources through `fs.FS` with a manifest. A policy merged from
   settings files carries its sources, with a path and a hash each,
   and `Build`'s result reports them, so the session can name the
   policy version in force.
3. Recording through entries the session format already has: a
   verdict on a call as the `decision` entry on that call, a guard's
   verdict and a grant as `custom` entries under `agentpolicy`, each
   written by the product from the observer. Nothing is added to the
   RFC.

## Invariants

- Precedence is deny, ask, allow, default, always, and never depends
  on which source a rule came from.
- One call, several subjects: deny if any, ask if any, allow only if
  all.
- A rule with a spec and no matcher never builds, and is never
  granted.
- A policy whose default is unset never builds.
- A carve-out reaches only rules from its own source.
- A grant never beats a deny rule, and never touches an ask rule from
  a source that outranks it.
- The policy in force is a value: `Engine.Policy` holds every grant,
  and an engine rebuilt from it decides the same.
- `Decide` never calls a model or opens a socket.
- Every decision, every grant, every guard verdict and every
  reviewer answer reaches the observer exactly once.
- The same `Policy` and the same call give the same `Verdict`.

## Testing

Table-driven: the grammar, precedence, matchers, subject folding,
carve-outs by source, the merge, presets over a fixed tool set, grants
and grants over an ask rule, and every verdict through the observer. A
run under `agentturn` with the `echo` adapter proves Defer ends the
run with the pending call and `Approve` resumes it, and that `Answers`
resumes it without a human. `classify` is tested against the echo
adapter with a canned answer.

## Milestones

1. `Rule`, `Source`, `ParseRules`, `Matcher`, `PrefixMatcher`,
   `Subject`, `ToolMatcher`, `Default`, `Policy`, `Merge`, `Build`,
   `Decide` folding over subjects, precedence tests.
2. `BeforeToolCall`, the observer, `Grant`, `GrantOver`, the loop
   integration test.
3. `Reviewer`, `Answers`, the denial bound.
4. `guard`: contract, the deterministic guards, `Chain` and both hook
   constructors.
5. `classify`: the guard and the reviewer.
6. The Codex and Claude Code study: presets and rule files wired into
   dex with an approval prompt in the TUI.

## Open questions

- Whether `Ask` should carry a remembered answer for the session
  (approve once, approve for this run). `GrantOver` covers always;
  the other two are the front's until a second product wants them
  here.
- Whether grants need a lifetime and a revocation. A skill's
  `allowed-tools` grants for one turn, and Claude Code's permission
  updates carry `removeRules`. A product rebuilds the engine today;
  `Revoke` and a scope on `Rule` wait for the second product.
- Whether a bare-name deny should also remove the tool from the
  request, as Claude Code does, through `Config.ToolProvider`. That
  is an `Engine.Offer` beside `Decide`; the study says whether dex
  needs it before dex's tool list exists.
- Whether the observer should be replaced by an app-only item the
  product appends after the batch, so verdicts sit in the transcript
  next to the call. The hook cannot append; a product could. Reopen
  when replay needs verdicts in context order rather than by call ID.
- Whether a spec grammar beyond `prefix:*` and exact match is worth
  defining here. Claude Code's has globs; the study says whether dex
  needs them.
