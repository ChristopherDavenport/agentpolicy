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
  approval. An ask holds its batch, so nothing the model asked for in
  the same turn runs before the answer.
- Guards over input and output that become `BeforeModelCall`,
  `OutputGuard` and `ShouldStopAfterTurn` values.
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
// without either module importing the other. The tool name may be a
// glob, "mcp__*", which the deny and ask lists honour as both
// references do; Build refuses one in the allow list and one with a
// specifier, since a glob names no matcher. (Round 2, issue 3.)
type Rule struct {
    Tool   string
    Spec   string // "" for a bare name
    Source Source // where the rule came from; zero for the product's own
}

// MatchesTool is the engine's own tool-name test, exported so a
// product that filters a tool list does not write a second one that
// can disagree with the one decisions are made with.
func (r Rule) MatchesTool(tool string) bool
func (r Rule) Glob() bool

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

// WithAliases names the tools a rule name governs, for the rules a
// product does not write: a skill's allowed-tools and a settings file
// copied out of the reference's documentation are spelled with the
// reference's tool names, and one of those names may govern several
// of a product's tools. Build expands a rule whose name has an entry
// into one rule per tool and still fails closed on a name with
// neither an entry nor a matcher. (Round 2, issue 4.)
func WithAliases(aliases map[string][]string) Option

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
    // Withheld are the allow rules of the untrusted sources, which
    // Merge keeps rather than drops so a front can show what trusting
    // a source would allow. Nothing evaluates them. (Round 2, issue 5.)
    Withheld []Rule
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

// A deny rule with no specifier denies every call of its tool, so the
// tool is not offered at all: the model never sees it, as in the
// reference. Removes reports the rule, Filter drops the tools it
// names and ToolProvider is the hook value over a changing list.
// (Round 2, issue 3.)
// SetPolicy replaces the rules without rebuilding the matchers, which
// are the expensive half and do not change, so a product re-derives
// its policy when its tool list changes without replacing the config
// the loop holds. (Round 2, issue 10.)
func (e *Engine) SetPolicy(p Policy) error

// PolicyOf returns one source's rules, which is what a product
// persists into that source's file. (Round 2, issue 7.)
func (e *Engine) PolicyOf(source string) RuleSet

func (e *Engine) Removes(tool string) (Rule, bool)
func (e *Engine) Filter(tools []agenttool.Tool) []agenttool.Tool
func (e *Engine) ToolProvider(base func(context.Context) []agenttool.Tool) func(context.Context) []agenttool.Tool
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
tool, from a source it does not rank below, is cancelled when the
carve-out's pattern matches the subject. The pattern after the `!` is
the tool's, as any spec is. A `Read(!.env.example)` in a repository's
settings cannot open a `Read(.env*)` an administrator denied, because
the repository ranks below the administrator. That is the whole reason
a rule carries a source. Rank rather than source identity is the test,
so a grant's carve-out can be filed under the grant's own source and
still reach the rule it answers. (Finding 3; round 2, issue 7.)

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
    Held   bool   // a call held for an ask in its batch, and its release
    // Subject is the Text of the subject whose verdict the fold kept,
    // so a prompt says which half of a compound command it is asking
    // about. (Round 2, issue 6.)
    Subject string
}

func WithObserver(fn func(context.Context, Verdict)) Option
```

A hook cannot append to the transcript, so a verdict reaches the
session two ways. The `ToolDecision` the hook returns is what the
loop's own recorder writes as the format's `decision` entry on the
call: Block is `reject` carrying the reason, Defer is `hold`, and an
approval on `Resume` is `proceed`, which the format has a writer
record only when it answers a hold or rewrote the arguments, since
the call's `dispatch` is otherwise the record. `by` is what the
decision names, and the engine names `policy`; an answer through
`Resume` names nobody, so a product that records a reviewer as
`agent` does so from the observer. What the entry cannot carry, the
rule that fired, a hold and its release, a guard's verdict on content,
a grant, reaches the session through the observer, and a product
writes it beside the decision as a `custom` entry under `agentpolicy`,
through the recorder's `Annotate`.

### Holding a batch

The loop runs `BeforeToolCall` for every call of a batch, in the
model's order, before any call executes, and hands each call its
`Batch` and `Index`. Deferring one call alone would let the rest of
the batch run while the user reads the question, so the user answers
about a push after the commit it follows has happened. The engine
therefore holds: a call the policy allows is deferred, with
`Verdict.Held` set and `held for approval: <the allow reason>` as its
reason, when any other call of its batch asks, wherever that call sits
in the batch. A blocked call is blocked whatever its batch holds, and
a batch with no ask holds nothing. The engine remembers the held calls
with the asked ones, and answers them once the front has answered the
asks:

```go
// Deferred returns the verdict that deferred the call in the run,
// asked or held, so a front tells the calls it must answer from the
// ones Release answers.
func (e *Engine) Deferred(runID, callID string) (Verdict, bool)

// Release completes the answers to a run that ended on an ask: given
// the front's answers to the asked calls, it answers each held call and
// returns every answer in the order of end.Pending, the model's order,
// which is the order a sequential batch runs in. A pending call it
// cannot answer is ErrUnanswered, which names it.
func (e *Engine) Release(ctx context.Context, end *agentturn.RunEnd, answers ...agentturn.Answer) ([]agentturn.Answer, error)

// Forget drops what a run that ended another way left behind, and Runs
// reports the runs still holding deferred calls.
func (e *Engine) Forget(runID string)
func (e *Engine) Runs() []string
```

The policy allowed a held call, so it is approved and runs with the
batch, on an approval and on a refusal alike: both references let the
other calls of a batch run when one is refused, and the model sees the
one refusal. An answer built with `agentturn.Refuse` ends the turn
instead, and then the held calls are refused with text that says so,
since the user said stop before anything ran. A front shows the held
calls beside the ask, since they run on any answer but a stop.

One engine serves every agent of a product, because the policy is the
product's and not a loop's. What the engine defers is therefore keyed
by the run it was deferred in, and a decision in one run never touches
another's; `Release` and `Answers` forget each call as they answer it,
and `Forget` drops what an abandoned run left, so the memory is
bounded by the calls still waiting. (Round 2, issue 1.)

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

// GrantSet activates a rule set under its source, as a skill's
// allowed-tools grants the tools the skill was written to run: there
// is no prompt behind it, so GrantOver has no verdict to answer, and
// an appended allow rule loses to any ask rule naming the tool. Its
// allow rules therefore shadow the ask rules they cover, from other
// sources, of equal or lower rank, while the set is active. A rule it
// cannot activate is reported with the reason, as GrantOver reports
// one. Revoke removes the set at the turn boundary, and Grants
// reports the sets in force. (Round 2, issues 2 and 9.)
func (e *Engine) GrantSet(ctx context.Context, set RuleSet) (granted []Rule, refused []Refusal)
func (e *Engine) Revoke(ctx context.Context, source string) int
func (e *Engine) Grants() []RuleSet
```

The way an ask rule is kept from firing is written into the policy,
not held in the engine: a grant with a specifier appends the
carve-out `<tool>(!<spec>)` beside the ask rule, under the grant's
own source, and a bare grant removes the ask rule. `Engine.Policy`
therefore holds the whole policy in force, an engine rebuilt from it
decides the same, and a persisted grant is the product's: it writes
what `Engine.PolicyOf` reports for its own source into that source's
settings and rebuilds the engine at the next start. The carve-out is
the grant's because the grant is, and a carve-out cancels a rule of
any source it does not rank below, which is what lets it reach the
rule it answers while a lower-ranked file still cannot carve out a
higher-ranked one. (Round 2, issue 7.) A grant never beats a deny rule, and a grant from
a lower-ranked source never touches an ask rule from a higher-ranked
one.

A scoped grant is not written into the policy, because it is not the
product's to persist: it lasts as long as the source that carries it,
a skill in use rather than a settings file, and a product that wrote
it into its settings would grant the tools of a skill the model opened
once. `Engine.Grants` reports the sets in force beside
`Engine.Policy`, and an engine rebuilt from the policy decides as this
one does once they are revoked. That is the one place the "policy in
force is a value" invariant is qualified, and `Revoke` is the
revocation the plan's open question left for a second product.

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
    Note    string          // what the model reads with the result, as a user's note does
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
// refusals are built with Refuse, so Resume ends the run without a
// model call, and the answers are returned with ErrDenialBound so the
// front can say why.
func (e *Engine) Answers(ctx context.Context, r Reviewer, end *agentturn.RunEnd) ([]agentturn.Answer, error)
```

The engine remembers what it deferred in each run, the hook's
`ToolCallInfo` and the verdict, so the reviewer sees the tool and the
reason the policy asked. It reviews only the calls the policy
asked about: a held call is released with them, as `Release` does for
a human's answers, and a call an abort cut off or one found unanswered
in a seeded transcript, which the loop marks as such on `PendingCall`,
is not the reviewer's to approve, since its tool may have run; it is
refused with text that says so, outside the denial bound, and the
model decides whether to ask for it again. The note is the reviewer's,
or the user's through the front: the engine sets none on its own
decisions, since a rule has nothing to tell the model beyond its
reason. `Decide` never calls a model; the reviewer the front passes in
may.

### Presets

`Suggest`, `AutoEdit` and `FullAuto` return a `Policy` over a given
set of tool names, split into read, edit and execute by the product,
matching Codex's three modes. They are examples of the grammar, kept
in the package so two products do not diverge. Each sets `Default` to
`Ask()`, so a tool the split does not name prompts.

### `guard`

```go
// Subject is what a guard looks at. An Input carries the request's
// instructions as well as its items, because that is where most of
// what enters the window is: an AGENTS.md chain, a skill catalogue, a
// memory block the model itself wrote, none of it typed by the person
// running the agent. (Round 2, issue 8.)
type Input struct {
    Items        openresponses.Items
    Instructions string
}
type Message struct{ Message *openresponses.Message } // an assistant message before the transcript keeps it
type Output struct{ Response *openresponses.Response } // a finished turn

type Verdict struct {
    Action agentturn.ToolAction // Allow passes; Block stops; Defer is not valid for content
    Reason string
    Items  openresponses.Items  // for Input or Message, a rewrite; nil keeps the subject
    // Instructions, for an Input, replaces the request's instructions,
    // so Redact rewrites the text nobody typed as it rewrites items.
    Instructions *string
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
func (c Chain) OutputGuard() func(context.Context, agentturn.OutputInfo) (*openresponses.Message, error)
func (c Chain) ShouldStopAfterTurn() func(context.Context, agentturn.TurnInfo) (bool, error)

func BeforeModelCall(guards ...Guard) func(context.Context, *openresponses.Request) error
func OutputGuard(guards ...Guard) func(context.Context, agentturn.OutputInfo) (*openresponses.Message, error)
func ShouldStopAfterTurn(guards ...Guard) func(context.Context, agentturn.TurnInfo) (bool, error)
```

An input guard may block, which fails the model call with the reason,
or rewrite, which replaces the request's input for that call and its
instructions when the verdict carries them; the loop already documents
that a changed input affects session verification like a `Transform`
does. `Limit` counts the instructions in an input's size, and `Deny`,
`Secrets` and `Redact` read them as they read the items. A guard on a message sees each assistant
message as the stream completes it, before the transcript, the record
or the front's `item_end` keeps it, so it may rewrite the message or
withhold it behind a placeholder; the deltas have already been
delivered, so a front that must not show withheld text renders on
`item_end`. A guard on a finished turn can only stop the run, since
the turn's items are already in the transcript; a product that wants
to re-prompt appends a message and continues. It stops the run as a
guard stop: the hook returns a `BlockedError` wrapping
`agentturn.ErrGuard`, so the run ends `ReasonStopped` with `StopGuard`
and the error on `RunEnd.Err`, and a policy stop is told from a
failure; the same error from `BeforeModelCall` fails the call.
Deterministic guards ship here: a byte size limit, a regex deny list,
a secret pattern scanner that blocks, and one that redacts, the input
and a message alike. Every verdict goes to the same observer.

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
3. Recording through entries the session format already has: the
   hook's decision as the call's `decision` entry, written by the
   loop's recorder, and the observer's verdict as a `custom` entry
   under `agentpolicy`, written by the product. Nothing is added to
   the RFC.

## Invariants

- Precedence is deny, ask, allow, default, always, and never depends
  on which source a rule came from.
- One call, several subjects: deny if any, ask if any, allow only if
  all.
- One batch, one answer: an ask holds every call of its batch the
  policy allows, a blocked call is never held, and a held call runs
  only once the ask is answered and never after a stop.
- A rule with a spec and no matcher never builds, and is never
  granted.
- A policy whose default is unset never builds.
- A carve-out reaches only rules of a source it does not rank below.
- A grant never beats a deny rule, and never touches an ask rule from
  a source that outranks it.
- The policy in force is a value: `Engine.Policy` holds every grant a
  prompt answered, and an engine rebuilt from it decides the same,
  absent the scoped grants `Engine.Grants` reports, which last only as
  long as their source.
- `Decide` never calls a model or opens a socket.
- Every decision, every hold and release, every grant, every guard
  verdict and every reviewer answer reaches the observer exactly once.
- The same `Policy` and the same call in the same batch give the same
  `Verdict`.

## Testing

Table-driven: the grammar, precedence, matchers, subject folding,
carve-outs by source, the merge, presets over a fixed tool set, grants
and grants over an ask rule, the hold and its release, and every
verdict through the observer. A run under `agentturn` with the `echo`
adapter proves Defer ends the run with the pending call and `Approve`
resumes it, and that `Answers` resumes it without a human; one with a
model that emits a batch proves an ask holds it, `Release` runs it in
the model's order and `Refuse` ends the turn with nothing run.
`classify` is tested against the echo adapter with a canned answer.

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
7. The loop's seams from that study, agentturn v0.0.6: the batch hold
   and `Release`, `Refuse` at the denial bound, `By` on decisions and
   `Note` on answers, `ErrGuard` and `OutputGuard`.

## Open questions

- Whether `Ask` should carry a remembered answer for the session
  (approve once, approve for this run). `GrantOver` covers always;
  the other two are the front's until a second product wants them
  here.
- Answered in round 2: grants need a lifetime and a revocation, and
  the second product is the composed one. A scope on `Rule` is not
  what they need, though: the scope is the rule set's source, so
  `GrantSet` activates a set under its source and `Revoke` removes it
  at the turn boundary. (Issues 2 and 9.)
- Answered in round 2: a bare-name deny removes the tool from the
  request, as Claude Code does. It is `Engine.Filter` beside `Decide`,
  with `Engine.ToolProvider` as the hook value and `Engine.Removes`
  for the front, and the engine's own tool-name test is exported as
  `Rule.MatchesTool` so the two cannot disagree. (Issue 3.)
- Whether the observer should be replaced by an app-only item the
  product appends after the batch, so verdicts sit in the transcript
  next to the call. The hook cannot append; a product could. Reopen
  when replay needs verdicts in context order rather than by call ID.
- Whether a spec grammar beyond `prefix:*` and exact match is worth
  defining here. Claude Code's has globs; the study says whether dex
  needs them. Round 2 answered the tool-name half only: a `*` in
  `Rule.Tool` is the module's, because the deny and ask lists must
  honour `mcp__*` and nothing else can match a tool that has no
  matcher. What a specifier means is still the tool's.
