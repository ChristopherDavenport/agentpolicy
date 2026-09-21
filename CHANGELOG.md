# Changelog

All user-visible changes to this library. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/); before v1.0.0 minor
versions may break the API.

## Unreleased

- **Breaking**: one engine serves every agent of a product. The calls
  the engine defers are remembered under their own run rather than in
  one map cleared whenever a decision names another run, so a
  sub-agent's first decision no longer erases what the main agent is
  waiting on. `Engine.Deferred` takes the run as well as the call,
  `Engine.Forget(runID)` drops what a run that ended another way left
  behind, and `Engine.Runs` reports the runs still holding deferred
  calls. `Release` and `Answers` take the run from the `RunEnd` they
  are given and forget each call as they answer it, so an engine
  shared by several agents does not grow with the runs they finish;
  a front that shows why a call waited reads the verdict from the
  observer rather than from `Deferred` after the answer. (#1)
- **Breaking**: `Engine.Release` returns an error as well as the
  answers. A call the run left pending that neither the caller
  answered nor the engine held is `ErrUnanswered`, whose text names
  every such call, `agentpolicy: pending call has no answer: call_a
  (bash)`, where before it was dropped and `Resume` failed with the
  loop's own error and nothing said which call was missed.
  `Engine.Answers` completes with `Release` and returns its error,
  joined with `ErrDenialBound` when both hold. (#1)

- A rule's tool name may be a glob, `mcp__*`, and the deny and ask
  lists honour it, where before `Build` accepted such a rule and
  `Engine.match` compared tool names with `==`, so a managed
  `deny: ["mcp__*"]` was listed by every front and fired on nothing.
  A `*` matches any run of characters at any position and nothing
  folds case. **Breaking**: `Build` now refuses a glob in the allow
  list and a glob with a specifier with the new `ErrToolGlob`, since
  neither can be honoured: `agentpolicy: tool-name glob: mcp__* is not
  honoured in the allow list`. `Rule.MatchesTool` and `Rule.Glob` are
  the engine's own tool-name test, exported so a product does not
  write a second one that disagrees. (#3)
- A deny rule with no specifier removes the tool from the request
  rather than refusing its calls one at a time, which is the most
  common deny form in the reference: `Engine.Filter` returns the tools
  a list still offers, `Engine.ToolProvider` is the hook value for
  `agentturn.Config.ToolProvider` over a base provider, consulted once
  per turn so a late tool and a changed policy are both picked up, and
  `Engine.Removes` reports the rule that withheld a tool. This is the
  `Offer` the round 1 study asked for. (#3)
- `ErrNoMatcher` names a near miss: a rule whose tool differs from a
  registered matcher only in case, as a rule copied out of the
  reference's documentation does, now reads `agentpolicy: no matcher
  for the rule's tool: Bash(git status:*); did you mean bash?`. (#4)
- `WithAliases` names the tools a rule name governs, so the rules a
  product does not write itself reach its tools: a skill's
  `allowed-tools` and a settings file spelled with the reference's
  `Bash`, `Read` and `Edit` now build against tools named `bash`,
  `read` and `edit`, and one rule name may govern several tools, as
  the reference's `Read` reaches its search tools. `Build` expands a
  rule whose name has an entry into one rule per tool, keeping the
  specifier and the source, and `Engine.Policy` reports the rules as
  they are evaluated; `Grant` and `GrantOver` expand one the same way.
  A name with no entry is still a tool's own name and still fails
  closed. An alias table that names no tool, or that names one with a
  glob, does not build. (#4)

## v0.0.2 - 2026-09-20

- Depends on `agentturn` v0.0.6 and, through it, `agenttool` v0.0.5.
  v0.0.1 does not build against agentturn v0.0.6, which made
  `RunEnd.Pending` a list of `PendingCall` values; a product importing
  both got v0.0.6 through minimum version selection and failed to
  build.
- **Breaking**: an ask holds its batch. `Decide` defers a call the
  policy allows when another call of its batch asks, with the new
  `Verdict.Held` set and `held for approval: <the allow reason>` as
  its reason, so nothing the model asked for in the same turn runs
  before the user has answered; the loop hands the hook every call of
  the batch before any executes, so the ask is seen wherever it sits.
  A blocked call is blocked whatever its batch holds. `Engine.Deferred`
  returns the verdict that deferred a pending call, asked or held, and
  `Engine.Release` completes a front's answers to the asked calls with
  one per held call, in the order of `end.Pending`: an approval or a
  plain refusal releases them, with `released: <the allow reason>` on
  the record, since the policy allowed them; an answer built with
  `agentturn.Refuse` refuses them with `not released: the turn was
  stopped` and the text `The call was held for an approval and the
  turn was stopped; the call did not run.` A front that answered a
  pending call itself keeps its answer. `GrantOver` refuses a held
  verdict with `nothing to grant over: the call was held for another
  call's approval`, since the policy allowed the call.
- `Decide` names the policy as the decision's decider through
  `ToolDecision.By`, so the loop's recorder writes `by: policy` on the
  call's decision entry.
- `Review.Note` is what the reviewer tells the model with the result:
  `Answers` attaches it to an approval or a refusal with
  `Answer.WithNote`, and the loop appends it after the outputs as a
  user message.
- `Answers` returns its answers in the order of `end.Pending`, reviews
  only the calls the policy asked about and releases the held ones
  with them. A call an abort cut off or one found unanswered in a
  seeded transcript is not reviewed: it is refused with `The call was
  cut off before it finished and may have run; it was not run again.`,
  recorded as `not reviewed: aborted` or `not reviewed: unknown`, and
  does not count toward the denial bound. When the bound is reached
  every refusal among the answers is built with `agentturn.Refuse`, so
  `Resume` appends the outputs and ends the run with `StopRefused`
  instead of calling the model; `ErrDenialBound` is still returned
  with them.
- `guard`: `Chain.ShouldStopAfterTurn` stops the run as a guard stop.
  Its `BlockedError` wraps `agentturn.ErrGuard`, so the run ends
  `ReasonStopped` with `StopGuard` and the error on `RunEnd.Err`
  rather than as a plain hook stop; the error from `BeforeModelCall`
  wraps it too, so `errors.Is` tells a guard's refusal from a failure
  either way. **Breaking**: `BlockedError` gains `Subject`, `"input"`
  or `"output"`, and its text reads `blocked the <subject>`.
- `guard`: `Message` is a new subject, one assistant message as the
  stream completes it, and `Chain.OutputGuard` and `OutputGuard` are
  the hook values for `agentturn.Config.OutputGuard`: a rewrite
  replaces the message before the transcript keeps it, and a Block
  withholds it behind a placeholder, `Withheld` unless the chain's
  `Placeholder` builds its own, that keeps the original's ID, status
  and phase. `Limit`, `Deny` and `Secrets` check a message as they do
  an input, with `message` as the noun in `Limit`'s reason; `Redact`
  rewrites one, since it is not in the transcript yet.
- `classify`: the guard classifies a `guard.Message` as output.

## v0.0.1 - 2026-09-20

- The rule grammar: `Rule` is a tool name or a name with a specifier,
  `Bash(git status:*)`, with a `Source` naming where it came from.
  `ParseRules` splits on whitespace outside parentheses, so a specifier
  may contain spaces and balanced parentheses. A specifier beginning
  with `!` is a carve-out that cancels a match of another rule in the
  same list, for the same tool, from the same source.
- `Policy` is allow, deny and ask lists and a `Default` that must be
  set with `Allow()`, `Deny()` or `Ask()`; `Build` refuses one left
  unset with `ErrNoDefault`, and a rule whose tool has no matcher
  with `ErrNoMatcher`. `Merge` unions the lists of several sources in
  rank order, stamps every rule with its source, withholds the allow
  rules of an untrusted source and lists the sources on the policy;
  `Engine.Sources` reports them.
- `Matcher` and `PrefixMatcher(field)`, and `ToolMatcher` with a
  `Subjects` splitter so one call is evaluated as several subjects. A
  subject may name another tool, as a shell redirect names the file
  tool. `Engine.Decide` folds the subjects: deny if any, ask if any,
  allow only if all. A splitter that fails blocks the call.
- `Engine.Decide` returns the loop's `ToolDecision` with precedence
  deny, ask, allow, default. The reasons the model reads are stable:
  `denied by <rule>`, `approval required by <rule>`,
  `allowed by <rule>`, `no rule allows <tool>: denied by default`,
  `no rule allows <tool>: approval required by default`,
  `allowed by default`, and `<tool> call could not be evaluated: <err>`.
  `Engine.BeforeToolCall` is the hook value.
- `Verdict` and `WithObserver`: every decision, grant, guard verdict
  and reviewer answer reaches the observer exactly once.
- `Engine.Grant` adds an allow rule and journals it. `Engine.GrantOver`
  answers the prompt an ask rule raised: it adds the allow rule and
  writes the carve-out `<tool>(!<spec>)` beside the ask rule under the
  rule's own source, or removes the rule for a bare grant, so
  `Engine.Policy` holds everything to persist. It reports why it
  cannot: over a deny rule, over an ask rule from a source that
  outranks the grant's, for a rule naming another tool, for a
  carve-out, or for a rule with no matcher.
- `Reviewer`, `Review`, `Outcome` and `Engine.Answers`: an answer
  source for deferred calls that is not a human. Every answer becomes
  an `agentturn.Answer` for `Resume`; a refusal, a timeout and a failed
  review each refuse with text the model reads, and `ErrDenialBound`
  reports Codex's bound of three consecutive refusals or ten within
  the last fifty reviews, configurable with `WithDenialBound` and reset
  with `Engine.ResetReviews`.
- Presets `Suggest`, `AutoEdit` and `FullAuto` over a `Tools` split,
  each asking by default.
- `guard`: the `Guard` contract over `Input` and `Output`, `Chain`
  with the shared observer, `BeforeModelCall` and `ShouldStopAfterTurn`
  hook values, `BlockedError`, and the deterministic guards `Limit`,
  `Deny`, `Secrets` and `Redact` with `DefaultSecrets`.
- `classify`: `New` builds a guard and `NewReviewer` a reviewer over an
  `openresponses.Streamer` with a rubric; the answer is one JSON
  object `{"allow": bool, "reason": string}` read leniently.
  `WithTimeout` makes a reviewer answer `TimedOut`; `WithRequest` sets
  the base request; `WithName` names the guard.
