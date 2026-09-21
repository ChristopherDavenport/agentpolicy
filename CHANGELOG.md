# Changelog

All user-visible changes to this library. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/); before v1.0.0 minor
versions may break the API.

## Unreleased

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
