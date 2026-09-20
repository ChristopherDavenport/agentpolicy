# Changelog

All user-visible changes to this library. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/); before v1.0.0 minor
versions may break the API.

## Unreleased

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
