# Changelog

All user-visible changes to this library. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/); before v1.0.0 minor
versions may break the API.

## v0.0.13 - 2026-10-09

- Added `Subject.Constrain`, a constraint subject: it is checked
  against its tool's deny and ask rules alone, with carve-outs, grant
  sets and confinement applying to them as for any subject, so it can
  block or defer a call and never allows one. Its tool's allow rules
  and the default do not apply to it, and one no deny or ask rule
  fires for adds nothing to the fold. When it is the strictest, its
  text is the verdict's subject and a block's reason cites it as for
  any subject. A splitter that returns only constraints has the call
  itself, its own arguments under the called tool, decided before
  them. It lets a product hold one tool's calls to another tool's asks
  and denies without borrowing that tool's allows, as dax holds its
  skill tool's file reads to `read`'s rules (dax#39). RFC 0001 is
  draft 0.2, and the corpus's subjects take `constrain` (#73).

## v0.0.12 - 2026-10-09

- **Breaking**: changed `Subjects` from
  `func(args json.RawMessage) ([]Subject, error)` to
  `func(ctx context.Context, args json.RawMessage) ([]Subject, error)`.
  The engine passes the context of the decision that asked: `Decide`'s,
  `Would`'s, and, when the batch hold reads a sibling, that of the
  decision being held. A splitter that asks a remote executor what a
  call would touch is cancelled with the decision and keeps its
  deadline. An error, a cancelled context's included, blocks the call
  with the error as the reason, as before. To migrate, change
  `func(args)` to `func(_ context.Context, args)` (#71).
- Fixed: a sibling the batch hold could not read now holds the call
  beside it, and the failed reading is not kept for the batch.
  Previously a sibling whose subjects could not be evaluated, its
  splitter or a hook's rewrite failing, read as blocked and so did not
  hold the call, and a sibling whose hook failed read as asking but was
  kept, so later calls of the batch never read it again. Either failure
  may pass, as a cancelled context or a remote executor that did not
  answer does. A later call of the batch now reads the sibling again. A
  sibling a rule blocks still does not hold (#71).

## v0.0.11 - 2026-10-02

- Requires `agentturn` v0.0.16, up from v0.0.15, `agenttool` v0.0.15,
  up from v0.0.14, and `openresponses` v0.0.14, up from v0.0.12.
  agentturn v0.0.16 is the release that adds `PendingCall.Ran`,
  `RanWhere`, `Refused` and `ToolCallInfo.Parent`, which the entries
  below read.
- `Verdict.Record` writes `source_hash`, the rule's `Source.Hash`, so a
  session says which skill frontmatter or settings file a grant or a
  decision was built from and not only the source's name. Omitted
  when empty, so every existing record is unchanged (#64).
- `Engine.Answers` refuses a reviewer's approval of a call that may
  have run when its arguments differ from those the call would run
  with and the tool does not say the rewrite is `agenttool.ReplaySafe`,
  as it already refused a hook's rewrite: the model reads `The call
  was cut off before it finished and may have run; it was not run
  again.` and the verdict is `not run again: the reviewer rewrote the
  arguments, and replay is X for the rewrite`, by policy, not counted
  toward the denial bound. An approval with the dispatch's own
  arguments stands, a hook's rewrite put back included, since `Resume`
  runs those under the dispatch's key. `Resume` refused the rewrite with
  `ErrAmbiguousCall` and the whole resume failed with it (#62).
- `Engine.Answers` answers a call pending as
  `agentturn.PendingUndispatched` with an approval, by policy, reason
  `not started: decided on resume`, since agentturn's `Resume` puts it
  to `BeforeToolCall` as a run would; it refused it as never run. The
  approval is no verdict: the decision on resume is. A call the record
  says never started through `WithNeverStarted` is still refused with
  `The call was cut off before it started; it did not run.` (#52).
- `Engine.Answers` answers a call pending as `agentturn.PendingRejected`
  without the reviewer, by policy, with `The call was refused before
  it ran; it did not run.` and the verdict `not run: the call was
  refused before it ran`; it sent the call to the reviewer, and an
  approval failed the resume with `ErrCallAnswered`. When the pending
  call carries the reason the refusing decision gave,
  `agentturn.PendingCall.Refused`, the answer is `The call was refused
  before it ran; it did not run: R.` and the verdict `not run: the
  call was refused before it ran: R`, `R` the reason trimmed of space
  and of one closing full stop; the fixed text stands without one
  (#53).
- A reviewer's refusal, timeout or failure on a call that may have run
  tells the model so: the output begins `The call was cut off before
  it finished and may have run; it was not run again.` and the timeout
  and failure texts no longer say the call did not run, reading `The
  reviewer did not answer in time.` and `The reviewer could not
  evaluate the call.` after it. Every refusal, timeout and failure
  `Answers` builds, and the refusal `Release` gives a held call when
  the turn was stopped, now carries the verdict's reason as
  `agentturn.Answer.Reason`, so the session's answer decision says why
  (#51).
- `Engine.Answers` answers a call that may have run, a deferred call
  held after its dispatch included, with the output the loop's pending
  call carries from where it ran, `agentturn.PendingCall.Ran`, on a
  branch a rebase left or in the session this one forks: by policy,
  with `RanWhere` as the reason, `ran elsewhere` when it is empty,
  before the reviewer and before the replay rule, as agentturn/session's
  `ReplayAnswers` answers an aborted one. It is read from `Ran` being
  set, not from `RanWhere`'s words, and such a call was refused as one
  that may have run, reviewed, or dispatched again. There is no
  `WithRan`: the option that stood in for the loop's word until it
  carried the output was removed before any release shipped it, since
  agentturn/session's `Pending` is the one reader of the record, and a
  second source would need a rule for when the two disagree (#63).
- `Engine.Decide` remembers no deferral for a nested call, one a tool
  made with `agentturn.Invoke`, whose `ToolCallInfo.Parent` is the
  call that made it. The verdict is still reported, but the loop
  settles the call inline with the invoking tool's elicitor and it
  never ends the run pending, so nothing would answer it and
  `Engine.Deferred` and `Engine.Runs` kept it until the run was
  forgotten (agentturn#208).
- `ContextWithGrantScope` and `GrantScopeFromContext`: a grant set is
  activated under the scope its context carries, a decision consults
  the unscoped sets and those of its own context's scope, and
  `Engine.Revoke` removes the set of its context's scope alone;
  `Engine.RevokeScope` removes every set of a scope when a conversation
  ends, journaled as `revoked the rules granted under S`, or `revoked
  the rules granted without a scope`, and `Engine.GrantsFor` lists the
  sets a decision consults. A context with no scope is the unscoped
  one, where a set decides every call as before; a context derived
  from a scoped one carries the scope, so a sub-agent run from a tool
  call is decided under its parent's scope unless its context is given
  one of its own. `Engine.ToolProvider` reads the scope of the context
  the loop consults it with; `Engine.Filter` and `Engine.Removes`,
  which take none, read the unscoped sets (#18).
- `WithToolsFor` is `WithTools` with the decision's context, so a
  lookup answers for the run whose batch is decided, through
  `agentturn.RunIDFromContext`; `Engine.Answers` puts the ended run's
  ID on the context when the caller's carries none (#43).
- `Policy.WithDefault` replaces a policy's default, so a host whose
  tools are discovered at run time says in one documented place what
  a tool a preset's split never named gets; each preset's doc says
  what that trades (#16).
- `Engine.Would` reports the verdict `Decide` would give a call, from
  the same rules, grants, confinement and hooks, without the batch
  hold, without remembering a deferral and without a verdict reaching
  the observer, so a front shows which rule will match before the
  call is made and a kit tells a call the policy allows on its own
  from one only a grant allowed, without re-deriving the precedence
  from `Engine.Policy` and `Engine.Grants` (agentkit#76).
- `guard.Redact` over a finished turn reads only the items that are
  not messages, since the messages were its to rewrite on
  `OutputGuard` and the output holds them as the model said them; it
  stopped the run on a secret it had already removed (#17).
- `guard.Output` carries `Final` from the loop's `TurnInfo`, so a
  guard over the answer passes a turn that only called tools; the
  `Chain` and package docs say the two output hooks see the same
  words, and the example wires a chain per hook. `classify.New`'s
  guard passes a `guard.Output` that is not final without a model
  call, since a turn of tool calls is not what the user will read and
  billed for a classification of each; `classify.WithEveryTurn` judges
  every turn as before (#20).
- `Chain.Placeholder` is handed the message as the guards before the
  blocking one left it, not as the model produced it, so a redaction
  ahead of a block is not undone in what the front shows (#22).
- RFC 0001: the answers without a human state every change above; the
  grant scope, the context on the sibling lookup and the preset's
  default are in their sections; the verdict record gains
  `source_hash`; the output subject says whether the turn is final;
  #16, #17, #18, #20, #22, #43 and #51 to #53 leave the open
  questions, and what the loop's pending call does not yet carry
  (#53, #63) enters them.

## v0.0.10 - 2026-10-01

- Requires `agentturn` v0.0.15, up from v0.0.13, and `agenttool`
  v0.0.14, up from v0.0.12. Neither changes what this module does.
  Under v0.0.15 a nested call the policy defers is put to the
  invoking tool's elicitor rather than refused; the engine still
  remembers it as deferred until `Engine.Forget`, since a nested
  call's `ToolCallInfo` does not say it is one.
- `Engine.Answers` decides a cut-off call on the arguments it would
  run again with, those of the dispatch it repeats on
  `PendingCall.Args`, where it decided the model's while `Resume` ran
  the dispatch's. A rule tightened since the first run, or a
  reviewer's or person's rewrite, is now what the policy judges, and
  the tool's replay is read for those arguments too (#50).
- `Engine.Answers` shows a reviewer the arguments a `WithHooks` hook
  rewrote a cut-off call to, the ones its verdict is about, as it
  does for a deferred call since #54; it showed the model's (#57). A
  rewrite to other arguments whose tool does not say the rewrite is
  safe to run is refused as one that may have run, with the verdict
  `not run again: a hook rewrote the arguments, and replay is X for
  the rewrite`, since `Resume` would refuse a keyed call run again
  with other arguments under its key.
- `guard.Chain.Stop` makes a Block of `OutputGuard` stop the run as a
  guard stop: it returns a `BlockedError` with the subject `message`,
  and agentturn withholds the message and ends the run with
  `StopGuard` and `RunEnd.Withheld`, so neither the message nor the
  guard's reason reaches the caller. Without it a Block puts a
  placeholder in the message's place and the run goes on, as before
  (#58, #49).
- A guard's `Check` error that wraps `agentturn.ErrGuard` is reported
  to the chain's observer as that guard's Block, on every hook, before
  the chain returns it; its reason is a `BlockedError`'s reason, else
  the error's text. The run stopped with no verdict naming the guard
  (#58).
- `Engine.Removes`, `Engine.Filter` and so `Engine.ToolProvider` keep
  a tool offered when a carve-out of the deny list reaches its bare
  deny: one for the same tool name from a source that does not rank
  below the rule's. The model was never offered calls the policy
  allows. `Engine.GrantSet` no longer refuses an allow rule over such
  a deny, or over a bare ask a carve-out reaches, and leaves it to the
  decision (#60).
- `ParseRules` checks the parentheses over the whole string before it
  reads any token, as RFC 0001 says and agentskill does, so `Read
  Bash() git)` is refused as `unbalanced parentheses` naming `git)`
  rather than as `empty specifier` naming `Bash()`. The RFC's grammar
  section says the order plainly, and `grammar.json` holds both cases
  and one that NEL does not separate tokens (#59).
- RFC 0001: the output guard's row says what a chain that stops does
  and that an error wrapping the guard error is a guard stop; the
  answers without a human say which arguments a cut-off call is
  decided on; offering tools and the grant set's refusals say what a
  carve-out does; #50 leaves the open questions.

## v0.0.9 - 2026-10-01

- Requires `agentturn` v0.0.13, up from v0.0.12, and `agenttool`
  v0.0.12, up from v0.0.11. An approval from `Engine.Answers` of a
  call a `WithHooks` hook rewrote and deferred now runs the rewritten
  arguments, as `Release` already did for a held call: the loop keeps
  them on `PendingCall.Args` and `Approve` runs them, where it ran the
  model's.
- `Engine.Answers` shows a reviewer the arguments a `WithHooks` hook
  rewrote a deferred call to, the ones its verdict is about, where it
  showed the model's beside a verdict about the rewrite, and an
  approval with no arguments of its own runs the rewrite, as `Release`
  does for a held call. A call the engine has forgotten, deferred
  before a restart, takes the rewrite from `PendingCall.Args`. A
  reviewer was asked about a call the policy said runs confined and
  approved arguments that escaped (#54).
- The policy is written down. `docs/rfcs/0001-agent-policy.md` states
  what the doc comments carried: the rule grammar and its five errors;
  the prefix and glob matchers; subjects and how their verdicts fold;
  sources, merge, rank and the reach of a carve-out; the precedence as
  an algorithm, with every reason text; confinement; the batch hold;
  grants, grant sets and their refusals; the release and the answers
  without a human; the guard contract; and the verdict's record under
  `agentpolicy:verdict`. The Go module and its agentturn hooks are
  binding tables, and every open issue the text touches is an open
  question with its number (#12).
- `testdata/policy/` is the conformance corpus: `grammar.json`,
  `matchers.json` and `decisions.json`, the last covering precedence,
  build errors, tool-name globs, carve-outs across sources, untrusted
  sources and notes, aliases, split subjects, confinement, the batch
  hold, grant sets and the tools offered. The tests run it, and the Go
  tables it replaces are gone, so the corpus is the test (#12).
- `ParseRules` ends a specifier at the parenthesis that closes the
  first one, which must end the token. `Bash(a)(b)` read as the
  specifier `a)(b` and `Bash(a)x(b)` as `a)x(b`; both are now
  `text after the specifier`, as agentskill already refused them.

## v0.0.8 - 2026-09-29

- Requires `agenttool` v0.0.11, up from v0.0.10, and `agentturn`
  v0.0.12, up from v0.0.11.
- `Engine.Answers` decides a call it would run again under the policy
  of the moment before it approves it, with its tool's confinement and
  the `WithHooks` fold, as `Decide` does without the hold (#46). A call
  a seeded transcript left may never have been decided, since it may
  have been waiting on the user when the product stopped, and a
  `ReplaySafe` tool was run again with no one asked and a
  `run again: replay safe` verdict by the policy, whatever its ask or
  deny rule said. Now a call the policy allows is approved with the
  verdict `run again: replay safe; <the policy's reason>`, and the
  arguments a hook rewrote; one it asks about goes to the reviewer with
  the policy's verdict and counts toward the denial bound; and one it
  denies is refused with `The call was cut off before it finished and
  may have run; it was not run again. Denied by policy: <reason>. Do
  not pursue the same outcome through a workaround, indirect execution
  or policy circumvention.` A hook that fails reads as asking.
- Every answer `Engine.Answers` makes without a reviewer carries its
  verdict's reason as `agentturn.Answer.Reason`, so the session's
  recorder writes it on the `proceed` or `answer` decision where it
  wrote a re-run with no decision and an answer with no reason (#44).
- Arguments a `WithHooks` hook rewrites are decided again, their
  confinement read from them (#47). The policy's verdict stood for
  arguments the call no longer had, so a hook that took a confined
  call out of its sandbox ran it unconfined with no prompt, the verdict
  saying `confined by ...`, and a hook that resolved a path skipped the
  deny rule for it. The stricter action stands; a verdict the policy
  still owns takes the rewrite's rule and reason; and
  `Verdict.Confined` is the rewrite's. The batch hold reads siblings
  the same way.
- The reason of a block on a call its `Subjects` split into several
  subjects says nothing in the command ran and names the other
  subjects: `denied by bash(rm:*) on "rm -rf scratch-old"; nothing in
  this command ran, including "ls -la"`, where it said `; the call did
  not run` and two models still reported the other half as having
  succeeded (#45).

## v0.0.7 - 2026-09-29

- Requires `agentturn` v0.0.11, up from v0.0.10, and `agenttool`
  v0.0.10, up from v0.0.9. `Engine.Answers` reads the pending states
  v0.0.11 adds: a call pending as `PendingUndispatched`, which the loop
  never handed to its tool, is refused as never run with a `not run:
  the call never started` verdict, where a call an abort cut before its
  turn read as one that may have run; a call pending as
  `PendingAnswered` is refused as one that may have run, with a `not
  reviewed: answered` verdict, and never approved, which `Resume`
  refuses with `ErrCallAnswered`; and a deferred call held after its
  dispatch is reviewed when its tool may run it again and refused with
  a `not reviewed: deferred` verdict when it may not, so an approval
  never meets `ErrAmbiguousCall`.
- `WithHooks` folds a product's own before-tool-call hooks into the
  engine's decision before the batch hold, strictest first, as
  `agentturn.ChainBeforeToolCall` folds them. A hook that defers a call
  now holds its siblings, where a hook chained after the engine let
  them run before anyone answered, and a hook that blocks a call the
  policy asked about leaves nothing held and nothing remembered, where
  it stranded the siblings on a question nobody was asked. A hook that
  makes the action stricter brings its reason and its decider; its
  note, `Terminate` and rewritten arguments reach the decision, and
  `Release` approves a held call with the arguments and the note a
  hook gave it. The engine calls a hook for a sibling of the call being
  decided, before the loop hands it that sibling's own call, so a hook
  must decide a call the same way each time; one that fails for a
  sibling reads as asking. `Decide`'s doc says a chained hook is
  outside the hold. (#38)
- `Engine.Answers` asks a cut-off call's tool whether it may run again.
  A call an abort cut off, or one found unanswered in a seeded
  transcript, whose tool says `agenttool.ReplaySafe` is approved and
  runs again, with a `run again: replay safe` verdict by the policy,
  where every such call was refused. The tool is the pending call's, or
  the one `WithTools` names for a call from a seeded transcript. A tool
  that says `ReplayKeyed` is approved, with a `run again: replay keyed`
  verdict, when the pending call carries its first run's idempotency
  key, and refused as one that may have run when it does not.
  `WithNeverStarted` tells
  `Answers` which calls the session's record shows never started, and
  those are refused with `The call was cut off before it started; it
  did not run.` and a `not run: the call never started` verdict, where
  the model read that the call may have run. (#36)
- The reason of a block on a call its `Subjects` split into several
  subjects names the subject it was for and says the call did not run:
  `denied by bash(rm:*) on "rm -rf scratch-old"; the call did not run`,
  where it was `denied by bash(rm:*)` and a model reported the other
  half as having succeeded. A call with one subject reads as before.
  (#37)
- A reviewer's refusal whose `Review.By` is `ByPolicy` reads to the
  model as `Denied by policy: ...`, where every refusal read `Denied
  by reviewer`. (#37)
- `Rule.Note` from a named source the user has not trusted is left out
  of the reason, which is what the model reads for a refused call: an
  untrusted repository's deny rule reads `denied by bash(curl:*)`
  whatever its note says, where the note was repeated to the model in
  the harness's voice. The note stays on `Verdict.Rule`. A rule the
  product built itself, with the zero `Source`, keeps its note in the
  reason. (#39)
- `Suggest` and `AutoEdit` say that confinement is one bit: under a
  sandbox that permits writes, `Suggest` allows every confined command
  `AutoEdit` does, and a product whose sandbox permits writes passes
  `WithConfinement(nil)` with `Suggest`. (#40)

## v0.0.6 - 2026-09-28

- **Breaking**: `WithObserver` adds an observer rather than replacing
  one. The engine calls every observer it was given, in the order
  given, with every verdict, where the last `WithObserver` won and
  silently dropped the others. A kit that records verdicts and a
  product that passes an observer of its own both see everything,
  whichever option comes last. A nil observer adds nothing. A product
  that passed two observers expecting the second to replace the first
  passes one. The guards' `Chain.Observer` is a single field, as
  before.

## v0.0.5 - 2026-09-28

- Dependencies: agenttool v0.0.8 to v0.0.9 and agentturn v0.0.9 to
  v0.0.10. A guard's Block from `Chain.BeforeModelCall` now stops the
  run as a guard stop, `ReasonStopped` with `StopGuard` and the
  `BlockedError` on `RunEnd.Err`, where it ended the run with
  `ReasonError`, since agentturn#116 treats an `ErrGuard` from that
  hook as it treats one from `ShouldStopAfterTurn`. A front that told
  a blocked input from a failure by `errors.Is(err, agentturn.ErrGuard)`
  on `Prompt`'s error reads `RunEnd.Err` instead. The guard docs and
  the README say so.
- **Breaking**: the engine reads confinement. A call whose tool says
  it runs confined, through `agenttool.Confined`, is not asked about by
  an ask rule with no specifier that names the called tool, as both
  references skip a bare `Bash` ask for a sandboxed command: it is
  allowed with `confined by landlock+seccomp, so bash does not ask`,
  and `Verdict.Rule` names the ask rule it skipped. A deny rule applies
  whatever the confinement, and so does an ask rule with a specifier,
  which is how a policy asks about a call that leaves the sandbox; the
  default applies as to any call, so a confined call no rule names
  still asks under `Ask()`. A subject a splitter checks against another
  tool's rules is not skipped for the shell's sandbox. A tool that
  does not implement `Confined` reads as unconfined, so nothing changes
  for it; a product whose tools do and that wants every ask to ask
  passes `WithConfinement(nil)`. `WithConfinement(fn)` replaces the
  reading, which is `agenttool.ConfinedBy` by default, and
  `Verdict.Confined` names what confined a call, on every verdict, for
  the prompt and the record. The batch hold reads the siblings'
  confinement too, so a confined `ls` beside a `read` the policy
  allows holds nothing: a sibling the hook has already been handed is
  read with its own tool, and `WithTools(set.Lookup)` names the tools
  of the ones it has not, which otherwise read as unconfined. A tool
  that says a call is confined and names nothing gives `confined, so
  bash does not ask`. The presets' docs say what a confined call does
  under them. (#25, #32)
- The batch hold keeps one reading per call of the batch, by its
  position, under a key naming the run, the turn and every call's ID,
  name and arguments, and a reading only moves toward asking. The
  count it kept before was keyed by the call IDs alone, so a provider
  that numbers its calls by position, `call_0` every turn, or another
  run on the same engine with the same IDs, could reuse a batch with no
  ask and run a call beside one that asked; a call whose ID was empty
  or repeated in its batch was read as its own sibling. Each call of a
  batch is still decided at most twice. `Release` answers a held call
  that `end.Pending` lists twice once.
- A grant set's bare deny takes the tool out of the offer.
  `Engine.Removes` and `Engine.Filter`, and `ToolProvider` over them,
  read the deny rules a decision reads, the policy's and every active
  grant set's, where they read the policy's alone and a skill's
  `disallowed-tools` refused the tool's calls one at a time while the
  model was still offered it. The tool leaves the request on the turn
  after `GrantSet` and comes back on the turn after `Revoke`. (#26, #33)
- `Engine.Release` forgets nothing when it returns `ErrUnanswered`.
  The answers returned with the error are a preview: no held call is
  forgotten and no verdict reaches the observer, so a front that
  released before every asked call was answered answers the missing
  one and releases again, where the second release found the held
  calls gone and failed naming them. (#30)
- Every answer the engine builds names its decider through
  `agentturn.Answer.By`, which the session recorder writes as the
  decision's `by`: `Release`'s approvals and refusals of held calls and
  `Answers`' refusals of cut-off calls, timeouts and failed reviews are
  `ByPolicy`, and a reviewer's approval or refusal is `Review.By`,
  `ByAgent` when unset. They were written with no decider. `Verdict.By`
  is unchanged. The README's record section says so. (#27)
- `VerdictNS`, `agentpolicy:verdict`, and `Verdict.Record() (ns
  string, data []byte)`, as `agentmemory.Manifest.Record` is, so
  agentkit and every product write a verdict under one namespace in
  one shape: a JSON object with the action as `allow`, `block` or
  `defer`, the rule as its token with its source's name and its note,
  and every empty member left out. The README showed a custom entry
  under `agentpolicy`, which no code wrote. (#31)
- `Rule.Note` says why a rule exists. `ParseRules` leaves it empty and
  the grammar is unchanged; a product's settings parser fills it. When
  set it follows the rule in the reason a decision gives, which the
  model reads for a denied call: `denied by bash(curl:*): outbound
  network is proxied; use fetch`, and likewise `approval required by`
  and `allowed by`. An alias keeps the note on every rule it expands
  to, and `GrantOver` finds the ask rule behind a verdict by its tool,
  specifier and source, so a note does not make a rule a different
  one. (#28)
- `GlobMatcher(field)` is the reference's pattern over one string
  field, beside `PrefixMatcher`: a `*` anywhere stands for any run of
  characters, `git log * main` and `* --version` match as documented,
  the space is part of the pattern so `ls *` does not match `lsof`
  while `ls*` does, and a trailing `:*` is a wildcard at a word
  boundary, a space, so `ls:*` does not match `lsof`; `:*` alone
  matches everything. Its test is the
  reference's table, on which `PrefixMatcher` still diverges in four
  rows; `PrefixMatcher` is unchanged and its doc says a settings file
  copied from the reference needs `GlobMatcher`. The path matcher's
  source-relative anchor needs the rule's source on `Matcher`'s
  signature, which is a separate change. (#29)

## v0.0.4 - 2026-09-28

- Dependencies: agenttool v0.0.7 to v0.0.8 and agentturn v0.0.8 to
  v0.0.9. No API of this module changes with them.

## v0.0.3 - 2026-09-24

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
- `Merge` keeps an untrusted source's allow rules on the new
  `Policy.Withheld` rather than dropping them, and `Engine.Withheld`
  reports them, so a front asking whether to trust a folder or a skill
  can show the user what trusting it would allow rather than only that
  something was withheld. Nothing evaluates the list: `Decide` walks
  the allow, deny and ask lists as before. (#5)
- `Engine.GrantSet` activates a rule set under its source, which is
  what a skill's `allowed-tools` needs and neither `Merge` nor
  `GrantOver` could give: there is no prompt behind a skill's rules,
  so there is no verdict to grant over, and an appended allow rule
  loses to any ask rule naming the tool, so a commit skill written by
  the very team whose settings ask before every `Bash` granted
  nothing. While a set is active its allow rules shadow the ask rules
  they cover, from other sources, of equal or lower rank; its deny and
  ask rules apply at once, trusted or not; and a grant still never
  beats a deny. Every rule is stamped with the set's source, so the
  verdict names where the permission came from. A rule the set cannot
  activate is returned as a `Refusal` with the same stable text
  `GrantOver` reports, so a front can show what a skill asked for and
  did not get. (#2, #9)
- `Engine.Revoke(source)` removes the rules a source granted, for the
  grant that lasts one turn, and `Engine.Grants` reports the sets in
  force. A set is keyed by its source name, so a product activates a
  skill when the skill tool returns it rather than merging every
  skill's rules into the policy before the run, and `Merge` no longer
  has to be given two sources with one name. `Engine.Policy` holds
  what a product persists and not the scoped grants; an engine rebuilt
  from it decides as this one does once they are revoked. (#2, #9)
- `Engine.Withheld` also reports the allow rules of a grant set from a
  source the user has not trusted. (#9)
- `Verdict.Subject` carries the text of the subject whose verdict the
  fold kept, which `Subject.Text` was written for and nothing read: a
  prompt about `npm run build && ./scripts/deploy.sh --prod` can now
  say that the deploy script is what raised the question, rather than
  naming the rule and leaving the user to guess which half of the
  command line they are approving. The reason strings are unchanged.
  (#6)
- **Breaking**: `GrantOver` stamps the carve-out it writes with the
  grant's source rather than the ask rule's, and a carve-out now
  cancels a rule of any source it does not rank below rather than only
  its own source's. A developer choosing "always allow" therefore
  writes `bash(!git push:*)` into their own settings instead of into
  the file the team shares and commits. The security property is
  unchanged, since rank is the test: a repository's
  `read(!.env.example)` still cannot open a `read(.env:*)` an
  administrator denied. A carve-out from a source that outranks a rule
  now cancels it, where before it did not. (#7)
- `Engine.PolicyOf(source)` returns one source's rules as a `RuleSet`,
  which is what a product writes back into that source's settings
  file. The README said to persist `Engine.Policy`, which holds every
  merged file's rules; doing so copied the managed and project files
  into the local one. (#7)
- `guard`: `Input` carries the request's instructions beside its
  items, and a `Verdict` may replace them. The instructions are where
  most of what enters an agent's window is, an AGENTS.md chain read
  out of a checkout, a skill catalogue, a memory block the model
  itself wrote, and no guard could see any of it: the same injection
  was blocked in a user message and passed in a repository's
  AGENTS.md, and `Limit(256)` passed a request carrying a hundred
  kilobytes of instructions. `Limit` now counts them in an input's
  size, so its reason reports a larger number for the same items;
  `Deny` and `Secrets` scan them, with the reasons unchanged; `Redact`
  rewrites them through the new `Verdict.Instructions`, which
  `Chain.BeforeModelCall` writes back to the request; and the
  `classify` guard sends them to the model with the items. A guard
  that reads only the items is unaffected. (#8)
- `Engine.SetPolicy` replaces the rules without rebuilding the
  matchers, which are the expensive half and do not change, and
  without replacing the config the loop holds, which
  `agentturn.Agent.SetConfig` refuses while a run is active. A tool an
  MCP server announces mid-session was a tool the policy had never
  heard of, so an `Ask()` default parked every call to it for an
  approval nobody would give. The new policy is validated and expanded
  as `Build` does, and the deferred calls, the scoped grants and the
  review log are untouched. A policy that cannot be re-derived covers
  the tools it has not seen with a bare name or a tool-name glob in
  the deny or ask list. (#10)
- The hold decides a batch once rather than once per call of it: the
  engine kept a per-pair pass, so the product's splitter ran ninety
  extra times on a batch of ten. The count of asking calls is cached
  for the batch and dropped whenever the rules change, so a grant made
  mid-batch is never read from a stale count.
- `Merge`'s duplicate-source error says what to do: `give each source
  its own name, "skill:<name>" for one skill of several`. A product
  with several skills more often wants `Engine.GrantSet`, which keys
  rules by source and takes them back at the turn boundary.
- The presets say what they are: approximations of Codex's three
  approval modes, not the modes themselves, since the reference pairs
  every mode with a sandbox policy and a network policy and this
  module decides without confining.
- `Verdict.By` names who decided, in the session format's words, with
  the new `ByPolicy`, `ByAgent` and `ByHuman` constants: the engine's
  own decisions are the policy's, a reviewer's answer is the
  reviewer's through the new `Review.By`, which the `classify`
  reviewer sets to `agent`, and the fail-closed answers the engine
  makes when a review times out or fails are the policy's. It is what
  an answer will carry once `agentturn.Answer` names a decider; until
  then the README says plainly that an approval on resume names
  nobody, where it used to claim the recorder writes `proceed` with
  `by` naming the policy.

- Dependencies: openresponses v0.0.9 to v0.0.12, agenttool v0.0.5 to
  v0.0.7, and agentturn v0.0.6 to v0.0.8. No API of this module changes
  with them.

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
