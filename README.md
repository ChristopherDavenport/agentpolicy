# agentpolicy

Decisions for Go agents over Open Responses: what an agent may do, and
what may enter or leave its window. One rule grammar, one engine that
becomes the loop's `BeforeToolCall`, guards that become
`BeforeModelCall`, `OutputGuard` and `ShouldStopAfterTurn`, an answer
source for the calls the engine defers, and a journal of every
verdict.

It sits above [`agentturn`](https://github.com/ChristopherDavenport/agentturn)
and produces its hook values; the loop never learns it exists. The
root package and `guard` never call a model or open a socket. Only
`classify` takes an `openresponses.Streamer`.

```sh
go get github.com/ChristopherDavenport/agentpolicy
```

## Rules

A rule is a tool name, or a name with a specifier in parentheses. It
is the grammar of a skill's `allowed-tools`, and a specifier may
contain spaces:

```go
rules, err := agentpolicy.ParseRules("read bash(git status:*) bash(npm test:*)")
```

What a specifier means belongs to the tool. A product registers a
matcher per tool that takes specifiers; `PrefixMatcher` covers the
common case, `<prefix>:*` or an exact value over one string argument.
A rule with a specifier for a tool without a matcher does not build.

A rule's tool name may be a glob, `mcp__*`, which the deny and ask
lists honour: a `*` stands for any run of characters, and nothing
folds case. A glob in the allow list does not build, since a glob
names no matcher and the reference refuses one too.

Rules a product did not write are spelled with the reference's tool
names, `Bash`, `Read`, `Edit`, and one of those names may govern
several of a product's tools. An alias table says which:

```go
agentpolicy.WithAliases(map[string][]string{
	"Bash": {"bash"},
	"Read": {"read", "grep", "glob"},
	"Edit": {"edit", "write"},
})
```

`Build` expands a rule whose name has an entry into one rule per tool,
so a skill's `allowed-tools` line and a settings file copied out of
the reference's documentation build against a product's own tools, and
`Engine.Policy` reports the rules as they are evaluated. A name with
no entry is a tool's own name and still fails closed.

## A policy

```go
policy := agentpolicy.Policy{
	Allow:   must(agentpolicy.ParseRules("read bash(git status:*) bash(npm test:*)")),
	Deny:    must(agentpolicy.ParseRules("bash(rm:*) bash(curl:*)")),
	Ask:     must(agentpolicy.ParseRules("bash(git push:*) edit")),
	Default: agentpolicy.Ask(),
}
eng, err := agentpolicy.Build(policy, map[string]agentpolicy.ToolMatcher{
	"bash": {Match: agentpolicy.PrefixMatcher("command"), Subjects: shell.Split},
	"edit": {Match: agentpolicy.PrefixMatcher("path")},
}, agentpolicy.WithObserver(record))

cfg.BeforeToolCall = eng.BeforeToolCall()
```

Precedence is deny, then ask, then allow, then the default, always. A
deny blocks the call with `denied by bash(rm:*)` as its error output;
an ask defers it, the run ends with the call pending, and the front
answers through `Agent.Resume`. The default must be set: a deny list
on its own never allows everything else by accident.

A deny with no specifier denies every call of its tool, so the tool is
not offered at all: the model never sees it and plans nothing around
it, as in the reference. `Engine.Filter` drops those tools from a
list, `Engine.ToolProvider` is the hook value over a list that
changes, and `Engine.Removes` names the rule for a front that shows
what a policy withheld.

```go
cfg.ToolProvider = eng.ToolProvider(mcp.Tools)
```

An ask holds its batch. When the model asks for `git add -A`,
`git commit -m wip` and `git push --force` in one turn and the policy
asks about the push, the two calls it allows are deferred too, with
`Verdict.Held` set, so nothing runs while the user reads the question.
The front asks about the calls `Engine.Deferred` reports as not held,
and `Release` answers the rest from the user's answer:

```go
answers, err := eng.Release(ctx, end, agentturn.Approve(callID).WithNote("last time"))
end, err = agent.Resume(ctx, answers...)
```

The held calls run with the approved one, in the model's order. An
answer built with `agentturn.Refuse` ends the turn instead, and the
held calls are answered with text that says so; a plain refusal lets
them run, since the policy allowed them and the model sees the one
refusal. A pending call neither the front nor the engine answers is
`ErrUnanswered`, which names it, rather than a `Resume` that fails
with nothing to say.

One engine serves every agent: what it defers is remembered under the
call's own run, so a sub-agent deciding a call while the user reads a
question costs the main agent nothing. `Release` and `Answers` forget
a call as they answer it, and `Engine.Forget(runID)` drops what an
abandoned run left behind.

When a tool's `Subjects` splits a call, a shell command into its
subcommands say, every subject is decided and the verdicts fold: the
call is denied if any subject is, asked about if any is, and allowed
only when every subject is. `git status && rm -rf /` is denied. A
subject may name another tool, so a redirect target is checked against
the file tool's rules. The splitter is the product's; there is no
shell parser here. `Verdict.Subject` is the text of the subject the
verdict was made on, so a prompt about
`npm run build && ./scripts/deploy.sh --prod` says that the deploy
script is what it is asking about.

## Where rules come from

Settings files merge rather than override:

```go
policy, err := agentpolicy.Merge(
	agentpolicy.RuleSet{Source: managed, Deny: managedDeny},
	agentpolicy.RuleSet{Source: project, Ask: projectAsk, Allow: projectAllow},
	agentpolicy.RuleSet{Source: user, Allow: userAllow},
)
policy.Default = agentpolicy.Ask()
```

Every rule carries its `Source`. An untrusted source's allow rules are
withheld while its deny and ask rules apply. A specifier beginning
with `!` is a carve-out, and it reaches only rules of a source it does
not rank below, so a repository's `read(!.env.example)` cannot open a
`read(.env:*)` an administrator denied. `Engine.Sources` reports the
sources, with their paths and hashes, so a session can name the policy
in force.

A withheld rule is kept rather than dropped: `Policy.Withheld` and
`Engine.Withheld` hold the allow rules of the untrusted sources, so a
front asking whether to trust a folder can show what trusting it would
allow. Nothing evaluates that list; trusting a source is a merge again
with `Trusted` set.

## Always allow

```go
granted, reason := eng.GrantOver(ctx, verdict, agentpolicy.Rule{Tool: "bash", Spec: "git push:*", Source: local})
```

A grant that answers a prompt the default raised is a plain allow
rule. A grant that answers a prompt an ask rule raised must also keep
that rule from firing, since precedence alone would let it ask again:
`GrantOver` writes the carve-out `bash(!git push:*)` beside the ask
rule, under the grant's own source, or removes the rule when the grant
is bare. It may only when the grant's source ranks at or above the
rule's, and it says when it cannot, so a front drops the "always"
option and offers a one-time approval instead. A carve-out cancels a
rule of any source it does not rank below, so a repository's
`read(!.env.example)` still cannot open a `read(.env:*)` an
administrator denied. A grant never beats a deny.

What a product persists is one source's rules:

```go
set := eng.PolicyOf("local") // the local settings file's rules, grants and all
```

not `Engine.Policy`, which holds every merged file's rules and would
copy the managed and project files into the local one.

## A skill's rules

A skill's `allowed-tools` is a grant with no prompt behind it, so
there is no verdict to grant over, and an appended allow rule loses to
any ask rule naming the tool. `GrantSet` activates a rule set under
its source instead:

```go
granted, refused := eng.GrantSet(ctx, agentpolicy.RuleSet{Source: skill, Allow: rules})
defer eng.Revoke(ctx, skill.Name)
```

While the set is active, its allow rules shadow the ask rules they
cover, from other sources, of equal or lower rank: the team that asks
before every `Bash` gets the `git` commands of the commit skill it
wrote, and nothing else. A rule the set cannot activate is in
`refused` with the reason, as `GrantOver` reports one, so a front can
show what the skill asked for and did not get: a bare deny for the
tool, a bare ask rule from a source that outranks the set, a source
the user has not trusted, whose allow rules go to `Engine.Withheld`.

The set is keyed by its source, so a product activates a skill when
the skill tool returns it and calls `Revoke` at the turn boundary,
rather than merging every skill's rules into the policy before the run
and granting the tools of skills the model never opened.
`Engine.Grants` reports the sets in force; `Engine.Policy` holds only
what a product persists.

## A reviewer instead of a human

```go
reviewer := classify.NewReviewer(model, "claude-sonnet-5", rubric, classify.WithTimeout(20*time.Second))
end, _ := agent.Prompt(ctx, prompt)
for end.Reason == agentturn.ReasonInputRequired {
	answers, err := eng.Answers(ctx, reviewer, end)
	if errors.Is(err, agentpolicy.ErrDenialBound) {
		break
	}
	end, _ = agent.Resume(ctx, answers...)
}
```

`Answers` gives the reviewer each call the policy asked about as the
hook saw it, with the verdict that deferred it, and returns one answer
per pending call. An approval runs the call inside the loop, with the
reviewer's `Note` after the result when it gives one; the calls held
behind it are released with it. A refusal, a timeout and a failed
review each answer with a refusal the model reads, so nothing runs
that was not approved, and the refusal tells the model not to pursue
the same outcome by another route. A call an abort cut off is not the
reviewer's to approve, since its tool may have run: it is refused with
text that says so. After three consecutive refusals, or ten within the
last fifty reviews, the refusals are built with `agentturn.Refuse`, so
resuming with them appends the outputs and ends the run without a
model call, and `ErrDenialBound` tells the front why.

## Guards

```go
chain := guard.Chain{
	Guards:   []guard.Guard{guard.Limit(1 << 20), guard.Redact(), guard.Deny(injection)},
	Observer: record,
}
cfg.BeforeModelCall = chain.BeforeModelCall()
cfg.OutputGuard = chain.OutputGuard()
cfg.ShouldStopAfterTurn = chain.ShouldStopAfterTurn()
```

An input guard sees the request's instructions beside its items, which
is where most of what enters an agent's window is: an AGENTS.md chain
read out of a checkout, a skill catalogue, a memory block the model
wrote. It may block, which fails the model call, or rewrite, which
replaces the request's input for that call, and its instructions when
the verdict carries them. An output guard sees
each assistant message as the stream completes it, before the
transcript, the record or the front's `item_end` keeps it: it may
rewrite the message or withhold it behind a placeholder, `Withheld by
deny: matched denied pattern "..."` unless the chain sets its own. A
guard over a finished turn can only stop the run, since the turn's
items are already in the transcript; it does so as a guard stop, with
a `BlockedError` wrapping `agentturn.ErrGuard` on the run's end, so a
policy stop is told from a failure. `Limit` bounds the wire size,
`Deny` matches patterns, `Secrets` blocks on a key or token and
`Redact` replaces one before the model reads it, or before a message
of the model's is kept. `classify.New` builds a guard that asks a
model with a rubric.

## The record

Every decision, hold, release, grant, guard verdict and reviewer
answer is a `Verdict` through the observer: the run, the turn, the
call, the action, the rule that fired and the reason. The decision the
hook returns is what the loop's recorder writes as the session
format's `decision` entry on the call, Block as `reject` with the
reason, Defer as `hold`, an approval on resume as `proceed`, with `by`
naming the policy. What that entry cannot carry, the rule that fired,
a guard's verdict, a grant, reaches the session through the observer,
which a product writes beside the decision as a `custom` entry under
`agentpolicy`.

## Development

```sh
make check
```

runs gofmt, `go mod tidy -diff`, vet, the dependency check,
staticcheck, govulncheck and the race tests. Tests are table-driven
and offline against the `echo` adapter. See `CONTRIBUTING.md`.
