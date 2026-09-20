# agentpolicy

Decisions for Go agents over Open Responses: what an agent may do, and
what may enter or leave its window. One rule grammar, one engine that
becomes the loop's `BeforeToolCall`, guards that become
`BeforeModelCall` and `ShouldStopAfterTurn`, an answer source for the
calls the engine defers, and a journal of every verdict.

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

When a tool's `Subjects` splits a call, a shell command into its
subcommands say, every subject is decided and the verdicts fold: the
call is denied if any subject is, asked about if any is, and allowed
only when every subject is. `git status && rm -rf /` is denied. A
subject may name another tool, so a redirect target is checked against
the file tool's rules. The splitter is the product's; there is no
shell parser here.

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
with `!` is a carve-out, and it reaches only rules from its own
source, so a repository's `read(!.env.example)` cannot open a
`read(.env:*)` an administrator denied. `Engine.Sources` reports the
sources, with their paths and hashes, so a session can name the policy
in force.

## Always allow

```go
granted, reason := eng.GrantOver(ctx, verdict, agentpolicy.Rule{Tool: "bash", Spec: "git push:*", Source: local})
```

A grant that answers a prompt the default raised is a plain allow
rule. A grant that answers a prompt an ask rule raised must also keep
that rule from firing, since precedence alone would let it ask again:
`GrantOver` writes the carve-out `bash(!git push:*)` beside the ask
rule, under the rule's own source, or removes the rule when the grant
is bare. It may only when the grant's source ranks at or above the
rule's, and it says when it cannot, so a front drops the "always"
option and offers a one-time approval instead. `Engine.Policy` holds
everything a grant changed, so a product persists it by writing what
the policy now holds. A grant never beats a deny.

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

`Answers` gives the reviewer each deferred call as the hook saw it,
with the verdict that deferred it, and returns one answer per call. An
approval runs the call inside the loop. A refusal, a timeout and a
failed review each answer with a refusal the model reads, so nothing
runs that was not approved, and the refusal tells the model not to
pursue the same outcome by another route. After three consecutive
refusals, or ten within the last fifty reviews, `ErrDenialBound` lets
the front stop the run.

## Guards

```go
chain := guard.Chain{
	Guards:   []guard.Guard{guard.Limit(1 << 20), guard.Redact(), guard.Deny(injection)},
	Observer: record,
}
cfg.BeforeModelCall = chain.BeforeModelCall()
cfg.ShouldStopAfterTurn = chain.ShouldStopAfterTurn()
```

An input guard may block, which fails the model call, or rewrite,
which replaces the request's input for that call. An output guard can
only stop the run, since the assistant's items are already in the
transcript. `Limit` bounds the wire size, `Deny` matches patterns,
`Secrets` blocks on a key or token and `Redact` replaces one before
the model reads it. `classify.New` builds a guard that asks a model
with a rubric.

## The record

Every decision, grant, guard verdict and reviewer answer is a
`Verdict` through the observer: the run, the turn, the call, the
action, the rule that fired and the reason. A hook cannot append to
the transcript, so a product's recorder writes it beside the session.
A verdict on a call is the session format's `decision` entry on that
call: Block is `reject` with the reason, Defer is `hold`, Allow is
`proceed`, and `by` is `policy` for the engine or `agent` for a
reviewer. A guard's verdict and a grant are not a call's fate, so
they are `custom` entries under `agentpolicy`.

## Development

```sh
make check
```

runs gofmt, `go mod tidy -diff`, vet, the dependency check,
staticcheck, govulncheck and the race tests. Tests are table-driven
and offline against the `echo` adapter. See `CONTRIBUTING.md`.
