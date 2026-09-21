# agentpolicy

Decisions for Go agents over Open Responses: a rule grammar and engine
that becomes the loop's `BeforeToolCall`, guards over input and output
that become `BeforeModelCall`, `OutputGuard` and `ShouldStopAfterTurn`,
and an observer so every verdict is recorded. The design is in
`docs/plans/policy-layer.md`; read it before writing code. `docs/feedback.md` holds the design studies' findings against that plan; apply them to the plan before building the piece they touch.

## Module

- Module path: `github.com/ChristopherDavenport/agentpolicy`.
- Go 1.25 is the floor. The root package name is `agentpolicy`.
- The root module depends on
  `github.com/ChristopherDavenport/openresponses`,
  `github.com/ChristopherDavenport/agenttool`,
  `github.com/ChristopherDavenport/agentturn` and the standard
  library. Nothing else. `make deps` and a test enforce it.
- `guard` and `classify` are packages of the root module. The root
  package and `guard` never call a model; only `classify` takes a
  `Streamer`.
- `agentskill` is never imported. Its `allowed-tools` rules map onto
  `Rule` field for field.

## Siblings

- `../open-responses`: the wire package. Copy its conventions.
- `../agenttool`: the tool contract, for `ToolCallInfo`'s tool.
- `../agentturn`: the loop. This module produces its hook values and
  sits above it, as `tools/agent` does.
- `../agentsession`: the session format. The loop's recorder writes
  the hook's decision as the call's `decision` entry, `by` naming the
  policy; the observer's verdict, with the rule, a guard's verdict or
  a grant, is what the product writes beside it as a `custom` entry
  under `agentpolicy`.
- `../agentskill`: skills carry `allowed-tools` in this grammar.

## Conventions

Mirror `../agenttool`: a `Makefile` with `build`, `deps`, `test`,
`vet`, `fmt`, `tidy`, `tidy-check`, `lint`, `vuln`, `check` and
`release` targets, the same CI shape, a `CHANGELOG.md` in Keep a
Changelog form, annotated `v*` tags. `make check` must pass before any
commit.

Tests are table-driven and offline against the `echo` adapter. Reason
strings the model reads are asserted exactly; change them in the
changelog.
