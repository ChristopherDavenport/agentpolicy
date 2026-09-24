# Contributing

Issues and pull requests are welcome.

## Before you start

This library decides; it does not confine, and it does not know what
a tool does. A change that needs a shell parser, a path resolver or
an OS sandbox belongs in the product that registers the matcher. A
change that needs the loop to do something new belongs in
`agentturn`, which this module depends on and never the reverse. The
root package and `guard` never call a model; `classify` is the one
package that takes a `Streamer`.

The design is in `docs/plans/policy-layer.md` and the findings of the
design studies against it in `docs/feedback.md`. Read both before a
change larger than a bug fix, and open an issue first so the shape of
the change can be discussed.

## Development

Go 1.25 or later is required. The full local check is:

```sh
make check        # gofmt, tidy, vet, deps, staticcheck, govulncheck, race tests
```

The module depends on `openresponses`, `agenttool`, `agentturn` and
the standard library only; `make deps` and a test fail if anything
else creeps in.

## Pull requests

- Keep the change focused; unrelated cleanups belong in their own PR.
- Add or update tests. Tests are table-driven and run offline against
  the `echo` adapter.
- The reason strings the model reads are asserted exactly. Changing
  one is a user-visible change; note it in the changelog.
- Run `make check` before pushing. CI runs the same steps on the
  minimum and current Go versions.
- Note user-visible changes under *Unreleased* in `CHANGELOG.md`.

## Releases

With the changelog's *Unreleased* section written:

```sh
make release VERSION=v0.1.0
```

dates the changelog, runs `make check`, commits, guards and tags
`v0.1.0` with the changelog section as the message, and pushes the
branch and the tag in one atomic push. The release workflow publishes a
GitHub release per tag, and the Go module proxy picks the version up.
Before v1.0.0 the API may change between minor versions; the changelog
records every break.

`make release-guard TAG=<tag>` is what stands between a mistake and a
permanent one, and `make release` runs it before the tag it writes. It
refuses a dirty tree, a tag that already exists locally or on origin,
and a version that does not sort above the current release — the one
mistake nothing can undo, since the proxy and the checksum database
keep every published version forever. It runs after the release commit
and before the tag, while everything is still local, so a refusal costs
a `git reset --hard HEAD~1`.

`SUBMODULES` in the Makefile is empty, so every tag here is a root tag.
The sibling repositories with nested modules carry a longer
`release-guard.sh` that also holds a `<dir>/vX.Y.Z` tag to its module's
`go.mod`. Adding a nested module means bringing that part over and
wiring it into `release`, which guards only the root tag today.
