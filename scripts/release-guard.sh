#!/usr/bin/env bash
# Checks a tag is safe to push before it is pushed. A pushed tag is
# permanent: the module proxy and the checksum database keep the version
# forever, so a mistake can only be retracted, never withdrawn.
#
#   scripts/release-guard.sh v0.0.7
#
# Exits non-zero, with the reason, if the tree is dirty, the tag already
# exists, or the version does not sort above the current release.
#
# Run it before the tag is written; make release does. Nothing is public
# until the push, so a refusal costs a git reset --hard HEAD~1 and a git
# tag -d at worst.
#
# SUBMODULES in the Makefile is empty, so every tag here is a root tag.
# The sibling repositories with nested modules carry a longer version of
# this script that also holds a <dir>/vX.Y.Z tag to its module's go.mod
# and to the root tag of the same version. Adding a nested module means
# bringing that part over and wiring it into release, which guards only
# the root tag below.

set -euo pipefail

TAG="${1:-}"

die() { echo "release-guard: $*" >&2; exit 1; }
ok()  { echo "  ok  $*"; }

[ -n "$TAG" ] || die "usage: $0 <tag>"

# Newest version wins a version sort; -V orders v0.0.9 before v0.0.10.
newest() { sort -V | tail -1; }

echo "release-guard: $TAG"

# --- Repository state -------------------------------------------------
[ -z "$(git status --porcelain)" ] || die "working tree is dirty; commit or stash first"
ok "working tree clean"

git rev-parse -q --verify "refs/tags/$TAG" >/dev/null \
  && die "tag $TAG already exists locally"
[ -z "$(git ls-remote --tags origin "refs/tags/$TAG")" ] \
  || die "tag $TAG already exists on origin"
ok "tag is new"

# --- Version moves forward --------------------------------------------
# A version that sorts below one already published is the one mistake
# this cannot be undone from: the proxy serves both forever, and nobody
# can supersede the older content.
LATEST="$(git tag -l 'v*' | newest)"
[ -n "$LATEST" ] || die "no tag found; cannot establish the version floor"

case "$TAG" in
  v*)
    [ "$(printf '%s\n%s\n' "$LATEST" "$TAG" | newest)" = "$TAG" ] \
      || die "$TAG does not sort above the current release $LATEST"
    ok "$TAG is newer than $LATEST"
    ;;

  */v*)
    die "$TAG names a nested module, and this repository has a single module.
            Release it as vX.Y.Z, or bring over the nested-module checks
            from a sibling repository's release-guard.sh first."
    ;;

  *)
    die "unrecognised tag shape: $TAG (expected vX.Y.Z)"
    ;;
esac

echo "release-guard: $TAG is safe to push"
