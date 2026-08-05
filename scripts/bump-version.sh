#!/usr/bin/env bash
#
# Bump the workspace version. This is the only supported way to change it.
#
# `[workspace.package] version` in Cargo.toml is the single source of truth for
# a release: it names the .deb and its control `Version:` field, the MSI's
# internal ProductVersion, the Windows .exe VERSIONINFO, and — via
# packaging/release-vars.sh — every published artifact filename. The release
# workflow refuses to build a `v*` tag that disagrees with it.
#
# Editing Cargo.toml by hand is what let it sit at 0.2.0 while tags ran to
# v0.4.2, shipping releases whose .deb and .msi disagreed with their own
# filenames. Use this instead.
#
# Usage:
#   scripts/bump-version.sh 0.4.4
#
# It stops short of committing or tagging: those stay a deliberate act, so the
# script prints the commands rather than running them.

set -euo pipefail

die() {
    echo "bump-version.sh: $*" >&2
    exit 1
}

[ $# -eq 1 ] || die "usage: scripts/bump-version.sh <version>   (e.g. 0.4.4)"

new_version="$1"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/Cargo.toml"

# Plain MAJOR.MINOR.PATCH. The release workflow's tag glob and the artifact
# naming scheme both assume no pre-release or build-metadata suffix.
case "$new_version" in
    v*) die "pass the bare version, not the tag: '${new_version#v}', not '$new_version'" ;;
esac
printf '%s' "$new_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
    || die "'$new_version' is not a MAJOR.MINOR.PATCH version"

cd "$repo_root"

[ -z "$(git status --porcelain)" ] \
    || die "the working tree is dirty — commit or stash first, so the bump lands as its own reviewable commit"

if git rev-parse -q --verify "refs/tags/v$new_version" >/dev/null; then
    die "tag v$new_version already exists"
fi

current="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')"
[ "$current" != "$new_version" ] || die "the workspace is already at $new_version"

# Rewrite only the `version` line inside the [workspace.package] table. Anchoring
# on the table header matters: a bare /^version = / would also match the
# [package] tables and any dependency stanza that happens to start a line that
# way.
awk -v new="$new_version" '
    /^\[/                  { in_wp = ($0 == "[workspace.package]") }
    in_wp && /^version = / { print "version = \"" new "\""; next }
                           { print }
' "$manifest" > "$manifest.tmp"
mv "$manifest.tmp" "$manifest"

updated="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')"
[ "$updated" = "$new_version" ] \
    || die "the rewrite did not take (Cargo.toml still reports $updated) — restore with 'git checkout Cargo.toml'"

# Cargo.lock records each workspace member's version, so it has to move too or
# every `cargo build --locked` in CI fails.
cargo update --workspace --offline >/dev/null

echo "Bumped $current -> $new_version (Cargo.toml + Cargo.lock)."
echo
echo "Next:"
echo "  git add Cargo.toml Cargo.lock"
echo "  git commit -m 'Release v$new_version'"
echo "  git tag v$new_version"
echo "  git push origin main v$new_version"
