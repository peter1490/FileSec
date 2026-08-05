#!/usr/bin/env bash
#
# The single source of truth for release artifact names.
#
# Every packaged file this project ships is named
#
#     <bin>-<version>-<target>.<ext>
#
# and that name is composed here, once, rather than inline in each packaging
# step. It used to be composed in four separate places in release.yml and the
# copies drifted: the NSIS installer invented `x86_64-windows`, the MSI dropped
# the triple entirely, and the .deb kept cargo-deb's Debian-style default. If you
# need a new artifact, derive its name from $ARTIFACT_BASE — do not hand-write
# one.
#
# The version comes from `[workspace.package] version` in Cargo.toml (read back
# through `cargo metadata`, never grepped). On a `v*` tag this script *verifies*
# the tag matches and fails the build if it does not, which is what keeps
# Cargo.toml and the git tag from diverging the way they did between v0.2.0 and
# v0.4.2 — during which the .deb and the MSI's internal ProductVersion kept
# saying 0.2.0 while every filename said otherwise.
#
# Usage:
#
#   release-vars.sh --version
#       Print `version=<v>` (the $GITHUB_OUTPUT form). Verifies tag agreement.
#
#   release-vars.sh <variant> <target>
#       Print the KEY=VALUE lines for $GITHUB_ENV. <variant> is `classical` or
#       `pqc`; <target> is the triple used in artifact names.
#
# Both modes are runnable locally:
#
#   GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v0.4.3 \
#     bash packaging/release-vars.sh classical x86_64-unknown-linux-gnu

set -euo pipefail

die() {
    echo "release-vars.sh: $*" >&2
    exit 1
}

repo_root() {
    cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd
}

# The workspace version, and a check that no crate has drifted off it. Every
# member inherits `version.workspace = true` today; if one ever stops doing so,
# its .deb/.msi would carry a different number from its filename, so fail loudly
# rather than ship a mismatch.
cargo_version() {
    local meta versions
    meta="$(cd "$(repo_root)" && cargo metadata --no-deps --format-version 1)" \
        || die "could not run 'cargo metadata' (is the Rust toolchain installed?)"

    versions="$(printf '%s' "$meta" | jq -r '.packages[].version' | sort -u)"
    if [ "$(printf '%s\n' "$versions" | wc -l | tr -d ' ')" != "1" ]; then
        die "workspace crates disagree on their version:
$(printf '%s' "$meta" | jq -r '.packages[] | "  \(.name) \(.version)"')
All crates must inherit '[workspace.package] version' via 'version.workspace = true'."
    fi
    printf '%s' "$versions"
}

# The version this run builds under.
#
# On a tag, the tag wins the argument only in the sense that it must agree —
# Cargo.toml is authoritative and a mismatch is a hard failure, because silently
# preferring either one is how the two drifted in the first place.
#
# Off a tag (workflow_dispatch), fall back to the Cargo version. GITHUB_REF_NAME
# is the *branch* name there, so the previous `${GITHUB_REF_NAME#v}` produced
# artifacts called `filesec-main-x86_64.msi`.
resolve_version() {
    local cargo_ver tag_ver
    cargo_ver="$(cargo_version)"

    if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
        tag_ver="${GITHUB_REF_NAME#v}"
        if [ "$tag_ver" != "$cargo_ver" ]; then
            die "tag/version mismatch — refusing to build a release that would ship two version numbers.

  git tag           v$tag_ver
  Cargo.toml        $cargo_ver

Cargo.toml is the source of truth. Bump it with 'scripts/bump-version.sh $tag_ver',
commit, then re-tag."
        fi
    fi

    printf '%s' "$cargo_ver"
}

# --------------------------------------------------------------------- modes

if [ "${1:-}" = "--version" ]; then
    # Assign first, print second. `printf ... "$(resolve_version)"` would swallow
    # the failure: `set -e` does not propagate out of a command substitution used
    # as an argument, so a mismatched tag would print `version=` and exit 0 —
    # a gate that never gates.
    resolved="$(resolve_version)"
    printf 'version=%s\n' "$resolved"
    exit 0
fi

[ $# -eq 2 ] || die "usage: release-vars.sh --version | release-vars.sh <variant> <target>"

variant="$1"
target="$2"
version="$(resolve_version)"

# The matrix keys are historical: `classical` is the standard build (post-quantum
# suites compiled in, networking off) and `pqc` is the networking build. They are
# kept only so artifact names stay stable across releases. See RELEASE.md.
case "$variant" in
    classical)
        bin="filesec"
        pkg="filesec-gui"
        build_args="-p filesec-gui --bin filesec --features pqc,keyring,passkey"
        bundle_id="dev.FileSec.FileSec"
        reg_key="FileSec"
        app_name="FileSec"
        ;;
    pqc)
        bin="filesec-pqc"
        pkg="filesec-pqc"
        build_args="-p filesec-pqc"
        bundle_id="dev.FileSec.FileSec.pqc"
        reg_key="FileSec-pqc"
        # Both variants used to pass APP_NAME=FileSec, and filesec.nsi derives
        # `InstallDir "$LOCALAPPDATA\Programs\${APP_NAME}"` and the Start Menu
        # shortcut from it — so installing both builds made the second overwrite
        # the first's install directory and shortcut while leaving two separate
        # uninstall entries behind. The display name has to differ per variant.
        # Matches the WiX `Product Name` in crates/filesec-pqc/wix/main.wxs.
        app_name="FileSec PQC"
        ;;
    *)
        die "unknown variant '$variant' (expected 'classical' or 'pqc')"
        ;;
esac

case "$target" in
    universal-apple-darwin | x86_64-pc-windows-msvc | x86_64-unknown-linux-gnu) ;;
    *) die "unknown target '$target'" ;;
esac

cat <<EOF
VERSION=$version
BIN=$bin
PKG=$pkg
TARGET=$target
APP_NAME=$app_name
BUNDLE_ID=$bundle_id
REG_KEY=$reg_key
BUILD_ARGS=$build_args
ARTIFACT_BASE=$bin-$version-$target
EOF
