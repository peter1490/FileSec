# Releasing FileSec

FileSec ships **two builds** from one source tree:

| Build | Binary | Cargo package | Features | Networking |
|-------|--------|---------------|----------|-----------|
| **Standard** | `filesec` | `filesec-gui` (`--bin filesec`) | `pqc`, `keyring`, `passkey` | off |
| **Post-quantum** | `filesec-pqc` | `filesec-pqc` | `pqc`, `keyring`, `passkey`, `net` | on (direct P2P) |

Both builds compile the post-quantum suites in and both default new identities to
**classical** crypto — the historical "classical vs post-quantum" naming is kept
only so release artifact names stay stable. The functional difference today is
**networking**: `filesec-pqc` additionally enables direct, server-less
peer-to-peer transfer (`net`); `filesec` does not. Each variant is built in a
separate `cargo build -p <package>` invocation so the networking code is never
compiled into the standard binary (see the `default-members` note in the root
`Cargo.toml`).

## How a release is built

**`[workspace.package] version` in `Cargo.toml` is the single source of truth.**
Bump it with the script, then tag to match:

```sh
scripts/bump-version.sh 0.4.4
git add Cargo.toml Cargo.lock
git commit -m 'Release v0.4.4'
git tag v0.4.4
git push origin main v0.4.4
```

The workflow's first job compares the tag against `cargo metadata` and **fails
the release if they disagree**, so the two can no longer drift. They did drift
once: `Cargo.toml` sat at `0.2.0` from v0.2.0 through v0.4.2 while the tags moved
on, and because the `.deb` and the MSI's internal `ProductVersion` come from
Cargo rather than the tag, every release in that window shipped installers whose
version contradicted their own filename — which also meant the MSI could never
detect and upgrade its predecessor.

Never edit the version by hand: `scripts/bump-version.sh` also refreshes
`Cargo.lock`, without which every `cargo build --locked` in CI fails.

### What gets published

[`.github/workflows/release.yml`](../.github/workflows/release.yml) is the
authoritative pipeline. Every artifact is named by
[`packaging/release-vars.sh`](../packaging/release-vars.sh) — the one place names
are composed — as:

```
<bin>-<version>-<target>.<ext>
```

For each of the two variants (`filesec`, `filesec-pqc`):

| OS | Target | Installers | Portable |
|----|--------|-----------|----------|
| macOS | `universal-apple-darwin` | `.dmg` (signed + notarized) | `.tar.gz` |
| Windows | `x86_64-pc-windows-msvc` | `.msi`, NSIS `…-setup.exe` (Authenticode-signed) | `.zip` |
| Linux | `x86_64-unknown-linux-gnu` | `.deb` | `.tar.gz` |

So a v0.4.4 release carries, for example,
`filesec-0.4.4-x86_64-pc-windows-msvc.msi` and
`filesec-pqc-0.4.4-x86_64-unknown-linux-gnu.deb`. The publish job re-checks every
collected filename against that scheme and fails on anything that does not match,
so a new artifact cannot quietly adopt its own convention. If you add one, derive
its name from `$ARTIFACT_BASE` and extend the check deliberately.

It also generates a per-variant **SBOM** (`filesec-<ver>.spdx.json`,
`filesec-pqc-<ver>.spdx.json`; SPDX 2.3 — no target, since they describe the
dependency graph rather than a build), then publishes every artifact plus a
**`SHA256SUMS`** file to a GitHub Release. Verify a download with:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

### Package identity

The Debian package is `filesec` (not the crate name `filesec-gui`); releases up
to v0.4.2 shipped as `filesec-gui`, so it declares `provides`/`replaces`/
`conflicts` for a clean upgrade. On Windows both installers present as **FileSec**
and **FileSec PQC** — these must stay distinct, because `filesec.nsi` derives the
install directory and the Start Menu shortcut from the display name, and
`package_macos.sh` names the `.app` bundle from it. When both variants used
`FileSec`, installing one overwrote the other's install directory, shortcut, and
`.app`.

### Provenance / attestation

The publish job emits **SLSA build-provenance attestations** (via
`actions/attest-build-provenance`) for every released file *and* for the
`SHA256SUMS` manifest itself. That lets a consumer confirm an artifact was built
by this repo's workflow from this commit — verify the checksum manifest, then
verify each download against it:

```sh
gh attestation verify SHA256SUMS --repo peter1490/FileSec
gh attestation verify filesec-<ver>-universal-apple-darwin.dmg --repo peter1490/FileSec
```

### Signing is required for official tags

Signing and notarization are **mandatory** for official version tags on the
upstream repo: the macOS and Windows jobs fail (rather than upload unsigned
artifacts) if the certificate/notarization secrets are missing, and the publish
job only runs on a tag pushed to `peter1490/FileSec`. Forks and manual
`workflow_dispatch` runs may still build *unsigned* artifacts for local testing,
but they never publish a stable GitHub Release. Configure the secrets below to get
signed, notarized upstream output.

## Required secrets (signing + notarization)

These are **the maintainer's own certificates** — Apple Developer ID and a
Windows code-signing certificate. Add them under
*Settings → Secrets and variables → Actions*.

### macOS (Developer ID + notarization)

| Secret | What it is |
|--------|-----------|
| `MACOS_CERT_P12_BASE64` | Your *Developer ID Application* cert + key exported as a `.p12`, base64-encoded: `base64 -i cert.p12 \| pbcopy`. |
| `MACOS_CERT_PASSWORD` | The password you set when exporting the `.p12`. |
| `MACOS_SIGN_IDENTITY` | The identity string, e.g. `Developer ID Application: Your Name (TEAMID)` (from `security find-identity -v -p codesigning`). |

Notarization uses an **App Store Connect API key** (recommended):

| Secret | What it is |
|--------|-----------|
| `AC_API_KEY_BASE64` | The `AuthKey_XXXX.p8` API key, base64-encoded. |
| `AC_API_KEY_ID` | The key ID (the `XXXX`). |
| `AC_API_ISSUER` | The issuer UUID from App Store Connect. |

(Alternatively the script accepts `AC_APPLE_ID` / `AC_APP_PASSWORD` /
`AC_TEAM_ID` — an Apple ID with an app-specific password. Wire these into the
job env in `release.yml` if you prefer that method.)

### Windows (Authenticode)

| Secret | What it is |
|--------|-----------|
| `WINDOWS_CERT_BASE64` | Your code-signing certificate as a base64-encoded `.pfx`. |
| `WINDOWS_CERT_PASSWORD` | The `.pfx` password. |

Using **Azure Trusted Signing** or a cloud HSM/CSP instead of a local `.pfx`?
Replace the `signtool sign /f …` call in
[`packaging/windows/sign.ps1`](../packaging/windows/sign.ps1) with the equivalent
`signtool sign /dlib …` (Trusted Signing) invocation.

## Supply-chain controls

Both CI and the release pipeline are hardened against dependency and toolchain
tampering:

- **Pinned actions.** Every third-party GitHub Action is pinned by commit SHA with
  the version in a trailing comment (e.g. `actions/checkout@11bd719… # v4.2.2`).
  Bump the SHA and the comment together.
- **Pinned tools.** `cargo-wix`, `cargo-deb`, `cargo-sbom`, `cargo-deny`, and
  `cargo-audit` are installed at explicit `--version`s.
- **Advisory + license + source gate.** The CI `supply-chain` job runs
  [`cargo deny`](../deny.toml) (RustSec advisories, a permissive-only license
  allow-list, and a crates.io-only source rule) and [`cargo audit`](../.cargo/audit.toml)
  as a canonical RustSec cross-check. Run them locally with `cargo deny check`
  and `cargo audit`.
- **Workflow lint.** `actionlint` (pinned + checksum-verified) validates the
  workflow files themselves.

### Dependency review process

FileSec does not run `cargo vet` (its from-scratch audit set would be empty and
block every build); instead the review process is:

1. **Every dependency change is gated** by `cargo deny` + `cargo audit` in CI, so
   a new advisory, a non-permissive license, or a non-crates.io source fails the
   build automatically.
2. **Crypto and parsing crates get manual review.** Anything touching the crypto
   primitives (`aes-gcm`, `chacha20poly1305`, `x25519-dalek`, `ed25519-dalek`,
   `ml-kem`, `ml-dsa`, `blake3`, `argon2`, `ring`) or untrusted-input parsing
   (`ciborium`, `x509-parser`, `quick-xml`, the container/transport parsers) is
   reviewed by hand before its version is bumped, and the MSRV-1.86 pin is
   re-checked (see [`Cargo.toml`](../Cargo.toml)).
3. **License policy is explicit.** The allow-list in `deny.toml` lists every
   license currently present in the graph; adding a crate under any other license
   is a deliberate, reviewed decision.
4. **Advisory exceptions are justified and time-boxed.** The `ignore` lists in
   `deny.toml` and `.cargo/audit.toml` are kept in lockstep, and each entry
   documents the reachability analysis and the condition under which it is
   dropped. As of this writing the accepted exceptions are all
   low-reachability transitive advisories that cannot be fixed under the 1.86
   MSRV / pinned-egui constraints:
   - `RUSTSEC-2026-0192` — `ttf-parser` unmaintained (no patch; egui text stack).
   - `RUSTSEC-2026-0194` / `-0195` — `quick-xml` DoS, patched only in ≥ 0.41
     (major); Linux AT-SPI via egui/accesskit, not untrusted input.
   - `RUSTSEC-2026-0009` — `time` RFC-2822 parser DoS, patched only in ≥ 0.3.47
     which requires Rust 1.88; the vulnerable path is unreached (passkey X.509
     cert dates).

## Packaging assets

```
packaging/
  macos/package_macos.sh     # assemble .app, codesign, build .dmg, notarize, staple
  windows/filesec.nsi        # NSIS installer (variant chosen via /D defines)
  windows/sign.ps1           # Authenticode signing helper
crates/filesec-gui/packaging/filesec.desktop       # Linux .desktop (cargo-deb)
crates/filesec-pqc/packaging/filesec-pqc.desktop   #   "
crates/filesec-gui/wix/main.wxs                    # committed WiX source (deterministic .msi)
crates/filesec-pqc/wix/main.wxs                    #   "
```

`.deb` metadata lives in each crate's `[package.metadata.deb]`. The `.msi` is
built by `cargo-wix` **from the committed `crates/<pkg>/wix/main.wxs`** — the
release no longer regenerates it with `wix init` on each run, so the installer
layout is deterministic and reviewable. To regenerate the source (e.g. after a
metadata change) run `cargo wix init -p <pkg> --force` locally and commit the
result.

## cargo-dist (optional, complementary)

The repo also carries a [`[workspace.metadata.dist]`](../Cargo.toml) configuration
so maintainers who prefer **cargo-dist** can get its cross-platform archives,
`curl | sh` / `irm | iex` installers, and Windows MSI with published checksums:

```sh
cargo install cargo-dist          # the `dist` CLI
dist plan                         # preview what would be built
dist build                        # build archives + installers locally
dist init                         # (re)generate dist's own CI if you want it
```

cargo-dist does **not** emit `.dmg`, `.deb`, or NSIS installers, sign/notarize,
or produce the SBOM/provenance — that is why `release.yml` is the authoritative
pipeline. If you adopt dist's generated workflow, retire `release.yml` to avoid
double releases.

## A note on "remember on this device"

The shipped builds enable the optional `keyring` feature: under
*My Identity → This device* a user can enable automatic unlock on that machine.
Enabling it stores a random **128-bit device token** (not the passphrase) in the
OS keychain (macOS Keychain / Windows Credential Manager / Linux Secret Service);
the token wraps the keystore's data-encryption key in a dedicated device keyslot
and is useless without this machine's keystore file. It is off until explicitly
enabled, the passphrase always remains the recovery secret, and turning it off
removes both the keyslot and the token. On Linux the Secret Service has no
device-binding guarantee, so the UI shows a caveat. See
[`crates/filesec-gui/src/autounlock.rs`](../crates/filesec-gui/src/autounlock.rs).
