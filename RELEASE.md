# Releasing FileSec

Phase 6 packaging. FileSec ships **two builds** from one source tree:

| Build | Binary | Cargo package | Features | Notes |
|-------|--------|---------------|----------|-------|
| **Classical** | `filesec` | `filesec-gui` | `keyring` | Default suite `0x0001`. |
| **Post-quantum** | `filesec-pqc` | `filesec-pqc` | `pqc`, `keyring` | Hybrid ML-KEM-768 / ML-DSA-65; PQC-at-rest. |

Both are built in separate `cargo build -p <package>` invocations so the
post-quantum features are never compiled into the classical binary
(see the `default-members` note in the root `Cargo.toml`).

## How a release is built

Push a version tag and GitHub Actions does the rest:

```sh
git tag v0.1.0
git push origin v0.1.0
```

[`.github/workflows/release.yml`](.github/workflows/release.yml) is the
authoritative pipeline. For each variant × OS it produces:

| OS | Installers | Portable |
|----|-----------|----------|
| macOS | `.dmg` (universal, signed + notarized) | `.tar.gz` |
| Windows | `.msi` + NSIS `…-setup.exe` (Authenticode-signed) | `.zip` |
| Linux | `.deb` | `.tar.gz` |

It then publishes every artifact plus a **`SHA256SUMS`** file to a GitHub
Release. Verify a download with:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

**Signing and notarization are gated on secrets being present.** With no secrets
configured the pipeline still completes and uploads *unsigned* artifacts — handy
on a fork. Configure the secrets below to get signed, notarized output.

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
[`packaging/windows/sign.ps1`](packaging/windows/sign.ps1) with the equivalent
`signtool sign /dlib …` (Trusted Signing) invocation.

## Packaging assets

```
packaging/
  macos/package_macos.sh     # assemble .app, codesign, build .dmg, notarize, staple
  windows/filesec.nsi        # NSIS installer (variant chosen via /D defines)
  windows/sign.ps1           # Authenticode signing helper
crates/filesec-gui/packaging/filesec.desktop       # Linux .desktop (cargo-deb)
crates/filesec-pqc/packaging/filesec-pqc.desktop   #   "
```

`.deb` metadata lives in each crate's `[package.metadata.deb]`; the `.msi` is
built by `cargo-wix` (commit `crates/<pkg>/wix/main.wxs` once if you want to
customize it — the MSI step is best-effort until then).

## cargo-dist (optional, complementary)

The repo also carries a [`[workspace.metadata.dist]`](Cargo.toml) configuration
so maintainers who prefer **cargo-dist** can get its cross-platform archives,
`curl | sh` / `irm | iex` installers, and Windows MSI with published checksums:

```sh
cargo install cargo-dist          # the `dist` CLI
dist plan                         # preview what would be built
dist build                        # build archives + installers locally
dist init                         # (re)generate dist's own CI if you want it
```

cargo-dist does **not** emit `.dmg`, `.deb`, or NSIS installers — that is why
`release.yml` (which does, with signing) is the authoritative pipeline. If you
adopt dist's generated workflow, retire `release.yml` to avoid double releases.

## A note on "remember on this device"

The shipped builds enable the optional `keyring` feature: under
*My Identity → This device* a user can save their passphrase in the OS keychain
(macOS Keychain / Windows Credential Manager / Linux Secret Service) for
automatic unlock on that machine. It is off until explicitly enabled, the
passphrase always remains the recovery secret, and it can be turned off again.
See [`crates/filesec-gui/src/autounlock.rs`](crates/filesec-gui/src/autounlock.rs).
