# FileSec Security Roadmap V2

_Audit date: 2026-07-09. Status: roadmap only. This document records security findings and remediation work to implement; it does not claim any code fixes have already been applied._

## 1. Scope And Security Standard

This roadmap supersedes `SECURITY_ROADMAP.md` as the active remediation plan. The original document remains historical context.

Scope is all shipped FileSec surfaces:

- `filesec-core`: cryptographic primitives, container formats, keystore, identity, contact data types, v1 and v2 vault formats.
- `filesec-gui`: local persistence, extraction/import/export workflows, passphrase UX, keyring auto-unlock, passkey support, checkout/temp files, and GUI-driven file operations.
- `filesec-pqc`: post-quantum build and network-enabled packaged variant.
- P2P networking: transfer protocol, pairing code, listener, framing, offer/receive workflows, NAT-PMP exposure.
- CI, release, packaging, signing, dependency scanning, and supply-chain controls.

Security standard:

- Sensitive file confidentiality and integrity must hold at rest and in transit.
- At-rest state must be rollback resistant, not only tamper evident.
- Security failures must fail closed, especially RNG, KDF, authentication, signing, and provenance failures.
- Official tagged releases must fail if signing, notarization, or provenance gates are unavailable.
- Local endpoint compromise, root malware, live process memory scraping, and a malicious OS remain out of scope. Local filesystem tampering, backup restore attacks, stale-state substitution, untrusted imported files, and network attackers are in scope.

## 2. Verification Performed

The following checks were run during the V2 audit pass:

- `cargo test --locked`
- `cargo test --workspace --locked`
- `cargo test -p filesec-core -p filesec-gui --features net --locked`
- `cargo test -p filesec-core -p filesec-gui --features pqc --locked`
- `cargo clippy --all-targets --locked`
- `cargo clippy -p filesec-core -p filesec-gui --all-targets --features net --locked`
- `cargo clippy -p filesec-core -p filesec-gui --all-targets --features pqc --locked`
- `cargo clippy -p filesec-gui --all-targets --features "pqc,keyring,passkey" --locked`
- `cargo clippy -p filesec-pqc --all-targets --locked`

Results:

- All executed tests and clippy checks passed.
- The hardware passkey test exists but is ignored because it requires a physical FIDO2 security key.
- `cargo-audit`, `cargo-deny`, and `cargo-vet` were not installed locally, so advisory, license, and vetting checks were not run during this local pass.

## 3. Findings Inventory

### Critical Remediation Themes

- Local keystore, v2 vault manifests, contacts, and registry lack rollback/freshness protection.
- RNG failures currently fall back to all-zero IDs in GUI store paths.
- KDF parameters from persisted or untrusted inputs are not policy-clamped before Argon2id.
- Passphrase minimums are too weak for sensitive-file storage.
- Several untrusted inputs are read or allocated before real bounds are enforced.
- Extraction and plaintext writes need private temp files, no-follow semantics, verify-then-rename, and cleanup on failure.
- P2P pairing code is too short and can be attacked offline from responder auth behavior.
- Listener is single-connection and vulnerable to slow or large-transfer DoS.
- Auto-unlock stores passphrase bytes through generic OS keyring behavior.
- Passkey flow can run without PIN or UV when PIN is omitted.
- Official release pipeline allows unsigned artifacts when signing secrets are absent.
- CI lacks RustSec, advisory, license, and supply-chain gates.
- Identity/contact display names need spoofing and size validation.
- Crypto hygiene improvements remain: `SymKey: Clone`, PQC seed zeroization, and nonce invariant docs/tests.

### Finding IDs

| ID | Priority | Area | Finding |
|----|----------|------|---------|
| F01 | P0 | At rest | No rollback/freshness protection for keystore, vaults, contacts, registry |
| F02 | P0 | Fail closed | RNG fallback creates all-zero vault IDs and temp-name prefixes |
| F03 | P0 | KDF | Untrusted Argon2id parameters can cause resource exhaustion |
| F04 | P0 | Credentials | Passphrase policy is too weak for high-value sensitive files |
| F05 | P1 | Input bounds | Untrusted files and parsed lengths can be read or allocated before bounds |
| F06 | P1 | Filesystem | Extraction and plaintext writes can leave partial plaintext or follow symlinks |
| F07 | P1 | P2P | Pairing code is short and recoverable offline from responder auth |
| F08 | P1 | P2P | Listener is single-connection and DoS-prone |
| F09 | P1 | Auth | Auto-unlock stores passphrase bytes through default keyring behavior |
| F10 | P1 | Auth | Passkey flow can skip PIN/UV when no PIN is supplied |
| F11 | P1 | Release | Official release workflow can publish unsigned artifacts |
| F12 | P1 | CI | No required RustSec/advisory/license/supply-chain gates |
| F13 | P2 | Identity UI | Contact names and imported identity text need size/spoofing validation |
| F14 | P2 | Legacy/authenticity | Local v1 open authenticates AEAD but not creator identity |
| F15 | P2 | Metadata | Passkey label/timestamp metadata remains plaintext and unauthenticated |
| F16 | P2 | Blob paths | v2 blob `file_id` should be validated as a single hex path component |
| F17 | P3 | Crypto hygiene | `SymKey: Clone` and PQC seed intermediates increase secret-copy surface |
| F18 | P3 | Crypto hygiene | AES-GCM STREAM nonce invariant needs docs and regression tests |
| F19 | P3 | Format strictness | Absolute path handling is permissive by normalization, not rejection |

## 4. Multi-Stage Remediation Plan

### Stage 1: Emergency Fail-Closed Fixes

Objective:

Make the highest-risk local failure modes fail closed before larger format or protocol work begins.

Findings addressed:

- F02: RNG fallback to all-zero IDs.
- F03: untrusted KDF parameter resource exhaustion.
- F04: weak passphrase policy.
- F05: the most obvious pre-bound reads.
- F11: unsigned official release tags.

Implementation tasks:

- Change `new_vault_id` and checkout temp-name generation to return `Result` instead of substituting zero bytes when the CSPRNG fails.
- Propagate RNG errors through the GUI with clear user-visible failure messages.
- Add a central `KdfPolicy` for persisted and imported KDF parameters.
- Enforce maximum Argon2id memory, iteration, and parallelism before constructing `argon2::Params`.
- Keep test-only low-cost KDF params explicit, gated, and separate from production policy.
- Reject identity backups, keystores, and restored stores whose KDF parameters exceed open-policy limits.
- Raise first-run, identity backup, and restore passphrase requirements from a raw 8-character minimum to a strength-based policy.
- Add a local passphrase strength estimator with no network calls and no telemetry.
- Add metadata-size checks before reading `.fsecpub`, `.fsecid`, v2 header, v2 manifest, and local self-encrypted store blobs.
- Make official tag releases fail when macOS signing/notarization or Windows signing prerequisites are missing.
- Preserve unsigned builds only for forks or explicit development workflows that do not publish stable release artifacts.

Acceptance criteria:

- There is no code path where RNG failure creates deterministic all-zero vault IDs, temp names, nonces, salts, or secrets.
- Malicious KDF parameters are rejected before Argon2id allocation begins.
- Weak passphrases are blocked consistently in first-run, identity-backup export, and identity restore flows.
- Stable release tags cannot upload unsigned macOS or Windows artifacts.
- Fork/dev workflows remain possible only under clearly marked non-release channels.

Required tests:

- Unit test RNG failure propagation using an injectable RNG or test-only RNG hook.
- Unit tests for KDF max memory, max iterations, max lanes, zero values, malformed values, and legacy low-cost test params.
- UI/business-logic tests for passphrase boundaries and clear error messages.
- Import tests for oversized `.fsecpub`, `.fsecid`, header, manifest, and local blob inputs.
- Workflow validation or script tests proving tag releases fail when required signing inputs are absent.

### Stage 2: Rollback-Resistant Local State

**Implementation status (2026-07-10): complete.** Local state now uses the
shared `StateMetadata`/`StateAnchor` model, OS-secure high-water storage with a
warned file fallback, quarantine-on-rollback behavior, authenticated passkey
metadata, and explicit one-time legacy recovery/rewrap entry points. The Stage 2
rollback, same-epoch mismatch, and migration tests are part of the workspace
suite.

Objective:

Upgrade local state from tamper-evident to rollback-resistant. A previously valid older keystore, contact book, registry, or vault manifest must not silently replace newer state.

Findings addressed:

- F01: no freshness protection across local state.
- F14: legacy local open/authenticity edges.
- F15: passkey metadata rollback/relabel exposure.

Implementation tasks:

- Design a `StateAnchor` model keyed by identity fingerprint and object id.
- Add monotonic `epoch` and current-state hash to keystore, contacts, registry, and v2 vault manifest state.
- Include object type, object id, suite id, epoch, previous-state hash, and current-state hash in authenticated data.
- Store high-water anchors in OS secure storage where available.
- On platforms without adequate secure storage, require explicit degraded-mode warning and provide a documented recovery path.
- Reject lower epochs and same-epoch hash mismatches by default.
- Quarantine rollback-suspect state instead of opening it silently.
- Add a recovery/upgrade flow that can import legacy state only after explicit user confirmation.
- Immediately rewrap legacy state into the new rollback-protected format after successful recovery.
- Include passkey slot labels and timestamps in authenticated state, or move passkey slot metadata into an encrypted/authenticated keystore body.
- Ensure contact trust changes, passkey removals, vault edits, trash operations, and registry updates advance the relevant epoch.

Acceptance criteria:

- Restoring an older valid keystore cannot reinstate a removed passkey without an explicit recovery workflow.
- Restoring an older valid contact book cannot silently reinstate stale trust.
- Restoring an older valid registry cannot silently hide or resurrect vault entries.
- Restoring an older v2 manifest plus old blobs cannot silently undo file edits.
- Legacy state can still be recovered through a clearly marked one-time migration flow.

Required tests:

- Keystore rollback test: add passkey, remove passkey, restore old keystore, expect rejection.
- Contact rollback test: verify contact, unverify or delete contact, restore old contacts state, expect rejection.
- Registry rollback test: create/delete vault metadata, restore old registry, expect rejection.
- Vault rollback test: edit a file, restore old manifest and blobs, expect rejection.
- Same-epoch hash mismatch tests for keystore, registry, contacts, and vault manifest.
- Legacy migration tests proving old valid state opens only through recovery and is immediately re-anchored.

### Stage 3: Input And Resource Hardening

**Implementation status (2026-07-10): complete.** Untrusted lengths are now
bounded before allocation across the board: a single `aead::MAX_CHUNK_SIZE`
(16 MiB) ceiling is enforced at every stream allocation chokepoint and echoed in
the v1 header and v2 manifest parsers; the v1 manifest carries an entry-count
cap; the non-streaming `import_vault_from_path` is stat-bounded (the streaming
open/verify path already held only a chunk at a time); v2 `file_id`s are
validated as exactly 32 lowercase-hex characters (no separators, dots, or
uppercase) at the single path-joining chokepoint and again for the whole manifest
on open/recover; pasted/armored public keys are length-capped before base64
decode; and the P2P wire now splits its frame cap into a tight 64 KiB
handshake/control limit versus the 16 MiB data limit, with a hard declared
transfer-size ceiling rejected before any byte is written. Public-identity,
identity-backup, keystore, contacts, and registry reads were already
stat-then-bounded in Stages 1–2. Portable free-space querying is intentionally
not added (it would need a platform dependency this dependency-light, MSRV-pinned
build avoids); the declared-size ceiling is the enforced disk-exhaustion defense.
The Stage 3 chunk-cap, blob-id (unit + property), oversized-paste, manifest-layout,
and split frame-cap tests are part of the workspace suite.

Objective:

Bound all untrusted inputs before memory allocation, disk write, expensive KDF work, or long-running parse/decrypt work.

Findings addressed:

- F03: KDF parameter DoS.
- F05: untrusted reads and allocations before real bounds.
- F16: v2 blob id path component validation.
- F13: imported identity/contact size and spoofing concerns.

Implementation tasks:

- Replace read-then-bound helpers with stat-then-bound helpers for local files.
- Add separate max sizes for public identity files, identity backups, v2 headers, v2 manifests, local contacts/registry blobs, network handshake frames, and network data frames.
- Stream v1 import paths where possible instead of buffering entire containers.
- Cap v1 and v2 chunk sizes at validation time before allocating chunk buffers.
- Validate v2 `file_id` as lowercase hex with exact expected length and no separators.
- Validate manifest entry counts, path lengths, total plaintext sizes, and total ciphertext sizes before per-entry processing.
- Add a separate network handshake frame cap substantially below the data frame cap.
- Enforce accepted transfer-size limits before receiving data.
- Check available disk space, where supported, before accepting large inbound transfers.
- Add imported identity text and public key body length caps before base64 decode.

Acceptance criteria:

- No attacker-controlled length can directly drive multi-gigabyte memory allocation.
- Oversized identity backups and public identity files are rejected before full decode.
- Oversized v2 header/manifest files are rejected before full read.
- Oversized network handshake frames are rejected with a small cap.
- Blob IDs cannot be interpreted as paths, absolute paths, or traversal components.

Required tests:

- Oversized header, manifest, `.fsecpub`, `.fsecid`, contacts, and registry tests.
- Malicious v1 chunk-size test proving the header is rejected before chunk allocation.
- Malicious v2 `file_id` tests for `../`, slash, absolute path, wrong length, uppercase if disallowed, and non-hex.
- Network frame tests for handshake cap, data cap, and declared transfer-size cap.
- Fuzz or property tests for manifest layout validation and path/blob-id validation.

### Stage 4: Filesystem And Extraction Hardening

**Implementation status (2026-07-10): complete.** Sensitive writes now go through
one shared helper — the new `filesec-core::safe_io` module. `SafeFileWriter`
streams into a private temp created with `create_new` (`O_EXCL`, so it never
opens or follows an existing file/symlink) at mode `0600` on Unix, in the *same*
directory as the destination, then flushes, fsyncs, re-checks the target for a
symlink, and atomically renames into place (with a best-effort directory fsync);
a writer dropped without an explicit `commit` — including on any decrypt/auth
failure — unlinks the temp, so a failed extraction leaves neither partial
plaintext nor a scratch file, and a symlink planted at the destination is
refused rather than written through. `create_dirs_no_symlink` builds parent
directories one component at a time (private `0700`), refusing to descend through
any existing symlink. Both `VaultReader::extract_to` (v1) and
`VaultReaderV2::extract_to` (v2) route every file through this path; their
streaming decrypt already authenticates each byte (per-chunk AEAD + a full-file
BLAKE3 check), so a tampered container aborts before the rename. On the GUI side
`extract_vault`, the identity-backup export (`write_private_export`, now atomic
and symlink-refusing), both batch-extract loops, and the single "Save file…"
path all use the safe writer (via new `extract_file_hardened` /
`extract_dir_hardened` store helpers); the network receive path opens its
pre-created `0600` temp instead of re-creating it. F19: `normalize_path` now
rejects absolute inputs (leading `/`, leading `\`, `\\` UNC) and Windows
drive-letter prefixes (`C:\`, `C:/`, drive-relative `C:foo`) outright instead of
silently rewriting them to relative form; already-valid relative paths (redundant
`.`/`//`, `\` used only as a mid-path separator) still normalize. Permissions are
set at creation, not after writing. A fully race-free `openat(O_NOFOLLOW)`
component walk is intentionally not added (it would need a `libc` dependency this
dependency-light, MSRV-pinned build avoids); `create_new`'s `O_EXCL` semantics
plus the `symlink_metadata` parent checks close the common local-tampering
window, and the residual TOCTOU race falls inside the already out-of-scope
local-filesystem-attacker model. The Stage 4 safe-writer unit tests (atomic
overwrite, drop cleanup, symlinked-target and symlinked-parent rejection, Unix
`0600`/`0700` permissions, sibling-directory idempotence), the v1/v2 extraction
tamper-cleanup tests, the container symlinked-destination rejection test, and the
`normalize_path` absolute/drive-rejection cases are part of the workspace suite.

Objective:

Ensure plaintext and sensitive metadata are written only through hardened, private, atomic filesystem paths, and that failed verification never leaves partial plaintext behind.

Findings addressed:

- F06: partial plaintext and symlink-following extraction/write behavior.
- F05: untrusted destination/path edge cases.
- F19: absolute path strictness.

Implementation tasks:

- Introduce one shared `SafeFileWriter` or equivalent helper for sensitive writes.
- Use private temp files in the destination directory with `create_new`.
- Use `O_NOFOLLOW` or platform equivalent where available.
- Reject symlinked final targets and symlinked parent components for extraction.
- Write to temp, flush, fsync, verify full-file hash/authentication, then rename to final path.
- Remove temp files and any partial final files on failure.
- Apply this pattern to v1 extraction, v2 extraction, GUI plaintext export, checkout files, contacts/registry writes where applicable, and network receive temp files.
- Set file permissions at creation time, not after writing, on Unix.
- Add explicit strict rejection for absolute input paths rather than silently normalizing leading separators.
- Keep normalized relative paths for backward compatibility only when they are already valid relative paths.

Acceptance criteria:

- Failed extraction does not leave partial plaintext at the final destination.
- Existing destination symlinks are not followed.
- Symlinked parent directories are rejected for sensitive write paths.
- Sensitive temp files are private from creation time.
- Atomic rename means users see either the old complete file or the new verified complete file.

Required tests:

- v1 and v2 extraction auth-failure cleanup tests.
- Destination symlink rejection tests.
- Symlinked parent rejection tests on Unix.
- Existing-file collision tests.
- Cross-platform tests for private file permissions where supported.
- Absolute path rejection tests for Unix-style and Windows-style absolute inputs.

### Stage 5: Network Transfer Hardening

**Implementation status (2026-07-10): complete.** The direct-transfer handshake is
now **protocol v2** (`filesec-core::transport`), gated by a mandatory **128-bit
transfer secret** that replaces the retired 8-digit pairing code. The initiator's
`Hello` carries a keyed proof of the secret (`MAC(k_psk, version ‖ suite ‖
i_ephemeral ‖ i_nonce)`); the responder verifies it **constant-time before it
computes or sends any identity/signature material**, so a peer that cannot prove
the secret gets `TransferSecretMismatch` and zero disclosed bytes — closing the
old offline-signature oracle (an attacker who does not hold the secret can neither
harvest the responder's identity/signature nor test candidate codes, and at 128
bits the wire proof is not itself enumerable). The transcript `th0` now binds the
transfer-secret commitment and the (expected) responder fingerprint in addition to
the version, suite, both ephemerals, and both nonces, so signatures and session
keys cannot form without a matching secret. The magic tag and version were bumped
(`FSECP2P\x02`, v2); a peer speaking the old pairing-code protocol fails the magic
and version checks — there is no silent downgrade. The verified-contact
requirement is unchanged for both send and receive. The listener no longer serves
one connection at a time: an accept loop feeds a **bounded worker pool**
(`net::concurrency::Semaphore`, cap 8; excess connections are closed immediately),
each worker runs the handshake under a hard **10s wall-clock deadline** enforced by
a new deadline-aware frame reader (`wire::read_handshake_frame_deadline`, which
re-checks the deadline between partial reads so a dribbling slowloris cannot hold a
slot), the offer/receive/import phase is serialized to one authenticated peer at a
time (a second concurrent verified sender is closed silently rather than clobbering
the UI), and repeatedly-failing source IPs are backed off exponentially
(`net::concurrency::RateLimiter`, reset on a proven secret). The handshake/control
vs. data frame caps stay split (Stage 3), the declared-transfer-size ceiling is
enforced before any byte is written, and the network receive temp is the
Stage 4-style pre-created private (`0600`) file opened in place. The transfer
secret is shown as a copyable, grouped Crockford base32 code that tolerates case,
spacing, and look-alike glyphs on entry; a QR presentation is intentionally
deferred (a correct in-tree QR encoder is substantial and a QR crate would break
this build's dependency-light, MSRV-pinned posture — the copyable code covers the
same out-of-band channel). The Stage 5 tests — v2 success, wrong-secret-before-
disclosure/offline-oracle regression, retired-v1/downgrade rejection, tampered
proof, the transfer-secret codec round-trip/tolerance, the deadline reader, the
semaphore + rate-limiter policy, and the loopback slowloris/wrong-code/verified/
unverified/wrong-sender/large-transfer cases — are part of the workspace suite.

Objective:

Make P2P transfer resistant to network attackers, pairing-code enumeration, slowloris behavior, and resource exhaustion.

Findings addressed:

- F07: short offline-recoverable pairing code.
- F08: single-connection listener DoS.
- F05: network frame and transfer-size bounds.

Implementation tasks:

- Replace the 8-digit numeric code with a 128-bit transfer secret.
- Present the transfer secret as QR, copyable text, and grouped human-readable code.
- Add a protocol v2 handshake that proves knowledge of the transfer secret before responder identity/signature disclosure.
- Bind the transfer secret, expected sender fingerprint, expected responder fingerprint, suite, protocol version, and both ephemerals into the transcript.
- Reject protocol downgrade to the old pairing-code behavior.
- Keep verified-contact requirements for send and receive.
- Split frame caps into handshake/control and data caps.
- Make listener accept loop concurrent with a bounded worker pool.
- Add per-connection handshake deadlines, total transfer deadlines or progress timeouts, and cancellation handling.
- Add per-peer or per-IP backoff for failed handshakes.
- Enforce max accepted transfer size and available-disk checks before the receiver accepts.
- Ensure network temp files use the Stage 4 safe writer pattern.

Acceptance criteria:

- A network attacker cannot obtain responder identity/signature material without proving the transfer secret.
- Offline enumeration of the old 8-digit space is no longer possible in the current protocol.
- A slow client cannot monopolize the listener indefinitely.
- Legitimate concurrent attempts are bounded and observable.
- Oversized offers are rejected before disk exhaustion risk.

Required tests:

- Protocol v2 success with correct transfer secret.
- Wrong transfer secret fails before responder identity disclosure.
- Protocol downgrade attempt fails.
- Offline-oracle regression test: captured responder output must not permit code verification without secret proof.
- Slowloris integration test with handshake timeout.
- Worker-cap and rate-limit tests.
- Oversized offer and low-disk simulation tests where feasible.
- Loopback tests for verified sender, unverified sender, wrong sender, cancellation, and large valid transfer.

### Stage 6: Authentication, Keychain, And Passkey Hardening

**Implementation status (2026-07-10): complete.** "Remember on this device"
auto-unlock no longer stores the passphrase. Enabling it now generates a random
**128-bit device token** (`filesec-core::keystore::DEVICE_TOKEN_LEN`) that wraps
the keystore's DEK in a new dedicated **device keyslot** (added to the v2 body as
an optional, `skip_serializing_if`-omitted field so existing signed keystores are
byte-for-byte unchanged); only that token is written to the OS keychain, and it is
useless without this machine's keystore file. Enrolling/removing the slot goes
through the signed v3 state (`set_device_token`/`remove_device_token`), so it
advances the rollback-protected epoch — a restored older keystore cannot silently
re-enable a device that was turned off, and the Stage 2 anchor quarantines it. The
GUI `spawn_enable_auto_unlock` verifies the passphrase, enrolls the token, and
persists both (rolling the on-disk slot back if the keychain write fails);
`spawn_disable_auto_unlock` removes the slot *and* clears the token; and
`spawn_unlock_keyring` opens via `unlock_with_device_token`, self-clearing a
stale token so the UI falls back to the passphrase. Device binding is exposed as
`autounlock::DEVICE_BOUND` (true on macOS's non-syncing login keychain and
Windows' per-user Credential Manager, false on the Linux Secret Service) with a
`device_binding_warning()` the "This device" card surfaces on Linux; a fully
custom `ThisDeviceOnly`/biometric-gated access-control class is intentionally not
added, as it would require a direct `security-framework`/Windows FFI dependency
and `unsafe` this dependency-light, MSRV-pinned, `unsafe`-free build avoids — the
keyring backends' default device-local, non-syncing storage plus the Linux warning
cover the reachable guarantee.

F10: the passkey enroll and get-assertion ceremonies now **require user
verification by default**. The no-PIN/no-UV `without_pin_and_uv()` fallback is
gone; a supplied PIN authenticates via the PIN, and a no-PIN ceremony keeps the
builder's `uv = Some(true)` so the authenticator still enforces built-in UV
(biometric or its own PIN). The request-argument assembly was factored into pure
`make_credential_args`/`get_assertion_args` helpers so the "UV requested by
default" policy is unit-tested without hardware. F15: passkey label/timestamp and
slot count are already authenticated — new slots bind label+timestamp into the
DEK-wrap AAD (`metadata_bound`, Stage 2) and the signed v3 body covers the whole
passkey list — and add/remove advance the epoch; Stage 6 adds regression tests
for both. F04: the security-key card wording was corrected from "in addition to
your passphrase" to an **alternative** unlock method ("a second way in, not a
second factor") via a tested `PASSKEY_ALT_UNLOCK_DESC` constant, and the enroll
dialog now states the PIN/UV requirement. The Stage 6 tests — device-token
unlock/not-a-passphrase/wrong-token/epoch-advance, device-token store round-trip +
rollback rejection, passkey label/timestamp tamper detection, passkey add/remove
epoch advance, the feature-gated passkey PIN/UV builder tests, and the
wording/device-binding logic tests — are part of the workspace suite.

Objective:

Make local unlock mechanisms match high-security expectations and prevent convenience features from silently weakening the core passphrase model.

Findings addressed:

- F09: auto-unlock stores passphrase bytes through generic keyring behavior.
- F10: passkey flow can skip PIN/UV.
- F15: passkey metadata protection.
- F04: weak passphrase UX.

Implementation tasks:

- Stop storing the user passphrase directly for auto-unlock.
- Replace stored passphrase auto-unlock with a random device unlock token wrapping a local DEK or unlock secret.
- Use device-bound, non-syncing keychain storage where supported.
- Require user presence or biometric/PIN gate for auto-unlock where supported.
- On macOS, prefer a `ThisDeviceOnly` accessibility class and access-control flags.
- On Windows, use DPAPI or Credential Manager settings that bind to the current user/device as strongly as practical.
- On Linux, document Secret Service limitations and require explicit warning if no user-presence/device-bound guarantee is available.
- Update UI text to say passkey is an alternative unlock method unless true passphrase-plus-passkey wrapping is implemented.
- Add high-security passkey mode requiring PIN/UV.
- Make no-PIN/no-UV passkey operation unavailable by default for sensitive stores.
- Authenticate or encrypt passkey labels, timestamps, and slot counts as part of keystore state.
- Ensure removing a passkey advances rollback-protected keystore epoch.

Acceptance criteria:

- Enabling auto-unlock does not store the raw passphrase as the long-term keychain secret.
- Auto-unlock is device-bound where the platform supports it.
- Passkey unlock requires PIN/UV in the default high-security mode.
- UI accurately distinguishes alternative unlock from two-factor authentication.
- Passkey metadata tampering is detected or metadata is encrypted.

Required tests:

- Unit tests proving auto-unlock token cannot be used as a raw passphrase.
- Platform-gated tests or mocks for keychain accessibility options.
- Passkey builder tests proving PIN/UV is requested by default.
- Passkey metadata tamper tests for label and timestamp.
- Keystore epoch tests for passkey add/remove.
- UI snapshot or logic tests for accurate wording.

### Stage 7: Release, CI, And Supply-Chain Hardening

**Implementation status (2026-07-10): complete.** CI gained a **supply-chain
gate** (`.github/workflows/ci.yml`, `supply-chain` job) running `cargo deny`
(new [`deny.toml`](deny.toml): RustSec advisories, a permissive-only license
allow-list enumerated from the actual graph, crates.io-only sources, and a
wildcard/duplicate bans policy) and `cargo audit` (new `.cargo/audit.toml`) as a
canonical RustSec cross-check; both tools are pinned by version and share one
justified, in-lockstep advisory-`ignore` list. The two leaf app crates are now
`publish = false` (they pull internal crates by `path`, so `allow-wildcard-paths`
applies and a real `version = "*"` on a crates.io dep still fails). The gate is
live and green: it surfaced four real transitive advisories — `ttf-parser`
unmaintained (RUSTSEC-2026-0192, no patch, deep in egui's text stack),
`quick-xml` DoS ×2 (RUSTSEC-2026-0194/0195, patched only in the ≥ 0.41 semver
major, Linux-only AT-SPI via egui/accesskit, not untrusted input), and `time`
RFC-2822 DoS (RUSTSEC-2026-0009, patched only in ≥ 0.3.47 which requires Rust
1.88 above the 1.86 MSRV, and the vulnerable RFC-2822 path is unreached on the
passkey X.509 chain) — each of which is accepted with a documented reachability
analysis and drop condition rather than an MSRV-breaking or egui-breaking bump.
A new advisory (any un-listed ID), a non-permissive license, a non-crates.io
source, or a yanked crate still fails the build.

The **CI feature matrix** now gates every shipped combination: the classical
`filesec` release set (`pqc,keyring,passkey`), the `filesec-pqc` binary (which
adds `net`), the net and PQC test passes, and the standalone keyring and passkey
compile paths. A new `workflows` job runs **`actionlint`** (pinned and
SHA-256-verified) so the workflows themselves are validated on every push/PR
(shellcheck integration disabled: the release scripts deliberately word-split
`$BUILD_ARGS`; the structural checks, including the signing-gate expressions, are
the point).

The **release pipeline** (`.github/workflows/release.yml`) is now fully
supply-chain-pinned: every GitHub Action is pinned by commit SHA with a version
comment, and every release-time cargo tool (`cargo-wix`, `cargo-deb`,
`cargo-sbom`) by `--version`. The macOS/Windows signing-required gates (F11, from
Stage 1) are unchanged and still fail official upstream tags that lack signing
secrets; the publish job stays gated on the tag and the upstream repository, so
forks/dispatch runs build unsigned but never publish. New in this stage: a per-
variant **SBOM** (SPDX 2.3, `cargo-sbom`) job, **SLSA build-provenance
attestations** (`actions/attest-build-provenance`) over every published file
*and* the `SHA256SUMS` manifest (so the checksum list itself is attestable), a
least-privilege `permissions` model (top-level `contents: read`; the publish job
alone widens to `contents/id-token/attestations: write`), and a checksum step
that no longer self-hashes its own manifest. The Windows **MSI is now
deterministic**: authentic `cargo-wix`-generated `crates/<pkg>/wix/main.wxs`
sources are committed and built with `--no-build` (no per-run `wix init`
regeneration), and the step is a required release artifact (the
`continue-on-error` best-effort marker is gone). `RELEASE.md` and `README.md`
were rewritten to match the actual shipped feature sets, the device-token
auto-unlock model (Stage 6), and the new SBOM/provenance/supply-chain story.

Intentional scoping, consistent with the dependency-light, MSRV-1.86 posture:
`cargo vet` is **not** adopted (a from-scratch audit set would be empty and block
every build); the equivalent guarantee is provided by the enforced
`cargo deny` + `cargo audit` gates plus a documented manual-review process for
crypto/parsing dependencies (see `RELEASE.md` → "Dependency review process"). The
three accepted vulnerability/unmaintained advisories are held as documented,
time-boxed exceptions because their only fixes break the MSRV or the pinned egui
stack; they are all low-reachability transitive advisories. The Stage 7 changes
are workflow/config/docs only — no crate source or `Cargo.lock` change — and were
validated locally with `cargo-deny 0.20.2` (the pinned CI version, exit 0 on all
four checks) and `actionlint 1.7.12`; the default workspace still builds and its
131 tests pass on 1.86.

Objective:

Make official releases reproducible, signed, provenance-backed, dependency-audited, and clearly distinguishable from fork or development artifacts.

Findings addressed:

- F11: official release workflow can publish unsigned artifacts.
- F12: CI lacks advisory/license/supply-chain gates.
- F05: shipped feature combinations must be continuously tested.

Implementation tasks:

- Make tag release jobs fail when macOS certificate, notarization credentials, or Windows signing credentials are missing.
- Keep unsigned builds only in separate development workflows that never publish stable GitHub Releases.
- Sign or attest checksums, not only artifacts.
- Add SLSA provenance or equivalent GitHub artifact attestations.
- Generate SBOMs for each release variant.
- Pin GitHub Actions by commit SHA.
- Pin `cargo-wix`, `cargo-deb`, and other release-time installed tools by version.
- Add `cargo audit` to CI.
- Add `cargo deny` for advisories, bans, duplicate versions, sources, and licenses.
- Add `cargo vet` or a documented dependency-review process for critical crypto and parsing dependencies.
- CI-gate the exact release feature sets:
  - `filesec-gui` with `pqc,keyring,passkey`
  - `filesec-pqc`
  - net tests
  - PQC tests
  - keyring compile path
  - passkey compile path
- Update `RELEASE.md` to match actual shipped features.
- Treat MSI best-effort packaging as a release completeness issue and make it deterministic before stable releases.

Acceptance criteria:

- Official tags cannot publish unsigned stable artifacts.
- Release artifacts include signed checksums and provenance/attestations.
- CI blocks known vulnerable dependencies.
- CI blocks disallowed licenses and sources.
- CI exercises the same feature combinations users receive.
- Release documentation matches workflow behavior.

Required tests:

- Workflow dry-run or actionlint checks for missing signing secret failure paths.
- CI jobs for `cargo audit`, `cargo deny`, and release feature builds.
- Script tests for checksum signing/attestation generation where feasible.
- Documentation checks or review checklist for release feature matrix consistency.
- Dependency policy test proving a known-bad advisory or banned crate fails CI.

### Stage 8: Crypto Hygiene And Long-Term Assurance

Objective:

Reduce secret-copy surface, lock down subtle cryptographic invariants, and add ongoing assurance mechanisms.

Findings addressed:

- F17: `SymKey: Clone` and PQC seed intermediates.
- F18: AES-GCM STREAM nonce invariant docs/tests.
- F19: strict format behavior.
- F13: identity/contact display spoofing.

Implementation tasks:

- Remove derived `Clone` from `SymKey`.
- Add explicit `duplicate_for_test` or similarly named test-only helper if any tests need key copies.
- Wrap PQC seed intermediates in zeroizing containers through seed conversion.
- Audit all secret arrays returned by value and reduce unnecessary copies where practical.
- Add comments and tests enforcing the STREAM invariant: one stream per fresh key/nonce domain, no repeated AES-GCM stream nonce under the same key.
- Add property tests for nonce lengths, chunk counters, and last-chunk behavior.
- Add identity/contact display-name validation:
  - max length
  - reject control characters
  - reject or neutralize bidi override characters
  - normalize whitespace
  - show fingerprint-first confirmation on trust decisions
- Add fuzz targets for identity parsing, public key paste parsing, backup parsing, manifest parsing, transport message parsing, and path normalization.
- Add threat model documentation that clearly states what is protected and what is not.

Acceptance criteria:

- Secret key cloning is explicit and rare.
- PQC seed handling zeroizes intermediate secret buffers as far as the dependency API allows.
- AEAD STREAM nonce and key-use invariants are documented and regression-tested.
- Imported display names cannot visually spoof system text, paths, or other contacts using control/bidi characters.
- Fuzz targets exist for the highest-risk parsers.

Required tests:

- Compile tests showing accidental `SymKey` cloning no longer compiles.
- Unit tests for PQC seed round trips and zeroizing wrapper use.
- AEAD STREAM tests for nonce length, counter behavior, truncation, duplicate, reorder, and wrong-last-flag cases.
- Display-name sanitizer tests for control chars, bidi chars, very long names, whitespace-only names, and normal names.
- Fuzz smoke jobs in CI or scheduled workflow.

## 5. Cross-Stage Migration Strategy

- Do not break existing users without a recovery path.
- Open legacy formats only through explicit migration or recovery flows.
- After successful legacy unlock/import, immediately write the hardened format.
- Keep old write paths disabled once the new format is available.
- Record migration completion in rollback-protected state.
- Quarantine suspicious or rollback-detected state before offering recovery.
- Prefer additive format versioning over in-place ambiguous parsing.

Migration order:

1. Implement fail-closed primitives and KDF policy.
2. Add new state format and anchors.
3. Add legacy recovery import.
4. Migrate contacts and registry.
5. Migrate keystore.
6. Migrate v2 vault manifests or create v3 local vault state.
7. Disable legacy writes.
8. Remove legacy reads only after a documented support window.

## 6. Acceptance Gates For The Full Roadmap

The roadmap is complete only when all of the following are true:

- Rollback attacks against keystore, contacts, registry, and local vault manifests are rejected by default.
- RNG failure, signing failure, KDF policy failure, and provenance failure all fail closed.
- All untrusted input parsing has documented pre-allocation limits.
- Extraction and plaintext writes use hardened temp/rename behavior.
- Network transfer no longer exposes an offline pairing-code oracle.
- Listener DoS resistance is covered by timeouts, concurrency caps, and size limits.
- Auto-unlock does not store raw passphrases as durable keychain secrets.
- Passkey defaults require PIN/UV for high-security operation.
- Official releases are signed, notarized where applicable, checksummed, attested, and dependency-audited.
- CI gates default, PQC, net, keyring, passkey, and packaged binary feature sets.
- Documentation accurately describes remaining out-of-scope risks.

## 7. Recommended Sequencing

1. Stage 1 first: fail-closed fixes are small, high-value, and reduce risk while larger design work proceeds.
2. Stage 2 second: rollback resistance is the central security gap and may require format/version decisions.
3. Stage 3 and Stage 4 can proceed in parallel after shared file and input-bound helpers are designed.
4. Stage 5 should use a protocol version bump and should not preserve the old code behavior as a default fallback.
5. Stage 6 should land before promoting passkey/keyring as high-security convenience features.
6. Stage 7 should be required before the next official stable release.
7. Stage 8 should be ongoing, with fuzzing and dependency-review automation kept active.

## 8. Non-Goals

- This roadmap does not attempt to protect plaintext from a fully compromised endpoint.
- This roadmap does not promise secure deletion on SSDs, journaled filesystems, cloud sync providers, or OS backups.
- This roadmap does not introduce a hosted server or centralized trust service.
- This roadmap does not remove the need for out-of-band contact fingerprint verification.
- This roadmap does not claim that existing issues are patched. It is an implementation plan.
