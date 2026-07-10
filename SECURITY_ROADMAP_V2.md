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
