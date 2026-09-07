# FileSec security review and optimization — 2026-09-07

## Scope and assurance

This is a source-level engineering review with implemented fixes, regression tests,
dependency scanning, and bounded parser fuzzing. It is **not an independent
cryptographic audit, penetration-test certification, or a guarantee of complete
security or optimal performance**. The baseline was commit `e106018` (v0.4.3).
The fixes are recorded with this review in repository history; this review does
not publish a release.

Reviewed boundaries: imported identities and backups, CBOR decoding, KDF policy,
recipient wrapping and signature verification, v1 transport containers, v2 vault
blobs and manifests, rollback anchors, sensitive file writes and cleanup, peer
handshake/framing/cancellation, GUI file browsing, dependency policy, and CI/fuzz
configuration. Existing tests also exercise contacts, passkeys, device tokens,
classical/hybrid interoperability, migration, and UI lifecycle behavior.

Validation ran on Apple Silicon macOS. Native Windows/Linux runtime behavior,
physical FIDO2 devices, router/NAT interoperability, signed installers, prolonged
load tests, and independent analysis of the custom cryptographic protocols were
not exercised. The repository's existing threat model still applies.

## Findings and implemented changes

Severity below describes the affected boundary, not a claim that every issue is
remotely exploitable. Local path substitution generally requires control of a
user-owned output/store directory; concurrent malicious filesystem modification
remains a separate limitation.

| ID | Priority / area | Finding and resolution |
|---|---|---|
| A01 | High / dependency hygiene | Updated `webbrowser` 1.2.1 → 1.2.2 for Unix browser-argument injection; `anyhow` 1.0.102 → 1.0.103, `event-listener` 5.4.1 → 5.4.2, and `memmap2` 0.9.10 → 0.9.11 for published memory-safety issues. Replaced yanked `der` 0.8.0 with 0.8.1. |
| A02 | Medium / filesystem integrity | v2 manifest/blob writes and store metadata used predictable temporary paths, with some permissions applied after creation. They now use private, randomly named, exclusively created files, sync before commit, and clean up on failure. Checkout creation also uses exclusive creation. |
| A03 | High / data preservation | Direct exports truncated their destination before encryption succeeded. All v1 path-based export/mutation wrappers and v2 export now use atomic replacement. A failed export preserves the prior file. |
| A04 | Medium / input resource limits | Metadata checks followed by unrestricted whole-file reads could exceed the declared limit if the source grew. Shared bounded reads now check the opened handle and consume at most the limit plus one byte. GUI identity imports, store metadata, v2 metadata and in-memory v1 imports use this helper. |
| A05 | Medium / portable paths | Windows alternate streams, device names (including extensions and superscript-number variants), invalid characters, and trailing dot/space aliases were accepted. These are rejected on all platforms before use as vault paths. |
| A06 | Medium / secret lifetime | Per-file keys in v2 manifests and export plans were ordinary arrays and appeared in derived debug output. A zeroizing, redacted key wrapper now covers stored and cloned keys while preserving the exact CBOR representation. |
| A07 | Medium / integrity validation | Empty v2 files skipped their blob authentication; blob lengths and chunk-counter bounds were incomplete. Reads, exports and rekey operations now authenticate empty blobs, require the expected ciphertext length, and reject chunk-counter/size overflow. |
| A08 | High / data preservation | A file changing between pre-hashing and encryption could replace a valid old entry with data that no longer matched its manifest. Staging now checks the actual encrypted source's length and digest before altering the manifest or deleting the old blob. |
| A09 | Medium / cleanup safety | Cleanup followed symlinks and could overwrite another file; Unix hardlinks had the same issue. Cleanup now unlinks these aliases without overwriting their targets, refuses non-regular files, and propagates unexpected metadata errors. |
| A10 | Medium / network availability | Sender authentication, offer decisions and received data relied on per-read timeouts, allowing dribbled reads to retain a connection. They now enforce whole-frame deadlines and check cancellation during partial reads using short socket read timeouts. Receiver offer waiting also observes stop requests. Empty data records and nonempty completion records are rejected; receive sync errors propagate. |
| A11 | Low / parser strictness | CBOR accepted trailing data. The decoder now requires one complete value with no trailing bytes and uses an explicit nesting limit of 64. |
| A12 | High / recovery preservation | Opening an invalid v2 directory could wipe the legacy v1 copy before the new format authenticated. Cleanup of the old copy now follows successful authentication and rollback-anchor validation. |
| A13 | Medium / continuous verification | Fuzz CI selected a dated nightly but invoked a different, potentially absent `+nightly` toolchain. It now uses the installed default, validates dispatch duration through environment variables, and bounds runtime. CI has read-only default permissions, timeouts, obsolete-run cancellation, a weekly scan, and tests all release features together. Audit treats unsoundness warnings as failures. |

## Performance changes

- File browser folder counts use one pass through entries, replacing a full scan
  per displayed folder. Sorting caches folded names once per row.
- The file list renders only visible rows. A headless test exercises 10,000 rows
  and verifies bounded paint output; existing selection/sort/browser tests remain.
- Network packetization sends complete chunks from the caller's slice and reuses
  one 64 KiB partial-chunk buffer. It no longer appends a potentially large write
  and repeatedly shifts its tail with `drain`. A fragmented-input regression
  decrypts the resulting records, verifies byte-for-byte content and framing, and
  checks the packetization buffer capacity.
- Transfer progress notifications are limited to roughly ten per second plus the
  final update, reducing event queue growth and GUI repaint work.
- Import/rekey hashing is centralized at staging, avoiding a duplicate hash pass
  while adding length validation.

A reproducible optimized microbenchmark (`scripts/benchmark-browser.py e106018`)
compiles the actual before/after browser helper functions with `rustc -O`.
For 20,000 entries containing 5,000 root folders, seven-run median row preparation
was **1,000,924 µs before and 998 µs after** (about 1,003× for this deliberately
folder-heavy workload). All four sort modes and three queries produced identical
rows. This measures row preparation only, excluding encryption, I/O and painting;
it is not a claim that the whole application is 1,003× faster. Timings vary by host.

## Compatibility and operational limits

- On-disk format versions and cryptographic algorithms are unchanged. A regression
  checks that the new key wrapper serializes identically to the previous array.
- Strict decoding rejects concatenated/trailing CBOR that was previously ignored.
  Portable path enforcement rejects historical Unix-only names containing colons,
  reserved Windows names, invalid characters, or trailing dots/spaces. Such
  archives require renaming/re-export from a trusted prior copy; do not discard
  the original. Ordinary files remain covered by round-trip/migration tests.
- Size limits remain substantial (including up to 512 MiB of encrypted manifest
  metadata and 64 GiB inbound transfers). This is bounded processing, not an
  application-wide memory or free-disk quota. In-memory APIs still materialize
  content by design; prefer streaming APIs for large files.
- Filesystem protection is not a handle-relative, race-free directory walk.
  Concurrent replacement of parent directories or a file between inspection and
  opening is not fully prevented. Unix owner-only modes do not establish Windows
  ACLs; Windows inherits its parent directory's permissions.
- Case/Unicode/short-name aliases can behave differently across filesystems.
  Extraction is atomic per file, not transactional for an entire directory.
- Secure wiping cannot promise physical erasure on SSDs, snapshots, journals or
  copy-on-write filesystems. Removing a hardlink intentionally preserves the
  other linked file. Plaintext opened in external editors may leave editor copies.
- Cancellation checks cover reads and offer waiting. Blocking DNS resolution,
  connection establishment, socket writes, and a running import/encryption stage
  are not all instantly cancellable; their existing limits still apply.
- OS-backed anchors resist object rollback; the documented local-file fallback
  cannot detect restoration of the whole data directory together with its anchors.
- This review does not certify the custom peer handshake or hybrid combiner.
  Independent cryptographic review and cross-platform hostile-filesystem testing
  remain appropriate before making stronger assurance claims.

## Dependency exceptions: explicitly still present

An additional scan ran outside the project configuration to avoid hiding accepted
advisories. It found three remaining vulnerability advisories and two maintenance
notices. No new ignore entries were added.

| Package | Advisory | Remaining constraint |
|---|---|---|
| `quick-xml` 0.39.4 | RUSTSEC-2026-0194, RUSTSEC-2026-0195 | Existing exceptions on the Linux accessibility stack. Patched versions require a dependency-stack upgrade. The repository documents this as local accessibility XML, not the FileSec container/network parser. Native Linux reachability was not independently runtime-tested here. |
| `time` 0.3.41 | RUSTSEC-2026-0009 | Existing exception: fixed versions require Rust ≥1.88. This patch preserves Rust 1.86. The repository's passkey certificate path uses ASN.1 dates, not the affected RFC 2822 parser. |
| `ttf-parser` 0.25.1 | RUSTSEC-2026-0192 | Existing unmaintained dependency exception; replacing the font stack is separate work. |
| `paste` 1.0.15 | RUSTSEC-2024-0436 | Unmaintained transitive build-time macro dependency; reported by audit. |

Thus, passing the configured gates means **no unaccepted known vulnerabilities**,
not an advisory-free dependency graph. These exceptions should be revisited with
an explicit compiler/UI-stack upgrade and Windows/Linux release validation.

## Validation

| Check | Result |
|---|---|
| `cargo test --workspace --all-features --locked` | 272 passed; 0 failed; 1 hardware-dependent test ignored. Baseline: 256 passed, 1 ignored. |
| `cargo test --locked` | 205 passed; 0 failed. This overlaps the full-feature suite. |
| `cargo clippy --workspace --all-features --all-targets --locked -- -D warnings` | Passed. |
| `cargo clippy --all-targets --locked -- -D warnings` | Passed. |
| `cargo +1.86.0 check --workspace --all-features --locked` | Passed on macOS. |
| `cargo fmt --all -- --check`, `git diff --check` | Passed. |
| `actionlint -shellcheck=` | All workflows passed structural validation. Shellcheck was not run. |
| `cargo audit --deny unsound --json` (0.22.1) | Passed with existing exceptions; zero unaccepted vulnerabilities/unsoundness advisories, one unmaintained warning. |
| `cargo deny --all-features check` (0.20.2) | Advisories, bans, licenses and sources passed under the existing policy. Duplicate-version warnings remain. |
| Unfiltered audit outside project configuration | Three vulnerability advisories and two maintenance notices remain, as detailed above. |
| `python3 scripts/benchmark-browser.py e106018` | Matching output for all benchmark cases; median timings above. |

The RustSec database used by the scan was commit
`5a0ebedfe8bdd2e295b171f4162f8c977bcad9a5` (2026-09-02).

Fuzzing used `cargo-fuzz` 0.13.2, `nightly-2026-07-01`, the default sanitizer,
and `-max_total_time=20 -rss_limit_mb=2048 -timeout=10` per target. Each target
reported 21 seconds and no crash or sanitizer failure; these are smoke runs,
not exhaustive coverage or proof of parser safety.

| Target | Executions |
|---|---:|
| `identity_from_bytes` | 1,837,258 |
| `identity_from_pasted` | 1,575,320 |
| `identity_backup` | 2,145,179 |
| `manifest` | 1,744,916 |
| `transport_hello` | 393,370 |
| `normalize_path` | 1,360,968 |
| **Total** | **9,057,011** |

The loopback network tests, crypto tampering tests, rollback/migration tests,
filesystem regressions, bounded packetization test and headless browser tests
are included in the 272 full-feature tests. A native signed release was not
built or published.

## Primary references

- [RustSec browser argument-injection advisory](https://rustsec.org/advisories/RUSTSEC-2026-0257.html).
- [RustSec anyhow advisory](https://rustsec.org/advisories/RUSTSEC-2026-0190.html),
  [event-listener advisory](https://rustsec.org/advisories/RUSTSEC-2026-0221.html),
  [memmap2 advisory](https://rustsec.org/advisories/RUSTSEC-2026-0186.html).
- [Microsoft file naming rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).
- [Ciborium bounded-recursion API](https://docs.rs/ciborium/0.2.2/ciborium/de/fn.from_reader_with_recursion_limit.html).
