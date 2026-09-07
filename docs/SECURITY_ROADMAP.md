# FileSec — Security Roadmap

_Audit date: 2026-07-02 · Scope: `filesec-core`, `filesec-gui` (incl. `net`), keystore/identity, P2P transport · Method: four parallel adversarial audits (crypto primitives, container/format parsing, identity/keystore/passkey, network layer), findings independently verified against source._

---

## 1. Executive summary

The cryptographic core is **strong and correctly implemented**. Verify-before-decrypt ordering, fully AAD-bound + signed container headers (no downgrade or field-flip), a correct hybrid X25519+ML-KEM combiner, `verify_strict` Ed25519, contributory-DH checks, per-container/per-blob fresh keys, the STREAM counter/last-flag construction, `subtle` constant-time comparisons, and thorough `Zeroize`/redacted-`Debug` hygiene are all in place. **No key-recovery, nonce-reuse, downgrade, signature-strip, or path-traversal vulnerability was found.** The SIGMA-I P2P handshake (transcript binding, UKS resistance, direction separation, replay protection) is correct.

The remediation work below concentrates in three areas:

1. **Freshness / rollback integrity of at-rest state** — the dominant gap, found independently by three of four audits. This is in the documented threat model.
2. **At-rest creator authenticity** for the local vault store.
3. **Hardening**: auto-unlock keychain scoping, unbounded-parameter DoS, a pairing-code disclosure oracle, listener DoS, and a set of low-severity defense-in-depth items.

Severity is calibrated against the [README threat model](README.md#threat-model--what-is-not-protected): data **in transit and at rest** is in scope (incl. tamper-evidence); **endpoint compromise, OS remnants, and DoS are explicitly out of scope**. Out-of-model items are still listed because the goal is to make the code as safe as practical, but they are marked and deprioritized accordingly.

### Priority overview

| Phase | Theme | Items | In threat model? |
|-------|-------|-------|------------------|
| **P0** | At-rest integrity (rollback + creator authenticity) | R1, R2 | Yes |
| **P1** | Concrete hardening (localized, high-value) | R3, R4, R5 | Mostly |
| **P2** | DoS resistance | R6, R7, R8 | No (goodwill) |
| **P3** | Defense-in-depth & hygiene | R9–R18 | Mixed |
| **P-CI** | Supply-chain / process | R19 | Process |

---

## 2. Remediation roadmap

### Phase P0 — At-rest integrity (do first)

These break the "tamper-evidence at rest" property the README promises. Both change the on-disk format, so they need a format-version bump and an explicit design decision.

#### R1 · Rollback / freshness protection across all at-rest state — **Severity: Medium (High impact)**
Nothing binds a monotonic version into the authenticated state, so an attacker with filesystem write access (or a restored old backup) can substitute an **earlier, still-valid** copy undetected — the AEAD tag verifies because it is a genuine prior version. Affects three stores:

- **Keystore** — `crates/filesec-core/src/keystore.rs` (`KeystoreV1` / `KeystoreV2` carry no epoch); saved via `crates/filesec-gui/src/store.rs:172` (`save_keystore`).
  _Exploit:_ user removes a lost/stolen passkey via `remove_passkey`; attacker restores the pre-removal keystore and the removed slot is reinstated.
- **Self-encrypted store files (contacts / registry / vaults)** — `crates/filesec-gui/src/store.rs:210` (`load_blob`/`save_blob`/`save_contacts`).
  _Exploit:_ user marks a contact unverified or deletes it after a key-swap scare; attacker restores the previous `contacts.fsec` (still validly self-signed) and the stale trust state silently returns. (Cross-*file* swaps are already blocked — the blob entry name must match; only same-file rollback is exposed.)
- **v2 vault manifest** — `crates/filesec-core/src/format_v2.rs` (`reseal_manifest`, `VaultHeaderV2` has no counter; `vault_id`/`created_at` are static).
  _Exploit:_ user edits a file to redact secrets (new blob written, old deleted); attacker who snapshotted `manifest` + `blobs/` copies both back and the un-redacted content returns.

**Fix:** add a monotonic `epoch: u64` to each header; bind it into the AEAD AAD; persist the last-seen epoch in a location the attacker cannot also roll back (OS keychain entry, or a separate high-water-mark). Reject any open whose epoch is below the last seen.
**Effort:** M–L (format change + migration). **Decision needed:** where to anchor the high-water-mark.

#### R2 · Local vault open verifies confidentiality but not creator authenticity — **Severity: Medium (High impact)**
`crates/filesec-core/src/format.rs:1555` — `open_vault_from_path` calls `open_reader_inner(..., None)`; the `None` hasher means **no signature over who created the vault is verified**. Because the manifest/content key is wrapped to the owner's **public** key, anyone who knows that public key + has filesystem write access can fabricate a vault of attacker-chosen files that opens with every tag valid and no tamper indication. (The received-from-peer path is safe — it uses `verify_and_open` and checks the sender fingerprint; only the local-store open skips it.)

**Fix:** MAC or self-sign local vaults with a key only the owner holds (e.g. derived from the keystore DEK) and verify it on open.
**Effort:** M. **Decision needed:** key to authenticate with; pairs naturally with R1.

---

### Phase P1 — Concrete hardening (localized, high-value)

#### R3 · Auto-unlock keychain item not device-scoped, no user-presence gate — **Severity: Medium**
`crates/filesec-gui/src/autounlock.rs:75` — `keyring::set_secret` uses the backend default accessibility. On macOS that is `kSecAttrAccessibleWhenUnlocked` (**not** `…ThisDeviceOnly`), so the stored passphrase can propagate to iCloud Keychain / backups, and there is no `SecAccessControl`/biometric requirement. With auto-unlock on, `spawn_unlock_keyring` (`app.rs:2062`) opens the keystore from one keychain read, entirely bypassing the Argon2id passphrase KDF — so the accessibility class is the whole security boundary.
**Fix:** request `WhenUnlockedThisDeviceOnly` (and platform equivalents) + a user-presence/biometric `SecAccessControl`; document that enabling auto-unlock bypasses the passphrase KDF.
**Effort:** S–M (backend-specific). **In model:** yes (backups are listed).

#### R4 · Untrusted Argon2 parameters → OOM/abort DoS — **Severity: Medium** _(verified)_
`crates/filesec-core/src/kdf.rs:34` (`derive_master_key`) applies caller-supplied params with no bounds; `crates/filesec-core/src/keystore.rs:417` (`import_identity_armored`) feeds `m_cost`/`t_cost`/`p_cost` straight from an untrusted `.fsecid` file. A few-hundred-byte file declaring `m_cost` ≈ 256 GiB makes Argon2id attempt the allocation **before** the passphrase is checked → process abort. Same applies to a tampered keystore on unlock.
**Fix:** clamp `m_cost`/`t_cost`/`p_cost` to sane min/max on every import/load path before calling Argon2.
**Effort:** S. **Note:** a *weak*-parameter downgrade is already safe (params are AEAD-bound → wrong key → `BadPassphrase`); only the *oversized* case is the issue.

#### R5 · Pairing code is offline-recoverable by any unauthenticated peer — **Severity: Medium**
`crates/filesec-core/src/transport.rs:580` — the responder answers any well-formed `Hello` with an Ed25519 signature over `th0`, and `th0` folds the pairing-code commitment (`mod.rs:255` — 8 decimal digits ≈ 2²⁶·⁶). Ed25519 verification is public and every other `th0` input is attacker-known, so one `Hello`/`Auth` exchange yields an offline oracle to enumerate all 10⁸ codes in minutes — **with no identity required**. This contradicts the module doc ([transport.rs:60](../crates/filesec-core/src/transport.rs)), which claims the code is only guessable by someone who already holds a verified identity. Impact is bounded (the code is a layered second factor over the public-key identity gate, not a standalone authenticator).
**Fix:** gate the `Auth` reply behind a code commitment carried in `Hello` that the responder checks before replying; or correct the documentation and stop treating the code as network-attacker-resistant.
**Effort:** M (protocol change) or S (docs). **Decision needed:** is the code meant to resist a network attacker?

---

### Phase P2 — DoS resistance (out of documented model; goodwill hardening)

#### R6 · Listener is single-threaded + blocking, no rate limit — **Severity: Medium (DoS)**
`crates/filesec-gui/src/net/listener.rs:77` — one connection is processed to completion before the next `accept()`; `read_frame`'s `read_exact` enforces the 30 s timeout *per syscall* (`wire.rs:27`), so a byte-every-<30 s slowloris holds the sole thread indefinitely and denies the receive capability. No per-IP limit also enables unlimited handshake retries (compounds R5).
**Fix:** non-blocking/concurrent accept with a connection cap and per-IP handshake backoff.
**Effort:** M.

#### R7 · Unbounded allocations from attacker-controlled lengths — **Severity: Low (DoS)**
- `crates/filesec-core/src/aead.rs:165` (`read_chunk`) allocates `vec![0u8; chunk_size]` where `chunk_size` comes from the header `data_chunk_size: u32` (checked non-zero only, `format.rs:712`) → up to ~4 GiB. Reached only after `sign::verify` in the import path, hence Low.
- `crates/filesec-core/src/format_v2.rs:842` (`read_bounded`) reads the **whole** file into RAM before applying the size cap.
- `crates/filesec-core/src/format.rs:951` (`import_vault_from_path`) buffers the entire container before bounds run.
- `crates/filesec-gui/src/net/listener.rs:240` — `Offer.size` is an unbounded `u64`; on accept, `receive_into` writes until the declared size or disk exhaustion.
- `crates/filesec-gui/src/net/wire.rs:28` — pre-auth frame buffer up to 16 MiB (`MAX_FRAME`).

**Fix:** stat-then-bound (don't read-then-bound); cap `data_chunk_size` at header validation (e.g. a few MiB); cap accepted `Offer.size`; use a smaller handshake-phase frame cap distinct from the data cap.
**Effort:** S each.

#### R8 · Failed mid-file extraction leaves partial plaintext on disk — **Severity: Low**
`crates/filesec-core/src/format.rs:1082` (`extract_to`) and `format_v2.rs:389`. Each chunk is AEAD-authenticated before its bytes are written (no *forged* plaintext is ever released — correct), but the whole-file BLAKE3 is verified only after the last chunk, and on failure the partially written output is not removed.
**Fix:** extract to a temp path and rename on success, or unlink the output on error.
**Effort:** S.

---

### Phase P3 — Defense-in-depth & hygiene (Low / Info)

| ID | Finding | Location | Fix |
|----|---------|----------|-----|
| **R9** | Imported contact display name unvalidated/unbounded → UI spoofing (RTL-override/control chars). Keys can't be substituted (name excluded from fingerprint); UI deception only. | `identity.rs:30`, `contacts.rs:84`, rendered `app.rs:3956` | Clamp length; strip control/bidi chars on import. |
| **R10** | RNG-failure fallback to all-zeros id/temp name → collision; `save_vault` `remove_dir_all`s the path, so two zero-ids overwrite. | `store.rs:687`, `store.rs:491` | Fail closed (propagate the RNG error). |
| **R11** | Keystore temp uses fixed name, no `O_EXCL`/`O_NOFOLLOW` → symlink-follow (needs same-user malware — out of model). | `store.rs:832`, `open_private_create` `store.rs:802` | Use `create_new` + `O_NOFOLLOW`. |
| **R12** | Extraction follows a pre-existing symlink at the destination target. | `format.rs:1091`, `format_v2.rs:396` | `create_new`/`O_NOFOLLOW` semantics on output. |
| **R13** | Secret-seed zeroization gaps: intermediate copies (`Array::from`, `random_array` return-by-value) not wiped; `SymKey: Clone` allows silent duplication. | `mlkem.rs:47`, `mldsa.rs:38`, `secret.rs:43`, `secret.rs:16` | Wrap intermediates in `Zeroizing`; gate `SymKey` cloning behind an explicit method. |
| **R14** | Passkey slot `label`/`added_at` are plaintext and outside the wrap AAD (security-critical fields *are* bound + tested). Metadata tamper/relabel + enrolled-key count leak. | `keystore.rs:441`, AAD `keystore.rs:205` | Bind `label`/`added_at` into the AAD; consider encrypting the slot list. |
| **R15** | `blob file_id` used as a path component with no hex validation; only manifest authentication prevents a `../` id. | `format_v2.rs:294` | `file_id.chars().all(is_ascii_hexdigit)` guard on open. |
| **R16** | Passphrase floor is 8 chars, no strength estimation → weak passphrase is the limiting factor vs. an offline Argon2 grind on a stolen keystore. | `app.rs:1727` | Add a strength meter / higher floor. |
| **R17** | Passkey is an alternative *first* factor, not 2FA — the passphrase slot can never be removed, so the keystore is always openable by passphrase alone. Combined with auto-unlock (R3) the hardware protection is moot. | `keystore.rs:458`, `unlock` vs `unlock_with_passkey` | Surface in the UI as "alternative way in," not "second factor." |
| **R18** | AES-GCM STREAM uses a 56-bit (7-byte) random nonce prefix — safe *only* because the CEK is fresh per stream. | `aead.rs:85` | Add a code comment locking in the "one stream per key" invariant. |

---

### Phase P-CI — Supply chain / process

#### R19 · No dependency vulnerability scanning — **Severity: Process**
`cargo-audit` is not installed, so dependencies were not checked against the RustSec advisory DB during this review.
**Fix:** add `cargo audit` (and ideally `cargo deny` for licenses + bans) to CI as a required gate. This is the one control this review cannot substitute for.
**Effort:** S.

---

## 3. Suggested sequencing

1. **Quick wins first (1 PR):** R4, R9, R10, R15, R18, R19 — all small, localized, no format change, no design decision.
2. **Keychain hardening (1 PR):** R3 — per-backend accessibility + access-control.
3. **DoS batch (1 PR):** R6, R7, R8 — listener concurrency + allocation caps + atomic extraction.
4. **At-rest integrity (design + format bump):** R1 then R2 together — the highest-value work; needs a format-version increment and a migration path. Draft the epoch/anchor design before coding.
5. **Protocol decision:** R5 — decide whether the pairing code must resist a network attacker; fix protocol or docs accordingly.
6. **Remaining hygiene:** R11–R14, R16, R17 as capacity allows.

---

## 4. What is already solid (no action needed)

- **Full header authentication & downgrade resistance** — suite id, KDF/chunk params, filenames, sizes, recipient stanzas, and sender keys live in the CBOR header, fed as AAD into every AEAD **and** covered by the Ed25519 (+ML-DSA hybrid) signature over `BLAKE3(preamble‖header‖manifest‖data)`. No field-flip or downgrade possible.
- **Verify-before-decrypt** — signatures verified and sender fingerprint `ct_eq`-checked before any decryption; CEK unwrapped only after.
- **Streaming AEAD integrity** — `aead 0.5` STREAM BE32 per-chunk nonce + last-chunk flag; truncation/reorder/duplication all fail `Error::Auth`; empty input still emits one tag-only chunk (zero-length streams non-truncatable); counter overflow errors rather than wraps.
- **Hybrid KEM combiner** — KWK binds both shared secrets + ephemeral + recipient X25519 + ML-KEM ciphertext + recipient ML-KEM key under a distinct context; secure unless *both* KEMs break; stanza hybrid-ness is implicitly authenticated (stripping/adding the ML-KEM ciphertext changes the KWK → AEAD open fails).
- **No cross-container/cross-vault splicing** — fresh random CEK per container, fresh key+nonce per v2 blob; per-container/vault AAD differs, so moved chunks/blobs fail to open.
- **Bounded allocation before it happens** — `validate_manifest_layout` reconciles plaintext total (+one tag/chunk) against declared ciphertext length before allocating, rejects duplicate paths, enforces contiguous ascending offsets, caps `num_chunks`; `checked_add`/`div_ceil`/`saturating_mul` throughout.
- **Path traversal well-contained** — `normalize_path` (`vault.rs:183`) is a single chokepoint rejecting absolute paths, `.`/`..`, backslashes, NUL/control bytes, over-deep/over-long paths, re-applied on extraction; `EntryKind` has only `File`/`Dir` (containers can't carry symlinks).
- **SIGMA-I handshake** — `th0` binds version/suite/both ephemerals/nonces/pairing-commitment; initiator signs **both** identities (UKS resistance); direction-separated keys, per-direction counters, AAD binds `th0‖type‖counter`; constant-time expected-fingerprint checks; `verify_strict`; contributory-DH checks (`kem.rs`).
- **Secret hygiene** — `SecretBundle` is `ZeroizeOnDrop` with no `Debug`; `SymKey` redacts `Debug`; secret accessors return `Zeroizing`; only the bundle derives `Serialize`, and only into to-be-encrypted plaintext.
- **KDF** — Argon2id 64 MiB / t=3 / p=1 (exceeds OWASP minimums); params + salt bound into the DEK-wrap AAD (no silent downgrade); every `derive_subkey` uses a unique hard-coded BLAKE3 context; fresh 16-byte salts.
- **Atomic, private writes** — keystore/blobs written to 0600 temp created `mode(0o600)` from the outset, fsync + rename + best-effort dir fsync, temp cleaned on error; dirs hardened to 0700.
- **Contact import safe against key substitution** — keyed by fingerprint; re-import can change only the advisory name, never keys/trust; single-key import can't overwrite the book.
- **Crate discipline** — `#![forbid(unsafe_code)]` + `deny(unwrap/expect/panic)` in `filesec-core`; no reachable panic on malformed container/handshake/gateway input across the audited paths (all `unwrap`/`panic` are `#[cfg(test)]`).

---

## 5. Findings index (by severity)

| ID | Severity | In model | Title |
|----|----------|----------|-------|
| R1 | Medium (high impact) | Yes | No rollback/freshness protection (keystore, store files, v2 manifest) |
| R2 | Medium (high impact) | Yes | Local vault open lacks creator authenticity |
| R3 | Medium | Yes | Auto-unlock keychain not device-scoped / no user-presence |
| R4 | Medium | Partial | Untrusted Argon2 params → OOM/abort |
| R5 | Medium | Yes | Pairing code offline-recoverable via responder signature oracle |
| R6 | Medium (DoS) | No | Single-threaded blocking listener → slowloris |
| R7 | Low (DoS) | No | Unbounded allocations from attacker lengths |
| R8 | Low | Yes | Partial plaintext left on failed extraction |
| R9 | Low | Partial | Imported display name unvalidated → UI spoofing |
| R10 | Low | Partial | RNG-failure fallback to all-zeros id → overwrite |
| R11 | Low | No | Keystore temp without `O_EXCL`/`O_NOFOLLOW` |
| R12 | Low/Info | Partial | Extraction follows destination symlinks |
| R13 | Low/Info | No | Secret-seed zeroization gaps; `SymKey: Clone` |
| R14 | Low | Partial | Passkey slot label/timestamp unauthenticated metadata |
| R15 | Low | Partial | `blob file_id` not validated as hex (defense-in-depth) |
| R16 | Info | Yes | Passphrase floor 8, no strength meter |
| R17 | Info | — | Passkey is alternative first factor, not 2FA |
| R18 | Info | — | AES-GCM 7-byte nonce prefix invariant undocumented |
| R19 | Process | — | No `cargo-audit`/`cargo-deny` in CI |

_This roadmap reflects the codebase as of the audit date. Re-verify file:line references before acting — the source may have moved._
