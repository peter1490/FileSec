# FileSec Threat Model

_Last updated: 2026-07-10. Reflects the code as shipped through Stage 8 of
`SECURITY_ROADMAP_V2.md`. This document states what FileSec protects, against
whom, and — just as importantly — what it deliberately does **not** protect._

FileSec is a native desktop app for exchanging files as encrypted vaults
(`.fsec`) between parties identified by public keys. There is no server and no
central trust authority; trust is established out-of-band by comparing safety
numbers. This document is the authoritative summary of the security posture; the
per-surface mechanisms are specified in `SECURITY_ROADMAP_V2.md` and the crate
docs.

## 1. Assets

| Asset | Where it lives | Protection goal |
|-------|----------------|-----------------|
| Sensitive file contents | Inside vaults, at rest and in transit | Confidentiality + integrity |
| File/folder names and structure | Inside the encrypted manifest | Confidentiality (the manifest is encrypted, not just the files) |
| Long-term private keys (Ed25519, X25519, ML-DSA, ML-KEM) | Keystore, encrypted under a passphrase-derived key | Confidentiality; never written in plaintext |
| Identity ↔ key binding | Fingerprints / safety numbers | Authenticity via out-of-band verification |
| Local state freshness (keystore, contacts, registry, vault manifests) | On-disk, anchored in OS secure storage | Rollback / stale-state resistance |
| Auto-unlock device secret | OS keychain (device-bound where supported) | Confidentiality; useless off the enrolling device |

## 2. Adversaries and scope

### In scope — FileSec is designed to resist these

- **A network attacker** on the path of a direct P2P transfer: passive
  eavesdropper or active man-in-the-middle. They must not obtain plaintext,
  responder identity/signature material, or be able to enumerate the transfer
  secret offline.
- **A malicious or careless sender**: an untrusted `.fsec` container, `.fsecpub`
  public key, or `.fsecid` backup crafted to crash, over-allocate, traverse out
  of the extraction directory, plant plaintext via a symlink, or visually spoof a
  display name.
- **A local filesystem tamperer / backup-restore attacker**: someone who can swap
  the on-disk keystore, contacts, registry, or vault blobs/manifest for an older
  but individually-valid copy, hoping to silently roll back a passkey removal,
  un-verify a contact, resurrect a deleted vault, or undo a file edit.
- **A stale-state substitution attacker**: presenting yesterday's valid state as
  today's.
- **A supply-chain adversary** targeting the release pipeline: unsigned artifacts,
  a moved Action tag, a vulnerable/typosquatted dependency, or a tampered checksum
  list.

### Out of scope — FileSec does **not** defend against these

- **A fully compromised endpoint**: root/administrator malware, a malicious OS or
  kernel, a hostile hypervisor, or a keylogger. Such an attacker sees plaintext
  and keystrokes directly; no user-space app can prevent this.
- **Live process-memory scraping** while a vault is unlocked. FileSec minimizes
  secret-copy surface and zeroizes keys on drop (see §4), but a debugger attached
  to the running process can read decrypted material that is legitimately in use.
- **Coercion / rubber-hose**: FileSec has no duress or deniability feature.
- **Traffic analysis / metadata of the *fact* of a transfer**: sizes and timing of
  a P2P transfer are not hidden from a network observer (the *contents* are).
- **Secure erasure guarantees** on SSDs, journaled/copy-on-write filesystems,
  cloud-sync folders, or OS backups. FileSec cannot promise that overwritten or
  deleted plaintext is physically unrecoverable on such media.
- **A local filesystem attacker winning a TOCTOU race** in the narrow window
  between the extraction path's symlink re-check and its atomic rename. The common
  local-tampering cases are closed (private `O_EXCL` temp, symlink refusal, atomic
  rename); the residual race falls inside the already out-of-scope
  local-filesystem-attacker model.
- **Replacing the need for out-of-band verification**: FileSec is trust-on-first-
  use. If a user marks a contact verified without actually comparing the safety
  number over a trusted channel, a MITM at first contact is not detectable.

## 3. Security properties by surface

### At rest (keystore, vaults, contacts, registry)

- **Confidentiality + integrity.** A fresh random per-vault content key encrypts
  the manifest and all file data with an AEAD (XChaCha20-Poly1305, or AES-256-GCM
  in suite `0x0002`). The content key is wrapped to each recipient via X25519 (and
  ML-KEM-768 in the hybrid suite). The container header is bound as AAD into every
  AEAD operation, so the algorithm suite and recipient set cannot be downgraded.
- **Streaming integrity.** File data uses the AEAD STREAM construction: fixed-size
  chunks, a per-chunk BE32 counter, and an explicit last-chunk flag, so
  truncation, reordering, and duplication are detected. The one-stream-per-
  fresh-`(key, nonce)` invariant is documented and regression-tested (F18).
- **Rollback resistance.** Keystore, contacts, registry, and v2 vault manifests
  carry a monotonic epoch and a previous/current-state hash, bound into
  authenticated data and anchored by a high-water mark in OS secure storage (with
  a warned file fallback). A lower epoch or a same-epoch hash mismatch is rejected
  and the suspect state quarantined rather than opened. Legacy state opens only
  through an explicit one-time recovery flow and is immediately re-anchored (F01,
  Stage 2).
- **Fail-closed primitives.** RNG failure is a hard error, never an all-zero ID or
  nonce. KDF (Argon2id) parameters from persisted or imported inputs are
  policy-clamped before allocation. Passphrase strength is enforced at first-run,
  backup export, and restore (F02/F03/F04, Stage 1).

### Untrusted input parsing

- Every attacker-controlled length is bounded before allocation: a single 16 MiB
  chunk ceiling at the stream chokepoints, entry-count/size caps in manifests,
  stat-then-bound reads for local files, and length caps on pasted keys before
  base64 decode (F05, Stage 3).
- Container blob IDs are validated as exactly 32 lowercase-hex characters; entry
  paths are normalized and **absolute/drive/traversal inputs are rejected
  outright**, not silently rewritten (F16/F19).
- The highest-risk parsers — public identity CBOR, pasted/armored keys, identity
  backups, the manifest, the transport handshake, and path normalization — have
  `cargo-fuzz` targets (`fuzz/`), smoke-run in CI (Stage 8).

### Extraction and plaintext writes

- Sensitive writes go through one hardened `SafeFileWriter`: a private `O_EXCL`
  temp (`0600` on Unix) in the destination directory, fsync, a symlink re-check on
  the target, then an atomic rename. A failed/aborted decrypt unlinks the temp, so
  a tampered container leaves **no partial plaintext and no scratch file**. Symlink
  destinations and symlinked parent directories are refused (F06, Stage 4).

### In transit (P2P networking build)

- The direct-transfer handshake (protocol v2) is gated by a mandatory **128-bit
  transfer secret**. The initiator proves knowledge of it before the responder
  discloses any identity or signature material, closing the old offline pairing-
  code oracle; the secret space is not offline-enumerable. Both parties must be
  verified contacts. Protocol downgrade to the retired pairing-code scheme is
  rejected (F07, Stage 5).
- The listener uses a bounded worker pool, per-connection handshake deadlines
  (slowloris-resistant), per-IP backoff, a hard declared-transfer-size ceiling,
  and split handshake/data frame caps (F08, Stage 5).

### Local unlock (auto-unlock, passkeys)

- **Auto-unlock never stores the passphrase.** Enabling it enrolls a random
  128-bit device token that wraps the keystore DEK in a dedicated keyslot; only
  the token goes to the OS keychain and it is useless without this machine's
  keystore file. Enrolling/removing advances the rollback-protected epoch. Device
  binding is real on macOS (login keychain) and Windows (Credential Manager); the
  Linux Secret Service cannot guarantee it, so the UI warns (F09, Stage 6).
- **Passkeys require user verification by default** (PIN or built-in UV); the
  no-PIN/no-UV fallback is gone. Passkey slot labels/timestamps are authenticated
  and add/remove advances the keystore epoch. The UI describes passkey as an
  *alternative* unlock method, not a second factor (F10/F15, Stage 6).

### Release and supply chain

- Official tags fail if macOS/Windows signing prerequisites are missing; forks/
  dispatch runs build unsigned but never publish. Releases ship per-variant SBOMs
  (SPDX), SLSA build-provenance attestations over every file and the `SHA256SUMS`
  manifest, SHA-pinned Actions, and version-pinned release tools. CI runs
  `cargo deny` + `cargo audit` supply-chain gates and `actionlint`, and exercises
  every shipped feature set (F11/F12, Stage 7).

## 4. Cryptographic hygiene (Stage 8)

- Symmetric keys (`SymKey`) are **not `Clone`** — every copy is explicit; the two
  cloneable container readers hold the key behind an `Arc` so a reader clone shares
  one key copy by refcount rather than duplicating secret bytes. All symmetric key
  material zeroizes on drop.
- PQC seed and shared-secret intermediates are copied straight into zeroizing
  buffers and the library's fixed-size seed wrappers are wiped after key
  derivation, so no stray seed/shared-secret lingers on the stack.
- Imported display names are sanitized before storage and display: bidi/invisible
  spoofing characters and control characters are stripped, whitespace normalized,
  and length bounded — so a crafted contact name cannot visually impersonate
  another contact, a file path, or system text. Trust decisions are gated on the
  safety number, shown alongside the fingerprint, never on the name.

### Primitive inventory

| Role | Classical (`0x0001`) | AES variant (`0x0002`) | Hybrid PQC (`0x0101`) |
|------|----------------------|------------------------|------------------------|
| Bulk AEAD | XChaCha20-Poly1305 | AES-256-GCM | XChaCha20-Poly1305 |
| KEM / agreement | X25519 | X25519 | X25519 **+** ML-KEM-768 |
| Signature | Ed25519 | Ed25519 | Ed25519 **+** ML-DSA-65 |
| KDF | Argon2id (policy-clamped) | ← | ← |
| Hash / fingerprint / KDF2 | BLAKE3 | ← | ← |

In the hybrid suite the post-quantum algorithm is always *combined with* its
classical counterpart, so breaking one scheme cannot weaken the container below
the classical baseline.

## 5. Trust assumptions the user must uphold

- Compare a new contact's **safety number out-of-band** before marking them
  verified. FileSec cannot detect a first-contact MITM otherwise.
- Keep the passphrase strong and secret; it is the root of the at-rest key
  hierarchy and is never stored.
- Treat the enrolling device as the trust boundary for auto-unlock; the device
  token is device-bound where the platform allows, but the device itself must be
  trusted.
- Verify official builds via their published, attested checksums.

## 6. Known residual risks and accepted exceptions

- Three low-reachability transitive dependency advisories are accepted as
  documented, time-boxed exceptions because their only fixes would break the 1.86
  MSRV or the pinned egui stack (see `deny.toml` / `RELEASE.md`). A new advisory
  still fails CI.
- A fully race-free `openat`-based extraction walk is not implemented (it would
  require a `libc`/`unsafe` dependency this build avoids); see the TOCTOU note in
  §2.
- Portable free-space checks before large inbound transfers are not implemented;
  the declared-size ceiling is the enforced disk-exhaustion defense.
- On Linux, auto-unlock cannot be guaranteed device-bound; the UI surfaces this.

These are conscious trade-offs consistent with FileSec's dependency-light,
`unsafe`-free, MSRV-pinned posture. They are revisited as the ecosystem changes.
