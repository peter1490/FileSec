# FileSec

A native, **offline** desktop app for securely exchanging files between parties
using public/private-key cryptography. Built in pure Rust (egui), with no
webview, no JavaScript, and no network.

The core idea is a **secure vault** — a container holding arbitrary files and
folders, fully managed through the app. A vault is exported as a single portable
encrypted file (`.fsec`) that you send to a recipient over any channel (email,
cloud, USB). Only the intended recipients — selected by their public key — can
open it.

> **Status: MVP + opt-in PQC & passkeys.** The classical crypto suite, vault
> management, in-place editing, and the full export/import/verify flow are
> implemented and tested. An **opt-in post-quantum** build (`--features pqc`) adds
> a hybrid X25519+ML-KEM-768 / Ed25519+ML-DSA-65 suite and an AES-256-GCM suite;
> an **opt-in passkey** build (`--features passkey`) lets you unlock with a FIDO2
> hardware key in addition to your passphrase. OS installers and a transparent
> filesystem mount are planned but not in this build (see [Roadmap](#roadmap)).

---

## Security goals (CIA)

- **Confidentiality** — A random per-vault content key encrypts the manifest and
  all file data. The content key is wrapped to each recipient's public key via
  X25519 key agreement, so only listed private-key holders can open a container.
  Because the *manifest* is encrypted too, filenames and folder structure are
  confidential, not just file contents.
- **Integrity** — Every chunk and the manifest are sealed with an AEAD
  (XChaCha20-Poly1305). The data stream uses an authenticated chunk counter and
  an explicit last-chunk flag, so truncation and reordering are detected. The
  whole container header is bound as associated data into every AEAD operation.
- **Authenticity** — The sender signs a BLAKE3 hash over the entire container
  (Ed25519). The importer **verifies the signature before decrypting anything**.

### Cryptography (suite `0x0001`, the default)

| Purpose            | Algorithm                              |
|--------------------|----------------------------------------|
| AEAD               | XChaCha20-Poly1305                     |
| Key agreement      | X25519 (ephemeral-static)              |
| Signatures         | Ed25519 (`verify_strict`)              |
| Passphrase KDF     | Argon2id (~64 MiB, t=3)                |
| Sub-key derivation | BLAKE3 (`derive_key`)                  |
| Hashing / fingerprint | BLAKE3                              |

The container format carries an atomic **algorithm-suite identifier**, bound as
AAD and covered by the signature, so an attacker cannot downgrade a container to
a weaker suite.

#### Opt-in post-quantum suites (`--features pqc`)

Building with the `pqc` feature adds two more suites and makes new identities
**hybrid** (they carry ML-DSA-65 and ML-KEM-768 keys alongside the classical
ones). The suite is chosen per export; a classical build supports only `0x0001`
and cleanly rejects the others.

| suite    | AEAD               | key agreement         | signature            |
|----------|--------------------|-----------------------|----------------------|
| `0x0001` | XChaCha20-Poly1305 | X25519                | Ed25519              |
| `0x0002` | AES-256-GCM        | X25519                | Ed25519              |
| `0x0101` | XChaCha20-Poly1305 | X25519 **+ ML-KEM-768** | Ed25519 **+ ML-DSA-65** |

The hybrid suite `0x0101` **combines** the classical and post-quantum primitives
so it is never weaker than the classical baseline:

- **KEM** — the content-key-wrapping key is derived from a KDF over *both* the
  X25519 shared secret *and* the ML-KEM-768 shared secret, bound to the full
  transcript (both public keys and the ML-KEM ciphertext). Recovering it requires
  breaking *both* KEMs.
- **Signature** — the container is signed with *both* Ed25519 and ML-DSA-65, and
  an importer requires *both* to verify, so forging requires breaking *both*
  schemes.

A hybrid identity's fingerprint (and thus its safety number) commits to all four
public keys, so verifying a contact out-of-band authenticates its post-quantum
keys too. The keystore persists each post-quantum keypair as its compact seed.

**Identities and migration (in a `pqc` build):**

- A **fresh** data dir generates a **hybrid** identity, and its local store
  (vaults, contacts, registry) is encrypted to itself under the hybrid suite —
  post-quantum protection at rest. It can still read and write classical and
  AES-256-GCM containers.
- An **existing classical** identity can **upgrade in place** ("My Identity →
  Upgrade to post-quantum"): the same X25519/Ed25519 keys are kept, fresh
  ML-KEM-768/ML-DSA-65 keys are added, and the entire local store is re-encrypted
  to the new identity. The migration is **crash-safe** — it bridges every store
  file to *both* identities under the classical suite, re-seals the keystore (the
  atomic commit point), then hardens to the new hybrid identity only, so an
  interruption at any step never locks you out. Because the fingerprint commits
  to the new keys, your **safety number changes**: re-share your public key so
  contacts can re-verify.
- Until you migrate, a classical identity is limited to the **classical
  encryptions** (Classic and AES-256-GCM); the export picker disables Hybrid and
  points you to the upgrade.

All secret material (private keys, content keys, derived keys, passphrases,
decrypted buffers) is held in zeroizing buffers and wiped on drop. Comparisons
of tags and fingerprints are constant-time.

#### Opt-in passkey unlock (`--features passkey`)

You can enroll a **hardware security key** (FIDO2: YubiKey, SoloKey, …) as an
*additional* way to unlock your identity, alongside your passphrase. Because
FileSec is offline there is no server to verify a WebAuthn assertion, so a
passkey can't "log you in" the usual way; instead FileSec uses the FIDO2
**`hmac-secret`** extension (a.k.a. WebAuthn PRF) — the authenticator
deterministically returns a stable 32-byte secret, gated by physical possession
of the key plus user verification (touch / PIN). That secret wraps the keystore.
This is the same mechanism behind systemd-cryptenroll, age-plugin-fido2-hmac,
and "unlock with passkey" in password managers.

The keystore uses a **keyslot** design (like LUKS / age). Your private identity
is encrypted once under a random data key (DEK); the DEK is then wrapped once per
unlock method:

- exactly **one passphrase slot** (Argon2id) — always present, so it can never
  be removed; and
- **zero or more passkey slots**, each wrapping the DEK under a key derived from
  that key's `hmac-secret` output. Each slot stores only public handles (the
  credential id, a random salt, a label) — all bound into the slot's AEAD so they
  can't be tampered with.

So **either** the passphrase **or** an enrolled security key opens the keystore.
**Keep your passphrase — it is your recovery: a lost or wiped key is never a
lockout.** Manage keys under *My Identity → Security keys* (Add / Remove); unlock
with *🔑 Unlock with security key* on the unlock screen. Enrolling asks for **two
touches** (the `hmac-secret` value is only returned by an assertion, so creating
the credential and deriving its secret are two user-presence steps); unlocking is
a single touch.

Backward compatible: a keystore with no passkeys stays in the original on-disk
format byte-for-byte (so a build without this feature still opens it). The first
enrollment migrates it to the keyslot format. Keystore writes are atomic
(temp + fsync + rename), so enrolling/removing a key can never half-write it.
Upgrading to post-quantum re-seals a fresh keystore, so re-enroll any keys after.

> The passkey backend talks to the key over USB HID via `ctap-hid-fido2`, which
> vendors the C `hidapi` library — it is **only** compiled with
> `--features passkey`, needs a physical key to test, and is pinned to a version
> that builds on the project's Rust 1.86 MSRV. The keyslot crypto itself lives in
> `filesec-core` with no hardware dependency and is fully unit-tested.

### Threat model — what is *not* protected

FileSec protects data **in transit and at rest**. It explicitly does **not**
protect against:

- **Endpoint compromise** — malware, keyloggers, or a malicious editor on either
  machine.
- **OS-level remnants** of decrypted files you extract to disk (editor swap
  files, indexers, backups, hibernation).
- **Metadata about the act of sending** (FileSec encrypts the container, not the
  channel you send it over).
- **Recipient misuse** after legitimate decryption (no DRM).
- **Forgotten passphrases** — there is no recovery. If you lose your passphrase,
  your vaults cannot be opened.

The "A" in CIA here means tamper-evidence and the offline, no-single-point-of-
failure transfer model — not anti-DoS or guaranteed delivery.

---

## Architecture

A Cargo workspace with a hard split between a pure, auditable security library
and a thin GUI:

```
crates/
  filesec-core/   # all cryptography + the .fsec container format. NO GUI.
                  # forbids unsafe, denies unwrap/expect/panic. Fuzz/audit target.
  filesec-gui/    # egui/eframe desktop app (lib + `filesec` binary).
```

The `.fsec` container layout (front to back):

```
preamble  : "FSEC\x1A" | format_version (u16) | header_len (u32)
header    : CBOR — suite id, sender public keys + fingerprint, recipient stanzas,
            nonces, lengths.  Plaintext, but bound as AAD everywhere and signed.
manifest  : suite-AEAD(CBOR manifest)           — encrypted tree + metadata
data      : STREAM of authenticated fixed chunks — encrypted file contents
trailer   : Ed25519 signature over BLAKE3(everything above)
            (hybrid suite 0x0101 appends an ML-DSA-65 signature; both required)
```

The same format is used both for transport (export to others) and for the local
at-rest store: vaults, the contact book, and the vault registry are each stored
as a container encrypted to your own identity, so they are confidential on disk.
Only the keystore differs — it is sealed with your Argon2id-derived passphrase
key, since it bootstraps everything else.

**Lazy opening.** Opening a vault decrypts only the small, authenticated manifest
(the folder tree and per-entry metadata) — *not* the file data — so opening a
multi-gigabyte vault is cheap and uses negligible memory. Individual files are
decrypted from disk **on demand** via random-access chunk decryption (only the
chunks covering the requested file are read and decrypted). Extraction streams
one file at a time, so peak memory is the size of the largest single file, not
the whole vault. Operations that inherently need the full plaintext (re-encrypt
after add/delete, or exporting to others) load it transiently on the worker
thread and drop it immediately. Each chunk is individually AEAD-authenticated, so
on-demand reads remain tamper-evident.

Data lives in the per-OS application directory (override with the
`FILESEC_DATA_DIR` environment variable):

- macOS: `~/Library/Application Support/dev.FileSec.FileSec/`
- Windows: `%APPDATA%\FileSec\FileSec\data\`
- Linux: `~/.local/share/filesec/` (XDG)

Files are created with `0600`/`0700` permissions on Unix.

---

## Build & run

Requires a recent stable Rust toolchain (built and tested with 1.86).

```sh
# Run the desktop app
cargo run -p filesec-gui --release

# Run all tests (crypto round-trips, tamper detection, persistence)
cargo test --workspace

# Lint & format
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

# Opt-in builds: post-quantum suites, and/or hardware-passkey unlock
cargo run -p filesec-gui --release --features pqc
cargo run -p filesec-gui --release --features passkey   # needs a FIDO2 key to use
```

The `filesec` binary is self-contained (single executable per OS). The `passkey`
feature compiles a USB-HID FIDO2 client (vendored `hidapi` C); it is off by
default and requires a physical security key to exercise.

### A typical two-party exchange

1. **Both** parties open FileSec and create an identity (name + passphrase).
2. On **My Identity**, each copies/saves their public key and sends it to the
   other (any channel). Each pastes or loads the other's key under **Contacts**
   and gets a **preview** (name, fingerprint, safety number, and whether it's
   new / already known / their own key) before confirming. They then open
   **Verify…**, compare the **safety number** out-of-band (in person / phone) —
   typing it back so the app checks the match, or ticking "I compared it myself"
   — and mark the contact *verified* (the date is recorded).
3. The sender creates a **vault**, adds files/folders, clicks **Send…**, selects
   the recipient, and saves the `.fsec`. If any selected recipient is still
   unverified, the dialog names them and warns before export.
4. The recipient clicks **Import .fsec…**. FileSec verifies the sender's
   signature, shows who sent it and whether they're a verified contact — with a
   one-click **Verify sender…** (known but unverified) or **Add sender to
   contacts…** (unknown) shortcut — and adds the decrypted vault locally. From
   the vault they can **Extract all…** or **Save as…** individual files.

---

## Testing

The security-critical logic lives in `filesec-core` and is covered by:

- Byte-for-byte encrypt → export → import round-trips (single & multi-recipient,
  "include self", empty files, empty vault, and a large multi-chunk file with a
  non-aligned final chunk).
- Negative/tamper tests: every probed single-bit flip across the preamble,
  header, manifest, data, and signature is rejected; truncation and extension
  are rejected; a non-recipient is refused; a corrupt file never yields plaintext.
- Path-traversal defense (`..`, absolute paths, backslashes, control chars).
- AEAD one-shot + streaming correctness and AAD/key binding; the X25519 envelope;
  Argon2id keystore unlock (incl. wrong-passphrase); contacts and armored-key
  round-trips; lenient safety-number matching; forgiving paste parsing (armored
  or bare base64); upsert rename/verification reporting; and that a contact book
  written before the `verified_at` field still loads.
- GUI persistence layer: keystore/vault/registry/contacts round-trips,
  confidentiality (a different identity cannot read your self-encrypted vault),
  and filesystem extraction — all without opening a window.

---

## Cross-platform notes

One egui codebase targets Windows, macOS, and Linux from a single source. The
default `glow` (OpenGL) backend is the most portable. On Linux, the windowing
stack needs system libraries (X11/Wayland + OpenGL); install your distro's
development packages for those.

---

## Roadmap

Implemented (this MVP): identity & keystore, contacts with trust/verification,
create/manage vaults, add files & folders, extract/save, **check-out / check-in
editing**, export to one or more recipients (with "include self"), import +
signature verification, and an encrypted-at-rest local store. All crypto and I/O
run on a **background worker thread**, so the UI stays responsive even for very
large vaults (a spinner shows while a job runs).

**Check-out / check-in editing** (the ✏ button on a file): the file is decrypted
to a temp file under a per-user `checkout/` directory (created with owner-only
`0600` permissions where the OS supports it) and opened in your default editor.
Edit and save in your own app, then **Check in** (the edited bytes are streamed
back into the vault and re-encrypted — single-pass, no full decrypt into memory)
or **Discard**. Either way the temp file is securely overwritten and deleted.
This overwrite is **best-effort, not forensic-grade**: on SSDs (wear leveling),
copy-on-write filesystems (APFS, Btrfs, ZFS), and journaling filesystems an
in-place overwrite is not guaranteed to hit the original physical blocks, and it
cannot reach editor swap/backup files (see the threat model). A crash that
bypasses check-in/discard leaves the temp until the next unlock, which wipes the
`checkout/` directory.

**Read-only View** (the 👁 button on a file): for a quick look without editing,
the file is decrypted to a disposable, read-only temp and opened in your default
app — there's nothing to check in. A background watcher securely wipes the temp
the moment the app you opened it with closes (via a blocking launcher: macOS
`open -W`, Windows `start /wait`), and any survivor is wiped when you leave the
vault, lock, or quit. Caveats of the close-detection: it fires when the
*application* exits, not when a single window closes, so if your viewer was
already running the wipe waits until that whole app quits (the leave-the-vault
backstop still covers it); on Linux there is no blocking launcher, so views are
wiped on leaving the vault rather than on close.

**Trust-UX polish** (the verification workflow): adding a contact is now a
preview-then-confirm step — paste an armored block *or* a bare base64 body (the
parser is forgiving of lost armor lines and stray whitespace), or load a
`.fsecpub` file, and FileSec shows the name, fingerprint, and safety number plus
whether the key is new, already known, your own, or a rename of an existing
contact *before* anything is saved. A dedicated **Verify…** dialog shows the
safety number and lets you type back what the other party reads (compared
leniently — case, spacing, and grouping dashes are ignored) or confirm a manual
comparison; verification records its date. Re-importing a key never silently
re-trusts or downgrades a contact, and **renaming a verified contact is called
out explicitly**. Export names any unverified recipients, and the import dialog
distinguishes a valid *signature* from a *trusted identity*, offering one-click
verify / add-to-contacts shortcuts.

**Delivered:** an opt-in hybrid post-quantum suite (X25519+ML-KEM-768,
Ed25519+ML-DSA-65) and an AES-256-GCM suite, behind `--features pqc`; and
**opt-in passkey unlock** (FIDO2 `hmac-secret` hardware keys, behind
`--features passkey`) as a co-equal alternative to the passphrase — see
[Cryptography](#cryptography-suite-0x0001-the-default) above.

Planned, in dependency order:

1. **Packaging & signing** — cross-platform installers (`cargo-dist`), macOS
   notarization, Windows Authenticode.
2. **Transparent OS mount** — FUSE / macFUSE / WinFsp virtual drive.

---

## License

Dual-licensed under MIT OR Apache-2.0.
