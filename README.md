# FileSec

A native, **offline** desktop app for securely exchanging files between parties
using public/private-key cryptography. Built in pure Rust (egui), with no
webview, no JavaScript, and no network.

The core idea is a **secure vault** — a container holding arbitrary files and
folders, fully managed through the app. A vault is exported as a single portable
encrypted file (`.fsec`) that you send to a recipient over any channel (email,
cloud, USB). Only the intended recipients — selected by their public key — can
open it.

> **Status: MVP.** The classical crypto suite, vault management, and the full
> export/import/verify flow are implemented and tested. Post-quantum crypto,
> in-place editing, OS installers, and a transparent filesystem mount are
> planned but not in this build (see [Roadmap](#roadmap)).

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
a weaker suite. This is the hook for the planned opt-in **hybrid post-quantum**
suite (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65).

All secret material (private keys, content keys, derived keys, passphrases,
decrypted buffers) is held in zeroizing buffers and wiped on drop. Comparisons
of tags and fingerprints are constant-time.

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
manifest  : XChaCha20-Poly1305(CBOR manifest)   — encrypted tree + metadata
data      : STREAM of authenticated fixed chunks — encrypted file contents
trailer   : Ed25519 signature over BLAKE3(everything above)
```

The same format is used both for transport (export to others) and for the local
at-rest store: vaults, the contact book, and the vault registry are each stored
as a container encrypted to your own identity, so they are confidential on disk.
Only the keystore differs — it is sealed with your Argon2id-derived passphrase
key, since it bootstraps everything else.

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
```

The `filesec` binary is self-contained (single executable per OS).

### A typical two-party exchange

1. **Both** parties open FileSec and create an identity (name + passphrase).
2. On **My Identity**, each copies/saves their public key and sends it to the
   other (any channel). Each imports the other under **Contacts**, then compares
   the **safety number** out-of-band (in person / phone) and marks it *verified*.
3. The sender creates a **vault**, adds files/folders, clicks **Send…**, selects
   the recipient, and saves the `.fsec`.
4. The recipient clicks **Import .fsec…**. FileSec verifies the sender's
   signature, shows who sent it and whether they're a verified contact, and adds
   the decrypted vault locally. From the vault they can **Extract all…** or
   **Save as…** individual files.

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
  round-trips.
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
create/manage vaults, add files & folders, extract/save, export to one or more
recipients (with "include self"), import + signature verification, and an
encrypted-at-rest local store.

Planned, in dependency order:

1. **Check-out / check-in editing** — decrypt to a restricted temp file, edit in
   your normal editor, re-encrypt on check-in, secure-wipe the temp (with honest
   SSD/CoW caveats).
2. **Trust-UX polish** and background worker threads (current crypto runs
   synchronously, so very large vaults briefly pause the UI).
3. **Opt-in hybrid post-quantum suite** (ML-KEM-768 + ML-DSA-65) and an
   AES-256-GCM suite — the format and dispatch are already designed for this.
4. **Packaging & signing** — cross-platform installers (`cargo-dist`), macOS
   notarization, Windows Authenticode.
5. **Transparent OS mount** — FUSE / macFUSE / WinFsp virtual drive.

---

## License

Dual-licensed under MIT OR Apache-2.0.
