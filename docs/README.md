# FileSec

See [the September 2026 security review](SECURITY_AUDIT.md) for implemented hardening, measured browser improvements, validation results, and remaining dependency exceptions.

A native desktop app for securely exchanging files between parties using
public/private-key cryptography. Built in pure Rust (egui), with no webview and
no JavaScript. The **standard build is fully offline**; an optional **networking
build** adds direct, server-less peer-to-peer transfer to a verified contact
(see [Direct transfer](#direct-transfer-networking-build)).

The core idea is a **secure vault** — a container holding arbitrary files and
folders, fully managed through the app. A vault is exported as a single portable
encrypted file (`.fsec`) that you send to a recipient over any channel (email,
cloud, USB) — or hand straight to a verified contact over the network with the
networking build. Only the intended recipients — selected by their public key —
can open it.

> **Status: MVP + opt-in PQC & passkeys, with signed installers.** The classical
> crypto suite, vault management, in-place editing, and the full
> export/import/verify flow are implemented and tested. An **opt-in post-quantum**
> build (`--features pqc`) adds a hybrid X25519+ML-KEM-768 / Ed25519+ML-DSA-65
> suite and an AES-256-GCM suite; an **opt-in passkey** build
> (`--features passkey`) lets you unlock with a FIDO2 hardware key, and an
> **opt-in keyring** build (`--features keyring`) can remember a device unlock key
> in the OS keychain for automatic unlock on a trusted device (your passphrase is
> never stored). FileSec now ships as
> **two signed installer builds — classical and post-quantum — for macOS, Windows,
> and Linux**, with published checksums (see [Packaging & releases](#packaging--releases)).

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
**alternative** way to unlock your identity — a second way in, not a second
factor layered on the passphrase. Because FileSec is offline there is no server
to verify a WebAuthn assertion, so a passkey can't "log you in" the usual way;
instead FileSec uses the FIDO2 **`hmac-secret`** extension (a.k.a. WebAuthn PRF)
— the authenticator deterministically returns a stable 32-byte secret, gated by
physical possession of the key plus **user verification** (PIN or biometric,
required by default). That secret wraps the keystore. This is the same mechanism
behind systemd-cryptenroll, age-plugin-fido2-hmac, and "unlock with passkey" in
password managers.

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

Every new keystore, including a passphrase-only one, uses the signed,
rollback-protected v3 state frame. Older v1/v2 keystores remain recoverable: the
unlock screen clearly marks the one-time migration, requires the passphrase as
explicit confirmation, and immediately rewraps the keystore. Keystore writes are
atomic (temp + fsync + rename), so enrolling/removing a key can never half-write
it. Upgrading to post-quantum re-seals a fresh keystore, so re-enroll any keys
after.

> The passkey backend talks to the key over USB HID via `ctap-hid-fido2`, which
> vendors the C `hidapi` library — it is **only** compiled with
> `--features passkey`, needs a physical key to test, and is pinned to a version
> that builds on the project's Rust 1.86 MSRV. The keyslot crypto itself lives in
> `filesec-core` with no hardware dependency and is fully unit-tested.

#### Opt-in keyring auto-unlock (`--features keyring`)

For a trusted personal device you can ask FileSec to unlock automatically. It does
this **without storing your passphrase**: enabling it generates a random 128-bit
**device unlock key** that wraps the keystore's data key in a dedicated device
keyslot, and only that token is kept in the OS keychain — macOS Keychain, Windows
Credential Manager, or the Linux Secret Service (GNOME Keyring / KWallet). The
token is useless without this machine's keystore file. Enable it under *My
Identity → This device → Remember on this device…* (it re-confirms your passphrase
first); the unlock screen then offers *🔓 Unlock on this device* and the next
launch auto-unlocks. Turn it off any time with *Forget on this device* — which
clears the token **and** removes the device keyslot, advancing the keystore's
rollback-protected epoch so a restored older keystore can't silently re-enable it.

This is strictly **opt-in and per-device**. Your passphrase is never stored or
replaced — it remains your recovery secret and keeps working everywhere — so this
can never become a lockout. The trade-off is explicit: the keychain becomes a
second way in, gated by your logged-in OS account, so only enable it on a machine
you trust. The token is device-local and non-syncing on macOS (login keychain)
and Windows (per-user Credential Manager); on Linux the Secret Service gives no
device-binding guarantee, so the UI shows a caveat there. The signed installer
builds enable this feature; the default `cargo` build leaves it (and its
secret-store dependency) out entirely. The backend crate is target-gated so each
OS pulls only its own (no `zbus` on macOS/Windows). See
[`crates/filesec-gui/src/autounlock.rs`](../crates/filesec-gui/src/autounlock.rs).

#### Rollback-resistant local state

The keystore, contact book, vault registry, and each local v2 vault manifest
carry a monotonically increasing epoch plus predecessor/current state hashes.
Their authenticated binding includes the owning identity fingerprint, object
type and id, suite id, epoch, and both hashes. Keystore state is additionally
signed by the identity; contacts/registry live inside authenticated self-encrypted
containers; v2 manifest state is bound into its manifest AEAD.

FileSec stores the latest accepted high-water anchors in the OS secure store
when the `keyring` feature/backend is available. An older valid state, a
different hash at the same epoch, or a broken successor chain is rejected and
moved into the data directory's `quarantine/` folder instead of opening. Legacy
state is never migrated silently: the unlock screen presents a clearly marked
one-time recovery action, verifies the legacy keystore passphrase and local-v1
vault signatures, and immediately re-anchors the recovered state.

Without a usable OS secure store, FileSec uses a private `.state-anchors` file
inside the data directory and shows a persistent degraded-mode warning under
*My Identity*. This still detects restoring an individual old state file, but a
whole-directory restore can roll back the fallback anchor too. In that mode,
keep an independent current backup; inspect anything in `quarantine/` before
using the explicit recovery APIs (`recover_legacy_keystore`,
`recover_legacy_contacts`, `recover_legacy_registry`, and
`recover_legacy_vault`). Never fix a rollback warning by copying an old anchor
file over the current one.

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

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full, authoritative threat model:
assets, the in-scope/out-of-scope adversary list, per-surface guarantees, and the
known residual risks and accepted exceptions.

---

## Architecture

A Cargo workspace with a hard split between a pure, auditable security library
and a thin GUI:

```
crates/
  filesec-core/   # all cryptography + the .fsec container format. NO GUI.
                  # forbids unsafe, denies unwrap/expect/panic. Fuzz/audit target.
  filesec-gui/    # egui/eframe desktop app (lib + classical `filesec` binary).
  filesec-pqc/    # same GUI compiled with the post-quantum suites on
                  # (the `filesec-pqc` binary). Built separately so PQC features
                  # never leak into the classical binary.
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

The contact book and vault registry are stored as containers encrypted to your
own identity. Local vaults use the v2 directory-of-independent-blobs format so a
single edit rewrites only one blob plus its manifest. Only the keystore differs
— it is sealed with your Argon2id-derived passphrase key, since it bootstraps
everything else. All four state families use the rollback anchors described
above.

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

Two files there are **not** encrypted, both by necessity and neither carrying
anything confidential: `.state-anchors` (the degraded-mode rollback high-water
marks, when no OS secure store is available) and `.prefs`, which holds the theme
choice shown in Settings. The theme has to be applied to the very first frame —
the unlock screen is painted before there is an identity to decrypt anything
with — so an encrypted preference could not do its job. The most an attacker
gains by rewriting `.prefs` is that the app opens in the wrong colour; anything
security-relevant belongs in the keychain or the encrypted store instead.

---

## Build & run

Requires a recent stable Rust toolchain (built and tested with 1.86).

```sh
# Run the desktop app (classical)
cargo run -p filesec-gui --release

# Run all tests (crypto round-trips, tamper detection, persistence)
cargo test

# Lint & format
cargo clippy --all-targets -- -D warnings
cargo fmt --all

# Opt-in builds: post-quantum suites, hardware-passkey unlock, OS-keychain unlock
cargo run -p filesec-gui --release --features pqc
cargo run -p filesec-gui --release --features passkey   # needs a FIDO2 key to use
cargo run -p filesec-gui --release --features keyring   # "remember on this device"

# The post-quantum desktop build (hybrid suites on by default)
cargo run -p filesec-pqc --release
```

> **Workspace layout.** The bare `cargo build` / `cargo test` / `cargo clippy`
> commands run against the **default members** (`filesec-core` + `filesec-gui`),
> i.e. the dependency-light classical path. The post-quantum binary lives in its
> own `filesec-pqc` package (built with `-p filesec-pqc`) so its features are
> never unified into the classical `filesec` binary. Use `--workspace` only when
> you intentionally want everything (it pulls the PQC/keychain dependencies in).

The `filesec` binary is self-contained (single executable per OS). The `passkey`
feature compiles a USB-HID FIDO2 client (vendored `hidapi` C); it is off by
default and requires a physical security key to exercise.

### Packaging & releases

Tagging `v*` builds, signs, and publishes **two installer families** — classical
(`filesec`) and post-quantum (`filesec-pqc`) — for macOS (`.dmg`), Windows
(`.msi` + NSIS) and Linux (`.deb`), each with a portable archive and a published
`SHA256SUMS`. macOS builds are codesigned + notarized and Windows builds are
Authenticode-signed; on the upstream repo an official tag **fails** rather than
publish unsigned artifacts. Every release also carries a per-variant **SBOM**
(SPDX) and **SLSA build-provenance attestations** covering the artifacts and the
`SHA256SUMS` manifest (`gh attestation verify <file> --repo peter1490/FileSec`).
The Windows `.msi` is built from a committed, reviewable WiX source so it is
deterministic. A complementary `cargo-dist` configuration provides `curl | sh`
installers. See [RELEASE.md](RELEASE.md) for the full process and required
secrets.

CI additionally runs a **supply-chain gate** — `cargo deny` (RustSec advisories,
license allow-list, crates.io-only sources) and `cargo audit` — on every push and
pull request, and lints the workflows with `actionlint`. All GitHub Actions are
pinned by commit SHA and all release-time cargo tools by version. See
[`deny.toml`](../deny.toml) for the policy and accepted, justified advisory
exceptions.

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

## Direct transfer (networking build)

The **networking build** (`filesec-pqc`, or any build compiled with
`--features net`) adds an optional way to hand a vault straight to a contact over
the network — **no relay or rendezvous server in between**. The standard
`filesec` build links no networking code at all.

How it works:

- The **receiver** opens *listen mode*. By default it's reachable only on the
  local network; an *internet* toggle additionally asks the router to open a port
  via **NAT-PMP** (a small, vendored, dependency-free client) and shows the public
  address. If the router doesn't speak NAT-PMP, the receiver stays reachable on
  the LAN and tells you so. The public address comes from the gateway itself — no
  third-party "what is my IP" service is contacted.
- The **sender** picks a **verified contact**, enters the address, and types the
  one-time **pairing code** the receiver is showing.
- The vault travels as the usual signed, recipient-encrypted `.fsec` *inside* an
  authenticated, forward-secret channel, and lands through the same
  verify-the-signature-then-import path as a file you'd import by hand.

Security model:

- **Only verified contacts.** A transfer completes only between two identities
  that each hold the other as a verified contact. The live peer is bound to the
  same BLAKE3 **safety number** you already compare out-of-band — so reaching the
  right IP but the wrong identity aborts.
- **Mutual authentication + forward secrecy.** The handshake is a SIGMA-I
  construction (as in Noise-IK / IKEv2) built only from FileSec's own primitives
  (X25519 + Ed25519 + BLAKE3 + XChaCha20-Poly1305): ephemeral keys give forward
  secrecy, Ed25519 signatures over the transcript authenticate each side, and
  identities are revealed only under the session key.
- **Pairing code as a second factor.** The one-time code is folded into the
  signed handshake transcript and the session keys, so a wrong code makes the
  channel fail to form. It's a *layered* second factor on top of the public-key
  identity gate, not a standalone authenticator — a short numeric code is low
  entropy and, against an attacker who already controls a valid verified identity,
  guessable; the identity check remains the real protection.
- **Defense in depth.** Even if the channel were broken, the payload is still the
  end-to-end-sealed, signed `.fsec` that only the recipient can open.

What it does **not** protect against (documented, not hidden): traffic analysis
(record sizes and timing reveal the file-size class), the receiver's address
being learned by anyone who connects, denial-of-service from unauthenticated
dialers (mitigated by handshake timeouts and a single-listener model), and
endpoint compromise. Internet mode also genuinely won't work behind carrier-grade
or double NAT — fall back to the LAN, a manual port-forward, or a VPN.

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

**Temp files carry no filenames.** Both flows name the temp `<random-hex>.<ext>`
— never the name the file has in the vault. A filename outlives the bytes: it
lands in the opening app's "Recent Items", in OS index caches, and in any backup
that snapshots the directory, so writing it out would leak vault contents even
after the file itself is shredded. Only a short, plain-ASCII extension survives,
because the OS launchers need it to pick the right application; the real name is
shown in FileSec's own banner while the file is open.

**Wiping never blocks the UI.** Securely overwriting a multi-gigabyte temp takes
a while, so it runs on a background shredder thread: leaving a vault, locking, or
navigating away returns immediately. Quitting holds the window open behind a
"Securing temporary files…" spinner until the queue drains (capped at five
seconds — the next unlock's `checkout/` sweep is the backstop), so the app never
appears frozen on the way out.

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
Ed25519+ML-DSA-65) and an AES-256-GCM suite, behind `--features pqc`;
**opt-in passkey unlock** (FIDO2 `hmac-secret` hardware keys, behind
`--features passkey`) as a co-equal alternative to the passphrase — see
[Cryptography](#cryptography-suite-0x0001-the-default) above; **opt-in OS-keychain
auto-unlock** (`--features keyring`); and **packaging & signing** — two signed
installer builds (classical + post-quantum) for macOS (`.dmg`, notarized),
Windows (`.msi` + NSIS, Authenticode) and Linux (`.deb`), plus portable archives
and published checksums, driven by GitHub Actions with a complementary
`cargo-dist` config (see [RELEASE.md](RELEASE.md)).

---

## License

Dual-licensed under MIT OR Apache-2.0.
