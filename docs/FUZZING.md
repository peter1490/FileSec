# FileSec fuzz targets

`cargo-fuzz` / libFuzzer harnesses for the highest-risk untrusted-input parsers
(Stage 8 of `SECURITY_ROADMAP_V2.md`). This is a **detached** crate: it has its
own `[workspace]` and `Cargo.lock`, is `exclude`d from the root workspace, and is
nightly-only. It never enters the MSRV-1.86 stable build or the supply-chain scan.

## Targets

| Target | Parser under test |
|--------|-------------------|
| `identity_from_bytes` | `PublicIdentity::from_bytes` — `.fsecpub` CBOR decode |
| `identity_from_pasted` | `PublicIdentity::from_pasted` / `from_armored` — armor + base64 |
| `identity_backup` | `keystore::import_identity_armored` — `.fsecid` framing/KDF-clamp/CBOR |
| `manifest` | container manifest CBOR decode |
| `transport_hello` | P2P handshake `Hello` parse (pre-disclosure) |
| `normalize_path` | untrusted relative-path normalizer (F19), with invariant asserts |

## Running

```sh
rustup toolchain install nightly-2026-07-01 --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked

# Run one target indefinitely:
cargo +nightly-2026-07-01 fuzz run identity_from_bytes

# Short smoke run (what CI does):
cargo +nightly-2026-07-01 fuzz run identity_from_bytes -- -max_total_time=60
```

Crashes are written under `fuzz/artifacts/<target>/`; reproduce with
`cargo +nightly-2026-07-01 fuzz run <target> fuzz/artifacts/<target>/<crash-file>`.

CI runs a weekly smoke of every target and a short smoke on PRs that touch the
core parsers (`.github/workflows/fuzz.yml`).
