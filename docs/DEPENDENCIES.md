# Dependencies: accepted advisories and the upgrade plan

FileSec's supply-chain gate (`cargo deny` + `cargo audit` in CI) fails on any
RustSec advisory that is not explicitly accepted. Accepting one is a dated
decision with an owner, not a permanent waiver:

- every exception in `deny.toml` is `{ id, reason }`, and the reason names an
  `owner:` and a `review-by:` date at most ~13 months out;
- `.cargo/audit.toml` carries the same IDs (plus clearly marked `audit-only`
  entries for crates that are in `Cargo.lock` but in no shipped build);
- `scripts/check_advisory_exceptions.py` fails CI when a date has passed or the
  two lists drift, forcing a re-assessment;
- CI also runs an **unsuppressed** `cargo audit` and publishes it to the job
  summary (`scripts/advisory_report.py`), so a green gate is never mistaken for
  "no known advisories". Run it locally from outside the repository:
  `cd /tmp && cargo audit --file <repo>/Cargo.lock`.

## Accepted advisories

| Advisory | Crate | Kind | Why accepted | Owner | Review by | Retired by |
|---|---|---|---|---|---|---|
| RUSTSEC-2026-0194, RUSTSEC-2026-0195 | quick-xml 0.39.4 | DoS (vulnerability) | Linux only, via accesskit's AT-SPI backend; parses the local accessibility bus, not untrusted files or network input | @peter1490 | 2027-01-31 | egui/accesskit upgrade (quick-xml ≥ 0.41) |
| RUSTSEC-2026-0009 | time 0.3.41 | DoS (vulnerability) | `passkey` feature only (x509 certificate dates built from ASN.1 numbers); the RFC 2822 parser is never called | @peter1490 | 2027-01-31 | MSRV ≥ 1.88, then `cargo update -p time` |
| RUSTSEC-2026-0192 | ttf-parser 0.25.1 | unmaintained | egui 0.32 text stack; no maintained drop-in | @peter1490 | 2027-01-31 | egui upgrade replacing ttf-parser |
| RUSTSEC-2024-0436 | paste 1.0.15 | unmaintained (audit-only) | compile-time proc-macro reachable only via wgpu-hal/metal, which no shipped build compiles | @peter1490 | 2027-01-31 | eframe/wgpu upgrade |

## Upgrade plan (compiler and UI stack)

Every accepted advisory above, the winit Windows multi-monitor workaround, and
`keyring` 3.x (whose Windows backend cannot request local-machine credential
persistence) trace back to one constraint: the **Rust 1.86 MSRV** pins eframe/egui
0.32, winit 0.30, accesskit, `time` < 0.3.47, `keyring` 3.6, and
`ctap-hid-fido2` 3.5.7. Retiring them is one planned change, not a series of
exceptions:

1. **Raise the MSRV to the oldest toolchain the target stack needs** (≥ 1.88 for
   `time` 0.3.47 and `keyring` 4; check eframe's current `rust-version`), update
   `rust-version`, the `msrv` CI job, and the README.
2. **Upgrade eframe/egui** to a release on winit ≥ 0.31 (fixes
   rust-windowing/winit#4041) with accesskit on quick-xml ≥ 0.41 and a font
   stack without ttf-parser. Then **revert the system-DPI manifest** in
   `crates/filesec-gui/build_support/windows_resources.rs` to per-monitor
   awareness and re-test mixed-DPI monitor movement on Windows 11 24H2.
3. **`cargo update -p time`** to ≥ 0.3.47; lift the `ctap-hid-fido2` pin to the
   newest release that builds on the new MSRV and re-test with a physical key.
4. **`keyring` 4.x**: re-evaluate whether Windows credentials can be stored with
   `CRED_PERSIST_LOCAL_MACHINE`; only then claim device binding on Windows again
   (see `autounlock.rs`).
5. Remove each retired ID from `deny.toml` and `.cargo/audit.toml`; the
   unsuppressed report must then show no accepted exceptions for them.

Until then, each review-by date forces a fresh look at whether the reachability
argument still holds and whether a patched release now fits the toolchain.
