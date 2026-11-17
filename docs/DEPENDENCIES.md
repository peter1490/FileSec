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

Since the move from egui/eframe to GPUI (see below), every accepted advisory
lives in the UI toolkit's graph — GPUI and GPUI Kit, pinned together as
`gpui-kit = "=0.10.0"`. None is on a path that parses a vault, a `.fsec`
container, a public key, or network input.

| Advisory | Crate | Kind | Why accepted | Owner | Review by | Retired by |
|---|---|---|---|---|---|---|
| RUSTSEC-2026-0194, RUSTSEC-2026-0195 | quick-xml 0.39.4 | DoS (vulnerability) | Build time only: the `wayland-scanner` proc-macro parses the Wayland protocol XML bundled in the wayland-protocols crates. Nothing parses XML with it at run time (accesskit already uses the patched 0.41) | @peter1490 | 2027-05-31 | wayland-scanner on quick-xml ≥ 0.41 |
| RUSTSEC-2026-0192 | ttf-parser 0.25.1 | unmaintained | GPUI's Linux text stack (cosmic-text → fontdb) and usvg; parses the bundled and installed system fonts only | @peter1490 | 2027-05-31 | GPUI text/SVG stack on skrifa |
| RUSTSEC-2026-0370, RUSTSEC-2026-0371, RUSTSEC-2026-0372 | zvariant, zbus_names, zvariant_derive (4.x and 5.x) | unmaintained | Standalone crates merged into zbus 6; no patched standalone releases. GPUI's Linux D-Bus users (AT-SPI, portal, notifications, Secret Service) still require zbus 5; not FileSec container or network parsers | @peter1490 | 2027-05-31 | zbus 6 migration upstream |
| RUSTSEC-2024-0384 | instant 0.1.13 | unmaintained | Timing shim inside GPUI Base; no input parsing | @peter1490 | 2027-05-31 | GPUI Kit replacing it (e.g. web-time) |
| RUSTSEC-2024-0436 | paste 1.0.15 | unmaintained | Compile-time proc-macro in GPUI Component; nothing of it is in the binary | @peter1490 | 2027-05-31 | GPUI Component replacing it |
| RUSTSEC-2026-0206 | rustybuzz 0.20.1 | unmaintained | Text shaping inside usvg, which renders GPUI's compiled-in SVG icons (FileSec never renders user content) | @peter1490 | 2027-05-31 | usvg moving to harfrust |
| RUSTSEC-2025-0134 | rustls-pemfile 2.2.0 | unmaintained (audit-only) | Only via GPUI Kit's asset-fetching HTTP client, which is in `Cargo.lock` but in no shipped target's build; FileSec makes no HTTP requests | @peter1490 | 2027-05-31 | GPUI Kit dropping rustls-pemfile |

Retired by the GPUI migration: RUSTSEC-2026-0009 (`time` < 0.3.47 — the raised
toolchain floor allowed `time` 0.3.55). `rustix` was moved to 1.1.6 for
RUSTSEC-2026-0486 (unsound, fixed upstream) rather than accepted.

## The UI stack and the toolchain floor

The desktop app moved from egui/eframe 0.32 to [GPUI](https://gpui.rs) (Zed's
UI framework) through the [GPUI Kit](https://gpui-kit.com) facade, which bundles
a matched GPUI snapshot (published as the `gpui-pre-*` crates) and the GPUI
Component library. The two are pinned exactly together: a newer `gpui-pre`
snapshot alone is not supported by a given Kit release.

That move set new toolchain floors: **Rust 1.95 on Linux and Windows, 1.98 on
macOS**. GPUI itself uses `std::hint::cold_path` (stable in 1.95), and its macOS
backend (`gpui-pre-macos`) also uses `Option::map_or_default` (stable in 1.98).
Both are higher than any `rust-version` its crates declare (the highest is
`oo7`'s 1.92), which is why CI's `msrv` job measures each floor by building
every shipped feature on macOS, Windows, and Linux with exactly that toolchain
instead of trusting manifests. The pinned CI and release toolchain
(`RUST_TOOLCHAIN`) moved from 1.97.0 to 1.98.0 for the same reason. The move
also retired the egui-era constraints recorded here before:

- **winit 0.30's Windows multi-monitor loop** is gone, and with it the
  system-DPI manifest workaround: the executables now declare per-monitor-v2
  awareness, which GPUI expects (`build_support/windows_resources.rs`).
- **egui's text stack** (ab_glyph → owned_ttf_parser) and **rfd** (with GTK on
  Linux) are no longer linked; file dialogs are GPUI's native prompts.
- **`time` < 0.3.47** is no longer forced (see above).

Still open:

1. **`keyring` 4.x**: re-evaluate whether Windows credentials can be stored with
   `CRED_PERSIST_LOCAL_MACHINE`; only then claim device binding on Windows again
   (see `autounlock.rs`). Needs hardware/OS testing, independent of the UI.
2. **`ctap-hid-fido2`**: lift the 3.5.7 pin to a newer release and re-test with a
   physical key.
3. **Upgrade GPUI Kit** as its releases retire the toolkit exceptions above
   (watch for usvg on harfrust, skrifa-based fonts, zbus 6, and wayland-scanner
   on quick-xml ≥ 0.41). Bump `gpui-kit` (which moves the `gpui-pre-*` pins with
   it), re-run the UI tests and the `msrv` job, and remove each retired ID from
   `deny.toml` and `.cargo/audit.toml`; the unsuppressed report must then show
   no accepted exceptions for them.

Until then, each review-by date forces a fresh look at whether the reachability
argument still holds and whether a patched release is available.

## October 2026 cryptography dependency fix

Both lockfiles now select `ctutils` 0.4.4 instead of 0.4.2, fixing
[RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html).
This transitive dependency is used by the ML-KEM/ML-DSA feature graph. The fix
removes secret-dependent branches in mask generation and certain comparisons;
it is not an advisory exception. The patched crate requires Rust 1.87, so the
workspace minimum and the macOS/Windows minimum-toolchain CI checks move to
1.87 together. The withdrawn `clipboard-win` 5.4.1 release is also replaced by
5.4.3 in the desktop lockfile. Linux keeps its existing 1.88 minimum. Vault and identity formats
are unchanged. (Superseded: the GPUI migration later raised the floor to 1.95 on
Linux and Windows and 1.98 on macOS; see "The UI stack and the toolchain floor"
above.)

The separate maintenance notices for
[zvariant](https://rustsec.org/advisories/RUSTSEC-2026-0370.html),
[zbus_names](https://rustsec.org/advisories/RUSTSEC-2026-0371.html), and
[zvariant_derive](https://rustsec.org/advisories/RUSTSEC-2026-0372.html) are
tracked in the table above with an owner, expiry date, and upstream migration
condition. The [upstream consolidation announcement](https://github.com/z-galaxy/zbus/issues/2043)
explains why there are no patched standalone releases.
