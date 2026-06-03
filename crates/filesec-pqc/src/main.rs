//! FileSec desktop app — **post-quantum build**.
//!
//! Identical to the classical `filesec` binary, but compiled with the `pqc`
//! feature so new identities are hybrid (X25519+ML-KEM-768 / Ed25519+ML-DSA-65),
//! the post-quantum and AES-256-GCM export suites are available, and the local
//! store is encrypted at rest under the hybrid suite. It presents the same
//! "FileSec" name as the classical build. See `filesec_gui::run`.

// On Windows, don't pop up a console window alongside the GUI in release.
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

fn main() -> eframe::Result<()> {
    filesec_gui::run("FileSec")
}
