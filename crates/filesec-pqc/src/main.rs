//! FileSec desktop app — the **networking build**.
//!
//! The same app as the standard `filesec` binary, plus the `net` feature: direct,
//! server-less peer-to-peer transfer of a vault to a verified contact (an
//! authenticated, forward-secret channel built from FileSec's own primitives,
//! with optional NAT-PMP router port mapping for internet transfers). The
//! post-quantum and AES-256-GCM suites are compiled in as well; new identities are
//! **classical** by default and can be upgraded to hybrid post-quantum in-app. It
//! presents the same "FileSec" name. See `filesec_gui::run`.

// On Windows, don't pop up a console window alongside the GUI in release.
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

fn main() -> eframe::Result<()> {
    filesec_gui::run("FileSec")
}
