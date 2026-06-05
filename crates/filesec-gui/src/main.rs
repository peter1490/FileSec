//! FileSec desktop app — the **standard build**.
//!
//! Pure-Rust egui front-end over the `filesec-core` cryptography and `.fsec`
//! container format. No webview. Works fully offline: vaults are exchanged as
//! portable `.fsec` files over any channel.
//!
//! Shipped with the post-quantum suites compiled in, but new identities are
//! **classical** by default (suite `0x0001`) and can be upgraded to hybrid
//! post-quantum in-app. The sibling `filesec-pqc` binary is the same app plus
//! direct peer-to-peer **network transfer** (`--features net`). Both call
//! [`filesec_gui::run`].

// On Windows, don't pop up a console window alongside the GUI in release.
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

fn main() -> eframe::Result<()> {
    filesec_gui::run("FileSec")
}
