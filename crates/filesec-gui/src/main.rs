//! FileSec desktop app — a native, offline secure file-exchange tool.
//!
//! Pure-Rust egui front-end over the `filesec-core` cryptography and `.fsec`
//! container format. No webview, no network.
//!
//! This is the **classical** build (default suite `0x0001`). The post-quantum
//! build is the sibling `filesec-pqc` binary, which is the same app compiled
//! with `--features pqc`. Both call [`filesec_gui::run`].

// On Windows, don't pop up a console window alongside the GUI in release.
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

fn main() -> eframe::Result<()> {
    filesec_gui::run("FileSec")
}
