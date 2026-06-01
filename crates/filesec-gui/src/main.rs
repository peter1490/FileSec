//! FileSec desktop app — a native, offline secure file-exchange tool.
//!
//! Pure-Rust egui front-end over the `filesec-core` cryptography and `.fsec`
//! container format. No webview, no network.

// On Windows, don't pop up a console window alongside the GUI in release.
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use filesec_gui::app::App;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([920.0, 640.0])
            .with_min_inner_size([640.0, 480.0])
            .with_title("FileSec"),
        ..Default::default()
    };
    eframe::run_native(
        "FileSec",
        native_options,
        Box::new(|_cc| Ok(Box::new(App::new()))),
    )
}
