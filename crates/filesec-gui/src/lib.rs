//! FileSec desktop app library: the egui [`app`] and the on-disk [`store`].
//!
//! Split into a library so the persistence layer can be integration-tested
//! without spawning a window. The `filesec` binary is a thin entry point over
//! [`app::App`].

pub mod app;
pub mod autounlock;
pub mod mount;
pub mod passkey;
pub mod store;
pub mod theme;

/// Launch the desktop app with the given window title.
///
/// Shared by the two binaries that ship from this workspace — `filesec`
/// (classical) and `filesec-pqc` (post-quantum) — which differ only in the cargo
/// features they compile, not in their entry point.
pub fn run(title: &str) -> eframe::Result<()> {
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_inner_size([1040.0, 700.0])
        .with_min_inner_size([720.0, 520.0])
        .with_title(title);
    // Window / taskbar / dock icon (the same FileSec logo as the release icons).
    if let Ok(icon) =
        eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon/icon-256.png"))
    {
        viewport = viewport.with_icon(icon);
    }
    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        title,
        native_options,
        Box::new(|cc| {
            theme::install(&cc.egui_ctx);
            Ok(Box::new(app::App::new()))
        }),
    )
}
