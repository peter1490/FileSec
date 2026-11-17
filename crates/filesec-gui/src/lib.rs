//! FileSec desktop app library: the GPUI [`app`] and the on-disk [`store`].
//!
//! Split into a library so the persistence layer can be integration-tested
//! without spawning a window. The `filesec` and `filesec-pqc` binaries are
//! thin entry points over [`run`].

pub mod anchors;
pub mod app;
pub mod autounlock;
#[cfg(feature = "net")]
pub mod net;
pub mod passkey;
pub mod prefs;
pub mod repaint;
pub mod secret_input;
pub mod store;
pub mod theme;
pub mod wipe;

use gpui_kit::{
    point, px, size, App, AppContext, Bounds, SharedString, TitlebarOptions, WindowBounds,
    WindowOptions,
};

/// The default and minimum window sizes (logical pixels).
pub const WINDOW_SIZE: (f32, f32) = (1100.0, 720.0);
pub const WINDOW_MIN_SIZE: (f32, f32) = (720.0, 520.0);

/// Whether the window draws its own (unified) titlebar: on macOS the content
/// runs under a transparent titlebar, the traffic lights sit over the
/// sidebar, and the top [`theme::HEADER_H`] strip moves the window. Windows
/// and Linux keep the system titlebar, which already behaves natively.
pub const UNIFIED_TITLEBAR: bool = cfg!(target_os = "macos");

/// The titlebar for the one window. On macOS the traffic lights are centred
/// vertically in the page-header strip.
fn titlebar(title: SharedString) -> TitlebarOptions {
    TitlebarOptions {
        title: Some(title),
        appears_transparent: UNIFIED_TITLEBAR,
        traffic_light_position: UNIFIED_TITLEBAR.then(|| point(px(18.0), px(21.0))),
    }
}

/// The desktop-environment application id. It matches the `.desktop` file each
/// package installs (`packaging/*.desktop`), which is how Linux shells find the
/// window's icon; Windows reads it from the embedded `.exe` resource and macOS
/// from the `.app` bundle.
fn app_id() -> &'static str {
    if cfg!(feature = "net") {
        "filesec-pqc"
    } else {
        "filesec"
    }
}

/// One-time global setup shared by the app and its UI tests: GPUI Component,
/// the FileSec theme and fonts, and the key bindings.
pub fn init(cx: &mut App) {
    gpui_kit::init(cx);
    theme::install(cx);
    secret_input::init(cx);
    app::init(cx);
}

/// Launch the desktop app with the given window title.
///
/// Shared by the two binaries that ship from this workspace — `filesec`
/// (standard) and `filesec-pqc` (networking) — which differ only in the cargo
/// features they compile, not in their entry point.
pub fn run(title: &str) {
    let title: SharedString = title.to_string().into();
    // GPUI Component draws its own glyphs (checkmarks, carets, the spinner)
    // from SVG assets; `AppAssets` is GPUI Kit's default bundle plus the
    // Lucide icons the app's own screens use.
    gpui_kit::application()
        .with_assets(theme::AppAssets)
        .run(move |cx: &mut App| {
            init(cx);
            let bounds = Bounds::centered(None, size(px(WINDOW_SIZE.0), px(WINDOW_SIZE.1)), cx);
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(titlebar(title.clone())),
                // The unified titlebar moves the window itself (see
                // `views::shell::window_drag_strip`), so AppKit must not also
                // claim the strip — that would swallow clicks on its buttons.
                app_owns_titlebar_drag: UNIFIED_TITLEBAR,
                window_min_size: Some(size(px(WINDOW_MIN_SIZE.0), px(WINDOW_MIN_SIZE.1))),
                app_id: Some(app_id().to_string()),
                ..Default::default()
            };
            // Quitting follows the last window: there is only ever one.
            cx.on_window_closed(|cx, _| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();
            if let Err(e) = gpui_kit::open_window(options, cx, |window, cx| {
                cx.new(|cx| app::FileSecApp::new(window, cx))
            }) {
                eprintln!("FileSec could not open its window: {e}");
                cx.quit();
                return;
            }
            cx.activate(true);
        });
}
