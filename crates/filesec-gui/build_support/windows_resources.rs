// Windows resources shared by BOTH shipped executables (`filesec.exe` from
// crates/filesec-gui and `filesec-pqc.exe` from crates/filesec-pqc). Each build
// script includes this file with `#[path]`, so the two binaries can never again
// diverge on required runtime metadata (audit FS-15: the PQC binary once shipped
// without the application manifest).
//
// What each executable carries, and who embeds it:
//
// - The **icon**: embedded here. Explorer, the taskbar and pinned shortcuts show
//   it, and GPUI takes the window icon from the executable.
// - The **application manifest** (`RT_MANIFEST` id 1): embedded by GPUI itself,
//   NOT here. gpui-kit depends on `gpui-pre` with its default `windows-manifest`
//   feature, whose build script compiles `resources/windows/gpui.manifest.xml`
//   into a resource library that is linked into every executable using GPUI,
//   and fails GPUI's own build if it cannot (`manifest_required`). That manifest
//   declares per-monitor-v2 DPI awareness (`true/pm` + `PerMonitorV2`), the
//   Common Controls v6 dependency GPUI's native message boxes need, `asInvoker`,
//   Windows 10 compatibility and the segment heap. A second manifest from this
//   crate would be a duplicate `RT_MANIFEST` #1 and fail the link (CVT1100), and
//   the feature cannot be switched off from here, so this module embeds only
//   the icon.
//
// Because the manifest now comes from a dependency, it is guarded by checking
// what ships: packaging/windows/verify_resources.ps1 reads `RT_MANIFEST` #1 back
// out of each final `.exe` in CI and in the release job, and fails unless it
// declares `PerMonitorV2` and the Common Controls v6 dependency. (The egui/winit
// build embedded its own *system*-DPI manifest here, to dodge winit#4041's
// multi-monitor resize loop; GPUI has no such loop.)

/// Escape hatch for development cross-checks from a host without a Windows
/// resource compiler (e.g. `cargo check --target x86_64-pc-windows-gnu` on
/// macOS). Never set it for a build that will be run or shipped.
pub const ALLOW_MISSING_ENV: &str = "FILESEC_ALLOW_MISSING_WINDOWS_RESOURCES";

/// Embed the icon when targeting Windows; a no-op for other targets (guarded on
/// `CARGO_CFG_WINDOWS`, so it is correct under cross-compilation).
///
/// A failure to embed it **fails the build** unless [`ALLOW_MISSING_ENV`] is
/// set, so a shipped executable never silently loses its icon.
pub fn embed(icon: &std::path::Path) {
    println!("cargo:rerun-if-env-changed={ALLOW_MISSING_ENV}");
    if std::env::var_os("CARGO_CFG_WINDOWS").is_none() {
        return;
    }
    println!("cargo:rerun-if-changed={}", icon.display());
    let mut res = winresource::WindowsResource::new();
    res.set_icon(&icon.to_string_lossy());
    if let Err(e) = res.compile() {
        if std::env::var_os(ALLOW_MISSING_ENV).is_some() {
            println!(
                "cargo:warning=Windows icon resource NOT embedded ({e}); \
                 {ALLOW_MISSING_ENV} is set, so this binary is for checking only"
            );
        } else {
            panic!(
                "could not embed the Windows icon resource: {e}. Install the Windows \
                 resource compiler, or set {ALLOW_MISSING_ENV}=1 for a check-only \
                 cross build."
            );
        }
    }
}
