// Windows resources shared by BOTH shipped executables (`filesec.exe` from
// crates/filesec-gui and `filesec-pqc.exe` from crates/filesec-pqc). Each build
// script includes this file with `#[path]`, so the two binaries can never again
// diverge on required runtime metadata (audit FS-15: the PQC binary shipped
// without the DPI manifest below).

/// Minimal application manifest, embedded as `RT_MANIFEST` (resource type 24)
/// id 1 so Windows reads it at process creation. It marks the app
/// **System**-DPI-aware on purpose.
///
/// This is a workaround for an upstream winit 0.30 bug on Windows 11 24H2
/// (rust-windowing/winit#4041): winit's `WM_DPICHANGED` handler mis-validates the
/// OS-suggested window rect when a window is dragged between monitors with
/// different scale factors and snaps it back onto the old monitor, which fires
/// the event again — a feedback loop that grows the window without bound until it
/// vanishes and the app has to be restarted. Awareness declared in a manifest is
/// locked in before any code runs, so winit's programmatic per-monitor-v2 call is
/// ignored and Windows stops emitting the per-monitor `WM_DPICHANGED` events that
/// drive the loop. The trade-off is that a secondary monitor whose scaling
/// differs from the primary is bitmap-stretched (slightly soft) rather than
/// crisp; single-monitor and uniform-scaling setups are unaffected. Drop this and
/// let winit go back to per-monitor-v2 once a fixed winit ships and eframe bumps.
// No `<?xml …?>` prolog: winresource wraps each line in a quoted RC string with
// surrounding spaces, so the blob starts with whitespace — and a prolog must be
// the very first bytes of the document. The `<assembly>` root (with harmless
// leading whitespace) is all Windows' manifest loader needs. This matches
// winresource's own documented `set_manifest` example.
// packaging/windows/verify_resources.ps1 checks the built .exe for the
// `<dpiAwareness>system</dpiAwareness>` element; keep them in sync.
pub const DPI_MANIFEST: &str = r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">system</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
"#;

/// Escape hatch for development cross-checks from a host without a Windows
/// resource compiler (e.g. `cargo check --target x86_64-pc-windows-gnu` on
/// macOS). Never set it for a build that will be run or shipped.
pub const ALLOW_MISSING_ENV: &str = "FILESEC_ALLOW_MISSING_WINDOWS_RESOURCES";

/// Embed the icon and the DPI manifest when targeting Windows; a no-op for
/// other targets (guarded on `CARGO_CFG_WINDOWS`, so it is correct under
/// cross-compilation).
///
/// The manifest is required runtime behavior, not decoration, so a failure to
/// embed it **fails the build** unless [`ALLOW_MISSING_ENV`] is set.
pub fn embed(icon: &std::path::Path) {
    println!("cargo:rerun-if-env-changed={ALLOW_MISSING_ENV}");
    if std::env::var_os("CARGO_CFG_WINDOWS").is_none() {
        return;
    }
    println!("cargo:rerun-if-changed={}", icon.display());
    let mut res = winresource::WindowsResource::new();
    res.set_icon(&icon.to_string_lossy());
    res.set_manifest(DPI_MANIFEST);
    if let Err(e) = res.compile() {
        if std::env::var_os(ALLOW_MISSING_ENV).is_some() {
            println!(
                "cargo:warning=Windows resources (icon + DPI manifest) NOT embedded ({e}); \
                 {ALLOW_MISSING_ENV} is set, so this binary is for checking only"
            );
        } else {
            panic!(
                "could not embed the required Windows resources (icon + DPI manifest): {e}. \
                 Install the Windows resource compiler, or set {ALLOW_MISSING_ENV}=1 for a \
                 check-only cross build."
            );
        }
    }
}
