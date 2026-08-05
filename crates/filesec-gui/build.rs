// Embed the application icon into the Windows `.exe` so Explorer, the taskbar
// and pinned shortcuts show it. Guarded on CARGO_CFG_WINDOWS so it runs only
// when *targeting* Windows (correct under cross-compilation) and is a no-op for
// the macOS/Linux builds. Embedding is best-effort: a missing resource compiler
// or icon emits a warning rather than failing the build — the NSIS installer
// wires the icon into the shortcut/installer regardless (packaging/windows).
//
// The same resource also carries an application manifest (see `DPI_MANIFEST`).

/// Minimal application manifest, embedded as `RT_MANIFEST` id 1 so Windows reads
/// it at process creation. It marks the app **System**-DPI-aware on purpose.
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
const DPI_MANIFEST: &str = r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">system</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
"#;

fn main() {
    // Record the target triple for the Settings page (`env!("FILESEC_TARGET")`).
    // Cargo exposes TARGET to build scripts only — it is not otherwise visible
    // to the crate being compiled. Emitted before the Windows-only early return
    // below so every platform gets it, and re-evaluated per target so
    // cross-compiles report the target rather than the host.
    println!(
        "cargo:rustc-env=FILESEC_TARGET={}",
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string())
    );

    if std::env::var_os("CARGO_CFG_WINDOWS").is_none() {
        return;
    }
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo");
    let icon = std::path::Path::new(&manifest)
        .join("assets")
        .join("icon")
        .join("filesec.ico");
    println!("cargo:rerun-if-changed={}", icon.display());

    let mut res = winresource::WindowsResource::new();
    res.set_icon(&icon.to_string_lossy());
    // System-DPI-aware manifest — works around rust-windowing/winit#4041 on
    // Windows 11 24H2 multi-monitor. See `DPI_MANIFEST` for the full rationale.
    res.set_manifest(DPI_MANIFEST);
    if let Err(e) = res.compile() {
        println!("cargo:warning=could not embed Windows resources: {e}");
    }
}
