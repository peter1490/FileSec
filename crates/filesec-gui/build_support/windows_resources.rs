// Windows resources shared by BOTH shipped executables (`filesec.exe` from
// crates/filesec-gui and `filesec-pqc.exe` from crates/filesec-pqc). Each build
// script includes this file with `#[path]`, so the two binaries can never again
// diverge on required runtime metadata (audit FS-15: the PQC binary shipped
// without the DPI manifest below).

/// Minimal application manifest, embedded as `RT_MANIFEST` (resource type 24)
/// id 1 so Windows reads it at process creation.
///
/// It marks the app **per-monitor-v2** DPI aware. GPUI renders at each
/// monitor's own scale factor and handles `WM_DPICHANGED` itself (moving the
/// window between monitors re-lays it out at the new scale), but it does not
/// declare the process's DPI awareness: that is the host executable's job, and
/// without it Windows bitmap-stretches the whole window. Awareness declared in a
/// manifest is locked in before any code runs. (The egui/winit build declared
/// *system* awareness instead, to dodge winit#4041's multi-monitor resize loop;
/// GPUI has no such loop, so a secondary monitor now renders crisp as well.)
///
/// The Common Controls v6 dependency is what GPUI's native message boxes
/// (`TaskDialogIndirect`) need, and matches the manifest Zed itself ships.
// No `<?xml …?>` prolog: winresource wraps each line in a quoted RC string with
// surrounding spaces, so the blob starts with whitespace — and a prolog must be
// the very first bytes of the document. The `<assembly>` root (with harmless
// leading whitespace) is all Windows' manifest loader needs. This matches
// winresource's own documented `set_manifest` example.
// packaging/windows/verify_resources.ps1 checks the built .exe for the
// `<dpiAwareness>PerMonitorV2</dpiAwareness>` element; keep them in sync.
pub const DPI_MANIFEST: &str = r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
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
