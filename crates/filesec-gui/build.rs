// Embed the application icon into the Windows `.exe` so Explorer, the taskbar
// and pinned shortcuts show it. Guarded on CARGO_CFG_WINDOWS so it runs only
// when *targeting* Windows (correct under cross-compilation) and is a no-op for
// the macOS/Linux builds. Embedding is best-effort: a missing resource compiler
// or icon emits a warning rather than failing the build — the NSIS installer
// wires the icon into the shortcut/installer regardless (packaging/windows).
fn main() {
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
    if let Err(e) = res.compile() {
        println!("cargo:warning=could not embed Windows icon: {e}");
    }
}
