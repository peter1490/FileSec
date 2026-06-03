// Embed the application icon into the Windows `.exe` (see the matching script in
// crates/filesec-gui/build.rs for the rationale). The icon assets live in the
// filesec-gui crate, so resolve it from there. No-op unless targeting Windows;
// embedding is best-effort and never fails the build.
fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_none() {
        return;
    }
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo");
    let icon = std::path::Path::new(&manifest)
        .join("..")
        .join("filesec-gui")
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
