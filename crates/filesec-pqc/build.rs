// Embed the application icon into `filesec-pqc.exe`, using exactly the same
// resources as `filesec.exe` (the shared module lives in the filesec-gui crate).
// The PQC binary once shipped without the required application manifest
// (FS-15); that manifest is now embedded by GPUI into every executable that
// links it, and the release job reads it back out of each final `.exe`.
// Failing to embed the icon fails the build.

#[path = "../filesec-gui/build_support/windows_resources.rs"]
mod windows_resources;

fn main() {
    println!("cargo:rerun-if-changed=../filesec-gui/build_support/windows_resources.rs");
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo");
    let icon = std::path::Path::new(&manifest)
        .join("..")
        .join("filesec-gui")
        .join("assets")
        .join("icon")
        .join("filesec.ico");
    windows_resources::embed(&icon);
}
