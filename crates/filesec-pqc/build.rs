// Embed the application icon and the required DPI-awareness manifest into
// `filesec-pqc.exe`, using exactly the same resources as `filesec.exe` (the
// shared module lives in the filesec-gui crate). The PQC binary used to embed
// only the icon and so shipped without the winit multi-monitor workaround
// (FS-15). Failing to embed the manifest fails the build.

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
