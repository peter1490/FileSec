// Embed the application icon and the required DPI-awareness manifest into the
// Windows `.exe` (shared with filesec-pqc; see build_support/windows_resources.rs).
// The icon is what Explorer, the taskbar and pinned shortcuts show; the
// manifest works around a winit multi-monitor bug and is mandatory, so failing
// to embed it fails the build.

#[path = "build_support/windows_resources.rs"]
mod windows_resources;

fn main() {
    // Record the target triple for the Settings page (`env!("FILESEC_TARGET")`).
    // Cargo exposes TARGET to build scripts only — it is not otherwise visible
    // to the crate being compiled. Emitted for every platform and re-evaluated
    // per target, so cross-compiles report the target rather than the host.
    println!(
        "cargo:rustc-env=FILESEC_TARGET={}",
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string())
    );
    println!("cargo:rerun-if-changed=build_support/windows_resources.rs");

    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo");
    let icon = std::path::Path::new(&manifest)
        .join("assets")
        .join("icon")
        .join("filesec.ico");
    windows_resources::embed(&icon);
}
