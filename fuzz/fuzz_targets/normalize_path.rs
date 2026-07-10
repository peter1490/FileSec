// Fuzz the untrusted-path normalizer (F19). Every entry path in an imported
// container passes through here; it must reject absolute/drive/traversal/control
// inputs and normalize valid relative paths — never panic, never emit an absolute
// or `..`-bearing result.
#![no_main]

use filesec_core::vault::normalize_path;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    if let Ok(norm) = normalize_path(&s) {
        // Invariants the normalizer promises on success.
        assert!(!norm.is_empty(), "normalized path is never empty");
        assert!(!norm.starts_with('/'), "normalized path is never absolute");
        assert!(
            !norm.split('/').any(|c| c == ".." || c == "." || c.is_empty()),
            "no traversal, `.`, or empty components survive normalization: {norm:?}"
        );
    }
});
