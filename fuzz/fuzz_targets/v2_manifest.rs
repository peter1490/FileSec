// Fuzz the v2 (local vault) manifest validator — the checks `VaultReaderV2::open`
// runs on a decrypted manifest before any blob is read: entry count, duplicate
// and malformed paths, tree shape, blob ids, chunk sizes, nonce lengths.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = filesec_core::format_v2::fuzz_validate_manifest(data);
});
