// Fuzz the CBOR decode of a container manifest. The manifest is the structured
// file/directory listing parsed out of every container; malformed layouts must
// error cleanly rather than panic or over-allocate.
#![no_main]

use filesec_core::manifest::Manifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = filesec_core::codec::from_slice::<Manifest>(data);
});
