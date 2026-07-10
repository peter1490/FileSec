// Fuzz the CBOR decode of a public identity (`.fsecpub` body). Untrusted bytes
// from an imported/received identity flow straight into this parser.
#![no_main]

use filesec_core::PublicIdentity;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic — only ever return Ok/Err. A successful parse is
    // round-tripped and its (cheap, name-free) fingerprint computed to exercise
    // the post-decode paths.
    if let Ok(id) = PublicIdentity::from_bytes(data) {
        let _ = id.fingerprint();
        let _ = id.display_name();
        let _ = id.to_bytes();
    }
});
