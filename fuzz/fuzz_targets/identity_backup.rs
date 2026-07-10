// Fuzz the identity-backup importer (`.fsecid`). It runs the armor/base64 decode,
// the magic + version framing check, the length/KDF-parameter clamps, and the
// CBOR decode of the backup body — all before (and independently of) the
// passphrase-gated AEAD open, so a fixed passphrase still exercises the parser.
#![no_main]

use filesec_core::keystore::import_identity_armored;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = import_identity_armored(&text, b"fuzz-passphrase");
});
