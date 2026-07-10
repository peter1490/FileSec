// Fuzz the pasted / ASCII-armored public-key parsers. These accept whatever a
// human copies out of chat or email: armor delimiters, bare base64, arbitrary
// whitespace — the most forgiving (and so most exposed) text parsers we ship.
#![no_main]

use filesec_core::PublicIdentity;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = PublicIdentity::from_pasted(&text);
    let _ = PublicIdentity::from_armored(&text);
});
