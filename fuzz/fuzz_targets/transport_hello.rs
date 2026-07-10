// Fuzz the P2P transport handshake parser. The responder decodes the initiator's
// first wire message (`Hello`) — magic, version, ephemeral keys, nonce, and the
// keyed transfer-secret proof — from fully attacker-controlled bytes, before any
// identity or signature material is disclosed. It must reject junk without
// panicking.
#![no_main]

use std::sync::OnceLock;

use filesec_core::transport::Responder;
use filesec_core::Identity;
use libfuzzer_sys::fuzz_target;

// A single fixed responder identity, built once, so each iteration only pays for
// a fresh ephemeral + the message parse rather than a full keygen.
static IDENTITY: OnceLock<Identity> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let identity = IDENTITY.get_or_init(|| {
        Identity::generate("fuzz-responder", 0).expect("keygen for fuzz identity")
    });
    // A fresh responder per iteration (cheap: ephemeral X25519 + a hash). The
    // transfer secret is fixed; the interesting surface is the Hello parse.
    let mut responder = match Responder::new(identity, b"fuzz-transfer-secret", None) {
        Ok(r) => r,
        Err(_) => return,
    };
    let _ = responder.read_hello_write_auth(data);
});
