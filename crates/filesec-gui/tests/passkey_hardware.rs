//! On-device smoke test for the hardware passkey backend.
//!
//! This exercises a real enroll → unlock round trip against a **physical FIDO2
//! security key** that supports the `hmac-secret` extension. It needs human
//! interaction (a touch, possibly a PIN) and a plugged-in key, so it is both
//! feature-gated and `#[ignore]`d — it never runs in CI. Run it by hand:
//!
//! ```sh
//! cargo test -p filesec-gui --features passkey \
//!     --test passkey_hardware -- --ignored --nocapture
//! ```
#![cfg(feature = "passkey")]

use filesec_core::identity::Identity;
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::KeystoreFile;
use filesec_gui::passkey;

#[test]
#[ignore = "requires a physical FIDO2 security key; run with --ignored"]
fn enroll_then_unlock_with_hardware_key() {
    let id = Identity::generate("Device Test", 0).unwrap();
    let params = KdfParams {
        m_cost: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    };
    let mut ks = KeystoreFile::create(&id, b"test passphrase", params).unwrap();

    eprintln!("\n>>> Touch your security key to ENROLL it…");
    let enrollment = passkey::enroll("smoke-test key", None, 0).expect("enroll");
    let credential_id = enrollment.credential_id.clone();
    let salt = enrollment.hmac_salt;
    ks.add_passkey(b"test passphrase", enrollment)
        .expect("add_passkey");
    assert!(ks.has_passkeys());

    eprintln!(">>> Touch your security key again to UNLOCK…");
    let secret = passkey::assert(&credential_id, &salt, None).expect("assert");
    let opened = ks
        .unlock_with_passkey(0, &secret)
        .expect("unlock_with_passkey");

    assert_eq!(opened.fingerprint(), id.fingerprint());
    // The passphrase must still work as a co-equal method.
    assert_eq!(
        ks.unlock(b"test passphrase").unwrap().fingerprint(),
        id.fingerprint()
    );
    eprintln!(">>> OK: enroll + passkey unlock + passphrase unlock all succeeded.");
}
