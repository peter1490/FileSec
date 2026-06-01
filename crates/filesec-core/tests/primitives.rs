//! Unit-level tests for the cryptographic primitives and key/identity stores.

use filesec_core::aead::{decrypt_stream, encrypt_stream, open, seal, NONCE_LEN, STREAM_NONCE_LEN};
use filesec_core::contacts::{ContactBook, Trust};
use filesec_core::identity::Identity;
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::KeystoreFile;
use filesec_core::secret::{ct_eq, random_vec, SymKey};
use filesec_core::{Error, PublicIdentity};
use std::io::Cursor;

#[test]
fn oneshot_aead_roundtrip_and_aad_binding() {
    let key = SymKey::random().unwrap();
    let nonce = random_vec(NONCE_LEN).unwrap();
    let ct = seal(&key, &nonce, b"aad", b"secret message").unwrap();
    assert_eq!(open(&key, &nonce, b"aad", &ct).unwrap(), b"secret message");

    // Wrong AAD must fail to authenticate.
    assert!(open(&key, &nonce, b"different", &ct).is_err());
    // Flipped ciphertext must fail.
    let mut bad = ct.clone();
    bad[0] ^= 1;
    assert!(open(&key, &nonce, b"aad", &bad).is_err());
}

#[test]
fn stream_roundtrips_across_sizes() {
    let key = SymKey::random().unwrap();
    let nonce = random_vec(STREAM_NONCE_LEN).unwrap();
    let chunk = 1024;
    for size in [0usize, 1, 1023, 1024, 1025, 2048, 4096, 4096 + 7] {
        let pt: Vec<u8> = (0..size).map(|i| (i * 7) as u8).collect();
        let mut ct = Vec::new();
        encrypt_stream(&key, &nonce, b"ctx", Cursor::new(&pt), &mut ct, chunk).unwrap();
        let mut out = Vec::new();
        decrypt_stream(&key, &nonce, b"ctx", Cursor::new(&ct), &mut out, chunk).unwrap();
        assert_eq!(pt, out, "mismatch at size {size}");
    }
}

#[test]
fn stream_wrong_key_or_aad_fails() {
    let key = SymKey::random().unwrap();
    let other = SymKey::random().unwrap();
    let nonce = random_vec(STREAM_NONCE_LEN).unwrap();
    let pt = vec![9u8; 5000];
    let mut ct = Vec::new();
    encrypt_stream(&key, &nonce, b"ctx", Cursor::new(&pt), &mut ct, 1024).unwrap();

    let mut out = Vec::new();
    assert!(decrypt_stream(&other, &nonce, b"ctx", Cursor::new(&ct), &mut out, 1024).is_err());
    out.clear();
    assert!(decrypt_stream(&key, &nonce, b"WRONG", Cursor::new(&ct), &mut out, 1024).is_err());
}

#[test]
fn ct_eq_behaves() {
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"ab"));
}

#[test]
fn envelope_two_party_key_agreement() {
    // The X25519 envelope: a content key wrapped to Bob can only be recovered
    // with Bob's private identity.
    use filesec_core::envelope::{unwrap_with_identity, wrap_for_recipient};
    let bob = Identity::generate("Bob", 0).unwrap();
    let mallory = Identity::generate("Mallory", 0).unwrap();
    let cek = SymKey::random().unwrap();
    let stanza = wrap_for_recipient(&cek, &bob.public()).unwrap();

    let recovered = unwrap_with_identity(&stanza, &bob).unwrap();
    assert_eq!(recovered.as_bytes(), cek.as_bytes());

    assert!(unwrap_with_identity(&stanza, &mallory).is_err());
}

#[test]
fn keystore_roundtrip_and_wrong_passphrase() {
    let id = Identity::generate("Alice", 42).unwrap();
    // Cheap KDF parameters keep the test fast; production uses the default.
    let params = KdfParams {
        m_cost: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    };
    let ks = KeystoreFile::create(&id, b"correct horse battery staple", params).unwrap();
    let bytes = ks.to_bytes().unwrap();

    let parsed = KeystoreFile::from_bytes(&bytes).unwrap();
    let opened = parsed.unlock(b"correct horse battery staple").unwrap();
    assert_eq!(opened.fingerprint(), id.fingerprint());
    assert_eq!(opened.name, "Alice");
    assert_eq!(opened.created_at, 42);

    match parsed.unlock(b"wrong passphrase") {
        Err(Error::BadPassphrase) => {}
        Err(e) => panic!("expected BadPassphrase, got {e:?}"),
        Ok(_) => panic!("unlock unexpectedly succeeded with the wrong passphrase"),
    }
}

#[test]
fn armored_public_key_roundtrip() {
    let id = Identity::generate("Bob", 7).unwrap();
    let pubid = id.public();
    let armored = pubid.to_armored().unwrap();
    assert!(armored.contains("BEGIN FILESEC PUBLIC KEY"));

    let parsed = PublicIdentity::from_armored(&armored).unwrap();
    assert_eq!(parsed.fingerprint(), pubid.fingerprint());
    assert_eq!(parsed.sign_public, pubid.sign_public);
    assert_eq!(parsed.kem_public, pubid.kem_public);

    // The fingerprint excludes the name, so it is stable across renames.
    let mut renamed = parsed.clone();
    renamed.name = "Robert".into();
    assert_eq!(renamed.fingerprint(), pubid.fingerprint());

    assert!(PublicIdentity::from_armored("not armored").is_err());
}

#[test]
fn contact_book_roundtrip_trust_and_upsert() {
    let id = Identity::generate("Bob", 7).unwrap();
    let fpr = id.fingerprint();

    let mut book = ContactBook::default();
    book.upsert(id.public(), 100);
    assert_eq!(book.find(&fpr).unwrap().trust, Trust::Unverified);

    assert!(book.set_trust(&fpr, Trust::Verified));

    let bytes = book.to_bytes().unwrap();
    let mut parsed = ContactBook::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.find(&fpr).unwrap().trust, Trust::Verified);

    // Re-importing the same key must not silently reset verified trust.
    parsed.upsert(id.public(), 200);
    assert_eq!(parsed.find(&fpr).unwrap().trust, Trust::Verified);

    assert!(parsed.remove(&fpr));
    assert!(parsed.find(&fpr).is_none());
}

#[test]
fn safety_number_is_grouped_and_stable() {
    let id = Identity::generate("Bob", 7).unwrap();
    let sn = id.public().safety_number();
    assert!(sn.contains('-'));
    assert_eq!(sn, id.public().safety_number());
}
