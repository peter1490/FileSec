//! Unit-level tests for the cryptographic primitives and key/identity stores.

use filesec_core::aead::{decrypt_stream, encrypt_stream, open, seal, NONCE_LEN, STREAM_NONCE_LEN};
use filesec_core::contacts::{ContactBook, Trust, UpsertOutcome};
use filesec_core::identity::Identity;
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::{KeystoreFile, PasskeyEnrollment, HMAC_SECRET_LEN};
use filesec_core::secret::{ct_eq, random_vec, SymKey};
use filesec_core::{Error, PublicIdentity};
use std::io::Cursor;
use zeroize::Zeroizing;

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
fn decrypt_chunk_enables_random_access() {
    use filesec_core::aead::{decrypt_chunk, TAG_LEN};
    let key = SymKey::random().unwrap();
    let nonce = random_vec(STREAM_NONCE_LEN).unwrap();
    let chunk = 100usize;
    // 350 bytes -> chunks of 100,100,100,50 = 4 chunks.
    let pt: Vec<u8> = (0..350u32).map(|i| (i % 256) as u8).collect();
    let mut ct = Vec::new();
    encrypt_stream(&key, &nonce, b"aad", Cursor::new(&pt), &mut ct, chunk).unwrap();

    let num_chunks = 4u32;
    let mut reassembled = Vec::new();
    let mut offset = 0usize;
    for c in 0..num_chunks {
        let is_last = c == num_chunks - 1;
        let pt_len = if is_last { 50 } else { 100 };
        let ct_len = pt_len + TAG_LEN;
        let slice = &ct[offset..offset + ct_len];
        let dec = decrypt_chunk(&key, &nonce, b"aad", c, is_last, slice).unwrap();
        reassembled.extend_from_slice(&dec);
        offset += ct_len;
    }
    assert_eq!(reassembled, pt);

    // A wrong index or last-flag must fail authentication.
    assert!(decrypt_chunk(&key, &nonce, b"aad", 0, true, &ct[0..100 + TAG_LEN]).is_err());
    assert!(decrypt_chunk(&key, &nonce, b"aad", 1, false, &ct[0..100 + TAG_LEN]).is_err());
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
    use filesec_core::SuiteId;
    let bob = Identity::generate("Bob", 0).unwrap();
    let mallory = Identity::generate("Mallory", 0).unwrap();
    let cek = SymKey::random().unwrap();
    let stanza = wrap_for_recipient(&cek, &bob.public(), SuiteId::Classic).unwrap();

    let recovered = unwrap_with_identity(&stanza, &bob).unwrap();
    assert_eq!(recovered.as_bytes(), cek.as_bytes());

    assert!(unwrap_with_identity(&stanza, &mallory).is_err());
}

#[test]
fn suite_parsing_respects_feature_gate() {
    use filesec_core::SuiteId;
    assert_eq!(SuiteId::from_u16(0x0001).unwrap(), SuiteId::Classic);
    assert!(SuiteId::from_u16(0x9999).is_err());
    // The post-quantum suites parse only when this build can perform them.
    #[cfg(feature = "pqc")]
    {
        assert!(SuiteId::from_u16(0x0002).is_ok());
        assert!(SuiteId::from_u16(0x0101).is_ok());
    }
    #[cfg(not(feature = "pqc"))]
    {
        assert!(matches!(
            SuiteId::from_u16(0x0002),
            Err(Error::UnsupportedSuite(0x0002))
        ));
        assert!(matches!(
            SuiteId::from_u16(0x0101),
            Err(Error::UnsupportedSuite(0x0101))
        ));
    }
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

/// Cheap Argon2id parameters so the keystore tests stay fast.
fn cheap_params() -> KdfParams {
    KdfParams {
        m_cost: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

/// A synthetic passkey enrollment. `secret` stands in for the authenticator's
/// 32-byte `hmac-secret` output (so these tests need no hardware); the same
/// `secret` must be supplied to `unlock_with_passkey`.
fn enrollment(secret: u8, credential_id: &[u8], label: &str) -> PasskeyEnrollment {
    PasskeyEnrollment {
        credential_id: credential_id.to_vec(),
        rp_id: "filesec.local".into(),
        hmac_salt: [secret ^ 0x5a; HMAC_SECRET_LEN],
        label: label.into(),
        added_at: 100,
        hmac_output: Zeroizing::new([secret; HMAC_SECRET_LEN]),
    }
}

#[test]
fn passphrase_only_keystore_is_rollback_protected() {
    let id = Identity::generate("Alice", 1).unwrap();
    let ks = KeystoreFile::create(&id, b"pw correct", cheap_params()).unwrap();
    let bytes = ks.to_bytes().unwrap();
    // New passphrase-only keystores use the signed v3 frame too; legacy v1/v2
    // files are accepted only by the explicit recovery entry point.
    assert!(bytes.starts_with(b"FSK\x1a\x00\x03"));
    assert_eq!(ks.state_metadata().unwrap().epoch, 1);
    assert!(!ks.has_passkeys());
    assert!(ks.passkey_slots().is_empty());
    let opened = KeystoreFile::from_bytes(&bytes)
        .unwrap()
        .unlock(b"pw correct")
        .unwrap();
    assert_eq!(opened.fingerprint(), id.fingerprint());
}

#[test]
fn passkey_and_passphrase_recover_same_identity() {
    let id = Identity::generate("Alice", 7).unwrap();
    let mut ks = KeystoreFile::create(&id, b"pw correct", cheap_params()).unwrap();
    assert!(!ks.has_passkeys());

    let secret = 0x11u8;
    ks.add_passkey(b"pw correct", enrollment(secret, b"cred-1", "Key A"))
        .unwrap();
    assert!(ks.has_passkeys());

    // The first passkey promotes the keystore to the framed v2 format.
    let bytes = ks.to_bytes().unwrap();
    assert!(bytes.starts_with(b"FSK\x1a"));
    let ks = KeystoreFile::from_bytes(&bytes).unwrap();

    // Both unlock paths recover the identical identity.
    assert_eq!(
        ks.unlock(b"pw correct").unwrap().fingerprint(),
        id.fingerprint()
    );
    assert_eq!(
        ks.unlock_with_passkey(0, &[secret; HMAC_SECRET_LEN])
            .unwrap()
            .fingerprint(),
        id.fingerprint()
    );
    // Wrong passphrase is still rejected after promotion.
    assert!(matches!(ks.unlock(b"nope"), Err(Error::BadPassphrase)));
}

#[test]
fn wrong_passkey_secret_and_bad_index_fail_cleanly() {
    let id = Identity::generate("Bob", 9).unwrap();
    let mut ks = KeystoreFile::create(&id, b"pw", cheap_params()).unwrap();
    ks.add_passkey(b"pw", enrollment(0x22, b"cred", "K"))
        .unwrap();
    // Wrong hmac secret cannot unwrap the DEK.
    assert!(ks.unlock_with_passkey(0, &[0x23; HMAC_SECRET_LEN]).is_err());
    // An out-of-range slot index errors rather than panicking.
    assert!(ks.unlock_with_passkey(5, &[0x22; HMAC_SECRET_LEN]).is_err());
}

#[test]
fn multiple_passkeys_each_unlock() {
    let id = Identity::generate("Carol", 3).unwrap();
    let mut ks = KeystoreFile::create(&id, b"pw", cheap_params()).unwrap();
    ks.add_passkey(b"pw", enrollment(0x31, b"cred-0", "Key Zero"))
        .unwrap();
    ks.add_passkey(b"pw", enrollment(0x32, b"cred-1", "Key One"))
        .unwrap();

    let slots = ks.passkey_slots();
    assert_eq!(slots.len(), 2);
    assert_eq!(slots[0].label, "Key Zero");
    assert_eq!(slots[0].credential_id, b"cred-0");
    assert_eq!(slots[0].rp_id, "filesec.local");
    assert_eq!(slots[1].label, "Key One");

    assert_eq!(
        ks.unlock_with_passkey(0, &[0x31; HMAC_SECRET_LEN])
            .unwrap()
            .fingerprint(),
        id.fingerprint()
    );
    assert_eq!(
        ks.unlock_with_passkey(1, &[0x32; HMAC_SECRET_LEN])
            .unwrap()
            .fingerprint(),
        id.fingerprint()
    );
}

#[test]
fn remove_passkey_keeps_passphrase_and_survivors() {
    let id = Identity::generate("Dave", 4).unwrap();
    let mut ks = KeystoreFile::create(&id, b"pw", cheap_params()).unwrap();
    ks.add_passkey(b"pw", enrollment(0x41, b"c0", "K0"))
        .unwrap();
    ks.add_passkey(b"pw", enrollment(0x42, b"c1", "K1"))
        .unwrap();

    ks.remove_passkey(0, &id).unwrap();
    let slots = ks.passkey_slots();
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].label, "K1");
    // The survivor is now index 0 and still unlocks; passphrase still works.
    assert_eq!(
        ks.unlock_with_passkey(0, &[0x42; HMAC_SECRET_LEN])
            .unwrap()
            .fingerprint(),
        id.fingerprint()
    );
    assert_eq!(ks.unlock(b"pw").unwrap().fingerprint(), id.fingerprint());

    // Out-of-range removal errors, doesn't panic.
    assert!(ks.remove_passkey(9, &id).is_err());

    // Removing the last passkey leaves the passphrase as the only way in.
    ks.remove_passkey(0, &id).unwrap();
    assert!(!ks.has_passkeys());
    assert_eq!(ks.unlock(b"pw").unwrap().fingerprint(), id.fingerprint());
}

#[test]
fn malformed_keystore_is_rejected_cleanly() {
    assert!(KeystoreFile::from_bytes(b"").is_err());
    assert!(KeystoreFile::from_bytes(b"not a keystore").is_err());
    // Magic present but an unsupported version → clean Format error, no panic.
    let mut framed = Vec::new();
    framed.extend_from_slice(b"FSK\x1a");
    framed.extend_from_slice(&99u16.to_be_bytes());
    framed.push(0xa0); // an empty CBOR map body
    assert!(matches!(
        KeystoreFile::from_bytes(&framed),
        Err(Error::Format(_))
    ));
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
    assert_eq!(book.upsert(id.public(), 100), UpsertOutcome::Added);
    let c = book.find(&fpr).unwrap();
    assert_eq!(c.trust, Trust::Unverified);
    assert_eq!(c.verified_at, None);

    assert!(book.set_trust(&fpr, Trust::Verified, 150));
    assert_eq!(book.find(&fpr).unwrap().verified_at, Some(150));

    let bytes = book.to_bytes().unwrap();
    let mut parsed = ContactBook::from_bytes(&bytes).unwrap();
    let c = parsed.find(&fpr).unwrap();
    assert_eq!(c.trust, Trust::Verified);
    assert_eq!(c.verified_at, Some(150));

    // Re-importing the same key with the same name changes nothing and must not
    // silently reset verified trust.
    assert_eq!(parsed.upsert(id.public(), 200), UpsertOutcome::Unchanged);
    assert_eq!(parsed.find(&fpr).unwrap().trust, Trust::Verified);

    // Dropping back to unverified clears the verification timestamp.
    assert!(parsed.set_trust(&fpr, Trust::Unverified, 300));
    assert_eq!(parsed.find(&fpr).unwrap().verified_at, None);

    assert!(parsed.remove(&fpr));
    assert!(parsed.find(&fpr).is_none());
}

#[test]
fn contact_book_loads_without_verified_at_field() {
    // A contact book written before the `verified_at` field existed must still
    // deserialize, defaulting the missing field to `None`. We reproduce the old
    // on-disk shape with a struct that lacks the field.
    #[derive(serde::Serialize)]
    struct OldContact {
        identity: PublicIdentity,
        trust: Trust,
        added_at: i64,
    }
    #[derive(serde::Serialize)]
    struct OldBook {
        contacts: Vec<OldContact>,
    }

    let id = Identity::generate("Bob", 7).unwrap();
    let fpr = id.fingerprint();
    let old = OldBook {
        contacts: vec![OldContact {
            identity: id.public(),
            trust: Trust::Verified,
            added_at: 42,
        }],
    };
    let bytes = filesec_core::codec::to_vec(&old).unwrap();

    let book = ContactBook::from_bytes(&bytes).unwrap();
    let c = book.find(&fpr).unwrap();
    assert_eq!(c.trust, Trust::Verified);
    assert_eq!(c.added_at, 42);
    assert_eq!(c.verified_at, None);
}

#[test]
fn upsert_reports_renames_and_preserves_verification() {
    let id = Identity::generate("Alice", 1).unwrap();
    let fpr = id.fingerprint();
    let mut book = ContactBook::default();
    book.upsert(id.public(), 0);
    assert!(book.set_trust(&fpr, Trust::Verified, 10));

    // Re-import the *same keys* under a different display name: the keys (and so
    // the verification) are unchanged, but the rename is reported.
    let mut renamed = id.public();
    renamed.name = "Alice (work)".into();
    assert_eq!(
        book.upsert(renamed, 20),
        UpsertOutcome::Renamed {
            old: "Alice".into(),
            new: "Alice (work)".into(),
            was_verified: true,
        }
    );
    let c = book.find(&fpr).unwrap();
    assert_eq!(c.identity.name, "Alice (work)");
    assert_eq!(c.trust, Trust::Verified);
}

#[test]
fn safety_number_matching_is_forgiving() {
    let id = Identity::generate("Bob", 7).unwrap();
    let pubid = id.public();
    let sn = pubid.safety_number();

    // The canonical rendering matches itself.
    assert!(pubid.safety_number_matches(&sn));
    // Spacing, case, and dashes are ignored when comparing.
    assert!(pubid.safety_number_matches(&sn.replace('-', " ").to_lowercase()));
    assert!(pubid.safety_number_matches(&format!("  {sn}\n")));
    // Empty input never counts as a match.
    assert!(!pubid.safety_number_matches(""));
    assert!(!pubid.safety_number_matches("   "));
    // A different identity's number does not match.
    let other = Identity::generate("Eve", 7).unwrap().public();
    assert!(!pubid.safety_number_matches(&other.safety_number()));
}

#[test]
fn from_pasted_accepts_armored_and_bare_base64() {
    let id = Identity::generate("Bob", 7).unwrap();
    let pubid = id.public();
    let armored = pubid.to_armored().unwrap();

    // Full armored block.
    assert_eq!(
        PublicIdentity::from_pasted(&armored).unwrap().fingerprint(),
        pubid.fingerprint()
    );
    // Bare base64 body, armor lines stripped — what survives a lossy copy/paste.
    let bare: String = armored
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        PublicIdentity::from_pasted(&bare).unwrap().fingerprint(),
        pubid.fingerprint()
    );
    // Garbage is rejected.
    assert!(PublicIdentity::from_pasted("hello there").is_err());
    assert!(PublicIdentity::from_pasted("").is_err());
}

#[test]
fn safety_number_is_grouped_and_stable() {
    let id = Identity::generate("Bob", 7).unwrap();
    let sn = id.public().safety_number();
    assert!(sn.contains('-'));
    assert_eq!(sn, id.public().safety_number());
}
