//! Phase 5 post-quantum suite tests: AES-256-GCM (`0x0002`) and the hybrid
//! X25519+ML-KEM-768 / Ed25519+ML-DSA-65 suite (`0x0101`).
//!
//! These only build with the `pqc` feature (the suites do not otherwise exist).

#![cfg(feature = "pqc")]

use filesec_core::aead::DEFAULT_CHUNK_SIZE;
use filesec_core::format::{self, ExportOptions};
use filesec_core::identity::Identity;
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::KeystoreFile;
use filesec_core::vault::Vault;
use filesec_core::{Error, SuiteId};
use std::path::PathBuf;

fn tmp_path(name: &str) -> PathBuf {
    let suffix = filesec_core::util::hex(&filesec_core::secret::random_vec(6).unwrap());
    std::env::temp_dir().join(format!("filesec-pqc-{suffix}-{name}"))
}

fn hybrid(name: &str) -> Identity {
    Identity::generate_hybrid(name, 0).expect("generate hybrid identity")
}

/// A vault with a small file plus a multi-chunk file whose size is not a
/// multiple of the chunk size (so random-access chunk decryption is exercised).
fn sample_vault() -> Vault {
    let mut v = Vault::new("PQC Vault", 1000);
    v.add_file("readme.txt", b"hello pqc".to_vec(), Some(7), Some(0o644))
        .unwrap();
    let big: Vec<u8> = (0..(DEFAULT_CHUNK_SIZE * 2 + 333))
        .map(|i| (i % 251) as u8)
        .collect();
    v.add_file("data/big.bin", big, None, None).unwrap();
    v.add_file("empty.bin", Vec::new(), None, None).unwrap();
    v
}

fn export_suite(
    vault: &Vault,
    sender: &Identity,
    recipients: &[filesec_core::PublicIdentity],
    suite: SuiteId,
) -> Vec<u8> {
    let opts = ExportOptions {
        suite,
        ..Default::default()
    };
    let mut buf = Vec::new();
    format::export_vault(vault, sender, recipients, &opts, &mut buf).expect("export");
    buf
}

fn assert_roundtrips(buf: &[u8], opener: &Identity, expect_suite: SuiteId) {
    let imported = format::import_vault(buf, opener).expect("import");
    assert_eq!(imported.suite, expect_suite);
    let orig = sample_vault();
    assert_eq!(imported.vault.entries().len(), orig.entries().len());
    for e in orig.entries() {
        let got = imported.vault.get(&e.path).expect("entry present");
        assert_eq!(&got.content[..], &e.content[..], "content for {}", e.path);
    }
}

#[test]
fn aes256gcm_suite_roundtrip() {
    let alice = hybrid("Alice");
    let bob = hybrid("Bob");
    // AES-256-GCM is a classical KEM/signature suite, so even a classical
    // recipient works — but here both are hybrid identities.
    let buf = export_suite(&sample_vault(), &alice, &[bob.public()], SuiteId::Aes256Gcm);
    assert_roundtrips(&buf, &bob, SuiteId::Aes256Gcm);
    // Sender is verified as Alice.
    let imported = format::import_vault(&buf, &bob).unwrap();
    assert_eq!(imported.sender_fingerprint, alice.fingerprint());
}

#[test]
fn aes256gcm_works_with_classical_recipient() {
    // AES-GCM uses the classical X25519/Ed25519 KEM+signature, so a classical
    // (non-PQC) recipient must be able to open it.
    let alice = Identity::generate("Alice", 0).unwrap();
    let bob = Identity::generate("Bob", 0).unwrap();
    let buf = export_suite(&sample_vault(), &alice, &[bob.public()], SuiteId::Aes256Gcm);
    assert_roundtrips(&buf, &bob, SuiteId::Aes256Gcm);
}

#[test]
fn hybrid_suite_roundtrip() {
    let alice = hybrid("Alice");
    let bob = hybrid("Bob");
    let buf = export_suite(&sample_vault(), &alice, &[bob.public()], SuiteId::Hybrid);
    assert_roundtrips(&buf, &bob, SuiteId::Hybrid);

    let imported = format::import_vault(&buf, &bob).unwrap();
    // The verified sender carries the post-quantum public keys, and its
    // reconstructed identity is hybrid-capable with a matching fingerprint.
    assert_eq!(imported.sender_fingerprint, alice.fingerprint());
    let sender = imported.sender_public();
    assert!(sender.is_hybrid_capable());
    assert_eq!(sender.fingerprint(), alice.fingerprint());
    assert_eq!(sender.mldsa_public.as_deref(), alice.mldsa_public());
    assert_eq!(sender.mlkem_public.as_deref(), alice.mlkem_public());
}

#[test]
fn hybrid_multi_recipient_and_self() {
    let alice = hybrid("Alice");
    let bob = hybrid("Bob");
    let buf = export_suite(
        &sample_vault(),
        &alice,
        &[alice.public(), bob.public()],
        SuiteId::Hybrid,
    );
    assert!(format::import_vault(&buf, &alice).is_ok());
    assert!(format::import_vault(&buf, &bob).is_ok());
    // A different hybrid identity is not a recipient.
    let carol = hybrid("Carol");
    match format::import_vault(&buf, &carol) {
        Err(Error::NotARecipient) => {}
        Err(e) => panic!("expected NotARecipient, got {e:?}"),
        Ok(_) => panic!("expected NotARecipient, but import succeeded"),
    }
}

#[test]
fn hybrid_export_to_classical_recipient_fails() {
    // A classical recipient has no ML-KEM key, so a hybrid wrap is impossible.
    let alice = hybrid("Alice");
    let classical_bob = Identity::generate("Bob", 0).unwrap();
    let opts = ExportOptions {
        suite: SuiteId::Hybrid,
        ..Default::default()
    };
    let mut buf = Vec::new();
    let r = format::export_vault(
        &sample_vault(),
        &alice,
        &[classical_bob.public()],
        &opts,
        &mut buf,
    );
    assert!(matches!(r, Err(Error::MissingPqcKey(_))));
}

#[test]
fn classical_sender_cannot_export_hybrid() {
    // A classical sender cannot produce the ML-DSA signature a hybrid needs.
    let classical_alice = Identity::generate("Alice", 0).unwrap();
    let bob = hybrid("Bob");
    let opts = ExportOptions {
        suite: SuiteId::Hybrid,
        ..Default::default()
    };
    let mut buf = Vec::new();
    let r = format::export_vault(
        &sample_vault(),
        &classical_alice,
        &[bob.public()],
        &opts,
        &mut buf,
    );
    assert!(matches!(r, Err(Error::MissingPqcKey(_))));
}

#[test]
fn upgraded_to_hybrid_preserves_classical_keys() {
    // Migrating a classical identity keeps its X25519/Ed25519 keys but yields a
    // new (hybrid) fingerprint, and the upgraded identity can sign/open hybrid.
    let classical = Identity::generate("Alice", 5).unwrap();
    let upgraded = classical.upgraded_to_hybrid().unwrap();

    assert_eq!(upgraded.sign_public(), classical.sign_public());
    assert_eq!(upgraded.kem_public(), classical.kem_public());
    assert_eq!(upgraded.name, classical.name);
    assert!(upgraded.is_hybrid_capable());
    assert_ne!(upgraded.fingerprint(), classical.fingerprint());

    // Upgrading an already-hybrid identity is rejected.
    assert!(upgraded.upgraded_to_hybrid().is_err());

    // The upgraded identity really works in a hybrid container addressed to it.
    let bob = hybrid("Bob");
    let buf = export_suite(&sample_vault(), &upgraded, &[bob.public()], SuiteId::Hybrid);
    let imported = format::import_vault(&buf, &bob).unwrap();
    assert_eq!(imported.sender_fingerprint, upgraded.fingerprint());

    // A container addressed to the OLD classical fingerprint is no longer
    // openable by the upgraded identity (its fingerprint changed).
    let to_old = export_suite(
        &sample_vault(),
        &bob,
        &[classical.public()],
        SuiteId::Classic,
    );
    assert!(matches!(
        format::import_vault(&to_old, &upgraded),
        Err(Error::NotARecipient)
    ));
}

#[test]
fn hybrid_identity_fingerprint_differs_from_classical() {
    // A hybrid identity's fingerprint commits to its PQC keys, so it is not the
    // same as the fingerprint of its classical keys alone.
    let h = hybrid("Alice");
    let mut classical_view = h.public();
    classical_view.mldsa_public = None;
    classical_view.mlkem_public = None;
    assert_ne!(h.fingerprint(), classical_view.fingerprint());
    // The full hybrid public still round-trips through CBOR.
    let bytes = h.public().to_bytes().unwrap();
    let back = filesec_core::PublicIdentity::from_bytes(&bytes).unwrap();
    assert_eq!(back, h.public());
    assert!(back.is_hybrid_capable());
}

#[test]
fn classical_publicidentity_serialization_unchanged() {
    // Adding the optional PQC fields must not change a classical key's bytes.
    let c = Identity::generate("Alice", 0).unwrap().public();
    let bytes = c.to_bytes().unwrap();
    let back = filesec_core::PublicIdentity::from_bytes(&bytes).unwrap();
    assert_eq!(back, c);
    assert!(back.mldsa_public.is_none() && back.mlkem_public.is_none());
}

#[test]
fn hybrid_lazy_open_and_random_access() {
    // Exercise verify_and_open (streamed dual-signature check) and on-demand
    // random-access chunk decryption for both new suites.
    for suite in [SuiteId::Aes256Gcm, SuiteId::Hybrid] {
        let alice = hybrid("Alice");
        let bob = hybrid("Bob");
        let path = tmp_path("lazy.fsec");
        let opts = ExportOptions {
            suite,
            ..Default::default()
        };
        format::export_vault_to_path(&sample_vault(), &alice, &[bob.public()], &opts, &path)
            .unwrap();

        // Lazy open verifies header+manifest only; suite is reported correctly.
        let reader = format::open_vault_from_path(&path, &bob).unwrap();
        assert_eq!(reader.suite(), suite);
        let big = reader.read_entry("data/big.bin").unwrap();
        let orig = sample_vault();
        assert_eq!(&big[..], &orig.get("data/big.bin").unwrap().content[..]);

        // verify_and_open checks the full end-to-end signature(s).
        let (vreader, sender) = format::verify_and_open(&path, &bob).unwrap();
        assert_eq!(sender.fingerprint, alice.fingerprint());
        assert_eq!(vreader.suite(), suite);

        std::fs::remove_file(&path).ok();
    }
}

#[test]
fn hybrid_bit_flips_are_detected() {
    let alice = hybrid("Alice");
    let bob = hybrid("Bob");
    let base = export_suite(&sample_vault(), &alice, &[bob.public()], SuiteId::Hybrid);
    // Probe across preamble, header (incl. stanzas), manifest, data, and both
    // signatures in the trailer (the last ~3.4 KiB).
    let probes = [
        0usize,
        12,
        base.len() / 3,
        base.len() / 2,
        base.len() - 3309, // start of the ML-DSA signature
        base.len() - 1500, // inside the ML-DSA signature
        base.len() - 65,   // Ed25519 signature
        base.len() - 1,
    ];
    for idx in probes {
        let mut t = base.clone();
        t[idx] ^= 0x01;
        assert!(
            format::import_vault(&t, &bob).is_err(),
            "a flipped byte at offset {idx} was NOT detected"
        );
    }
}

#[test]
fn hybrid_suite_id_cannot_be_downgraded() {
    // The suite id lives in the signed header (and is AAD for every AEAD), so
    // altering it always breaks import. Find the CBOR-encoded u16 `0x0101`
    // (major-0 two-byte: 19 01 01) and bump it to a different suite id.
    let alice = hybrid("Alice");
    let bob = hybrid("Bob");
    let base = export_suite(&sample_vault(), &alice, &[bob.public()], SuiteId::Hybrid);
    let needle = [0x19u8, 0x01, 0x01];
    let pos = base
        .windows(3)
        .position(|w| w == needle)
        .expect("encoded suite id present in header");
    let mut tampered = base.clone();
    tampered[pos + 2] = 0x02; // 0x0101 -> 0x0102 (unknown suite)
    assert!(
        format::import_vault(&tampered, &bob).is_err(),
        "a downgraded/altered suite id was NOT rejected"
    );
}

#[test]
fn keystore_persists_hybrid_seeds() {
    let alice = hybrid("Alice");
    let pass = b"correct horse battery staple";
    let ks = KeystoreFile::create(&alice, pass, KdfParams::default()).unwrap();
    let bytes = ks.to_bytes().unwrap();

    let reloaded = KeystoreFile::from_bytes(&bytes)
        .unwrap()
        .unlock(pass)
        .unwrap();
    // The reloaded identity is byte-identical in its public material...
    assert_eq!(reloaded.fingerprint(), alice.fingerprint());
    assert!(reloaded.is_hybrid_capable());
    assert_eq!(reloaded.mldsa_public(), alice.mldsa_public());
    assert_eq!(reloaded.mlkem_public(), alice.mlkem_public());

    // ...and the persisted seeds still work: it can sign and open a hybrid
    // container addressed to itself.
    let bob = hybrid("Bob");
    let buf = export_suite(&sample_vault(), &reloaded, &[bob.public()], SuiteId::Hybrid);
    let imported = format::import_vault(&buf, &bob).unwrap();
    assert_eq!(imported.sender_fingerprint, alice.fingerprint());
}
