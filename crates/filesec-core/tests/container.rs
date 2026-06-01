//! End-to-end `.fsec` container tests: round-trip, multi-recipient, and the
//! negative/tamper cases that must never leak plaintext.

use filesec_core::format::{self, ExportOptions};
use filesec_core::identity::Identity;
use filesec_core::vault::{normalize_path, Vault};
use filesec_core::Error;

fn ident(name: &str) -> Identity {
    Identity::generate(name, 0).expect("generate identity")
}

/// A vault exercising: a small file, a nested file, an empty file, an explicit
/// empty directory, and a large multi-chunk file whose size is not a multiple
/// of the chunk size.
fn sample_vault() -> Vault {
    let mut v = Vault::new("Test Vault", 1000);
    v.add_file(
        "readme.txt",
        b"hello world".to_vec(),
        Some(123),
        Some(0o644),
    )
    .unwrap();
    v.add_file("docs/notes.md", b"# Notes\n".to_vec(), None, None)
        .unwrap();
    v.add_file("empty.bin", Vec::new(), None, None).unwrap();
    let big: Vec<u8> = (0..(64 * 1024 * 3 + 777))
        .map(|i| (i % 251) as u8)
        .collect();
    v.add_file("data/big.bin", big, None, None).unwrap();
    v.add_dir("emptydir").unwrap();
    v
}

fn export(
    vault: &Vault,
    sender: &Identity,
    recipients: &[filesec_core::PublicIdentity],
) -> Vec<u8> {
    let mut buf = Vec::new();
    format::export_vault(
        vault,
        sender,
        recipients,
        &ExportOptions::default(),
        &mut buf,
    )
    .expect("export");
    buf
}

#[test]
fn roundtrip_single_recipient_matches_byte_for_byte() {
    let alice = ident("Alice");
    let bob = ident("Bob");
    let vault = sample_vault();
    let buf = export(&vault, &alice, &[bob.public()]);

    let imported = format::import_vault(&buf, &bob).expect("import");

    // Sender is cryptographically verified as Alice.
    assert_eq!(imported.sender_fingerprint, alice.fingerprint());
    assert_eq!(imported.vault.name, "Test Vault");
    assert_eq!(imported.vault.created_at, 1000);

    let orig = sample_vault();
    assert_eq!(imported.vault.entries().len(), orig.entries().len());
    for e in orig.entries() {
        let got = imported
            .vault
            .get(&e.path)
            .expect("entry present after import");
        assert_eq!(got.kind, e.kind, "kind for {}", e.path);
        assert_eq!(&got.content[..], &e.content[..], "content for {}", e.path);
        assert_eq!(got.mtime, e.mtime, "mtime for {}", e.path);
        assert_eq!(got.mode, e.mode, "mode for {}", e.path);
    }
}

#[test]
fn non_recipient_is_refused() {
    let alice = ident("Alice");
    let bob = ident("Bob");
    let carol = ident("Carol");
    let buf = export(&sample_vault(), &alice, &[bob.public()]);

    match format::import_vault(&buf, &carol) {
        Err(Error::NotARecipient) => {}
        Err(e) => panic!("expected NotARecipient, got {e:?}"),
        Ok(_) => panic!("expected NotARecipient, but import succeeded"),
    }
}

#[test]
fn include_self_and_multiple_recipients() {
    let alice = ident("Alice");
    let bob = ident("Bob");
    let buf = export(&sample_vault(), &alice, &[alice.public(), bob.public()]);

    // Both the sender (self) and the recipient can open it.
    assert!(format::import_vault(&buf, &alice).is_ok());
    assert!(format::import_vault(&buf, &bob).is_ok());
}

#[test]
fn export_with_no_recipients_fails() {
    let alice = ident("Alice");
    let mut buf = Vec::new();
    let r = format::export_vault(
        &sample_vault(),
        &alice,
        &[],
        &ExportOptions::default(),
        &mut buf,
    );
    assert!(r.is_err());
}

#[test]
fn single_bit_flips_anywhere_are_detected() {
    let alice = ident("Alice");
    let bob = ident("Bob");
    let base = export(&sample_vault(), &alice, &[bob.public()]);

    // Probe representative offsets across preamble, header, manifest, data, sig.
    let probes = [
        0usize,
        6,
        12,
        base.len() / 4,
        base.len() / 2,
        base.len() - 33,
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
fn truncation_and_extension_are_detected() {
    let alice = ident("Alice");
    let bob = ident("Bob");
    let base = export(&sample_vault(), &alice, &[bob.public()]);

    assert!(format::import_vault(&base[..base.len() - 1], &bob).is_err());

    let mut extended = base.clone();
    extended.push(0x00);
    assert!(format::import_vault(&extended, &bob).is_err());

    assert!(format::import_vault(&[], &bob).is_err());
    assert!(format::import_vault(b"FSEC\x1a not really", &bob).is_err());
}

#[test]
fn empty_vault_roundtrips() {
    let alice = ident("Alice");
    let bob = ident("Bob");
    let vault = Vault::new("Empty", 5);
    let buf = export(&vault, &alice, &[bob.public()]);
    let imported = format::import_vault(&buf, &bob).expect("import empty");
    assert_eq!(imported.vault.entries().len(), 0);
    assert_eq!(imported.vault.name, "Empty");
}

#[test]
fn path_normalization_blocks_traversal() {
    assert_eq!(normalize_path("a/b/c").unwrap(), "a/b/c");
    assert_eq!(normalize_path("./a//b/").unwrap(), "a/b");
    assert_eq!(normalize_path("a\\b\\c").unwrap(), "a/b/c");
    assert_eq!(normalize_path("/abs/path").unwrap(), "abs/path");

    assert!(normalize_path("").is_err());
    assert!(normalize_path("../etc/passwd").is_err());
    assert!(normalize_path("a/../../b").is_err());
    assert!(normalize_path("a/\0/b").is_err());
}
