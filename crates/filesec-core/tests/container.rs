//! End-to-end `.fsec` container tests: round-trip, multi-recipient, and the
//! negative/tamper cases that must never leak plaintext.

use filesec_core::format::{self, ExportOptions};
use filesec_core::identity::Identity;
use filesec_core::manifest::EntryKind;
use filesec_core::vault::{normalize_path, Vault};
use filesec_core::Error;
use std::path::PathBuf;

fn tmp_path(name: &str) -> PathBuf {
    let suffix = filesec_core::util::hex(&filesec_core::secret::random_vec(6).unwrap());
    std::env::temp_dir().join(format!("filesec-{suffix}-{name}"))
}

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
fn lazy_open_decrypts_files_on_demand() {
    let alice = ident("Alice");
    let orig = sample_vault();
    let path = tmp_path("lazy.fsec");
    format::export_vault_to_path(
        &orig,
        &alice,
        &[alice.public()],
        &ExportOptions::default(),
        &path,
    )
    .unwrap();

    // Opening reads only header + manifest (no file data) yet exposes metadata.
    let reader = format::open_vault_from_path(&path, &alice).unwrap();
    assert_eq!(reader.name(), "Test Vault");
    assert_eq!(reader.file_count(), orig.file_count());
    assert_eq!(reader.total_size(), orig.total_size());

    // On-demand per-file decryption matches, including the large multi-chunk file.
    for e in orig.entries() {
        if e.kind == EntryKind::File {
            let got = reader.read_entry(&e.path).unwrap();
            assert_eq!(&got[..], &e.content[..], "content mismatch for {}", e.path);
        }
    }

    // Full load also matches.
    let full = reader.to_vault().unwrap();
    assert_eq!(full.entries().len(), orig.entries().len());
    assert_eq!(
        &full.get("data/big.bin").unwrap().content[..],
        &orig.get("data/big.bin").unwrap().content[..]
    );

    // A non-recipient cannot open it.
    let bob = ident("Bob");
    assert!(format::open_vault_from_path(&path, &bob).is_err());

    // Extraction round-trips to the real filesystem.
    let dest = tmp_path("out");
    std::fs::create_dir_all(&dest).unwrap();
    reader.extract_to(&dest).unwrap();
    assert_eq!(
        std::fs::read(dest.join("data/big.bin")).unwrap(),
        orig.get("data/big.bin").unwrap().content.to_vec()
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&dest);
}

#[test]
fn reexport_streams_to_a_new_recipient() {
    // Alice owns a self-encrypted vault on disk (the local-store shape).
    let alice = ident("Alice");
    let bob = ident("Bob");
    let carol = ident("Carol");
    let orig = sample_vault();
    let src = tmp_path("reexport-src.fsec");
    format::export_vault_to_path(
        &orig,
        &alice,
        &[alice.public()],
        &ExportOptions::default(),
        &src,
    )
    .unwrap();

    // Open it lazily and re-encrypt it to Bob, streaming from the encrypted
    // source — without ever materializing the whole vault.
    let reader = format::open_vault_from_path(&src, &alice).unwrap();
    let dst = tmp_path("reexport-dst.fsec");
    reader
        .reexport_to_path(&alice, &[bob.public()], &ExportOptions::default(), &dst)
        .unwrap();

    // Bob can import the re-export, with Alice verified as the signer, and every
    // file matches the original — including the large multi-chunk file.
    let imported = format::import_vault_from_path(&dst, &bob).expect("bob imports re-export");
    assert_eq!(imported.sender_fingerprint, alice.fingerprint());
    assert_eq!(imported.vault.name, "Test Vault");
    assert_eq!(imported.vault.created_at, 1000);
    assert_eq!(imported.vault.entries().len(), orig.entries().len());
    for e in orig.entries() {
        let got = imported.vault.get(&e.path).expect("entry present");
        assert_eq!(got.kind, e.kind, "kind for {}", e.path);
        assert_eq!(&got.content[..], &e.content[..], "content for {}", e.path);
        assert_eq!(got.mtime, e.mtime, "mtime for {}", e.path);
        assert_eq!(got.mode, e.mode, "mode for {}", e.path);
    }

    // The re-export is addressed to Bob only: Carol (a non-recipient) is refused.
    assert!(format::import_vault_from_path(&dst, &carol).is_err());

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}

#[test]
fn append_files_streams_without_materializing() {
    use filesec_core::format::AddedFile;

    // A self-encrypted vault on disk with one large multi-chunk file already in it.
    let alice = ident("Alice");
    let mut base_vault = Vault::new("Box", 1000);
    let existing_big: Vec<u8> = (0..(64 * 1024 * 2 + 9)).map(|i| (i % 251) as u8).collect();
    base_vault
        .add_file("existing/big.bin", existing_big.clone(), Some(5), None)
        .unwrap();
    let vault_path = tmp_path("append.fsec");
    format::export_vault_to_path(
        &base_vault,
        &alice,
        &[alice.public()],
        &ExportOptions::default(),
        &vault_path,
    )
    .unwrap();

    // Two new files staged on disk (one large, not a chunk multiple; one empty).
    let new_big: Vec<u8> = (0..(64 * 1024 * 3 + 123)).map(|i| (i % 97) as u8).collect();
    let big_src = tmp_path("new-big.bin");
    std::fs::write(&big_src, &new_big).unwrap();
    let empty_src = tmp_path("new-empty.bin");
    std::fs::write(&empty_src, b"").unwrap();

    // Append them, streaming from the encrypted source and from disk.
    let reader = format::open_vault_from_path(&vault_path, &alice).unwrap();
    let out_path = tmp_path("append-out.fsec");
    reader
        .append_files_to_path(
            &alice,
            &[alice.public()],
            &ExportOptions::default(),
            &[
                AddedFile {
                    vault_path: "added/new.bin".into(),
                    source: big_src.clone(),
                    mtime: Some(42),
                    mode: Some(0o600),
                },
                AddedFile {
                    vault_path: "added/empty.bin".into(),
                    source: empty_src.clone(),
                    mtime: None,
                    mode: None,
                },
            ],
            &["spare/dir".to_string()],
            &out_path,
        )
        .unwrap();

    // The result imports cleanly and contains the old file plus the new ones,
    // with intact content and an implied parent directory.
    let imported = format::import_vault_from_path(&out_path, &alice).expect("import appended");
    assert_eq!(imported.vault.name, "Box");
    assert_eq!(
        &imported.vault.get("existing/big.bin").unwrap().content[..],
        &existing_big[..]
    );
    assert_eq!(
        &imported.vault.get("added/new.bin").unwrap().content[..],
        &new_big[..]
    );
    let added = imported.vault.get("added/new.bin").unwrap();
    assert_eq!(added.mtime, Some(42));
    assert_eq!(added.mode, Some(0o600));
    assert_eq!(
        imported.vault.get("added/empty.bin").unwrap().content.len(),
        0
    );
    assert_eq!(imported.vault.get("added").unwrap().kind, EntryKind::Dir);
    assert_eq!(imported.vault.get("spare/dir").unwrap().kind, EntryKind::Dir);

    // Adding a path that already exists is refused.
    let dup = format::open_vault_from_path(&out_path, &alice).unwrap();
    let dup_out = tmp_path("append-dup.fsec");
    assert!(dup
        .append_files_to_path(
            &alice,
            &[alice.public()],
            &ExportOptions::default(),
            &[AddedFile {
                vault_path: "existing/big.bin".into(),
                source: big_src.clone(),
                mtime: None,
                mode: None,
            }],
            &[],
            &dup_out,
        )
        .is_err());

    for p in [&vault_path, &big_src, &empty_src, &out_path] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn remove_paths_streams_and_recomputes_offsets() {
    let alice = ident("Alice");
    let orig = sample_vault();
    let path = tmp_path("remove.fsec");
    format::export_vault_to_path(
        &orig,
        &alice,
        &[alice.public()],
        &ExportOptions::default(),
        &path,
    )
    .unwrap();

    // Remove the "data" directory subtree (drops "data" and "data/big.bin", a
    // large multi-chunk file sitting in the middle of the data stream).
    let reader = format::open_vault_from_path(&path, &alice).unwrap();
    let out = tmp_path("remove-out.fsec");
    reader
        .remove_paths_to_path(
            &alice,
            &[alice.public()],
            &ExportOptions::default(),
            &["data".to_string()],
            &out,
        )
        .unwrap();

    let imported = format::import_vault_from_path(&out, &alice).expect("import after remove");
    // The removed file and its directory are gone...
    assert!(imported.vault.get("data/big.bin").is_none());
    assert!(imported.vault.get("data").is_none());
    // ...and every survivor is intact with correct content (offsets recomputed).
    for e in orig.entries() {
        if e.path == "data" || e.path == "data/big.bin" {
            continue;
        }
        let got = imported.vault.get(&e.path).expect("survivor present");
        assert_eq!(got.kind, e.kind, "kind for {}", e.path);
        assert_eq!(&got.content[..], &e.content[..], "content for {}", e.path);
    }

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&out);
}

#[test]
fn extract_to_streams_files_to_disk() {
    let alice = ident("Alice");
    let orig = sample_vault();
    let path = tmp_path("extract.fsec");
    format::export_vault_to_path(
        &orig,
        &alice,
        &[alice.public()],
        &ExportOptions::default(),
        &path,
    )
    .unwrap();

    let reader = format::open_vault_from_path(&path, &alice).unwrap();
    let dest = tmp_path("extract-out");
    std::fs::create_dir_all(&dest).unwrap();
    reader.extract_to(&dest).unwrap();

    // Every file lands on disk byte-for-byte, including the large multi-chunk one.
    for e in orig.entries() {
        if e.kind == EntryKind::File {
            assert_eq!(
                std::fs::read(dest.join(&e.path)).unwrap(),
                e.content.to_vec(),
                "content mismatch for {}",
                e.path
            );
        }
    }

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&dest);
}

#[test]
fn verify_and_open_streams_signature_check() {
    // Alice sends a container to Bob.
    let alice = ident("Alice");
    let bob = ident("Bob");
    let orig = sample_vault();
    let path = tmp_path("verifyopen.fsec");
    format::export_vault_to_path(
        &orig,
        &alice,
        &[bob.public()],
        &ExportOptions::default(),
        &path,
    )
    .unwrap();

    // Bob verifies the end-to-end signature (streamed) and opens lazily.
    let (reader, sender) = format::verify_and_open(&path, &bob).expect("verify + open");
    assert_eq!(sender.fingerprint, alice.fingerprint());
    assert_eq!(reader.name(), "Test Vault");

    // The verified reader streams content correctly, including the big file.
    let full = reader.to_vault().unwrap();
    for e in orig.entries() {
        let got = full.get(&e.path).expect("entry present");
        assert_eq!(&got.content[..], &e.content[..], "content for {}", e.path);
    }

    // A non-recipient cannot verify-open it.
    let carol = ident("Carol");
    assert!(format::verify_and_open(&path, &carol).is_err());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn verify_and_open_rejects_tampered_data() {
    let alice = ident("Alice");
    let path = tmp_path("verifytamper.fsec");
    format::export_vault_to_path(
        &sample_vault(),
        &alice,
        &[alice.public()],
        &ExportOptions::default(),
        &path,
    )
    .unwrap();

    // Flip a byte in the data section (before the 64-byte signature trailer).
    let mut bytes = std::fs::read(&path).unwrap();
    let idx = bytes.len() - 100;
    bytes[idx] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();

    // The streamed signature check rejects it before any data is transcoded.
    assert!(format::verify_and_open(&path, &alice).is_err());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn lazy_open_detects_data_tampering_on_read() {
    let alice = ident("Alice");
    let path = tmp_path("tamper.fsec");
    format::export_vault_to_path(
        &sample_vault(),
        &alice,
        &[alice.public()],
        &ExportOptions::default(),
        &path,
    )
    .unwrap();

    // Flip a byte in the data section (just before the 64-byte signature).
    let mut bytes = std::fs::read(&path).unwrap();
    let idx = bytes.len() - 100;
    bytes[idx] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();

    // Opening still works (header + manifest are intact)...
    let reader = format::open_vault_from_path(&path, &alice).unwrap();
    // ...but reading the file whose chunk was corrupted fails authentication.
    assert!(reader.read_entry("data/big.bin").is_err());

    let _ = std::fs::remove_file(&path);
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
