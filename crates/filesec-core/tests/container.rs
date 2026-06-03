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
    assert_eq!(
        imported.vault.get("spare/dir").unwrap().kind,
        EntryKind::Dir
    );

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
fn replace_file_streams_and_preserves_others() {
    let alice = ident("Alice");
    let orig = sample_vault();
    let path = tmp_path("replace.fsec");
    format::export_vault_to_path(
        &orig,
        &alice,
        &[alice.public()],
        &ExportOptions::default(),
        &path,
    )
    .unwrap();

    // New contents for the mid-stream, multi-chunk file (different size, so every
    // surviving file after it must have its offset recomputed).
    let new_big: Vec<u8> = (0..(64 * 1024 + 5)).map(|i| (i % 131) as u8).collect();
    let new_src = tmp_path("replace-src.bin");
    std::fs::write(&new_src, &new_big).unwrap();

    let reader = format::open_vault_from_path(&path, &alice).unwrap();
    let out = tmp_path("replace-out.fsec");
    reader
        .replace_file_to_path(
            &alice,
            &[alice.public()],
            &ExportOptions::default(),
            "data/big.bin",
            &new_src,
            Some(99),
            Some(0o600),
            &out,
        )
        .unwrap();

    let imported = format::import_vault_from_path(&out, &alice).expect("import after replace");
    // Entry count is unchanged (the file is dropped then re-appended).
    assert_eq!(imported.vault.entries().len(), orig.entries().len());
    // The replaced file has the new content + metadata.
    let got = imported
        .vault
        .get("data/big.bin")
        .expect("replaced present");
    assert_eq!(&got.content[..], &new_big[..]);
    assert_eq!(got.mtime, Some(99));
    assert_eq!(got.mode, Some(0o600));
    // Every other entry is byte-identical (offsets recomputed correctly).
    for e in orig.entries() {
        if e.path == "data/big.bin" {
            continue;
        }
        let s = imported.vault.get(&e.path).expect("survivor present");
        assert_eq!(s.kind, e.kind, "kind for {}", e.path);
        assert_eq!(&s.content[..], &e.content[..], "content for {}", e.path);
    }

    // Replacing a directory or a missing path is refused.
    let reader = format::open_vault_from_path(&path, &alice).unwrap();
    let bad = tmp_path("replace-bad.fsec");
    assert!(reader
        .replace_file_to_path(
            &alice,
            &[alice.public()],
            &ExportOptions::default(),
            "emptydir",
            &new_src,
            None,
            None,
            &bad,
        )
        .is_err());
    assert!(reader
        .replace_file_to_path(
            &alice,
            &[alice.public()],
            &ExportOptions::default(),
            "nope.txt",
            &new_src,
            None,
            None,
            &bad,
        )
        .is_err());

    for p in [&path, &new_src, &out] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn replace_file_with_empty_source_roundtrips() {
    let alice = ident("Alice");
    let orig = sample_vault();
    let path = tmp_path("replace-empty.fsec");
    format::export_vault_to_path(
        &orig,
        &alice,
        &[alice.public()],
        &ExportOptions::default(),
        &path,
    )
    .unwrap();

    // Replace a non-empty file with an empty one: total plaintext shrinks and the
    // new entry has size 0.
    let empty_src = tmp_path("replace-empty-src.bin");
    std::fs::write(&empty_src, b"").unwrap();
    let reader = format::open_vault_from_path(&path, &alice).unwrap();
    let out = tmp_path("replace-empty-out.fsec");
    reader
        .replace_file_to_path(
            &alice,
            &[alice.public()],
            &ExportOptions::default(),
            "readme.txt",
            &empty_src,
            None,
            None,
            &out,
        )
        .unwrap();

    let imported =
        format::import_vault_from_path(&out, &alice).expect("import after empty replace");
    assert_eq!(imported.vault.get("readme.txt").unwrap().content.len(), 0);
    // A survivor is still intact.
    assert_eq!(
        &imported.vault.get("data/big.bin").unwrap().content[..],
        &sample_vault().get("data/big.bin").unwrap().content[..]
    );

    for p in [&path, &empty_src, &out] {
        let _ = std::fs::remove_file(p);
    }
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

/// Open `sample_vault()` lazily and return a `(reader, path)`; caller removes the
/// file. `data/big.bin` is multi-chunk and starts at stream offset 19, so its
/// 64 KiB chunk boundaries fall mid-file — ideal for exercising `read_at`.
fn lazy_sample(name: &str) -> (format::VaultReader, PathBuf) {
    let alice = ident("Alice");
    let path = tmp_path(name);
    format::export_vault_to_path(
        &sample_vault(),
        &alice,
        &[alice.public()],
        &ExportOptions::default(),
        &path,
    )
    .unwrap();
    let reader = format::open_vault_from_path(&path, &alice).unwrap();
    (reader, path)
}

#[test]
fn read_at_matches_read_entry_over_random_windows() {
    let (reader, path) = lazy_sample("readat.fsec");
    let full = reader.read_entry("data/big.bin").unwrap();
    let size = full.len() as u64;

    // Pseudo-random (offset, len) windows: read_at must always equal the same
    // slice of the whole-file decryption, including short reads past EOF.
    for _ in 0..200 {
        let r = filesec_core::secret::random_vec(8).unwrap();
        let offset = u64::from(u32::from_le_bytes([r[0], r[1], r[2], r[3]])) % (size + 1);
        let len = (u64::from(u32::from_le_bytes([r[4], r[5], r[6], r[7]])) % (size + 200)) as usize;
        let mut buf = vec![0u8; len];
        let n = reader.read_at("data/big.bin", offset, &mut buf).unwrap();
        let expected: &[u8] = if offset >= size {
            &[]
        } else {
            let end = (offset + len as u64).min(size) as usize;
            &full[offset as usize..end]
        };
        assert_eq!(n, expected.len(), "len at offset={offset} len={len}");
        assert_eq!(&buf[..n], expected, "bytes at offset={offset} len={len}");
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn read_at_spans_chunk_boundaries() {
    let (reader, path) = lazy_sample("readat-bnd.fsec");
    let full = reader.read_entry("data/big.bin").unwrap();
    let size = full.len();

    // big.bin starts at stream offset 19, so stream-chunk boundaries land at
    // big.bin offsets (chunk - 19) and (2*chunk - 19). Straddle each, plus the
    // file's start and tail, with a range of widths.
    let chunk = 64 * 1024usize;
    for win_start in [0usize, chunk - 19 - 5, 2 * chunk - 19 - 5, size - 10] {
        for len in [1usize, 10, 64, chunk] {
            let end = (win_start + len).min(size);
            let mut buf = vec![0u8; len];
            let n = reader
                .read_at("data/big.bin", win_start as u64, &mut buf)
                .unwrap();
            assert_eq!(&buf[..n], &full[win_start..end], "window {win_start}+{len}");
        }
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn read_at_past_eof_and_empty_file() {
    let (reader, path) = lazy_sample("readat-eof.fsec");
    let big_size = reader.read_entry("data/big.bin").unwrap().len() as u64;

    let mut buf = [0u8; 64];
    // offset at/after EOF → 0 bytes, no chunk touched.
    assert_eq!(
        reader.read_at("data/big.bin", big_size, &mut buf).unwrap(),
        0
    );
    assert_eq!(
        reader
            .read_at("data/big.bin", big_size + 1000, &mut buf)
            .unwrap(),
        0
    );
    // empty output buffer → 0 bytes.
    assert_eq!(reader.read_at("data/big.bin", 0, &mut []).unwrap(), 0);
    // a zero-length file is always a 0-byte read.
    assert_eq!(reader.read_at("empty.bin", 0, &mut buf).unwrap(), 0);
    // a directory or a missing path is an error, not a read.
    assert!(reader.read_at("emptydir", 0, &mut buf).is_err());
    assert!(reader.read_at("nope.bin", 0, &mut buf).is_err());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn read_at_on_tampered_chunk_errors() {
    let alice = ident("Alice");
    let path = tmp_path("readat-tamper.fsec");
    format::export_vault_to_path(
        &sample_vault(),
        &alice,
        &[alice.public()],
        &ExportOptions::default(),
        &path,
    )
    .unwrap();

    // Flip a byte in the data section (just before the 64-byte signature) — this
    // lands in big.bin's final chunk (it is the last file in the stream).
    let mut bytes = std::fs::read(&path).unwrap();
    let idx = bytes.len() - 100;
    bytes[idx] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();

    let reader = format::open_vault_from_path(&path, &alice).unwrap();
    let size = sample_vault().get("data/big.bin").unwrap().content.len();
    // A ranged read covering the corrupted chunk fails per-chunk authentication.
    let mut buf = vec![0u8; size];
    assert!(reader.read_at("data/big.bin", 0, &mut buf).is_err());

    let _ = std::fs::remove_file(&path);
}
