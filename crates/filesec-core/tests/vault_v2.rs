//! Tests for the `.fsv2` directory-of-blobs at-rest format: roundtrip, ranged
//! reads, the O(change) locality guarantees (a mutation touches only its blob +
//! the manifest), nonce freshness, tamper/anti-downgrade detection, and the
//! v2 <-> v1 transport bridge.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use filesec_core::format::{self, ExportOptions};
use filesec_core::format_v2::{export_v2_to_path, VaultReaderV2};
use filesec_core::identity::Identity;
use filesec_core::manifest::EntryKind;
use filesec_core::SuiteId;

fn ident(name: &str) -> Identity {
    Identity::generate(name, 0).expect("generate identity")
}

fn tmp_dir(name: &str) -> PathBuf {
    let suffix = filesec_core::util::hex(&filesec_core::secret::random_vec(6).unwrap());
    std::env::temp_dir().join(format!("filesec-v2-{suffix}-{name}"))
}

fn tmp_file(name: &str) -> PathBuf {
    let suffix = filesec_core::util::hex(&filesec_core::secret::random_vec(6).unwrap());
    std::env::temp_dir().join(format!("filesec-v2-{suffix}-{name}"))
}

fn big_bytes() -> Vec<u8> {
    (0..(64 * 1024 * 3 + 777))
        .map(|i| (i % 251) as u8)
        .collect()
}

/// Build a sample v2 vault mirroring the v1 `sample_vault`: a small file, a
/// nested file, an empty file, a large multi-chunk file, and an empty dir.
fn build_sample(dir: &Path, id: &Identity, suite: SuiteId) -> VaultReaderV2 {
    let mut v = VaultReaderV2::create(dir, id, suite, "Test Vault", 1000).unwrap();
    v.put_file_bytes("readme.txt", b"hello world", Some(123), Some(0o644))
        .unwrap();
    v.put_file_bytes("docs/notes.md", b"# Notes\n", None, None)
        .unwrap();
    v.put_file_bytes("empty.bin", b"", None, None).unwrap();
    v.put_file_bytes("data/big.bin", &big_bytes(), None, None)
        .unwrap();
    v.mkdir("emptydir").unwrap();
    v
}

/// Snapshot every blob file as `file_id -> bytes` (ignoring temp leftovers).
fn snapshot_blobs(dir: &Path) -> HashMap<String, Vec<u8>> {
    let mut m = HashMap::new();
    if let Ok(rd) = std::fs::read_dir(dir.join("blobs")) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.ends_with(".tmp") {
                continue;
            }
            m.insert(name, std::fs::read(e.path()).unwrap());
        }
    }
    m
}

/// The bytes of the single blob present in `after` but not `before`.
fn added_blob(before: &HashMap<String, Vec<u8>>, after: &HashMap<String, Vec<u8>>) -> Vec<u8> {
    after
        .iter()
        .find(|(k, _)| !before.contains_key(*k))
        .map(|(_, v)| v.clone())
        .expect("exactly one new blob")
}

fn largest_blob(dir: &Path) -> PathBuf {
    let mut best: Option<(u64, PathBuf)> = None;
    for e in std::fs::read_dir(dir.join("blobs")).unwrap().flatten() {
        let len = e.metadata().unwrap().len();
        if best.as_ref().is_none_or(|(b, _)| len > *b) {
            best = Some((len, e.path()));
        }
    }
    best.expect("at least one blob").1
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn v2_roundtrip_reads_match_and_reopen() {
    let id = ident("Alice");
    let dir = tmp_dir("roundtrip.fsv2");
    let v = build_sample(&dir, &id, SuiteId::Classic);

    let big = big_bytes();
    assert_eq!(&*v.read_entry("readme.txt").unwrap(), b"hello world");
    assert_eq!(&*v.read_entry("docs/notes.md").unwrap(), b"# Notes\n");
    assert_eq!(&*v.read_entry("empty.bin").unwrap(), b"");
    assert_eq!(&*v.read_entry("data/big.bin").unwrap(), &big[..]);
    drop(v);

    // Reopening reads only header + manifest, yet exposes everything.
    let v = VaultReaderV2::open(&dir, &id).unwrap();
    assert_eq!(v.name(), "Test Vault");
    assert_eq!(v.created_at(), 1000);
    assert_eq!(v.file_count(), 4);
    assert_eq!(v.total_size(), 11 + 8 + big.len() as u64);
    assert_eq!(&*v.read_entry("data/big.bin").unwrap(), &big[..]);
    // Implied ancestor dirs ("docs", "data") and the explicit "emptydir" exist.
    for d in ["docs", "data", "emptydir"] {
        assert!(
            v.entries()
                .iter()
                .any(|e| e.path == d && e.kind == EntryKind::Dir),
            "missing dir {d}"
        );
    }
    // A different identity cannot open it.
    assert!(VaultReaderV2::open(&dir, &ident("Mallory")).is_err());

    cleanup(&dir);
}

#[test]
fn v2_put_is_local() {
    let id = ident("Alice");
    let dir = tmp_dir("local.fsv2");
    let mut v = build_sample(&dir, &id, SuiteId::Classic);

    let before = snapshot_blobs(&dir);
    let manifest_before = std::fs::read(dir.join("manifest")).unwrap();

    v.put_file_bytes("notes/new.txt", b"a brand new file", None, None)
        .unwrap();

    let after = snapshot_blobs(&dir);
    let manifest_after = std::fs::read(dir.join("manifest")).unwrap();

    // Every pre-existing blob is byte-for-byte untouched (the O(change) proof).
    for (id, bytes) in &before {
        assert_eq!(after.get(id), Some(bytes), "pre-existing blob {id} changed");
    }
    // Exactly one new blob; the manifest was rewritten.
    assert_eq!(after.len(), before.len() + 1, "expected one new blob");
    assert_ne!(
        manifest_before, manifest_after,
        "manifest should be resealed"
    );
    cleanup(&dir);
}

#[test]
fn v2_overwrite_swaps_only_that_blob() {
    let id = ident("Alice");
    let dir = tmp_dir("overwrite.fsv2");
    let mut v = build_sample(&dir, &id, SuiteId::Classic);

    let before = snapshot_blobs(&dir);
    v.put_file_bytes("readme.txt", b"updated contents!", None, None)
        .unwrap();
    let after = snapshot_blobs(&dir);

    assert_eq!(&*v.read_entry("readme.txt").unwrap(), b"updated contents!");
    // One blob removed, one added → count unchanged.
    assert_eq!(after.len(), before.len());
    // Other files still read correctly.
    assert_eq!(&*v.read_entry("data/big.bin").unwrap(), &big_bytes()[..]);
    cleanup(&dir);
}

#[test]
fn v2_remove_unlinks_only_target_blob() {
    let id = ident("Alice");
    let dir = tmp_dir("remove.fsv2");
    let mut v = build_sample(&dir, &id, SuiteId::Classic);

    let before = snapshot_blobs(&dir);
    v.remove_path("data/big.bin").unwrap();
    let after = snapshot_blobs(&dir);

    assert_eq!(after.len(), before.len() - 1, "exactly one blob removed");
    assert!(v.read_entry("data/big.bin").is_err());
    assert_eq!(&*v.read_entry("readme.txt").unwrap(), b"hello world");

    // Removing a directory drops its whole subtree.
    v.remove_path("docs").unwrap();
    assert!(v.read_entry("docs/notes.md").is_err());
    assert!(!v.entries().iter().any(|e| e.path == "docs"));
    cleanup(&dir);
}

#[test]
fn v2_rename_does_not_touch_blobs() {
    let id = ident("Alice");
    let dir = tmp_dir("rename.fsv2");
    let mut v = build_sample(&dir, &id, SuiteId::Classic);

    let mut before: Vec<Vec<u8>> = snapshot_blobs(&dir).into_values().collect();
    before.sort();
    let big = v.read_entry("data/big.bin").unwrap().to_vec();

    v.rename("data/big.bin", "archive/big-renamed.bin").unwrap();

    let mut after: Vec<Vec<u8>> = snapshot_blobs(&dir).into_values().collect();
    after.sort();
    // Same blob contents (and same file_ids) — only the manifest changed.
    assert_eq!(before, after, "rename must not touch any blob");
    assert_eq!(&*v.read_entry("archive/big-renamed.bin").unwrap(), &big[..]);
    assert!(v.read_entry("data/big.bin").is_err());
    cleanup(&dir);
}

#[test]
fn v2_same_plaintext_reencrypts_with_fresh_nonce() {
    let id = ident("Alice");
    let dir = tmp_dir("nonce.fsv2");
    let mut v = VaultReaderV2::create(&dir, &id, SuiteId::Classic, "N", 1).unwrap();

    let s0 = snapshot_blobs(&dir);
    v.put_file_bytes("k.bin", b"identical plaintext", None, None)
        .unwrap();
    let s1 = snapshot_blobs(&dir);
    let ct1 = added_blob(&s0, &s1);

    // Overwrite with the *same* plaintext: a fresh key + nonce must yield
    // different ciphertext (otherwise a (key, nonce) pair was reused).
    v.put_file_bytes("k.bin", b"identical plaintext", None, None)
        .unwrap();
    let s2 = snapshot_blobs(&dir);
    let ct2 = added_blob(&s1, &s2);

    assert_ne!(
        ct1, ct2,
        "same plaintext re-encrypted identically — nonce/key reuse!"
    );
    cleanup(&dir);
}

#[test]
fn v2_blob_tamper_is_detected() {
    let id = ident("Alice");
    let dir = tmp_dir("tamper.fsv2");
    let v = build_sample(&dir, &id, SuiteId::Classic);
    drop(v);

    // big.bin owns the largest blob; flip a byte in it.
    let blob = largest_blob(&dir);
    let mut bytes = std::fs::read(&blob).unwrap();
    let i = bytes.len() / 2;
    bytes[i] ^= 0x01;
    std::fs::write(&blob, &bytes).unwrap();

    // The manifest still authenticates (open succeeds) but reading the file fails.
    let v = VaultReaderV2::open(&dir, &id).unwrap();
    assert!(v.read_entry("data/big.bin").is_err());
    cleanup(&dir);
}

#[test]
fn v2_header_tamper_is_rejected() {
    let id = ident("Alice");
    let dir = tmp_dir("header.fsv2");
    let v = build_sample(&dir, &id, SuiteId::Classic);
    drop(v);

    // The plaintext header (carrying the suite id) is fed as AAD into the
    // manifest AEAD and every blob STREAM, so any change breaks authentication —
    // the anti-downgrade binding. Flip a byte and confirm the open is refused.
    let hpath = dir.join("header");
    let mut hb = std::fs::read(&hpath).unwrap();
    let i = hb.len() / 2;
    hb[i] ^= 0x01;
    std::fs::write(&hpath, &hb).unwrap();
    assert!(VaultReaderV2::open(&dir, &id).is_err());
    cleanup(&dir);
}

#[test]
fn v2_manifest_tamper_is_rejected() {
    let id = ident("Alice");
    let dir = tmp_dir("mtamper.fsv2");
    let v = build_sample(&dir, &id, SuiteId::Classic);
    drop(v);

    let mpath = dir.join("manifest");
    let mut mb = std::fs::read(&mpath).unwrap();
    let i = mb.len() - 1;
    mb[i] ^= 0x01;
    std::fs::write(&mpath, &mb).unwrap();
    assert!(VaultReaderV2::open(&dir, &id).is_err());
    cleanup(&dir);
}

#[test]
fn v2_exports_to_v1_and_reimports() {
    let id = ident("Alice");
    let dir = tmp_dir("export.fsv2");
    let v = build_sample(&dir, &id, SuiteId::Classic);

    // Export the v2 vault as a signed single-stream v1 `.fsec` (the unchanged
    // transport path), verify+open it, then unpack it back into a fresh v2 dir.
    let fsec = tmp_file("exported.fsec");
    export_v2_to_path(&v, &id, &[id.public()], &ExportOptions::default(), &fsec).unwrap();

    let (reader, sender) = format::verify_and_open(&fsec, &id).unwrap();
    assert_eq!(sender.fingerprint, id.fingerprint());

    let dir2 = tmp_dir("reimported.fsv2");
    let v_re = VaultReaderV2::from_reader_v1(&dir2, &id, SuiteId::Classic, &reader).unwrap();

    assert_eq!(v_re.name(), "Test Vault");
    assert_eq!(v_re.created_at(), 1000);
    for path in ["readme.txt", "docs/notes.md", "empty.bin", "data/big.bin"] {
        assert_eq!(
            v.read_entry(path).unwrap().to_vec(),
            v_re.read_entry(path).unwrap().to_vec(),
            "content mismatch for {path} after v2->v1->v2"
        );
    }

    let _ = std::fs::remove_file(&fsec);
    cleanup(&dir);
    cleanup(&dir2);
}

#[test]
fn export_omits_the_trash_subtree() {
    use filesec_core::format_v2::{is_trashed, TRASH_DIR};

    // `is_trashed` recognizes the root and anything under it, but not look-alikes.
    assert!(is_trashed(TRASH_DIR));
    assert!(is_trashed(".trash/123-ab/report.pdf"));
    assert!(!is_trashed(".trashy"));
    assert!(!is_trashed("docs/.trash"));

    let id = ident("Alice");
    let dir = tmp_dir("trash-export.fsv2");
    let mut v = build_sample(&dir, &id, SuiteId::Classic);
    // A soft-deleted file lives under the trash subtree (a plain manifest entry).
    v.put_file_bytes(".trash/9-deadbeef/secret.txt", b"top secret", None, None)
        .unwrap();
    // The trashed file is still readable locally (restorable) ...
    assert_eq!(
        &*v.read_entry(".trash/9-deadbeef/secret.txt").unwrap(),
        b"top secret"
    );

    // ... but a faithful materialization keeps it while an export drops it.
    assert!(v
        .to_vault()
        .unwrap()
        .entries()
        .iter()
        .any(|e| e.path == ".trash/9-deadbeef/secret.txt"));
    assert!(v
        .to_vault_for_export()
        .unwrap()
        .entries()
        .iter()
        .all(|e| !is_trashed(&e.path)));

    // The exported, re-imported container has no trace of the trashed file.
    let fsec = tmp_file("trash-export.fsec");
    export_v2_to_path(&v, &id, &[id.public()], &ExportOptions::default(), &fsec).unwrap();
    let (reader, _sender) = format::verify_and_open(&fsec, &id).unwrap();
    assert!(reader.entries().iter().all(|e| !is_trashed(&e.path)));
    assert!(reader.read_entry(".trash/9-deadbeef/secret.txt").is_err());
    // The live files survived the round-trip untouched.
    assert_eq!(&*reader.read_entry("readme.txt").unwrap(), b"hello world");

    let _ = std::fs::remove_file(&fsec);
    cleanup(&dir);
}

#[cfg(feature = "pqc")]
#[test]
fn v2_hybrid_suite_roundtrips_at_rest() {
    // A hybrid identity stores a v2 vault under the Hybrid suite: the manifest
    // key is wrapped with the X25519+ML-KEM combiner, so PQC protects it at rest.
    let alice = Identity::generate_hybrid("Alice", 0).unwrap();
    let dir = tmp_dir("hybrid.fsv2");
    let mut v = VaultReaderV2::create(&dir, &alice, SuiteId::Hybrid, "H", 7).unwrap();
    v.put_file_bytes("a.txt", b"hybrid at rest", None, None)
        .unwrap();
    assert_eq!(&*v.read_entry("a.txt").unwrap(), b"hybrid at rest");
    drop(v);

    let v = VaultReaderV2::open(&dir, &alice).unwrap();
    assert_eq!(v.suite(), SuiteId::Hybrid);
    assert_eq!(&*v.read_entry("a.txt").unwrap(), b"hybrid at rest");
    // A wrong identity still cannot open it.
    assert!(VaultReaderV2::open(&dir, &Identity::generate_hybrid("Bob", 0).unwrap()).is_err());
    cleanup(&dir);
}
