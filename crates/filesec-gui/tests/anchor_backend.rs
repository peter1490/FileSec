//! Rollback-anchor backend selection and recovery (audit FS-01).
//!
//! These tests drive the real store against an in-memory secure storage, so
//! they exercise marker tampering, an unavailable keychain, and the explicit
//! recovery flow deterministically and without touching the host keychain.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use filesec_core::contacts::ContactBook;
use filesec_core::identity::Identity;
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::KeystoreFile;
use filesec_core::vault::Vault;
use filesec_gui::anchors::{MemoryAnchorStorage, SecureAnchorStorage};
use filesec_gui::store::{
    new_vault_id, AnchorProtection, Registry, Store, VaultMeta, ANCHOR_RECOVERY_REQUIRED,
};

const PASS: &[u8] = b"correct horse battery staple";

fn tmp() -> PathBuf {
    let suffix = filesec_core::util::hex(&filesec_core::secret::random_vec(8).unwrap());
    std::env::temp_dir().join(format!("filesec-anchor-test-{suffix}"))
}

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_cost: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn open(dir: &Path, secure: &Arc<MemoryAnchorStorage>) -> Result<Store, String> {
    let secure: Arc<dyn SecureAnchorStorage> = secure.clone();
    Store::at_with_secure_storage(dir, Some(secure))
}

fn marker(dir: &Path) -> String {
    std::fs::read_to_string(dir.join(".state-anchor-backend"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// A store with a keystore at epoch 2, returning the identity and the bytes
/// of the superseded epoch-1 keystore (a valid, signed, but stale copy).
fn populated(dir: &Path, secure: &Arc<MemoryAnchorStorage>) -> (Identity, Vec<u8>) {
    let store = open(dir, secure).unwrap();
    assert_eq!(store.anchor_protection(), AnchorProtection::SecureStorage);
    let identity = Identity::generate("Alice", 0).unwrap();
    let mut ks = KeystoreFile::create(&identity, PASS, fast_kdf()).unwrap();
    store.save_keystore(&ks).unwrap();
    let stale = std::fs::read(dir.join("keystore.fsk")).unwrap();
    ks.set_device_token(PASS, &[7u8; 32]).unwrap();
    store.save_keystore(&ks).unwrap();
    let mut book = ContactBook::default();
    book.upsert(Identity::generate("Bob", 0).unwrap().public(), 1);
    store.save_contacts(&identity, &book).unwrap();
    let id = new_vault_id().unwrap();
    store
        .save_vault(&identity, &id, &Vault::new("Docs", 1))
        .unwrap();
    let mut registry = Registry::default();
    registry.upsert(VaultMeta {
        id,
        name: "Docs".into(),
        created_at: 1,
        modified_at: 1,
        file_count: 0,
        total_size: 0,
    });
    store.save_registry(&identity, &registry).unwrap();
    (identity, stale)
}

#[test]
fn fresh_store_records_its_backend_outside_the_directory_immediately() {
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    let store = open(&dir, &secure).unwrap();
    assert_eq!(store.anchor_protection(), AnchorProtection::SecureStorage);
    assert_eq!(secure.len(), 1, "provenance must exist before any state");
    assert_eq!(marker(&dir), "secure-v1");
    drop(store);

    // Tampering with the marker before any state exists still cannot select
    // file anchors: secure storage already vouches for this store.
    std::fs::write(dir.join(".state-anchor-backend"), b"degraded-v1\n").unwrap();
    let store = open(&dir, &secure).unwrap();
    assert_eq!(store.anchor_protection(), AnchorProtection::SecureStorage);
    assert_eq!(marker(&dir), "secure-v1", "the marker is repaired");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn degraded_marker_cannot_downgrade_established_secure_anchors() {
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    let (_identity, stale) = populated(&dir, &secure);

    // The FS-01 attack: replace the marker, plant a file anchor set that
    // vouches for nothing, and restore an older (valid, signed) keystore.
    std::fs::write(dir.join(".state-anchor-backend"), b"degraded-v1\n").unwrap();
    std::fs::write(dir.join(".state-anchors"), b"").unwrap();
    std::fs::write(dir.join("keystore.fsk"), &stale).unwrap();

    let before = secure.lookups();
    let store = open(&dir, &secure).unwrap();
    assert!(
        secure.lookups() > before,
        "secure storage must be consulted"
    );
    assert_eq!(store.anchor_protection(), AnchorProtection::SecureStorage);
    assert!(store.rollback_protection_warning().is_none());
    let error = store
        .load_keystore()
        .err()
        .expect("rollback must be detected");
    assert!(error.contains("rollback detected"), "{error}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn deleted_or_malformed_marker_cannot_downgrade_established_secure_anchors() {
    for tamper in ["delete", "garbage", "directory", "oversized"] {
        let dir = tmp();
        let secure = Arc::new(MemoryAnchorStorage::new());
        let (_identity, stale) = populated(&dir, &secure);
        let marker_path = dir.join(".state-anchor-backend");
        std::fs::remove_file(&marker_path).unwrap();
        match tamper {
            "delete" => {}
            "garbage" => std::fs::write(&marker_path, b"plaintext-v9\n").unwrap(),
            "directory" => std::fs::create_dir(&marker_path).unwrap(),
            _ => std::fs::write(&marker_path, vec![b'x'; 4096]).unwrap(),
        }
        std::fs::write(dir.join("keystore.fsk"), &stale).unwrap();
        if tamper == "directory" {
            // A marker that is not even a file cannot be repaired in place, so
            // the store fails closed instead of guessing.
            let error = open(&dir, &secure).err().expect("must fail closed");
            assert!(!error.is_empty());
            let _ = std::fs::remove_dir_all(&dir);
            continue;
        }
        let store = open(&dir, &secure).unwrap();
        assert_eq!(
            store.anchor_protection(),
            AnchorProtection::SecureStorage,
            "{tamper}"
        );
        assert!(store.load_keystore().is_err(), "{tamper}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn malformed_marker_without_secure_provenance_fails_closed() {
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    secure.set_unavailable(true);
    drop(open(&dir, &secure).unwrap()); // fresh, degraded
    std::fs::write(dir.join(".state-anchor-backend"), b"bogus\n").unwrap();
    let error = open(&dir, &secure).err().expect("must fail closed");
    assert!(error.starts_with(ANCHOR_RECOVERY_REQUIRED), "{error}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unavailable_keychain_with_protected_state_fails_closed() {
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    populated(&dir, &secure);
    secure.set_unavailable(true);

    // Secure marker: refuse rather than silently starting a fresh file anchor.
    let error = open(&dir, &secure).err().expect("must fail closed");
    assert!(error.starts_with(ANCHOR_RECOVERY_REQUIRED), "{error}");

    // Marker removed while the keychain cannot be consulted: still refuse.
    std::fs::remove_file(dir.join(".state-anchor-backend")).unwrap();
    let error = open(&dir, &secure).err().expect("must fail closed");
    assert!(error.starts_with(ANCHOR_RECOVERY_REQUIRED), "{error}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn deliberately_file_backed_store_stays_degraded_and_warns() {
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    secure.set_unavailable(true);
    let store = open(&dir, &secure).unwrap();
    assert_eq!(store.anchor_protection(), AnchorProtection::DegradedFile);
    let identity = Identity::generate("Alice", 0).unwrap();
    store
        .save_keystore(&KeystoreFile::create(&identity, PASS, fast_kdf()).unwrap())
        .unwrap();
    drop(store);

    // Secure storage later answers but holds nothing for this store: it was
    // file-backed from creation, which remains its documented mode.
    secure.set_unavailable(false);
    let store = open(&dir, &secure).unwrap();
    assert_eq!(store.anchor_protection(), AnchorProtection::DegradedFile);
    assert!(store.rollback_protection_warning().is_some());
    store.load_keystore().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lost_secure_anchors_require_authenticated_recovery() {
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    let (identity, _stale) = populated(&dir, &secure);

    // The keychain was reset: the store refuses to trust its state.
    let reset = Arc::new(MemoryAnchorStorage::new());
    let error = open(&dir, &reset).err().expect("must require recovery");
    assert!(error.starts_with(ANCHOR_RECOVERY_REQUIRED), "{error}");

    // A wrong passphrase authenticates nothing and writes nothing.
    let reset_dyn: Arc<dyn SecureAnchorStorage> = reset.clone();
    assert!(Store::recover_rollback_anchors(&dir, Some(reset_dyn.clone()), b"wrong").is_err());
    assert!(reset.is_empty());
    assert!(open(&dir, &reset).is_err());

    // The real passphrase re-anchors every protected object.
    let store = Store::recover_rollback_anchors(&dir, Some(reset_dyn), PASS).unwrap();
    assert_eq!(store.anchor_protection(), AnchorProtection::SecureStorage);
    drop(store);
    let store = open(&dir, &reset).unwrap();
    let ks = store.load_keystore().unwrap();
    assert_eq!(
        ks.unlock(PASS).unwrap().fingerprint(),
        identity.fingerprint()
    );
    assert_eq!(store.load_contacts(&identity).unwrap().contacts.len(), 1);
    let registry = store.load_registry(&identity).unwrap();
    assert_eq!(registry.vaults.len(), 1);
    store.open_vault(&identity, &registry.vaults[0].id).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn recovery_without_secure_storage_falls_back_to_degraded_file_anchors() {
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    let (identity, _stale) = populated(&dir, &secure);
    secure.set_unavailable(true);
    assert!(open(&dir, &secure).is_err());

    let secure_dyn: Arc<dyn SecureAnchorStorage> = secure.clone();
    let store = Store::recover_rollback_anchors(&dir, Some(secure_dyn), PASS).unwrap();
    assert_eq!(store.anchor_protection(), AnchorProtection::DegradedFile);
    drop(store);
    let store = open(&dir, &secure).unwrap();
    assert_eq!(store.anchor_protection(), AnchorProtection::DegradedFile);
    assert_eq!(store.load_contacts(&identity).unwrap().contacts.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn many_vaults_fit_a_capacity_limited_secure_store() {
    // Windows Credential Manager caps one credential blob at 2,560 bytes; the
    // old single-record layout overflowed it after about ten vaults (FS-06).
    const WINDOWS_CREDENTIAL_BLOB_LIMIT: usize = 2560;
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::with_record_capacity(
        WINDOWS_CREDENTIAL_BLOB_LIMIT,
    ));
    let store = open(&dir, &secure).unwrap();
    let identity = Identity::generate("Alice", 0).unwrap();
    store
        .save_keystore(&KeystoreFile::create(&identity, PASS, fast_kdf()).unwrap())
        .unwrap();
    store
        .save_contacts(&identity, &ContactBook::default())
        .unwrap();
    let mut registry = Registry::default();
    for n in 0..64 {
        let id = new_vault_id().unwrap();
        store
            .save_vault(&identity, &id, &Vault::new(format!("Vault {n}"), 1))
            .unwrap();
        registry.upsert(VaultMeta {
            id,
            name: format!("Vault {n}"),
            created_at: 1,
            modified_at: 1,
            file_count: 0,
            total_size: 0,
        });
    }
    store.save_registry(&identity, &registry).unwrap();
    assert!(secure.len() >= 64 + 4);
    assert!(secure.largest_record() <= WINDOWS_CREDENTIAL_BLOB_LIMIT);
    drop(store);

    let store = open(&dir, &secure).unwrap();
    store.load_keystore().unwrap();
    for meta in &store.load_registry(&identity).unwrap().vaults {
        store.open_vault(&identity, &meta.id).unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_anchor_commit_leaves_no_unanchored_vault_directory() {
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    let store = open(&dir, &secure).unwrap();
    let identity = Identity::generate("Alice", 0).unwrap();
    let id = new_vault_id().unwrap();
    secure.set_fail_saves(true);
    assert!(store
        .save_vault(&identity, &id, &Vault::new("Docs", 1))
        .is_err());
    secure.set_fail_saves(false);
    assert!(!dir.join("vaults").join(format!("{id}.fsv2")).exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn legacy_single_record_secure_layout_is_upgraded_in_place() {
    #[derive(serde::Serialize)]
    struct LegacyAnchorSet {
        version: u16,
        anchors: Vec<filesec_core::state::StateAnchor>,
    }

    // Build state with file anchors, then move them into secure storage in
    // the pre-FS-06 layout: one record holding every anchor.
    let dir = tmp();
    let store = Store::at_with_secure_storage(&dir, None).unwrap();
    let identity = Identity::generate("Alice", 0).unwrap();
    let mut ks = KeystoreFile::create(&identity, PASS, fast_kdf()).unwrap();
    store.save_keystore(&ks).unwrap();
    let stale = std::fs::read(dir.join("keystore.fsk")).unwrap();
    ks.set_device_token(PASS, &[3u8; 32]).unwrap();
    store.save_keystore(&ks).unwrap();
    drop(store);
    let account = std::fs::canonicalize(&dir).unwrap().display().to_string();
    let legacy = LegacyAnchorSet {
        version: 1,
        anchors: vec![filesec_core::state::StateAnchor::from_metadata(
            ks.state_metadata().unwrap(),
        )],
    };
    let secure = Arc::new(MemoryAnchorStorage::new());
    secure
        .save(&account, &filesec_core::codec::to_vec(&legacy).unwrap())
        .unwrap();
    std::fs::remove_file(dir.join(".state-anchors")).unwrap();
    std::fs::write(dir.join(".state-anchor-backend"), b"secure-v1\n").unwrap();

    let store = open(&dir, &secure).unwrap();
    assert_eq!(store.anchor_protection(), AnchorProtection::SecureStorage);
    assert_eq!(secure.len(), 2, "root + one object record");
    store.load_keystore().unwrap();
    std::fs::write(dir.join("keystore.fsk"), &stale).unwrap();
    let error = store
        .load_keystore()
        .err()
        .expect("rollback must be detected");
    assert!(error.contains("rollback detected"), "{error}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Lower-priority audit item: loading a keystore never establishes its first
/// anchor — only a confirmed unlock does — so a self-signed keystore planted
/// in an empty namespace cannot claim it before the owner unlocks.
#[test]
fn a_planted_keystore_cannot_claim_an_empty_namespace() {
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    let store = open(&dir, &secure).unwrap();
    let owner = Identity::generate("Owner", 0).unwrap();
    let owner_ks = KeystoreFile::create(&owner, PASS, fast_kdf()).unwrap();
    let mallory = Identity::generate("Mallory", 0).unwrap();
    let planted = KeystoreFile::create(&mallory, b"attacker passphrase", fast_kdf()).unwrap();

    // The planted keystore is merely looked at (e.g. by the unlock screen).
    std::fs::write(dir.join("keystore.fsk"), planted.to_bytes().unwrap()).unwrap();
    store.load_keystore().unwrap();
    let records_before = secure.len();

    // The owner's keystore still loads and, once unlocked, is anchored.
    std::fs::write(dir.join("keystore.fsk"), owner_ks.to_bytes().unwrap()).unwrap();
    let ks = store.load_keystore().unwrap();
    assert_eq!(secure.len(), records_before, "loading anchors nothing");
    let identity = ks.unlock(PASS).unwrap();
    store.confirm_unlocked_keystore(&ks, &identity).unwrap();
    assert_eq!(secure.len(), records_before + 1);

    // From now on another identity's keystore is refused.
    assert!(store.confirm_unlocked_keystore(&ks, &mallory).is_err());
    std::fs::write(dir.join("keystore.fsk"), planted.to_bytes().unwrap()).unwrap();
    let error = store.load_keystore().err().expect("must be refused");
    assert!(
        error.contains("different identity") || error.contains("state-anchor mismatch"),
        "{error}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
