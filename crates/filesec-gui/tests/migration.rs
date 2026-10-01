//! Post-quantum identity migration safety (audit FS-02/FS-03).
#![cfg(feature = "pqc")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use filesec_core::contacts::ContactBook;
use filesec_core::identity::Identity;
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::{KeystoreFile, PasskeyEnrollment, HMAC_SECRET_LEN};
use filesec_core::vault::Vault;
use filesec_gui::anchors::{MemoryAnchorStorage, SecureAnchorStorage};
use filesec_gui::store::{new_vault_id, Registry, Store, VaultMeta};
use zeroize::Zeroizing;

const PASS: &[u8] = b"correct horse battery staple";
const DEVICE_TOKEN: [u8; 32] = [9u8; 32];
const PASSKEY_SECRET: [u8; HMAC_SECRET_LEN] = [5u8; HMAC_SECRET_LEN];

fn tmp() -> PathBuf {
    let suffix = filesec_core::util::hex(&filesec_core::secret::random_vec(8).unwrap());
    std::env::temp_dir().join(format!("filesec-migration-test-{suffix}"))
}

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_cost: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn open(dir: &Path, secure: &Arc<MemoryAnchorStorage>) -> Store {
    let secure: Arc<dyn SecureAnchorStorage> = secure.clone();
    Store::at_with_secure_storage(dir, Some(secure)).unwrap()
}

/// Every file under `dir` with its bytes, for "nothing changed" assertions.
///
/// Skips the empty `.lock` file the open [`Store`] holds: it carries no state,
/// and on Windows the lock is mandatory, so even this process cannot read it
/// (os error 33) while the store is alive.
fn tree(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path() != dir.join(".lock"))
        .map(|e| {
            (
                e.path().strip_prefix(dir).unwrap().to_path_buf(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect()
}

/// A classical store with a passkey slot, a device slot, contacts, a registry,
/// and one vault. Returns the store's classical identity and the vault id.
fn populated(store: &Store) -> (Identity, String) {
    let identity = Identity::generate("Alice", 0).unwrap();
    let mut ks = KeystoreFile::create(&identity, PASS, fast_kdf()).unwrap();
    ks.add_passkey(
        PASS,
        PasskeyEnrollment {
            credential_id: b"cred".to_vec(),
            rp_id: "filesec.local".into(),
            hmac_salt: [1u8; HMAC_SECRET_LEN],
            label: "Key".into(),
            added_at: 1,
            hmac_output: Zeroizing::new(PASSKEY_SECRET),
        },
    )
    .unwrap();
    ks.set_device_token(PASS, &DEVICE_TOKEN).unwrap();
    store.save_keystore(&ks).unwrap();
    let mut book = ContactBook::default();
    book.upsert(Identity::generate("Bob", 0).unwrap().public(), 1);
    store.save_contacts(&identity, &book).unwrap();
    let id = new_vault_id().unwrap();
    let mut vault = Vault::new("Docs", 1);
    vault
        .add_file("a.txt", b"hello".to_vec(), None, None)
        .unwrap();
    store.save_vault(&identity, &id, &vault).unwrap();
    let mut registry = Registry::default();
    registry.upsert(VaultMeta {
        id: id.clone(),
        name: "Docs".into(),
        created_at: 1,
        modified_at: 1,
        file_count: 1,
        total_size: 5,
    });
    store.save_registry(&identity, &registry).unwrap();
    (identity, id)
}

#[test]
fn wrong_confirmation_is_rejected_without_changing_anything() {
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    let store = open(&dir, &secure);
    let (identity, _id) = populated(&store);
    let files_before = tree(&dir);
    let anchors_before = secure.snapshot();

    let error = store
        .migrate_to_hybrid(&identity, b"correct horse battery stapel")
        .err()
        .expect("a mistyped confirmation must not migrate");
    assert!(error.contains("incorrect passphrase"), "{error}");

    assert_eq!(tree(&dir), files_before, "no file may change");
    assert_eq!(secure.snapshot(), anchors_before, "no anchor may change");
    let ks = store.load_keystore().unwrap();
    assert_eq!(
        ks.unlock(PASS).unwrap().fingerprint(),
        identity.fingerprint()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn confirmation_from_another_session_is_rejected() {
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    let store = open(&dir, &secure);
    populated(&store);
    let files_before = tree(&dir);
    let stranger = Identity::generate("Mallory", 0).unwrap();
    assert!(store.migrate_to_hybrid(&stranger, PASS).is_err());
    assert_eq!(tree(&dir), files_before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn migration_preserves_passphrase_passkeys_and_device_unlock() {
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    let store = open(&dir, &secure);
    let (identity, id) = populated(&store);

    let new = store.migrate_to_hybrid(&identity, PASS).unwrap();
    assert!(new.is_hybrid_capable());

    let ks = store.load_keystore().unwrap();
    assert_eq!(ks.unlock(PASS).unwrap().fingerprint(), new.fingerprint());
    assert_eq!(ks.passkey_slots().len(), 1);
    assert_eq!(
        ks.unlock_with_passkey(0, &PASSKEY_SECRET)
            .unwrap()
            .fingerprint(),
        new.fingerprint()
    );
    assert!(ks.has_device_token());
    assert_eq!(
        ks.unlock_with_device_token(&DEVICE_TOKEN)
            .unwrap()
            .fingerprint(),
        new.fingerprint()
    );
    assert_eq!(store.load_contacts(&new).unwrap().contacts.len(), 1);
    assert_eq!(store.load_registry(&new).unwrap().vaults.len(), 1);
    let vault = store.load_vault(&new, &id).unwrap();
    assert_eq!(&vault.get("a.txt").unwrap().content[..], b"hello");
    let _ = std::fs::remove_dir_all(&dir);
}
