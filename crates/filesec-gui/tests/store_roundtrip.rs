//! Integration tests for the GUI persistence layer (`store`), exercised
//! without opening a window.

use filesec_core::contacts::ContactBook;
use filesec_core::identity::Identity;
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::KeystoreFile;
use filesec_core::vault::Vault;
use filesec_gui::store::{extract_vault, new_vault_id, Registry, Store, VaultMeta};
use std::path::PathBuf;

fn tmp() -> PathBuf {
    let suffix = filesec_core::util::hex(&filesec_core::secret::random_vec(8).unwrap());
    std::env::temp_dir().join(format!("filesec-test-{suffix}"))
}

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_cost: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

#[test]
fn full_persistence_roundtrip() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    assert!(!store.keystore_exists());

    // Keystore create / load / unlock.
    let id = Identity::generate("Alice", 0).unwrap();
    let ks = KeystoreFile::create(&id, b"passphrase123", fast_kdf()).unwrap();
    store.save_keystore(&ks).unwrap();
    assert!(store.keystore_exists());
    let unlocked = store
        .load_keystore()
        .unwrap()
        .unlock(b"passphrase123")
        .unwrap();
    assert_eq!(unlocked.fingerprint(), id.fingerprint());

    // Vault save / load (encrypted-to-self at rest).
    let vid = new_vault_id();
    let mut v = Vault::new("Docs", 10);
    v.add_file("a/b.txt", b"hello".to_vec(), None, None)
        .unwrap();
    store.save_vault(&id, &vid, &v).unwrap();
    let v2 = store.load_vault(&id, &vid).unwrap();
    assert_eq!(v2.name, "Docs");
    assert_eq!(&v2.get("a/b.txt").unwrap().content[..], b"hello");

    // Registry round-trip.
    let mut reg = Registry::default();
    reg.upsert(VaultMeta {
        id: vid.clone(),
        name: "Docs".into(),
        created_at: 10,
        modified_at: 11,
        file_count: 1,
        total_size: 5,
    });
    store.save_registry(&id, &reg).unwrap();
    let reg2 = store.load_registry(&id).unwrap();
    assert_eq!(reg2.vaults.len(), 1);
    assert_eq!(reg2.vaults[0].name, "Docs");

    // Contacts round-trip.
    let mut book = ContactBook::default();
    book.upsert(id.public(), 0);
    store.save_contacts(&id, &book).unwrap();
    assert!(store
        .load_contacts(&id)
        .unwrap()
        .find(&id.fingerprint())
        .is_some());

    // A fresh store yields empty defaults.
    let dir2 = tmp();
    let store2 = Store::at(&dir2).unwrap();
    assert_eq!(store2.load_registry(&id).unwrap().vaults.len(), 0);
    assert!(store2.load_contacts(&id).unwrap().contacts.is_empty());

    // Confidentiality: a different identity cannot read the self-encrypted vault.
    let mallory = Identity::generate("Mallory", 0).unwrap();
    assert!(store.load_vault(&mallory, &vid).is_err());

    // Extraction to the real filesystem reproduces the content.
    let out = tmp();
    std::fs::create_dir_all(&out).unwrap();
    extract_vault(&v2, &out).unwrap();
    assert_eq!(std::fs::read(out.join("a/b.txt")).unwrap(), b"hello");

    // Best-effort cleanup.
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn data_dir_env_override_is_respected() {
    let dir = tmp();
    // Safety: single-threaded test process section; we set then clear.
    std::env::set_var("FILESEC_DATA_DIR", &dir);
    let store = Store::discover().unwrap();
    assert!(store.data_dir().starts_with(&dir));
    std::env::remove_var("FILESEC_DATA_DIR");
    let _ = std::fs::remove_dir_all(&dir);
}
