//! Registry/vault consistency across interruptions (audit FS-11).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use filesec_core::identity::Identity;
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::KeystoreFile;
use filesec_core::vault::Vault;
use filesec_gui::anchors::{MemoryAnchorStorage, SecureAnchorStorage};
use filesec_gui::store::{new_vault_id, Registry, Store, VaultMeta};

fn tmp() -> PathBuf {
    let suffix = filesec_core::util::hex(&filesec_core::secret::random_vec(8).unwrap());
    std::env::temp_dir().join(format!("filesec-registry-test-{suffix}"))
}

struct Fixture {
    dir: PathBuf,
    secure: Arc<MemoryAnchorStorage>,
    identity: Identity,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fixture {
    fn new() -> Self {
        let f = Self {
            dir: tmp(),
            secure: Arc::new(MemoryAnchorStorage::new()),
            identity: Identity::generate("Alice", 0).unwrap(),
        };
        let kdf = KdfParams {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        f.store()
            .save_keystore(&KeystoreFile::create(&f.identity, b"pw", kdf).unwrap())
            .unwrap();
        f
    }

    fn store(&self) -> Store {
        let secure: Arc<dyn SecureAnchorStorage> = self.secure.clone();
        Store::at_with_secure_storage(&self.dir, Some(secure)).unwrap()
    }

    fn vault_dir(&self, id: &str) -> PathBuf {
        self.dir.join("vaults").join(format!("{id}.fsv2"))
    }

    /// A registered vault holding one file.
    fn registered_vault(&self, store: &Store, name: &str) -> (String, Registry) {
        let id = new_vault_id().unwrap();
        let mut vault = Vault::new(name, 1);
        vault
            .add_file("doc.txt", b"content".to_vec(), None, None)
            .unwrap();
        store.save_vault(&self.identity, &id, &vault).unwrap();
        let mut registry = store.load_registry(&self.identity).unwrap();
        registry.upsert(VaultMeta {
            id: id.clone(),
            name: name.into(),
            created_at: 1,
            modified_at: 1,
            file_count: 1,
            total_size: 7,
        });
        store.save_registry(&self.identity, &registry).unwrap();
        (id, registry)
    }

    /// Reload and reconcile, as every unlock does.
    fn unlock(&self, store: &Store) -> (Registry, Vec<String>) {
        store.clean_partial_dirs();
        let registry = store.load_registry(&self.identity).unwrap();
        store.reconcile_vaults(&self.identity, registry).unwrap()
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    for entry in walkdir::WalkDir::new(source) {
        let entry = entry.unwrap();
        let target = destination.join(entry.path().strip_prefix(source).unwrap());
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(target).unwrap();
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn a_created_but_unregistered_vault_is_recovered_on_unlock() {
    let f = Fixture::new();
    let store = f.store();
    let id = new_vault_id().unwrap();
    // The vault commits; the registry update never happens (crash or error).
    store
        .save_vault(&f.identity, &id, &Vault::new("Orphan", 1))
        .unwrap();
    let (registry, notes) = f.unlock(&store);
    let meta = registry
        .vaults
        .iter()
        .find(|v| v.id == id)
        .expect("recovered");
    assert_eq!(meta.name, "Orphan");
    assert!(notes.iter().any(|n| n.contains("Orphan")), "{notes:?}");
    // The repair is durable.
    assert_eq!(store.load_registry(&f.identity).unwrap().vaults.len(), 1);
}

#[test]
fn an_interrupted_creation_leaves_nothing_behind() {
    let f = Fixture::new();
    let store = f.store();
    let partial = f.dir.join("vaults").join("0011aabb.fsv2.partial");
    std::fs::create_dir_all(partial.join("blobs")).unwrap();
    std::fs::write(partial.join("header"), b"half-written").unwrap();
    let (registry, notes) = f.unlock(&store);
    assert!(registry.vaults.is_empty());
    assert!(notes.is_empty());
    assert!(!partial.exists());
}

#[test]
fn deleting_a_vault_commits_through_the_registry() {
    let f = Fixture::new();
    let store = f.store();
    let (id, registry) = f.registered_vault(&store, "Docs");
    let registry = store.delete_vault(&f.identity, &registry, &id).unwrap();
    assert!(registry.vaults.is_empty());
    assert!(!f.vault_dir(&id).exists());
    assert!(!f
        .dir
        .join("vaults")
        .join(format!("{id}.fsv2.deleted"))
        .exists());
    assert!(store.load_registry(&f.identity).unwrap().vaults.is_empty());
}

#[test]
fn a_failed_registry_commit_keeps_the_vault() {
    let f = Fixture::new();
    let store = f.store();
    let (id, registry) = f.registered_vault(&store, "Docs");
    f.secure.set_fail_saves(true);
    assert!(store.delete_vault(&f.identity, &registry, &id).is_err());
    f.secure.set_fail_saves(false);
    assert!(f.vault_dir(&id).exists(), "the tombstone is restored");
    // Whatever the half-saved registry says, the next unlock lists the vault.
    drop(store);
    let store = f.store();
    let (registry, _) = f.unlock(&store);
    assert!(registry.vaults.iter().any(|v| v.id == id));
    let vault = store.load_vault(&f.identity, &id).unwrap();
    assert_eq!(&vault.get("doc.txt").unwrap().content[..], b"content");
}

#[test]
fn a_deletion_interrupted_before_its_commit_is_undone() {
    let f = Fixture::new();
    let store = f.store();
    let (id, _) = f.registered_vault(&store, "Docs");
    // Crash right after the tombstone rename: the registry still lists it.
    std::fs::rename(
        f.vault_dir(&id),
        f.dir.join("vaults").join(format!("{id}.fsv2.deleted")),
    )
    .unwrap();
    let (registry, notes) = f.unlock(&store);
    assert!(registry.vaults.iter().any(|v| v.id == id));
    assert!(notes.iter().any(|n| n.contains("Docs")), "{notes:?}");
    store.open_vault(&f.identity, &id).unwrap();
}

#[test]
fn a_deletion_interrupted_after_its_commit_is_finished_and_stays_deleted() {
    let f = Fixture::new();
    let store = f.store();
    let (id, mut registry) = f.registered_vault(&store, "Docs");
    let backup = tmp();
    copy_tree(&f.vault_dir(&id), &backup);

    // Crash right after the registry commit, before the tombstone was retired.
    std::fs::rename(
        f.vault_dir(&id),
        f.dir.join("vaults").join(format!("{id}.fsv2.deleted")),
    )
    .unwrap();
    registry.remove(&id);
    store.save_registry(&f.identity, &registry).unwrap();
    let (registry, _) = f.unlock(&store);
    assert!(registry.vaults.is_empty());
    assert!(!f
        .dir
        .join("vaults")
        .join(format!("{id}.fsv2.deleted"))
        .exists());

    // A restored copy of the deleted vault is not resurrected.
    copy_tree(&backup, &f.vault_dir(&id));
    let (registry, _) = f.unlock(&store);
    assert!(
        registry.vaults.is_empty(),
        "a deleted vault must stay deleted"
    );
    assert!(store.open_vault(&f.identity, &id).is_err());
    let _ = std::fs::remove_dir_all(&backup);
}
