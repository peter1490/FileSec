//! Persistence coordination across threads and processes (audit FS-05).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use filesec_core::contacts::ContactBook;
use filesec_core::identity::Identity;
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::KeystoreFile;
use filesec_core::vault::Vault;
use filesec_gui::anchors::{MemoryAnchorStorage, SecureAnchorStorage};
use filesec_gui::store::{new_vault_id, Registry, Store, VaultMeta, STALE_STATE, STORE_IN_USE};

const CHILD_ENV: &str = "FILESEC_STORE_LOCK_CHILD_DIR";

fn tmp() -> PathBuf {
    let suffix = filesec_core::util::hex(&filesec_core::secret::random_vec(8).unwrap());
    std::env::temp_dir().join(format!("filesec-lock-test-{suffix}"))
}

fn open(dir: &Path, secure: &Arc<MemoryAnchorStorage>) -> Store {
    let secure: Arc<dyn SecureAnchorStorage> = secure.clone();
    Store::at_with_secure_storage(dir, Some(secure)).unwrap()
}

fn meta(id: &str, n: u64) -> VaultMeta {
    VaultMeta {
        id: id.into(),
        name: format!("Vault {n}"),
        created_at: 1,
        modified_at: n as i64,
        file_count: n,
        total_size: n,
    }
}

/// Not a test on its own: re-invoked as a separate process by
/// `a_second_process_cannot_open_an_open_store`, it reports whether it could
/// open the store named by `CHILD_ENV`.
#[test]
fn child_process_open_probe() {
    let Some(dir) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    match Store::at_with_secure_storage(PathBuf::from(dir), None) {
        Ok(_) => println!("CHILD-OPEN=ok"),
        Err(e) => println!("CHILD-OPEN=err {e}"),
    }
}

/// Poll `attempt` for up to two seconds. A child process spawned by another
/// test in this binary briefly inherits every open descriptor (including other
/// tests' lock files) between fork and exec, so a just-released lock can stay
/// held for a moment; anything persistent still fails.
fn eventually(mut attempt: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if attempt() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn child_open(dir: &Path) -> String {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_process_open_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    stdout
        .lines()
        .find_map(|line| line.split_once("CHILD-OPEN=").map(|(_, v)| v.to_string()))
        .unwrap_or_else(|| panic!("child produced no verdict: {stdout}"))
}

#[test]
fn a_second_process_cannot_open_an_open_store() {
    let dir = tmp();
    // No secure storage on either side, so the child's only obstacle is the lock.
    let store = Store::at_with_secure_storage(&dir, None).unwrap();
    let verdict = child_open(&dir);
    assert!(
        verdict.starts_with("err") && verdict.contains(STORE_IN_USE),
        "{verdict}"
    );
    drop(store);
    assert!(
        eventually(|| child_open(&dir) == "ok"),
        "the lock is released on drop"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_external_lock_holder_is_refused_and_the_same_process_shares() {
    use fs4::fs_std::FileExt;
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    let first = open(&dir, &secure);
    // Several stores in one process share the lock.
    let second = open(&dir, &secure);
    let holder = std::fs::File::open(dir.join(".lock")).unwrap();
    assert!(!holder.try_lock_exclusive().unwrap(), "lock must be held");
    drop((first, second));
    assert!(
        eventually(|| holder.try_lock_exclusive().unwrap()),
        "lock must be released"
    );

    // Something else now holds it: the store refuses to open.
    let error = {
        let secure: Arc<dyn SecureAnchorStorage> = secure.clone();
        Store::at_with_secure_storage(&dir, Some(secure))
            .err()
            .expect("must refuse")
    };
    assert!(error.starts_with(STORE_IN_USE), "{error}");
    drop(holder);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_saves_of_distinct_and_same_objects_never_fork_state() {
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    let store = Arc::new(open(&dir, &secure));
    let identity = Arc::new(Identity::generate("Alice", 0).unwrap());
    let mut handles = Vec::new();
    for worker in 0..4u64 {
        let store = store.clone();
        let identity = identity.clone();
        handles.push(std::thread::spawn(move || {
            for n in 0..8u64 {
                if worker % 2 == 0 {
                    let mut registry = Registry::default();
                    registry.upsert(meta(&format!("{worker:02}"), n));
                    store.save_registry(&identity, &registry).unwrap();
                } else {
                    let mut book = ContactBook::default();
                    book.upsert(Identity::generate("Bob", 0).unwrap().public(), n as i64);
                    store.save_contacts(&identity, &book).unwrap();
                }
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    drop(store);
    let store = open(&dir, &secure);
    assert_eq!(store.load_registry(&identity).unwrap().vaults.len(), 1);
    assert_eq!(store.load_contacts(&identity).unwrap().contacts.len(), 1);
    assert!(
        !dir.join("quarantine").exists(),
        "nothing may be quarantined"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_stale_vault_reader_cannot_overwrite_a_newer_commit() {
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    let store = open(&dir, &secure);
    let identity = Identity::generate("Alice", 0).unwrap();
    let id = new_vault_id().unwrap();
    store
        .save_vault(&identity, &id, &Vault::new("Docs", 1))
        .unwrap();
    let reader = store.open_vault(&identity, &id).unwrap();
    let stale = reader.clone();
    store
        .put_bytes_in_vault(&identity, &id, &reader, "first.txt", b"one", None)
        .unwrap();
    let error = store
        .put_bytes_in_vault(&identity, &id, &stale, "second.txt", b"two", None)
        .expect_err("stale reader must be refused");
    assert!(error.starts_with(STALE_STATE), "{error}");

    let vault = store.load_vault(&identity, &id).unwrap();
    assert!(vault.get("first.txt").is_some());
    assert!(vault.get("second.txt").is_none());
    assert!(!dir.join("quarantine").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn interruption_between_data_and_anchor_commit_recovers_forward() {
    let dir = tmp();
    let secure = Arc::new(MemoryAnchorStorage::new());
    let store = open(&dir, &secure);
    let identity = Identity::generate("Alice", 0).unwrap();
    store
        .save_keystore(
            &KeystoreFile::create(
                &identity,
                b"pw",
                KdfParams {
                    m_cost: 8 * 1024,
                    t_cost: 1,
                    p_cost: 1,
                },
            )
            .unwrap(),
        )
        .unwrap();
    let mut registry = Registry::default();
    registry.upsert(meta("aa", 1));
    store.save_registry(&identity, &registry).unwrap();

    // The state file commits, then the anchor update fails.
    registry.upsert(meta("bb", 2));
    secure.set_fail_saves(true);
    assert!(store.save_registry(&identity, &registry).is_err());
    secure.set_fail_saves(false);

    // The authenticated successor on disk is accepted on the next load and
    // becomes the new high-water mark; nothing forks or is quarantined.
    drop(store);
    let store = open(&dir, &secure);
    assert_eq!(store.load_registry(&identity).unwrap().vaults.len(), 2);
    registry.upsert(meta("cc", 3));
    store.save_registry(&identity, &registry).unwrap();
    assert_eq!(store.load_registry(&identity).unwrap().vaults.len(), 3);
    assert!(!dir.join("quarantine").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
