//! Integration tests for the GUI persistence layer (`store`), exercised
//! without opening a window.

use filesec_core::contacts::{ContactBook, Trust};
use filesec_core::identity::Identity;
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::{KeystoreFile, PasskeyEnrollment, DEVICE_TOKEN_LEN, HMAC_SECRET_LEN};
use filesec_core::state::{StateAnchor, StateObjectType};
use filesec_core::vault::Vault;
use filesec_gui::prefs::{Prefs, ThemeChoice};
use filesec_gui::store::{
    extract_vault, make_readonly, new_vault_id, secure_wipe, Registry, Store, VaultMeta,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroizing;

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

fn enrollment(secret: u8, credential_id: &[u8], label: &str) -> PasskeyEnrollment {
    PasskeyEnrollment {
        credential_id: credential_id.to_vec(),
        rp_id: "filesec.local".into(),
        hmac_salt: [secret ^ 0xa5; HMAC_SECRET_LEN],
        label: label.into(),
        added_at: 10,
        hmac_output: Zeroizing::new([secret; HMAC_SECRET_LEN]),
    }
}

fn copy_tree(source: &std::path::Path, destination: &std::path::Path) {
    std::fs::create_dir_all(destination).unwrap();
    for entry in walkdir::WalkDir::new(source) {
        let entry = entry.unwrap();
        let relative = entry.path().strip_prefix(source).unwrap();
        if relative.as_os_str().is_empty() {
            continue;
        }
        let target = destination.join(relative);
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(target).unwrap();
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn quarantine_has(dir: &std::path::Path, prefix: &str) -> bool {
    std::fs::read_dir(dir.join("quarantine"))
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
}

#[derive(Serialize, Deserialize)]
struct TestAnchorSet {
    version: u16,
    anchors: Vec<StateAnchor>,
}

fn corrupt_anchor_hash(dir: &std::path::Path, object_type: StateObjectType) {
    let path = dir.join(".state-anchors");
    let from_file = path.exists();
    let anchor_account = std::fs::canonicalize(dir)
        .unwrap_or_else(|_| dir.to_path_buf())
        .display()
        .to_string();
    let bytes = if from_file {
        std::fs::read(&path).unwrap()
    } else {
        filesec_gui::autounlock::load_state_anchors(&anchor_account)
            .unwrap()
            .expect("secure object anchors")
    };
    let mut set: TestAnchorSet = filesec_core::codec::from_slice(&bytes).unwrap();
    let anchor = set
        .anchors
        .iter_mut()
        .find(|anchor| anchor.object_type == object_type)
        .expect("object anchor");
    anchor.current_state_hash[0] ^= 1;
    let bytes = filesec_core::codec::to_vec(&set).unwrap();
    if from_file {
        std::fs::write(path, bytes).unwrap();
    } else {
        filesec_gui::autounlock::save_state_anchors(&anchor_account, &bytes).unwrap();
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
    let vid = new_vault_id().unwrap();
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
fn keystore_rollback_is_rejected_and_quarantined() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    let identity = Identity::generate("Alice", 0).unwrap();
    let passphrase = b"correct horse battery staple";
    let mut keystore = KeystoreFile::create(&identity, passphrase, fast_kdf()).unwrap();
    store.save_keystore(&keystore).unwrap();

    keystore
        .add_passkey(passphrase, enrollment(0x31, b"key-a", "Key A"))
        .unwrap();
    store.save_keystore(&keystore).unwrap();
    let old = std::fs::read(dir.join("keystore.fsk")).unwrap();

    keystore.remove_passkey(0, &identity).unwrap();
    store.save_keystore(&keystore).unwrap();
    std::fs::write(dir.join("keystore.fsk"), old).unwrap();

    let error = store.load_keystore().err().expect("rollback must fail");
    assert!(error.contains("rollback detected"), "{error}");
    assert!(!dir.join("keystore.fsk").exists());
    assert!(quarantine_has(&dir, "keystore.fsk.rollback-"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn device_token_roundtrips_through_the_store_and_is_rollback_protected() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    let id = Identity::generate("Alice", 0).unwrap();
    let pass = b"correct horse battery staple";
    let mut ks = KeystoreFile::create(&id, pass, fast_kdf()).unwrap();
    store.save_keystore(&ks).unwrap();
    assert!(!store.load_keystore().unwrap().has_device_token());

    // Enroll a random device token (the "remember on this device" flow) and
    // persist it. The passphrase is never written; only this token wraps the DEK.
    let token = [0x5eu8; DEVICE_TOKEN_LEN];
    ks.set_device_token(pass, &token).unwrap();
    store.save_keystore(&ks).unwrap();

    // Reloaded from disk, the device slot survives and opens the keystore, the
    // passphrase still works, and the token is not usable as a passphrase.
    let reloaded = store.load_keystore().unwrap();
    assert!(reloaded.has_device_token());
    assert_eq!(
        reloaded
            .unlock_with_device_token(&token)
            .unwrap()
            .fingerprint(),
        id.fingerprint()
    );
    assert_eq!(
        reloaded.unlock(pass).unwrap().fingerprint(),
        id.fingerprint()
    );
    assert!(reloaded.unlock(&token).is_err());

    // Forgetting the device (disable flow) removes the slot and advances the
    // signed epoch, so restoring the token-enrolled keystore is a rollback and is
    // rejected + quarantined.
    let with_token = std::fs::read(dir.join("keystore.fsk")).unwrap();
    let mut latest = store.load_keystore().unwrap();
    latest.remove_device_token(&id).unwrap();
    store.save_keystore(&latest).unwrap();
    std::fs::write(dir.join("keystore.fsk"), with_token).unwrap();
    let error = store.load_keystore().err().expect("rollback must fail");
    assert!(error.contains("rollback detected"), "{error}");
    assert!(quarantine_has(&dir, "keystore.fsk.rollback-"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn contact_trust_rollback_is_rejected_and_quarantined() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    let owner = Identity::generate("Owner", 0).unwrap();
    let contact = Identity::generate("Contact", 0).unwrap();
    let fingerprint = contact.fingerprint();
    let mut book = ContactBook::default();
    book.upsert(contact.public(), 1);
    book.set_trust(&fingerprint, Trust::Verified, 2);
    store.save_contacts(&owner, &book).unwrap();
    let verified = std::fs::read(dir.join("contacts.fsec")).unwrap();

    book.set_trust(&fingerprint, Trust::Unverified, 3);
    store.save_contacts(&owner, &book).unwrap();
    std::fs::write(dir.join("contacts.fsec"), verified).unwrap();

    let error = store.load_contacts(&owner).expect_err("rollback must fail");
    assert!(error.contains("rollback detected"), "{error}");
    assert!(quarantine_has(&dir, "contacts.fsec.rollback-"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn registry_rollback_is_rejected_and_quarantined() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    let owner = Identity::generate("Owner", 0).unwrap();
    let mut registry = Registry::default();
    registry.upsert(VaultMeta {
        id: "00112233445566778899aabbccddeeff".into(),
        name: "Docs".into(),
        created_at: 1,
        modified_at: 2,
        file_count: 1,
        total_size: 5,
    });
    store.save_registry(&owner, &registry).unwrap();
    let populated = std::fs::read(dir.join("index.fsec")).unwrap();

    registry.remove("00112233445566778899aabbccddeeff");
    store.save_registry(&owner, &registry).unwrap();
    std::fs::write(dir.join("index.fsec"), populated).unwrap();

    let error = store.load_registry(&owner).expect_err("rollback must fail");
    assert!(error.contains("rollback detected"), "{error}");
    assert!(quarantine_has(&dir, "index.fsec.rollback-"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vault_manifest_rollback_is_rejected_and_quarantined() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    let owner = Identity::generate("Owner", 0).unwrap();
    let vault_id = new_vault_id().unwrap();
    let mut vault = Vault::new("Docs", 1);
    vault
        .add_file("note.txt", b"old".to_vec(), None, None)
        .unwrap();
    store.save_vault(&owner, &vault_id, &vault).unwrap();

    let vault_dir = dir.join("vaults").join(format!("{vault_id}.fsv2"));
    let snapshot = tmp();
    copy_tree(&vault_dir, &snapshot);

    let reader = store.open_vault(&owner, &vault_id).unwrap();
    store
        .put_bytes_in_vault(&owner, &vault_id, &reader, "note.txt", b"new", Some(2))
        .unwrap();
    assert_eq!(
        &*store
            .open_vault(&owner, &vault_id)
            .unwrap()
            .read_entry("note.txt")
            .unwrap(),
        b"new"
    );

    std::fs::remove_dir_all(&vault_dir).unwrap();
    copy_tree(&snapshot, &vault_dir);
    let error = store
        .open_vault(&owner, &vault_id)
        .err()
        .expect("rollback must fail");
    assert!(error.contains("rollback detected"), "{error}");
    assert!(quarantine_has(&dir, &format!("{vault_id}.fsv2.rollback-")));
    let _ = std::fs::remove_dir_all(&snapshot);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn same_epoch_hash_mismatches_fail_for_every_anchored_object() {
    // Keystore.
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    let owner = Identity::generate("Owner", 0).unwrap();
    store
        .save_keystore(&KeystoreFile::create(&owner, b"strong passphrase", fast_kdf()).unwrap())
        .unwrap();
    corrupt_anchor_hash(&dir, StateObjectType::Keystore);
    let error = store.load_keystore().err().unwrap();
    assert!(error.contains("state-anchor mismatch"), "{error}");
    let _ = std::fs::remove_dir_all(&dir);

    // Contacts.
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    store
        .save_contacts(&owner, &ContactBook::default())
        .unwrap();
    corrupt_anchor_hash(&dir, StateObjectType::Contacts);
    let error = store.load_contacts(&owner).err().unwrap();
    assert!(error.contains("state-anchor mismatch"), "{error}");
    let _ = std::fs::remove_dir_all(&dir);

    // Registry.
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    store.save_registry(&owner, &Registry::default()).unwrap();
    corrupt_anchor_hash(&dir, StateObjectType::Registry);
    let error = store.load_registry(&owner).err().unwrap();
    assert!(error.contains("state-anchor mismatch"), "{error}");
    let _ = std::fs::remove_dir_all(&dir);

    // Vault manifest.
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    let vault_id = new_vault_id().unwrap();
    store
        .save_vault(&owner, &vault_id, &Vault::new("Docs", 0))
        .unwrap();
    corrupt_anchor_hash(&dir, StateObjectType::VaultManifest);
    let error = store.open_vault(&owner, &vault_id).err().unwrap();
    assert!(error.contains("state-anchor mismatch"), "{error}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn legacy_local_v1_vault_opens_only_through_explicit_recovery() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    let owner = Identity::generate("Owner", 0).unwrap();
    let vault_id = new_vault_id().unwrap();
    let mut vault = Vault::new("Legacy", 1);
    vault
        .add_file("legacy.txt", b"authenticated".to_vec(), None, None)
        .unwrap();
    let legacy_path = dir.join("vaults").join(format!("{vault_id}.fsec"));
    filesec_core::format::export_vault_to_path(
        &vault,
        &owner,
        &[owner.public()],
        &filesec_core::ExportOptions::default(),
        &legacy_path,
    )
    .unwrap();

    let error = store.open_vault(&owner, &vault_id).err().unwrap();
    assert!(error.contains("explicit recovery"), "{error}");
    let recovered = store.recover_legacy_vault(&owner, &vault_id).unwrap();
    assert_eq!(
        &*recovered.read_entry("legacy.txt").unwrap(),
        b"authenticated"
    );
    assert!(!legacy_path.exists());
    assert!(dir.join("vaults").join(format!("{vault_id}.fsv2")).exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn valid_vault_directory_cannot_be_substituted_at_another_vault_id() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    let owner = Identity::generate("Owner", 0).unwrap();
    let first_id = new_vault_id().unwrap();
    let second_id = new_vault_id().unwrap();
    store
        .save_vault(&owner, &first_id, &Vault::new("First", 1))
        .unwrap();
    store
        .save_vault(&owner, &second_id, &Vault::new("Second", 2))
        .unwrap();
    let first_path = dir.join("vaults").join(format!("{first_id}.fsv2"));
    let second_path = dir.join("vaults").join(format!("{second_id}.fsv2"));
    std::fs::remove_dir_all(&first_path).unwrap();
    std::fs::rename(&second_path, &first_path).unwrap();

    let error = store.open_vault(&owner, &first_id).err().unwrap();
    assert!(error.contains("object id"), "{error}");
    assert!(quarantine_has(&dir, &format!("{first_id}.fsv2.rollback-")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn replace_file_in_vault_roundtrip() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    let id = Identity::generate("Alice", 0).unwrap();
    let vid = new_vault_id().unwrap();
    let mut v = Vault::new("Docs", 10);
    v.add_file("a/b.txt", b"original".to_vec(), Some(1), Some(0o644))
        .unwrap();
    v.add_file("keep.txt", b"untouched".to_vec(), None, None)
        .unwrap();
    store.save_vault(&id, &vid, &v).unwrap();

    // Stage the replacement on disk, then replace via the streaming path.
    let src = tmp();
    std::fs::write(&src, b"rewritten and longer").unwrap();
    let reader = store.open_vault(&id, &vid).unwrap();
    store
        .replace_file_in_vault(&id, &vid, &reader, "a/b.txt", &src, Some(77), Some(0o600))
        .unwrap();

    // Reloaded vault has the new content + metadata; the sibling is intact.
    let v2 = store.load_vault(&id, &vid).unwrap();
    assert_eq!(
        &v2.get("a/b.txt").unwrap().content[..],
        b"rewritten and longer"
    );
    assert_eq!(v2.get("a/b.txt").unwrap().mtime, Some(77));
    assert_eq!(v2.get("a/b.txt").unwrap().mode, Some(0o600));
    assert_eq!(&v2.get("keep.txt").unwrap().content[..], b"untouched");

    // The atomic-rename temp file is gone.
    let tmp_vault = store
        .data_dir()
        .join("vaults")
        .join(format!("{vid}.fsec.tmp"));
    assert!(!tmp_vault.exists());

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn secure_wipe_removes_file_and_tolerates_absent() {
    let p = tmp();
    std::fs::write(&p, b"sensitive bytes").unwrap();
    assert!(p.exists());
    secure_wipe(&p).unwrap();
    assert!(!p.exists());
    // Wiping an already-absent path is a no-op success.
    secure_wipe(&p).unwrap();
}

#[test]
fn secure_wipe_handles_readonly_view_temp() {
    // A view temp is marked read-only; secure_wipe must still be able to
    // overwrite and remove it (it restores owner write first).
    let p = tmp();
    std::fs::write(&p, b"viewed copy").unwrap();
    make_readonly(&p).unwrap();
    assert!(std::fs::metadata(&p).unwrap().permissions().readonly());
    secure_wipe(&p).unwrap();
    assert!(!p.exists());
}

#[test]
fn create_private_checkout_file_is_hardened_and_keeps_only_the_extension() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    let path = store.create_private_checkout_file("notes.md").unwrap();
    assert!(path.exists());
    assert!(path.starts_with(store.checkout_dir()));
    let name = path.file_name().unwrap().to_str().unwrap();
    // Extension preserved so the OS opens it with the right application...
    assert!(name.ends_with(".md"), "{name}");
    // ...but the vault's own filename never touches the disk.
    assert!(
        !name.contains("notes"),
        "temp name {name} leaks the filename"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "checkout temp must be owner-only");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn clean_checkout_dir_removes_stale_files() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    let stale = store.create_private_checkout_file("leftover.txt").unwrap();
    std::fs::write(&stale, b"orphaned plaintext").unwrap();
    assert!(stale.exists());
    store.clean_checkout_dir();
    assert!(!stale.exists());
    // The directory itself remains for future checkouts.
    assert!(store.checkout_dir().exists());
    let _ = std::fs::remove_dir_all(&dir);
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

#[cfg(feature = "pqc")]
#[test]
fn migrate_classical_store_to_post_quantum() {
    use filesec_core::SuiteId;

    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    let pass = b"correct horse battery staple";

    // Start with a classical identity and a populated, classical-at-rest store.
    let old = Identity::generate("Alice", 0).unwrap();
    store
        .save_keystore(&KeystoreFile::create(&old, pass, fast_kdf()).unwrap())
        .unwrap();
    let vid = new_vault_id().unwrap();
    let mut v = Vault::new("Docs", 10);
    v.add_file("a/b.txt", b"hello".to_vec(), None, None)
        .unwrap();
    // A multi-chunk file so streaming re-encryption is exercised.
    let big: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
    v.add_file("big.bin", big.clone(), None, None).unwrap();
    store.save_vault(&old, &vid, &v).unwrap();
    let mut book = ContactBook::default();
    book.upsert(Identity::generate("Bob", 0).unwrap().public(), 0);
    store.save_contacts(&old, &book).unwrap();
    let mut reg = Registry::default();
    reg.upsert(VaultMeta {
        id: vid.clone(),
        name: "Docs".into(),
        created_at: 10,
        modified_at: 11,
        file_count: 2,
        total_size: big.len() as u64 + 5,
    });
    store.save_registry(&old, &reg).unwrap();

    // At rest, a classical identity stores under the classical suite.
    assert_eq!(
        store.open_vault(&old, &vid).unwrap().suite(),
        SuiteId::Classic
    );

    // Migrate.
    let new = store.migrate_to_hybrid(&old, pass, fast_kdf()).unwrap();
    assert!(new.is_hybrid_capable());
    assert_ne!(new.fingerprint(), old.fingerprint());

    // The keystore now unlocks to the new hybrid identity.
    let reloaded = store.load_keystore().unwrap().unlock(pass).unwrap();
    assert_eq!(reloaded.fingerprint(), new.fingerprint());
    assert!(reloaded.is_hybrid_capable());

    // Everything is readable by the new identity, content intact, and now stored
    // under the hybrid post-quantum suite at rest.
    assert_eq!(
        store.open_vault(&new, &vid).unwrap().suite(),
        SuiteId::Hybrid
    );
    let v2 = store.load_vault(&new, &vid).unwrap();
    assert_eq!(&v2.get("a/b.txt").unwrap().content[..], b"hello");
    assert_eq!(&v2.get("big.bin").unwrap().content[..], &big[..]);
    assert_eq!(store.load_registry(&new).unwrap().vaults.len(), 1);
    assert_eq!(store.load_contacts(&new).unwrap().contacts.len(), 1);

    // The old identity can no longer open the hardened store (its fingerprint
    // changed; the files are now addressed to the new one only).
    assert!(store.load_vault(&old, &vid).is_err());

    // A normal save under the new identity keeps it on the hybrid suite.
    store.save_registry(&new, &reg).unwrap();
    assert_eq!(
        store.open_vault(&new, &vid).unwrap().suite(),
        SuiteId::Hybrid
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// UI preferences — the one file the store keeps unencrypted, so the theme can be
// applied to the first frame (before there is an identity to decrypt with).
// ---------------------------------------------------------------------------

#[test]
fn prefs_default_when_absent_and_survive_a_restart() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();

    // Nothing written yet: follow the system, as every build before this did.
    assert_eq!(store.load_prefs(), Prefs::default());
    assert_eq!(store.load_prefs().theme, ThemeChoice::System);

    store
        .save_prefs(&Prefs {
            theme: ThemeChoice::Dark,
            ..Prefs::default()
        })
        .unwrap();

    // A *fresh* Store proves this came off disk rather than out of memory.
    let reopened = Store::at(&dir).unwrap();
    assert_eq!(reopened.load_prefs().theme, ThemeChoice::Dark);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join(".prefs"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "prefs file must be owner-only");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn every_theme_choice_survives_a_restart() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    for choice in ThemeChoice::ALL {
        store
            .save_prefs(&Prefs {
                theme: choice,
                ..Prefs::default()
            })
            .unwrap();
        assert_eq!(
            Store::at(&dir).unwrap().load_prefs().theme,
            choice,
            "{choice:?} did not survive"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn corrupt_or_future_prefs_fall_back_to_defaults() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();

    // Not CBOR at all.
    std::fs::write(dir.join(".prefs"), b"this is not cbor").unwrap();
    assert_eq!(store.load_prefs(), Prefs::default());

    // Valid CBOR, but written by a build whose format we cannot interpret.
    let future = filesec_core::codec::to_vec(&Prefs {
        version: 999,
        theme: ThemeChoice::Dark,
    })
    .unwrap();
    std::fs::write(dir.join(".prefs"), &future).unwrap();
    assert_eq!(store.load_prefs(), Prefs::default());

    // Empty file.
    std::fs::write(dir.join(".prefs"), b"").unwrap();
    assert_eq!(store.load_prefs(), Prefs::default());

    // A preference that cannot be read must never block the app: the store is
    // still fully usable afterwards.
    store
        .save_prefs(&Prefs {
            theme: ThemeChoice::Light,
            ..Prefs::default()
        })
        .unwrap();
    assert_eq!(store.load_prefs().theme, ThemeChoice::Light);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oversized_prefs_are_rejected_without_reading_them() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    std::fs::write(dir.join(".prefs"), vec![0u8; 128 * 1024]).unwrap();
    assert_eq!(store.load_prefs(), Prefs::default());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn corrupt_v2_vault_does_not_destroy_the_legacy_recovery_copy() {
    let dir = tmp();
    let store = Store::at(&dir).unwrap();
    let identity = Identity::generate("Owner", 1).unwrap();
    let id = new_vault_id().unwrap();
    let mut vault = Vault::new("Recovery", 1);
    vault
        .add_file("file.txt", b"recover me".to_vec(), None, None)
        .unwrap();
    store.save_vault(&identity, &id, &vault).unwrap();
    let legacy = dir.join("vaults").join(format!("{id}.fsec"));
    filesec_core::format::export_vault_to_path(
        &vault,
        &identity,
        &[identity.public()],
        &Default::default(),
        &legacy,
    )
    .unwrap();
    let original = std::fs::read(&legacy).unwrap();
    std::fs::write(
        dir.join("vaults")
            .join(format!("{id}.fsv2"))
            .join("manifest"),
        b"corrupt",
    )
    .unwrap();
    assert!(store.open_vault(&identity, &id).is_err());
    assert_eq!(std::fs::read(&legacy).unwrap(), original);
    std::fs::remove_dir_all(dir).unwrap();
}
