//! Journaled, resumable post-quantum identity migration (audit FS-03).
//!
//! Upgrading a classical identity to a hybrid one gives it a new fingerprint,
//! so every protected object — keystore, contacts, registry, each vault — must
//! be re-written for the new identity and re-anchored. The previous
//! implementation erased the old identity's high-water anchors first and then
//! rewrote objects in place; any failure in between left state that neither
//! identity could load, with no way to resume.
//!
//! The migration is now a transaction with one durable commit point:
//!
//! 1. **Validate** (no writes). The passphrase must open the current keystore
//!    and every object must load and pass its anchor check under the old
//!    identity. Unrecovered legacy vaults abort the upgrade.
//! 2. **Stage** (no live file touched). Complete new-identity copies of every
//!    object are written under `migration/` and re-opened to validate them.
//! 3. **Journal.** `migration/journal` lists each staged→live move and the
//!    anchor each staged state must receive.
//! 4. **Commit.** A [`MigrationRecord`] binding the journal's BLAKE3 hash is
//!    written into the anchor backend's root record (one keychain write, or one
//!    atomic file write in degraded mode). Before this point a crash leaves the
//!    old state and *all* of its anchors untouched, and the staging directory is
//!    discarded on the next open. After it, the migration always completes.
//! 5. **Apply** (idempotent). Each live object is moved aside into
//!    `migration/old/`, its staged replacement moved into place, and the
//!    journal's anchors installed.
//! 6. **Finish.** The record is cleared and `migration/` (old copies included)
//!    is securely wiped.
//!
//! [`Store::at`] resumes a committed migration before anything else can load
//! state, so an interruption at any step yields either the complete old store
//! or the complete new one.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use filesec_core::state::StateAnchor;

use super::{err, read_bounded_file, secure_wipe, AnchorBackend, Store, StoreResult};

/// Stable prefix of the error that means an identity migration reached its
/// commit point but has not finished applying. Nothing is lost: reopening the
/// store (restarting FileSec) completes it.
pub const MIGRATION_RESUME_PENDING: &str =
    "the post-quantum upgrade was committed but has not finished";

/// Staging area for a migration, relative to the data directory.
pub(super) const MIGRATION_DIR: &str = "migration";
const JOURNAL_FILE: &str = "journal";
const OLD_COPIES_DIR: &str = "old";
const JOURNAL_VERSION: u16 = 1;
const RECORD_VERSION: u16 = 1;
const MAX_JOURNAL_LEN: u64 = 16 * 1024 * 1024;

/// Commitment to a migration journal, held by the anchor backend (outside the
/// data directory when that backend is the OS secure store). Its presence is
/// the migration's commit point.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MigrationRecord {
    version: u16,
    old_fingerprint: [u8; 32],
    new_fingerprint: [u8; 32],
    journal_hash: [u8; 32],
}

/// Everything needed to finish a committed migration without any secret.
#[derive(Serialize, Deserialize)]
struct MigrationJournal {
    version: u16,
    old_fingerprint: [u8; 32],
    new_fingerprint: [u8; 32],
    /// `(staged, live)` paths relative to the data directory, in apply order.
    moves: Vec<(String, String)>,
    /// The high-water anchor each staged state receives once it is live.
    anchors: Vec<StateAnchor>,
}

#[cfg(test)]
thread_local! {
    /// Test-only fault injection: the named step fails as if the process had
    /// crashed there (no cleanup runs).
    pub(super) static FAULT: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

/// A simulated crash at `step`. Compiled to nothing outside unit tests.
fn fault(step: &str) -> StoreResult<()> {
    #[cfg(test)]
    if FAULT.with(|f| f.borrow().as_deref() == Some(step)) {
        return Err(format!("injected fault at {step}"));
    }
    let _ = step;
    Ok(())
}

/// Whether `rel` is a live path a migration may replace: the keystore, the
/// contact book, the registry, or one v2 vault directory.
fn is_migratable_live_path(rel: &str) -> bool {
    if matches!(
        rel,
        super::KEYSTORE_FILE | super::CONTACTS_FILE | super::INDEX_FILE
    ) {
        return true;
    }
    rel.strip_prefix("vaults/")
        .and_then(|leaf| leaf.strip_suffix(".fsv2"))
        .is_some_and(|id| {
            !id.is_empty()
                && id.len() <= 64
                && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

fn sync_dir(path: &Path) {
    if let Ok(dir) = std::fs::File::open(path) {
        let _ = dir.sync_all();
    }
}

impl Store {
    fn migration_dir(&self) -> PathBuf {
        self.data_dir.join(MIGRATION_DIR)
    }

    /// The committed-but-unfinished migration recorded in the anchor backend.
    fn migration_record(&self) -> StoreResult<Option<MigrationRecord>> {
        let _guard = self
            .lock
            .anchors
            .lock()
            .map_err(|_| "state anchor lock is unavailable".to_string())?;
        match self.anchor_backend {
            AnchorBackend::SecureStorage => {
                let Some(bytes) = self
                    .secure_storage()?
                    .load(&self.anchor_account)
                    .map_err(|e| format!("could not read rollback anchors: {e}"))?
                else {
                    return Ok(None);
                };
                let root: super::AnchorRoot =
                    filesec_core::codec::from_slice(&bytes).map_err(err)?;
                Ok(root.migration)
            }
            AnchorBackend::DegradedFile => Ok(self.load_file_anchor_set_locked()?.migration),
        }
    }

    /// Record (or clear) the migration commitment in a single backend write.
    fn set_migration_record(&self, record: Option<&MigrationRecord>) -> StoreResult<()> {
        let _guard = self
            .lock
            .anchors
            .lock()
            .map_err(|_| "state anchor lock is unavailable".to_string())?;
        match self.anchor_backend {
            AnchorBackend::SecureStorage => {
                let bytes = filesec_core::codec::to_vec(&super::AnchorRoot {
                    version: super::ANCHOR_ROOT_VERSION,
                    migration: record.cloned(),
                })
                .map_err(err)?;
                self.secure_storage()?
                    .save(&self.anchor_account, &bytes)
                    .map_err(|e| format!("could not save rollback anchors: {e}"))
            }
            AnchorBackend::DegradedFile => {
                let mut set = self.load_file_anchor_set_locked()?;
                set.migration = record.cloned();
                self.save_file_anchor_set_locked(&set)
            }
        }
    }

    /// Securely wipe the migration staging area (staged copies, old copies,
    /// and the journal). Only ever called when no committed record needs it.
    fn discard_migration_dir(&self) {
        let dir = self.migration_dir();
        if !exists(&dir) {
            return;
        }
        for entry in walkdir::WalkDir::new(&dir)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            if entry.file_type().is_file() || entry.file_type().is_symlink() {
                let _ = secure_wipe(entry.path());
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Called by [`Store::at`] before any state is loaded: finish a committed
    /// migration, or discard the staging left by one that never committed.
    pub(super) fn resume_identity_migration(&self) -> StoreResult<()> {
        match self.migration_record()? {
            Some(record) => self
                .finish_migration(&record)
                .map_err(|e| format!("{MIGRATION_RESUME_PENDING}: {e}")),
            None => {
                self.discard_migration_dir();
                Ok(())
            }
        }
    }

    /// Apply and finish a committed migration. Idempotent: every step checks
    /// what an earlier, interrupted run already did.
    fn finish_migration(&self, record: &MigrationRecord) -> StoreResult<()> {
        let root = self.migration_dir();
        let bytes = read_bounded_file(
            &root.join(JOURNAL_FILE),
            MAX_JOURNAL_LEN,
            "migration journal",
        )?;
        if *blake3::hash(&bytes).as_bytes() != record.journal_hash {
            return Err("the migration journal does not match its committed record".into());
        }
        let journal: MigrationJournal = filesec_core::codec::from_slice(&bytes).map_err(err)?;
        if journal.version != JOURNAL_VERSION
            || record.version != RECORD_VERSION
            || journal.old_fingerprint != record.old_fingerprint
            || journal.new_fingerprint != record.new_fingerprint
        {
            return Err("unsupported or inconsistent migration journal".into());
        }
        let old_copies = root.join(OLD_COPIES_DIR);
        std::fs::create_dir_all(&old_copies).map_err(err)?;
        for (index, (staged_rel, live_rel)) in journal.moves.iter().enumerate() {
            if !is_migratable_live_path(live_rel)
                || *staged_rel != format!("{MIGRATION_DIR}/{live_rel}")
            {
                return Err("the migration journal names an unexpected path".into());
            }
            fault(&format!("apply:{index}"))?;
            let staged = self.data_dir.join(staged_rel);
            let live = self.data_dir.join(live_rel);
            let leaf = live_rel.replace('/', "-");
            let old_copy = old_copies.join(format!("{index}-{leaf}"));
            match (exists(&staged), exists(&live), exists(&old_copy)) {
                (true, true, false) => {
                    std::fs::rename(&live, &old_copy).map_err(err)?;
                    std::fs::rename(&staged, &live).map_err(err)?;
                }
                (true, false, _) => std::fs::rename(&staged, &live).map_err(err)?,
                (false, true, _) => {}
                (true, true, true) => {
                    return Err(format!("migration state for {live_rel} is inconsistent"))
                }
                (false, false, _) => {
                    return Err(format!("migrated {live_rel} is missing"));
                }
            }
        }
        sync_dir(&self.data_dir);
        sync_dir(&self.vaults_dir);
        fault("anchors")?;
        {
            let _guard = self
                .lock
                .anchors
                .lock()
                .map_err(|_| "state anchor lock is unavailable".to_string())?;
            for anchor in &journal.anchors {
                if anchor.identity_fingerprint != journal.new_fingerprint {
                    return Err("the migration journal anchors another identity".into());
                }
                self.put_anchor_locked(anchor)?;
            }
        }
        fault("finish")?;
        self.set_migration_record(None)?;
        self.discard_migration_dir();
        Ok(())
    }
}

#[cfg(feature = "pqc")]
mod upgrade {
    use super::*;

    use serde::de::DeserializeOwned;

    use filesec_core::contacts::ContactBook;
    use filesec_core::format_v2::VaultReaderV2;
    use filesec_core::identity::Identity;
    use filesec_core::keystore::KeystoreFile;
    use filesec_core::state::{StateMetadata, StateObjectType};

    use super::super::{
        self_suite, write_private_atomic, ProtectedState, Registry, CONTACTS_BLOB, CONTACTS_FILE,
        INDEX_FILE, KEYSTORE_FILE, MAX_KEYSTORE_FILE_LEN, PROTECTED_STATE_VERSION, REGISTRY_BLOB,
    };

    impl Store {
        /// Migrate a classical identity to a hybrid (post-quantum) one,
        /// re-encrypting the entire local store to the new identity. Returns the
        /// new identity.
        ///
        /// `passphrase` must be the current keystore passphrase: it is verified
        /// against the existing keystore before anything is written, and it
        /// stays the passphrase afterwards (FS-02). The re-sealed keystore keeps
        /// every passkey and device-unlock slot.
        ///
        /// Crash-safe and resumable (FS-03; see the [module docs](self)): until
        /// the single commit write, the old store and all of its anchors are
        /// untouched; after it, the migration completes — here, or on the next
        /// [`Store::at`] if this process cannot finish (the error then starts
        /// with [`MIGRATION_RESUME_PENDING`]).
        ///
        /// The new identity has a **new fingerprint** — the caller must re-share
        /// its public key and have contacts re-verify the new safety number. Any
        /// `.fsec` addressed to the *old* fingerprint that has not been imported
        /// yet should be imported before migrating.
        pub fn migrate_to_hybrid(
            &self,
            old: &Identity,
            passphrase: &[u8],
        ) -> StoreResult<Identity> {
            if old.is_hybrid_capable() {
                return Err("this identity is already post-quantum".to_string());
            }
            self.exclusively(|| self.migrate_to_hybrid_exclusive(old, passphrase))
        }

        fn migrate_to_hybrid_exclusive(
            &self,
            old: &Identity,
            passphrase: &[u8],
        ) -> StoreResult<Identity> {
            if self.migration_record()?.is_some() {
                return Err(format!(
                    "{MIGRATION_RESUME_PENDING}; restart FileSec to complete it"
                ));
            }
            let new = old.upgraded_to_hybrid().map_err(err)?;

            // 1. Validate. Nothing is written before every object authenticates.
            let resealed = self
                .load_keystore()?
                .continue_identity(passphrase, old, &new)
                .map_err(err)?;
            fault("validate")?;
            let contacts = self.load_contacts(old)?;
            let registry = self.load_registry(old)?;
            if let Some(id) = self.unrecovered_legacy_vaults().first() {
                return Err(format!(
                    "legacy vault {id} must be recovered before upgrading"
                ));
            }
            let mut vaults = Vec::new();
            for (id, _) in self.v2_vaults() {
                let reader = self
                    .open_vault(old, &id)
                    .map_err(|e| format!("vault {id} must open before upgrading: {e}"))?;
                vaults.push((id, reader));
            }

            // 2–3. Stage and journal. A failure here discards the staging; the
            // old store was never touched.
            self.discard_migration_dir();
            let journal = self
                .stage_migration(old, &new, &resealed, &contacts, &registry, &vaults)
                .inspect_err(|_| self.abandon_uncommitted())?;
            drop(vaults);

            // 4. Commit.
            let bytes = filesec_core::codec::to_vec(&journal).map_err(err)?;
            let record = MigrationRecord {
                version: RECORD_VERSION,
                old_fingerprint: journal.old_fingerprint,
                new_fingerprint: journal.new_fingerprint,
                journal_hash: *blake3::hash(&bytes).as_bytes(),
            };
            let committed = fault("journal")
                .and_then(|()| {
                    write_private_atomic(
                        Path::new(""),
                        &self.migration_dir().join(JOURNAL_FILE),
                        &bytes,
                    )
                })
                .and_then(|()| fault("commit"))
                .and_then(|()| self.set_migration_record(Some(&record)));
            committed.inspect_err(|_| self.abandon_uncommitted())?;

            // 5–6. Apply and finish.
            self.finish_migration(&record).map_err(|e| {
                format!("{MIGRATION_RESUME_PENDING} ({e}); restart FileSec to complete it")
            })?;
            Ok(new)
        }

        /// Clean up after a failure before the commit point. The old store was
        /// never touched, so only the staging goes. (Unit tests inject faults as
        /// simulated crashes, so there the cleanup is left to the next open,
        /// exactly as after a real crash.)
        fn abandon_uncommitted(&self) {
            #[cfg(not(test))]
            self.discard_migration_dir();
        }

        /// Legacy `vaults/<id>.fsec` containers with no committed v2 directory.
        fn unrecovered_legacy_vaults(&self) -> Vec<String> {
            let mut ids = Vec::new();
            if let Ok(rd) = std::fs::read_dir(&self.vaults_dir) {
                for entry in rd.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if let Some(id) = name.strip_suffix(".fsec") {
                        if !self.vault_dir_v2(id).exists() {
                            ids.push(id.to_string());
                        }
                    }
                }
            }
            ids.sort();
            ids
        }

        /// Write complete new-identity copies of every object under
        /// `migration/`, re-open each to validate it, and return the journal.
        fn stage_migration(
            &self,
            old: &Identity,
            new: &Identity,
            resealed: &KeystoreFile,
            contacts: &ContactBook,
            registry: &Registry,
            vaults: &[(String, VaultReaderV2)],
        ) -> StoreResult<MigrationJournal> {
            let root = self.migration_dir();
            std::fs::create_dir_all(root.join("vaults")).map_err(err)?;
            super::super::harden_dir(&root);
            let mut moves = Vec::new();
            let mut anchors = Vec::new();

            fault("stage:keystore")?;
            let ks_state = resealed
                .state_metadata()
                .cloned()
                .ok_or_else(|| "re-sealed keystore has no state".to_string())?;
            let staged = root.join(KEYSTORE_FILE);
            write_private_atomic(Path::new(""), &staged, &resealed.to_bytes().map_err(err)?)?;
            let check = KeystoreFile::from_bytes(&read_bounded_file(
                &staged,
                MAX_KEYSTORE_FILE_LEN,
                "staged keystore",
            )?)
            .map_err(err)?;
            if check.state_metadata() != Some(&ks_state) {
                return Err("staged keystore failed validation".into());
            }
            moves.push(staged_move(KEYSTORE_FILE));
            anchors.push(StateAnchor::from_metadata(&ks_state));

            fault("stage:contacts")?;
            let state = self.stage_protected(
                new,
                &root.join(CONTACTS_FILE),
                CONTACTS_BLOB,
                StateObjectType::Contacts,
                "contacts",
                contacts,
            )?;
            moves.push(staged_move(CONTACTS_FILE));
            anchors.push(StateAnchor::from_metadata(&state));

            fault("stage:registry")?;
            let state = self.stage_protected(
                new,
                &root.join(INDEX_FILE),
                REGISTRY_BLOB,
                StateObjectType::Registry,
                "registry",
                registry,
            )?;
            moves.push(staged_move(INDEX_FILE));
            anchors.push(StateAnchor::from_metadata(&state));

            for (id, current) in vaults {
                fault("stage:vault")?;
                let live = format!("vaults/{id}.fsv2");
                let staged = root.join(&live);
                // Stream the re-key blob-by-blob straight from the open source,
                // so a multi-GB vault never materializes in RAM.
                let state = VaultReaderV2::from_reader_v2_with_object_id(
                    &staged,
                    new,
                    self_suite(new),
                    current,
                    id,
                )
                .map_err(err)?
                .state_metadata()
                .cloned()
                .ok_or_else(|| format!("staged vault {id} has no state"))?;
                let check = VaultReaderV2::open(&staged, new).map_err(err)?;
                if check.state_metadata() != Some(&state)
                    || check.entries().len() != current.entries().len()
                {
                    return Err(format!("staged vault {id} failed validation"));
                }
                moves.push(staged_move(&live));
                anchors.push(StateAnchor::from_metadata(&state));
            }
            Ok(MigrationJournal {
                version: JOURNAL_VERSION,
                old_fingerprint: old.fingerprint(),
                new_fingerprint: new.fingerprint(),
                moves,
                anchors,
            })
        }

        /// Write `payload` as a fresh (epoch 1) protected record for `identity`
        /// at a staging `path`, then read it back through the normal
        /// authentication path.
        fn stage_protected<T: Serialize + DeserializeOwned>(
            &self,
            identity: &Identity,
            path: &Path,
            entry_name: &str,
            object_type: StateObjectType,
            object_id: &str,
            payload: &T,
        ) -> StoreResult<StateMetadata> {
            let payload_bytes = filesec_core::codec::to_vec(payload).map_err(err)?;
            let state = StateMetadata::next(
                identity.fingerprint(),
                object_type,
                object_id,
                self_suite(identity).to_u16(),
                None,
                &payload_bytes,
            )
            .map_err(err)?;
            let record = ProtectedState {
                version: PROTECTED_STATE_VERSION,
                state: state.clone(),
                payload,
            };
            let bytes = filesec_core::codec::to_vec(&record).map_err(err)?;
            self.save_blob(identity, path, entry_name, &bytes)?;
            let check = self
                .read_protected_record::<T>(identity, path, entry_name, object_type, object_id)?
                .ok_or_else(|| format!("staged {object_type} is missing"))?;
            if check.state != state {
                return Err(format!("staged {object_type} failed validation"));
            }
            Ok(state)
        }
    }

    fn staged_move(live: &str) -> (String, String) {
        (format!("{MIGRATION_DIR}/{live}"), live.to_string())
    }
}

#[cfg(all(test, feature = "pqc"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use filesec_core::contacts::ContactBook;
    use filesec_core::identity::Identity;
    use filesec_core::kdf::KdfParams;
    use filesec_core::keystore::KeystoreFile;
    use filesec_core::vault::Vault;
    use filesec_core::SuiteId;

    use super::*;
    use crate::anchors::{MemoryAnchorStorage, SecureAnchorStorage};
    use crate::store::{new_vault_id, Registry, VaultMeta};

    const PASS: &[u8] = b"correct horse battery staple";
    const PRE_COMMIT: &[&str] = &[
        "validate",
        "stage:keystore",
        "stage:contacts",
        "stage:registry",
        "stage:vault",
        "journal",
        "commit",
    ];
    // Moves run keystore, contacts, registry, then each vault: `apply:1` is a
    // crash after the new keystore is live but before anything else moved.
    const POST_COMMIT: &[&str] = &[
        "apply:0", "apply:1", "apply:2", "apply:3", "apply:4", "anchors", "finish",
    ];

    struct Fixture {
        dir: PathBuf,
        secure: Option<Arc<MemoryAnchorStorage>>,
        old: Identity,
        vaults: Vec<String>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn inject(step: Option<&str>) {
        FAULT.with(|f| *f.borrow_mut() = step.map(str::to_string));
    }

    fn open(f: &Fixture) -> StoreResult<Store> {
        let secure = f
            .secure
            .clone()
            .map(|s| -> Arc<dyn SecureAnchorStorage> { s });
        Store::at_with_secure_storage(&f.dir, secure)
    }

    fn fixture(secure_backend: bool) -> Fixture {
        let suffix = filesec_core::util::hex(&filesec_core::secret::random_array::<8>().unwrap());
        let mut f = Fixture {
            dir: std::env::temp_dir().join(format!("filesec-migration-unit-{suffix}")),
            secure: secure_backend.then(|| Arc::new(MemoryAnchorStorage::new())),
            old: Identity::generate("Alice", 0).unwrap(),
            vaults: Vec::new(),
        };
        let store = open(&f).unwrap();
        let kdf = KdfParams {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        store
            .save_keystore(&KeystoreFile::create(&f.old, PASS, kdf).unwrap())
            .unwrap();
        let mut book = ContactBook::default();
        book.upsert(Identity::generate("Bob", 0).unwrap().public(), 1);
        store.save_contacts(&f.old, &book).unwrap();
        let mut registry = Registry::default();
        for n in 0..2 {
            let id = new_vault_id().unwrap();
            let mut vault = Vault::new(format!("Vault {n}"), 1);
            vault
                .add_file("doc.txt", format!("content {n}").into_bytes(), None, None)
                .unwrap();
            store.save_vault(&f.old, &id, &vault).unwrap();
            registry.upsert(VaultMeta {
                id: id.clone(),
                name: format!("Vault {n}"),
                created_at: 1,
                modified_at: 1,
                file_count: 1,
                total_size: 9,
            });
            f.vaults.push(id);
        }
        store.save_registry(&f.old, &registry).unwrap();
        f
    }

    fn assert_complete(store: &Store, f: &Fixture, identity: &Identity, suite: SuiteId) {
        assert!(!f.dir.join(MIGRATION_DIR).exists(), "staging must be gone");
        assert_eq!(store.load_contacts(identity).unwrap().contacts.len(), 1);
        assert_eq!(store.load_registry(identity).unwrap().vaults.len(), 2);
        for (n, id) in f.vaults.iter().enumerate() {
            assert_eq!(store.open_vault(identity, id).unwrap().suite(), suite);
            let vault = store.load_vault(identity, id).unwrap();
            assert_eq!(
                &vault.get("doc.txt").unwrap().content[..],
                format!("content {n}").as_bytes()
            );
        }
    }

    fn unlocked(store: &Store) -> Identity {
        store.load_keystore().unwrap().unlock(PASS).unwrap()
    }

    #[test]
    fn a_crash_before_the_commit_point_leaves_the_old_store_and_anchors_intact() {
        for secure_backend in [true, false] {
            for step in PRE_COMMIT {
                let f = fixture(secure_backend);
                let store = open(&f).unwrap();
                inject(Some(step));
                let result = store.migrate_to_hybrid(&f.old, PASS);
                inject(None);
                assert!(result.is_err(), "{step}");
                drop(store);

                let store = open(&f).unwrap();
                let identity = unlocked(&store);
                assert_eq!(identity.fingerprint(), f.old.fingerprint(), "{step}");
                assert_complete(&store, &f, &f.old, SuiteId::Classic);

                // The upgrade can simply be retried.
                let new = store.migrate_to_hybrid(&f.old, PASS).unwrap();
                assert_complete(&store, &f, &new, SuiteId::Hybrid);
            }
        }
    }

    #[test]
    fn a_crash_after_the_commit_point_completes_on_the_next_open() {
        for secure_backend in [true, false] {
            for step in POST_COMMIT {
                let f = fixture(secure_backend);
                let store = open(&f).unwrap();
                inject(Some(step));
                let error = store
                    .migrate_to_hybrid(&f.old, PASS)
                    .err()
                    .expect("injected fault");
                inject(None);
                assert!(
                    error.starts_with(MIGRATION_RESUME_PENDING),
                    "{step}: {error}"
                );
                // A second attempt in the same process is refused, not stacked.
                let again = store.migrate_to_hybrid(&f.old, PASS).err().unwrap();
                assert!(again.starts_with(MIGRATION_RESUME_PENDING), "{step}");
                drop(store);

                let store = open(&f).unwrap();
                let new = unlocked(&store);
                assert_ne!(new.fingerprint(), f.old.fingerprint(), "{step}");
                assert!(new.is_hybrid_capable());
                assert_complete(&store, &f, &new, SuiteId::Hybrid);
                assert!(store.load_contacts(&f.old).is_err(), "{step}");
            }
        }
    }

    #[test]
    fn a_tampered_journal_is_never_applied() {
        let f = fixture(true);
        let store = open(&f).unwrap();
        inject(Some("apply:0"));
        assert!(store.migrate_to_hybrid(&f.old, PASS).is_err());
        inject(None);
        drop(store);
        let journal = f.dir.join(MIGRATION_DIR).join(JOURNAL_FILE);
        let mut bytes = std::fs::read(&journal).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&journal, bytes).unwrap();
        let error = open(&f).err().expect("tampered journal must not apply");
        assert!(error.starts_with(MIGRATION_RESUME_PENDING), "{error}");
        assert!(error.contains("does not match"), "{error}");
    }

    #[test]
    fn journal_paths_are_restricted_to_migratable_objects() {
        for ok in [
            "keystore.fsk",
            "contacts.fsec",
            "index.fsec",
            "vaults/ab12.fsv2",
        ] {
            assert!(is_migratable_live_path(ok), "{ok}");
        }
        for bad in [
            "../keystore.fsk",
            "vaults/../../x.fsv2",
            "vaults/.fsv2",
            "prefs",
            "vaults/a/b.fsv2",
            "/etc/passwd",
        ] {
            assert!(!is_migratable_live_path(bad), "{bad}");
        }
    }
}
