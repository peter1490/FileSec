//! On-disk persistence for the desktop app.
//!
//! Everything except the passphrase-protected keystore is stored as a FileSec
//! container encrypted to the user's own identity, so vault names, the contact
//! list, and the vault registry are all confidential at rest — not just file
//! contents. Files are created with restrictive permissions where the OS
//! supports it.

use std::cell::Cell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use filesec_core::contacts::ContactBook;
use filesec_core::format::{self, ExportOptions};
use filesec_core::format_v2::VaultReaderV2;
use filesec_core::identity::Identity;
use filesec_core::keystore::KeystoreFile;
use filesec_core::manifest::EntryKind;
use filesec_core::state::{StateAnchor, StateMetadata, StateObjectType};
use filesec_core::util::now_unix;
use filesec_core::vault::Vault;
use filesec_core::SuiteId;

use crate::anchors::SecureAnchorStorage;
use crate::prefs::Prefs;

mod migration;
use migration::MigrationRecord;
pub use migration::MIGRATION_RESUME_PENDING;

/// The algorithm suite the local at-rest store encrypts itself under for
/// `identity`. The suite **tracks the identity**: a hybrid (post-quantum)
/// identity stores its vaults, contacts, and registry under the hybrid suite
/// (`0x0101`), so the local store gets post-quantum protection at rest; a
/// classical identity stays on the classical default (`0x0001`).
fn self_suite(identity: &Identity) -> SuiteId {
    #[cfg(feature = "pqc")]
    if identity.is_hybrid_capable() {
        return SuiteId::Hybrid;
    }
    let _ = identity;
    SuiteId::Classic
}

/// [`ExportOptions`] for encrypting a store file to `identity` itself.
fn self_options(identity: &Identity) -> ExportOptions {
    ExportOptions {
        suite: self_suite(identity),
        ..ExportOptions::default()
    }
}

const KEYSTORE_FILE: &str = "keystore.fsk";
const CONTACTS_FILE: &str = "contacts.fsec";
const INDEX_FILE: &str = "index.fsec";
const REGISTRY_BLOB: &str = "registry";
const CONTACTS_BLOB: &str = "contacts";
const MAX_KEYSTORE_FILE_LEN: u64 = 16 * 1024 * 1024;
const MAX_SELF_BLOB_CONTAINER_LEN: u64 = 64 * 1024 * 1024;
const MAX_SELF_BLOB_PLAINTEXT_LEN: u64 = 16 * 1024 * 1024;
const PROTECTED_STATE_VERSION: u16 = 1;
/// The keystore's fixed state object id (see `filesec_core::keystore`).
const KEYSTORE_OBJECT_ID: &str = "identity-keystore";
/// Version of the degraded `.state-anchors` file (and of the legacy single
/// secure-storage record that held every anchor in one blob).
const ANCHORS_VERSION: u16 = 1;
/// Version of the per-store root record in secure storage. Its presence
/// establishes the store as secure-anchored; anchors themselves live in one
/// bounded record per object (FS-06).
const ANCHOR_ROOT_VERSION: u16 = 2;
/// Version of one per-object anchor record in secure storage.
const OBJECT_ANCHOR_VERSION: u16 = 1;
/// Upper bound for any single secure-storage record. Windows Credential
/// Manager rejects a `CredentialBlob` over 2,560 bytes; one object anchor is
/// roughly 250 bytes, so this leaves ample margin and turns any future growth
/// into a clear error instead of a platform failure.
const MAX_SECURE_ANCHOR_RECORD: usize = 2048;
/// Longest object id accepted into an anchor (vault ids are 32 hex chars).
const MAX_ANCHOR_OBJECT_ID: usize = 128;
const ANCHORS_FILE: &str = ".state-anchors";
const ANCHORS_BACKEND_FILE: &str = ".state-anchor-backend";
const QUARANTINE_DIR: &str = "quarantine";
const BACKEND_MARKER_SECURE: &str = "secure-v1";
const BACKEND_MARKER_DEGRADED: &str = "degraded-v1";
const MAX_BACKEND_MARKER_LEN: u64 = 64;

/// Stable prefix of every error that means "the rollback-anchor backend cannot
/// be trusted as found and needs the explicit, passphrase-authenticated
/// [`Store::recover_rollback_anchors`] flow". The GUI matches on it to offer
/// that recovery instead of a dead-end error screen.
pub const ANCHOR_RECOVERY_REQUIRED: &str = "rollback-protection anchors need recovery";

/// Stable prefix of the error returned when another FileSec process already has
/// this data directory open (FS-05: one active writer per store).
pub const STORE_IN_USE: &str = "this FileSec data directory is already in use";

/// Stable prefix of the error returned when a mutation was based on a vault
/// state that is no longer current (another operation committed first).
pub const STALE_STATE: &str = "this vault changed since it was opened";

/// Advisory lock file marking the data directory as in use by one process.
const LOCK_FILE: &str = ".lock";

/// Store locks currently held by this process, by canonical data directory.
/// Several [`Store`] values for one directory share one OS lock and one set of
/// transaction locks; a second process is refused.
static STORE_LOCKS: OnceLock<Mutex<HashMap<PathBuf, Weak<StoreLock>>>> = OnceLock::new();

fn store_locks() -> &'static Mutex<HashMap<PathBuf, Weak<StoreLock>>> {
    STORE_LOCKS.get_or_init(Default::default)
}

/// The single-writer guard for one data directory (audit FS-05).
///
/// The OS-level exclusive lock on [`LOCK_FILE`] is held for as long as any
/// `Store` for the directory lives in this process, so two FileSec processes
/// (for example the standard and the post-quantum build, which share a data
/// directory) can never interleave reads, state-file commits, and anchor
/// updates. Within the process, each protected object has its own transaction
/// lock held across the whole read → candidate → file commit → anchor update
/// sequence, and anchor storage itself is read-modify-written under `anchors`.
struct StoreLock {
    path: PathBuf,
    file: Option<std::fs::File>,
    /// Shared by every ordinary transaction; taken exclusively by operations
    /// that must see and change the whole store at once (identity migration).
    exclusive: RwLock<()>,
    anchors: Mutex<()>,
    objects: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

thread_local! {
    /// Set while this thread holds a store's `exclusive` lock for writing, so
    /// the transactions it runs inside don't try to re-take it for reading.
    static EXCLUSIVE_HELD: Cell<bool> = const { Cell::new(false) };
}

/// Clears [`EXCLUSIVE_HELD`] when an exclusive section ends, however it ends.
#[cfg_attr(not(feature = "pqc"), allow(dead_code))]
struct ExclusiveFlag;

impl Drop for ExclusiveFlag {
    fn drop(&mut self) {
        EXCLUSIVE_HELD.with(|held| held.set(false));
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        // Release the OS lock and forget the entry atomically with respect to
        // `acquire_store_lock`, so a store reopened right after the last one
        // closes never races its own predecessor's file handle.
        let held = store_locks().lock();
        drop(self.file.take());
        if let Ok(mut held) = held {
            if held
                .get(&self.path)
                .is_some_and(|weak| weak.strong_count() == 0)
            {
                held.remove(&self.path);
            }
        }
    }
}

fn open_lock_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// How long a contended lock is retried before the store is reported in use.
const LOCK_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

/// Try the exclusive lock, retrying for [`LOCK_GRACE`]. A process that really
/// holds the store keeps it far longer; the grace only absorbs transient holds —
/// a previous FileSec instance that is still exiting, or a child process that
/// briefly inherited the lock descriptor between fork and exec.
fn try_lock_with_grace(file: &std::fs::File) -> std::io::Result<bool> {
    let deadline = std::time::Instant::now() + LOCK_GRACE;
    loop {
        if fs4::fs_std::FileExt::try_lock_exclusive(file)? {
            return Ok(true);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

fn acquire_store_lock(canonical: &Path) -> StoreResult<Arc<StoreLock>> {
    loop {
        let mut held = store_locks()
            .lock()
            .map_err(|_| "store lock registry is unavailable".to_string())?;
        if let Some(weak) = held.get(canonical) {
            if let Some(lock) = weak.upgrade() {
                return Ok(lock);
            }
            // The last `Store` is mid-drop; its `Drop` removes the entry under
            // this mutex. Let it finish rather than racing its file handle.
            drop(held);
            std::thread::yield_now();
            continue;
        }
        let file = open_lock_file(&canonical.join(LOCK_FILE))
            .map_err(|e| format!("could not open the data directory lock: {e}"))?;
        match try_lock_with_grace(&file) {
            Ok(true) => {}
            Ok(false) => {
                return Err(format!(
                    "{STORE_IN_USE} by another FileSec window ({}). Close it first; two \
                     processes writing the same store could fork its rollback-protected state.",
                    canonical.display()
                ))
            }
            Err(e) => {
                return Err(format!(
                    "could not lock the data directory {}: {e}",
                    canonical.display()
                ))
            }
        }
        let lock = Arc::new(StoreLock {
            path: canonical.to_path_buf(),
            file: Some(file),
            exclusive: RwLock::new(()),
            anchors: Mutex::new(()),
            objects: Mutex::new(HashMap::new()),
        });
        held.insert(canonical.to_path_buf(), Arc::downgrade(&lock));
        return Ok(lock);
    }
}
/// Unencrypted UI preferences. Dot-prefixed like the other non-container files.
/// See [`crate::prefs`] for why this one is deliberately not encrypted.
const PREFS_FILE: &str = ".prefs";
const PREFS_TMP_FILE: &str = ".prefs.tmp";
const MAX_PREFS_FILE_LEN: u64 = 64 * 1024;

/// Quality of the independent high-water anchor backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorProtection {
    /// Anchors are held by the platform keychain/credential manager.
    SecureStorage,
    /// Anchors are stored as a private local file and can be rolled back along
    /// with the data directory. Object-only restores remain detectable, but a
    /// whole-directory restore requires careful manual recovery.
    DegradedFile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnchorBackend {
    SecureStorage,
    DegradedFile,
}

/// The degraded file's anchor set, and the legacy (pre-FS-06) secure-storage
/// layout that kept every anchor in a single, unboundedly growing record.
#[derive(Default, Serialize, Deserialize)]
struct AnchorSet {
    version: u16,
    anchors: Vec<StateAnchor>,
    /// A committed, not yet finished identity migration (FS-03).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    migration: Option<MigrationRecord>,
}

/// The per-store root record in secure storage (`version` 2). Bounded: it
/// never lists objects.
#[derive(Serialize, Deserialize)]
struct AnchorRoot {
    version: u16,
    /// A committed, not yet finished identity migration (FS-03). Bounded:
    /// the record is a fixed-size commitment to the journal in the data
    /// directory, never the journal itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    migration: Option<MigrationRecord>,
}

/// Reads just the `version` of any anchor record, ignoring other fields.
#[derive(Deserialize)]
struct AnchorVersionProbe {
    version: u16,
}

/// One object's high-water anchor in secure storage.
#[derive(Serialize, Deserialize)]
struct ObjectAnchorRecord {
    version: u16,
    anchor: StateAnchor,
}

/// The terminal high-water mark of a deleted vault: no state can ever be its
/// successor, so a restored copy of the deleted directory is refused as a
/// rollback (and quarantined) instead of silently reappearing (FS-11).
fn deleted_vault_anchor(identity: &Identity, id: &str) -> StateAnchor {
    StateAnchor {
        identity_fingerprint: identity.fingerprint(),
        object_type: StateObjectType::VaultManifest,
        object_id: id.to_string(),
        suite_id: 0,
        epoch: u64::MAX,
        current_state_hash: [0xff; 32],
    }
}

fn object_tag(object_type: StateObjectType) -> &'static str {
    match object_type {
        StateObjectType::Keystore => "keystore",
        StateObjectType::Contacts => "contacts",
        StateObjectType::Registry => "registry",
        StateObjectType::VaultManifest => "vault",
    }
}

/// Secure-storage account for one object's anchor. Root accounts are absolute
/// canonical paths, which never begin with `anchor:`, and neither the tag nor
/// the hex id can contain `:` or `@`, so no two keys can collide.
fn object_anchor_account(root: &str, object_type: StateObjectType, object_id: &str) -> String {
    format!(
        "anchor:{}:{}@{root}",
        object_tag(object_type),
        filesec_core::util::hex(object_id.as_bytes())
    )
}

fn encode_root_record() -> StoreResult<Vec<u8>> {
    filesec_core::codec::to_vec(&AnchorRoot {
        version: ANCHOR_ROOT_VERSION,
        migration: None,
    })
    .map_err(err)
}

#[derive(Serialize, Deserialize)]
struct ProtectedState<T> {
    version: u16,
    state: StateMetadata,
    payload: T,
}

/// GUI-layer result type: errors are user-facing strings.
pub type StoreResult<T> = Result<T, String>;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// Lightweight, displayable metadata for one local vault. The actual contents
/// live in the encrypted `vaults/<id>.fsec` file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultMeta {
    /// Random opaque identifier (also the on-disk filename stem).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Unix creation time.
    pub created_at: i64,
    /// Unix time of the last save.
    pub modified_at: i64,
    /// Number of files (excludes directories).
    pub file_count: u64,
    /// Total plaintext byte size.
    pub total_size: u64,
}

/// The registry of local vaults (persisted encrypted-to-self).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Registry {
    /// All known local vaults.
    pub vaults: Vec<VaultMeta>,
}

impl Registry {
    /// Insert or replace a vault's metadata.
    pub fn upsert(&mut self, meta: VaultMeta) {
        if let Some(existing) = self.vaults.iter_mut().find(|v| v.id == meta.id) {
            *existing = meta;
        } else {
            self.vaults.push(meta);
        }
    }

    /// Remove a vault's metadata.
    pub fn remove(&mut self, id: &str) {
        self.vaults.retain(|v| v.id != id);
    }
}

/// Owns the application data directory and all file paths.
pub struct Store {
    data_dir: PathBuf,
    vaults_dir: PathBuf,
    checkout_dir: PathBuf,
    anchor_backend: AnchorBackend,
    anchor_account: String,
    secure: Option<Arc<dyn SecureAnchorStorage>>,
    lock: Arc<StoreLock>,
}

impl Store {
    /// Discover (and create) the per-OS application data directory.
    ///
    /// Honors the `FILESEC_DATA_DIR` environment variable as an override
    /// (useful for portable installs and tests); otherwise uses the standard
    /// per-OS location via `directories`.
    pub fn discover() -> StoreResult<Self> {
        Self::at(Self::default_data_dir()?)
    }

    /// The data directory [`Self::discover`] opens: `FILESEC_DATA_DIR` when set,
    /// otherwise the standard per-OS location.
    pub fn default_data_dir() -> StoreResult<PathBuf> {
        if let Some(dir) = std::env::var_os("FILESEC_DATA_DIR") {
            return Ok(PathBuf::from(dir));
        }
        let pd = directories::ProjectDirs::from("dev", "FileSec", "FileSec")
            .ok_or_else(|| "could not determine the application data directory".to_string())?;
        Ok(pd.data_dir().to_path_buf())
    }

    /// Open (and create) a store rooted at a specific directory, keeping its
    /// rollback anchors in this build's platform secure storage when available.
    pub fn at(data_dir: impl Into<PathBuf>) -> StoreResult<Self> {
        Self::at_with_secure_storage(data_dir, crate::anchors::platform_storage())
    }

    /// Open (and create) a store whose rollback anchors use `secure` as the OS
    /// secure storage (`None` = no secure storage on this system). Production
    /// code uses [`Self::at`]; this seam lets tests substitute
    /// [`crate::anchors::MemoryAnchorStorage`].
    pub fn at_with_secure_storage(
        data_dir: impl Into<PathBuf>,
        secure: Option<Arc<dyn SecureAnchorStorage>>,
    ) -> StoreResult<Self> {
        let mut store = Self::unselected(data_dir.into(), secure)?;
        store.anchor_backend = select_anchor_backend(
            &store.data_dir,
            &store.anchor_account,
            store.secure.as_deref(),
        )?;
        store.upgrade_secure_anchor_layout()?;
        store.resume_identity_migration()?;
        Ok(store)
    }

    /// Lay out the directory tree without deciding the anchor backend yet.
    fn unselected(
        data_dir: PathBuf,
        secure: Option<Arc<dyn SecureAnchorStorage>>,
    ) -> StoreResult<Self> {
        let vaults_dir = data_dir.join("vaults");
        let checkout_dir = data_dir.join("checkout");
        std::fs::create_dir_all(&vaults_dir).map_err(err)?;
        std::fs::create_dir_all(&checkout_dir).map_err(err)?;
        harden_dir(&data_dir);
        harden_dir(&vaults_dir);
        harden_dir(&checkout_dir);
        let canonical = std::fs::canonicalize(&data_dir).map_err(err)?;
        let lock = acquire_store_lock(&canonical)?;
        let anchor_account = canonical.display().to_string();
        Ok(Self {
            data_dir,
            vaults_dir,
            checkout_dir,
            anchor_backend: AnchorBackend::DegradedFile,
            anchor_account,
            secure,
            lock,
        })
    }

    /// The application data directory (shown in the UI).
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Whether high-water anchors are protected by OS secure storage or by the
    /// explicitly degraded local-file fallback.
    #[must_use]
    pub fn anchor_protection(&self) -> AnchorProtection {
        match self.anchor_backend {
            AnchorBackend::SecureStorage => AnchorProtection::SecureStorage,
            AnchorBackend::DegradedFile => AnchorProtection::DegradedFile,
        }
    }

    /// Persistent warning shown by the GUI when secure anchor storage is not
    /// available. The documented recovery path is to inspect quarantined state,
    /// restore the intended newest copy, and call the explicit `recover_legacy_*`
    /// or `reanchor_*` API rather than copying an old anchor file over the store.
    #[must_use]
    pub fn rollback_protection_warning(&self) -> Option<&'static str> {
        (self.anchor_backend == AnchorBackend::DegradedFile).then_some(
            "Rollback protection is in degraded mode: this system has no usable OS secure storage, so high-water anchors are kept in the FileSec data directory. Restoring the whole directory can also restore its anchors; keep an independent current backup and use the explicit recovery flow for quarantined state.",
        )
    }

    /// Explicit, passphrase-authenticated re-establishment of rollback anchors.
    ///
    /// This is the only way to move a store whose anchor backend cannot be
    /// trusted as found (an error carrying [`ANCHOR_RECOVERY_REQUIRED`]) onto a
    /// new backend — for example after the OS keychain was reset or the data
    /// directory moved to another machine. An unauthenticated edit of the
    /// `.state-anchor-backend` marker never does this.
    ///
    /// The passphrase must unlock the signed keystore, and every protected
    /// object currently on disk (keystore, contacts, registry, each v2 vault)
    /// must authenticate under that identity. Their current states then become
    /// the new high-water anchors, in OS secure storage when it is reachable
    /// and in the degraded file otherwise.
    ///
    /// **This trusts the on-disk state as the newest intended state.** Only run
    /// it after confirming the data directory is the copy you mean to keep: an
    /// older copy recovered here becomes the new high-water mark. Nothing is
    /// deleted, re-encrypted, or quarantined.
    pub fn recover_rollback_anchors(
        data_dir: impl Into<PathBuf>,
        secure: Option<Arc<dyn SecureAnchorStorage>>,
        passphrase: &[u8],
    ) -> StoreResult<Self> {
        let mut store = Self::unselected(data_dir.into(), secure)?;
        let bytes = read_bounded_file(
            &store.keystore_path(),
            MAX_KEYSTORE_FILE_LEN,
            "keystore file",
        )?;
        let ks = KeystoreFile::from_bytes(&bytes).map_err(err)?;
        let identity = ks.unlock(passphrase).map_err(err)?;
        let ks_state = ks
            .state_metadata()
            .cloned()
            .ok_or_else(|| "keystore has no rollback-protection metadata".to_string())?;
        if ks_state.identity_fingerprint != identity.fingerprint() {
            return Err("keystore state does not belong to the unlocked identity".into());
        }
        let mut anchors = vec![StateAnchor::from_metadata(&ks_state)];
        if let Some(record) = store.read_protected_record::<ContactBook>(
            &identity,
            &store.contacts_path(),
            CONTACTS_BLOB,
            StateObjectType::Contacts,
            "contacts",
        )? {
            anchors.push(StateAnchor::from_metadata(&record.state));
        }
        if let Some(record) = store.read_protected_record::<Registry>(
            &identity,
            &store.index_path(),
            REGISTRY_BLOB,
            StateObjectType::Registry,
            "registry",
        )? {
            anchors.push(StateAnchor::from_metadata(&record.state));
        }
        for (id, dir) in store.v2_vaults() {
            let reader = VaultReaderV2::open(&dir, &identity)
                .map_err(|e| format!("vault {id} could not be authenticated: {e}"))?;
            let state = reader
                .state_metadata()
                .ok_or_else(|| format!("vault {id} has no rollback-protection metadata"))?;
            if state.object_id != id || state.identity_fingerprint != identity.fingerprint() {
                return Err(format!("vault {id} does not belong to this store"));
            }
            anchors.push(StateAnchor::from_metadata(state));
        }
        store.anchor_backend = match probe_secure(store.secure.as_deref(), &store.anchor_account) {
            SecureProbe::Unreachable => AnchorBackend::DegradedFile,
            SecureProbe::Established | SecureProbe::Empty => AnchorBackend::SecureStorage,
        };
        {
            let _guard = store
                .lock
                .anchors
                .lock()
                .map_err(|_| "state anchor lock is unavailable".to_string())?;
            match store.anchor_backend {
                AnchorBackend::SecureStorage => {
                    for anchor in &anchors {
                        store.put_anchor_locked(anchor)?;
                    }
                    store
                        .secure_storage()?
                        .save(&store.anchor_account, &encode_root_record()?)
                        .map_err(|e| format!("could not save rollback anchors: {e}"))?;
                }
                AnchorBackend::DegradedFile => store.save_file_anchor_set_locked(&AnchorSet {
                    version: ANCHORS_VERSION,
                    anchors,
                    migration: None,
                })?,
            }
        }
        write_backend_marker(&store.data_dir, store.anchor_backend)?;
        Ok(store)
    }

    /// Load the non-secret UI preferences.
    ///
    /// **Infallible by design.** A missing, unreadable, oversized, corrupt, or
    /// newer-versioned file yields [`Prefs::default`]. This runs before the
    /// keystore is even opened, and the only thing in it is the theme — failing
    /// to read it must never be able to keep someone out of their vaults.
    #[must_use]
    pub fn load_prefs(&self) -> Prefs {
        let path = self.prefs_path();
        if !path.exists() {
            return Prefs::default();
        }
        let Ok(bytes) = read_bounded_file(&path, MAX_PREFS_FILE_LEN, "preferences file") else {
            return Prefs::default();
        };
        match filesec_core::codec::from_slice::<Prefs>(&bytes) {
            Ok(p) if p.version == crate::prefs::PREFS_VERSION => p,
            _ => Prefs::default(),
        }
    }

    /// Persist the non-secret UI preferences.
    ///
    /// Written atomically (private temp → fsync → rename) like everything else
    /// this module writes, so a crash mid-write leaves either the old
    /// preferences or the new ones — never a truncated file that would silently
    /// read back as defaults.
    ///
    /// Deliberately outside the state-anchor machinery: these preferences are
    /// unauthenticated and there is nothing an attacker gains by rolling them
    /// back. See [`crate::prefs`].
    pub fn save_prefs(&self, prefs: &Prefs) -> StoreResult<()> {
        let bytes = filesec_core::codec::to_vec(prefs).map_err(err)?;
        let final_path = self.prefs_path();
        let tmp = self.data_dir.join(PREFS_TMP_FILE);
        write_private_atomic(&tmp, &final_path, &bytes)
    }

    fn prefs_path(&self) -> PathBuf {
        self.data_dir.join(PREFS_FILE)
    }

    fn keystore_path(&self) -> PathBuf {
        self.data_dir.join(KEYSTORE_FILE)
    }
    fn contacts_path(&self) -> PathBuf {
        self.data_dir.join(CONTACTS_FILE)
    }
    fn index_path(&self) -> PathBuf {
        self.data_dir.join(INDEX_FILE)
    }
    fn vault_path(&self, id: &str) -> PathBuf {
        self.vaults_dir.join(format!("{id}.fsec"))
    }

    /// The v2 (directory-of-blobs) on-disk path for a vault.
    fn vault_dir_v2(&self, id: &str) -> PathBuf {
        self.vaults_dir.join(format!("{id}.fsv2"))
    }

    fn anchors_path(&self) -> PathBuf {
        self.data_dir.join(ANCHORS_FILE)
    }

    fn secure_storage(&self) -> StoreResult<&dyn SecureAnchorStorage> {
        self.secure
            .as_deref()
            .ok_or_else(|| "OS secure storage is not available in this build".to_string())
    }

    /// The degraded file's anchor set (caller holds `lock.anchors`).
    fn load_file_anchor_set_locked(&self) -> StoreResult<AnchorSet> {
        let path = self.anchors_path();
        let bytes = if path.exists() {
            read_bounded_file(&path, 4 * 1024 * 1024, "state anchor file")?
        } else {
            Vec::new()
        };
        if bytes.is_empty() {
            return Ok(AnchorSet {
                version: ANCHORS_VERSION,
                anchors: Vec::new(),
                migration: None,
            });
        }
        let set: AnchorSet = filesec_core::codec::from_slice(&bytes).map_err(err)?;
        if set.version != ANCHORS_VERSION {
            return Err("unsupported state anchor format".into());
        }
        Ok(set)
    }

    fn save_file_anchor_set_locked(&self, set: &AnchorSet) -> StoreResult<()> {
        let bytes = filesec_core::codec::to_vec(set).map_err(err)?;
        let final_path = self.anchors_path();
        let tmp = self.data_dir.join(".state-anchors.tmp");
        write_private_atomic(&tmp, &final_path, &bytes)
    }

    /// Read one object's anchor, whichever backend holds it (caller holds
    /// `lock.anchors`).
    fn get_anchor_locked(
        &self,
        object_type: StateObjectType,
        object_id: &str,
    ) -> StoreResult<Option<StateAnchor>> {
        match self.anchor_backend {
            AnchorBackend::SecureStorage => {
                let account = object_anchor_account(&self.anchor_account, object_type, object_id);
                let Some(bytes) = self
                    .secure_storage()?
                    .load(&account)
                    .map_err(|e| format!("could not read rollback anchors: {e}"))?
                else {
                    return Ok(None);
                };
                let record: ObjectAnchorRecord =
                    filesec_core::codec::from_slice(&bytes).map_err(err)?;
                if record.version != OBJECT_ANCHOR_VERSION
                    || record.anchor.object_type != object_type
                    || record.anchor.object_id != object_id
                {
                    return Err(format!(
                        "malformed rollback anchor record for {object_type} {object_id}"
                    ));
                }
                Ok(Some(record.anchor))
            }
            AnchorBackend::DegradedFile => Ok(self
                .load_file_anchor_set_locked()?
                .anchors
                .into_iter()
                .find(|a| a.object_type == object_type && a.object_id == object_id)),
        }
    }

    /// Create or replace one object's anchor (caller holds `lock.anchors`).
    fn put_anchor_locked(&self, anchor: &StateAnchor) -> StoreResult<()> {
        if anchor.object_id.len() > MAX_ANCHOR_OBJECT_ID {
            return Err("state object id is too long to anchor".into());
        }
        match self.anchor_backend {
            AnchorBackend::SecureStorage => {
                let bytes = filesec_core::codec::to_vec(&ObjectAnchorRecord {
                    version: OBJECT_ANCHOR_VERSION,
                    anchor: anchor.clone(),
                })
                .map_err(err)?;
                if bytes.len() > MAX_SECURE_ANCHOR_RECORD {
                    return Err("rollback anchor record exceeds the secure-storage limit".into());
                }
                let account = object_anchor_account(
                    &self.anchor_account,
                    anchor.object_type,
                    &anchor.object_id,
                );
                self.secure_storage()?
                    .save(&account, &bytes)
                    .map_err(|e| format!("could not save rollback anchors: {e}"))
            }
            AnchorBackend::DegradedFile => {
                let mut set = self.load_file_anchor_set_locked()?;
                match set.anchors.iter_mut().find(|a| {
                    a.object_type == anchor.object_type && a.object_id == anchor.object_id
                }) {
                    Some(existing) => *existing = anchor.clone(),
                    None => set.anchors.push(anchor.clone()),
                }
                self.save_file_anchor_set_locked(&set)
            }
        }
    }

    /// Convert a store whose secure storage still holds the legacy layout (one
    /// record with every anchor, which outgrows Windows Credential Manager's
    /// 2,560-byte limit after a handful of vaults) into one bounded record per
    /// object plus a small root record. Idempotent: an interruption leaves the
    /// legacy root in place and the conversion simply runs again.
    fn upgrade_secure_anchor_layout(&self) -> StoreResult<()> {
        if self.anchor_backend != AnchorBackend::SecureStorage {
            return Ok(());
        }
        let _guard = self
            .lock
            .anchors
            .lock()
            .map_err(|_| "state anchor lock is unavailable".to_string())?;
        let storage = self.secure_storage()?;
        let Some(bytes) = storage
            .load(&self.anchor_account)
            .map_err(|e| format!("could not read rollback anchors: {e}"))?
        else {
            return Err(format!(
                "{ANCHOR_RECOVERY_REQUIRED}: the anchor root record disappeared from OS secure storage"
            ));
        };
        let probe: AnchorVersionProbe = filesec_core::codec::from_slice(&bytes).map_err(err)?;
        match probe.version {
            ANCHOR_ROOT_VERSION => Ok(()),
            ANCHORS_VERSION => {
                let legacy: AnchorSet = filesec_core::codec::from_slice(&bytes).map_err(err)?;
                for anchor in &legacy.anchors {
                    self.put_anchor_locked(anchor)?;
                }
                storage
                    .save(&self.anchor_account, &encode_root_record()?)
                    .map_err(|e| format!("could not save rollback anchors: {e}"))
            }
            _ => Err("unsupported state anchor format".into()),
        }
    }

    /// Run `f` as one transaction on a protected object: the object's lock is
    /// held across reading its anchor, computing the candidate, committing the
    /// state file, and updating the anchor (FS-05). Never nest two objects'
    /// transactions; anchor storage access inside `f` takes the short
    /// `anchors` lock on its own.
    fn in_txn<R>(
        &self,
        object_type: StateObjectType,
        object_id: &str,
        f: impl FnOnce() -> StoreResult<R>,
    ) -> StoreResult<R> {
        let _shared = if EXCLUSIVE_HELD.with(Cell::get) {
            None
        } else {
            Some(
                self.lock
                    .exclusive
                    .read()
                    .map_err(|_| "store lock is unavailable".to_string())?,
            )
        };
        let txn = {
            let mut objects = self
                .lock
                .objects
                .lock()
                .map_err(|_| "state transaction table is unavailable".to_string())?;
            objects
                .entry(format!("{object_type}/{object_id}"))
                .or_default()
                .clone()
        };
        let _guard = txn
            .lock()
            .map_err(|_| "state transaction lock is unavailable".to_string())?;
        f()
    }

    /// Run `f` with the whole store to itself: every other transaction (in any
    /// thread) waits until it returns. Transactions `f` runs itself proceed.
    #[cfg_attr(not(feature = "pqc"), allow(dead_code))]
    fn exclusively<R>(&self, f: impl FnOnce() -> StoreResult<R>) -> StoreResult<R> {
        let _write = self
            .lock
            .exclusive
            .write()
            .map_err(|_| "store lock is unavailable".to_string())?;
        EXCLUSIVE_HELD.with(|held| held.set(true));
        let _flag = ExclusiveFlag;
        f()
    }

    /// Compare-and-swap precondition for a vault mutation: `reader` must be the
    /// vault's current anchored state. A reader left behind by a mutation that
    /// another operation already committed is refused instead of forking the
    /// manifest chain or silently discarding that other change.
    fn ensure_current_vault(&self, reader: &VaultReaderV2) -> StoreResult<()> {
        let state = reader
            .state_metadata()
            .ok_or_else(|| "vault has no rollback-protection metadata".to_string())?;
        match self.current_anchor(
            state.identity_fingerprint,
            state.object_type,
            &state.object_id,
        )? {
            Some(anchor)
                if anchor.epoch != state.epoch
                    || anchor.current_state_hash != state.current_state_hash =>
            {
                Err(format!(
                    "{STALE_STATE}; reopen it and try again (vault {})",
                    state.object_id
                ))
            }
            _ => Ok(()),
        }
    }

    /// Run a mutation of an open vault as one transaction: check that `reader`
    /// is current, apply `mutate` to a clone, and commit the resulting state.
    fn mutate_vault(
        &self,
        reader: &VaultReaderV2,
        mutate: impl FnOnce(&mut VaultReaderV2) -> StoreResult<()>,
    ) -> StoreResult<()> {
        let object_id = reader
            .state_metadata()
            .map(|state| state.object_id.clone())
            .ok_or_else(|| "vault has no rollback-protection metadata".to_string())?;
        self.in_txn(StateObjectType::VaultManifest, &object_id, || {
            self.ensure_current_vault(reader)?;
            let mut writer = reader.clone();
            mutate(&mut writer)?;
            self.commit_vault_reader(&writer)
        })
    }

    fn current_anchor(
        &self,
        identity_fingerprint: [u8; 32],
        object_type: StateObjectType,
        object_id: &str,
    ) -> StoreResult<Option<StateAnchor>> {
        let _guard = self
            .lock
            .anchors
            .lock()
            .map_err(|_| "state anchor lock is unavailable".to_string())?;
        match self.get_anchor_locked(object_type, object_id)? {
            Some(anchor) if anchor.identity_fingerprint != identity_fingerprint => Err(format!(
                "state-anchor mismatch for {object_type} {object_id}: it belongs to a different identity"
            )),
            other => Ok(other),
        }
    }

    fn accept_state(&self, state: &StateMetadata, suspect_path: &Path) -> StoreResult<()> {
        let result = (|| {
            let _guard = self
                .lock
                .anchors
                .lock()
                .map_err(|_| "state anchor lock is unavailable".to_string())?;
            let should_update = match self.get_anchor_locked(state.object_type, &state.object_id)? {
                Some(anchor) => anchor.check_candidate(state).map_err(err)?,
                None => true,
            };
            if should_update {
                self.put_anchor_locked(&StateAnchor::from_metadata(state))?;
            }
            Ok(())
        })();
        if result.is_err() && suspect_path.exists() {
            let _ = self.quarantine(suspect_path);
        }
        result
    }

    fn check_state_transition(&self, state: &StateMetadata) -> StoreResult<()> {
        let _guard = self
            .lock
            .anchors
            .lock()
            .map_err(|_| "state anchor lock is unavailable".to_string())?;
        if let Some(anchor) = self.get_anchor_locked(state.object_type, &state.object_id)? {
            anchor.check_candidate(state).map_err(err)?;
        }
        Ok(())
    }

    fn commit_state(&self, state: &StateMetadata) -> StoreResult<()> {
        // No quarantine on save: the authenticated candidate is in memory and
        // the caller still controls the write path. `accept_state` is reserved
        // for suspect bytes loaded from disk.
        self.accept_state(state, Path::new(""))
    }

    fn quarantine(&self, path: &Path) -> StoreResult<PathBuf> {
        let dir = self.data_dir.join(QUARANTINE_DIR);
        std::fs::create_dir_all(&dir).map_err(err)?;
        harden_dir(&dir);
        let leaf = path.file_name().and_then(|n| n.to_str()).unwrap_or("state");
        let suffix = random_hex::<8>()?;
        let target = dir.join(format!("{leaf}.rollback-{suffix}"));
        std::fs::rename(path, &target).map_err(err)?;
        Ok(target)
    }

    fn commit_vault_reader(&self, reader: &VaultReaderV2) -> StoreResult<()> {
        let state = reader
            .state_metadata()
            .ok_or_else(|| "vault has no rollback-protection metadata".to_string())?;
        self.commit_state(state)
    }

    /// Whether an identity has already been created.
    pub fn keystore_exists(&self) -> bool {
        self.keystore_path().exists()
    }

    /// Persist the keystore (passphrase- and, once enrolled, passkey-protected).
    ///
    /// Written **atomically**: bytes go to a private (0600) temp file that is
    /// fsync'd and then renamed into place, with a best-effort directory fsync so
    /// the rename is durable. Because the keystore is now mutated in place
    /// (enrolling/removing a passkey), a crash mid-write must never leave a
    /// half-written file — a half-written keystore would be permanent lockout.
    pub fn save_keystore(&self, ks: &KeystoreFile) -> StoreResult<()> {
        let state = ks.state_metadata().ok_or_else(|| {
            "legacy keystore must be recovered before it can be saved".to_string()
        })?;
        self.in_txn(state.object_type, &state.object_id, || {
            self.check_state_transition(state)?;
            let bytes = ks.to_bytes().map_err(err)?;
            let final_path = self.keystore_path();
            let tmp = self.data_dir.join("keystore.fsk.tmp");
            write_private_atomic(&tmp, &final_path, &bytes)?;
            harden_file(&final_path);
            self.commit_state(state)
        })
    }

    /// Load the keystore (still encrypted — call `unlock`).
    pub fn load_keystore(&self) -> StoreResult<KeystoreFile> {
        self.in_txn(StateObjectType::Keystore, KEYSTORE_OBJECT_ID, || {
            let bytes = read_bounded_file(
                &self.keystore_path(),
                MAX_KEYSTORE_FILE_LEN,
                "keystore file",
            )?;
            let ks = KeystoreFile::from_bytes(&bytes).map_err(err)?;
            let state = ks
                .state_metadata()
                .ok_or_else(|| "keystore has no rollback-protection metadata".to_string())?;
            self.accept_state(state, &self.keystore_path())?;
            Ok(ks)
        })
    }

    /// Explicit one-time recovery for a valid pre-anchor keystore. The supplied
    /// passphrase authenticates the legacy state; success immediately replaces
    /// it with a signed epoch-1 v3 keystore and establishes its high-water
    /// anchor. Normal [`Self::load_keystore`] never performs this implicitly.
    pub fn recover_legacy_keystore(&self, passphrase: &[u8]) -> StoreResult<KeystoreFile> {
        let bytes = read_bounded_file(
            &self.keystore_path(),
            MAX_KEYSTORE_FILE_LEN,
            "keystore file",
        )?;
        let ks = KeystoreFile::recover_legacy(&bytes, passphrase).map_err(err)?;
        self.save_keystore(&ks)?;
        Ok(ks)
    }

    /// Save an arbitrary blob as a single-file container encrypted to self.
    fn save_blob(
        &self,
        identity: &Identity,
        path: &Path,
        name: &str,
        bytes: &[u8],
    ) -> StoreResult<()> {
        let mut v = Vault::new(name, now_unix());
        v.add_file(name, bytes.to_vec(), None, None).map_err(err)?;
        format::export_vault_to_path(
            &v,
            identity,
            &[identity.public()],
            &self_options(identity),
            path,
        )
        .map_err(err)?;
        harden_file(path);
        Ok(())
    }

    /// Load an arbitrary self-encrypted blob, or `None` if the file is absent.
    fn load_blob(
        &self,
        identity: &Identity,
        path: &Path,
        name: &str,
    ) -> StoreResult<Option<(Vec<u8>, SuiteId)>> {
        if !path.exists() {
            return Ok(None);
        }
        reject_oversized_file(path, MAX_SELF_BLOB_CONTAINER_LEN, "stored metadata file")?;
        let reader = format::open_vault_from_path(path, identity).map_err(err)?;
        let entry = reader
            .entries()
            .iter()
            .find(|entry| entry.path == name && entry.kind == EntryKind::File)
            .ok_or_else(|| "stored blob is missing its entry".to_string())?;
        if entry.size > MAX_SELF_BLOB_PLAINTEXT_LEN {
            return Err("stored metadata blob is too large".to_string());
        }
        let bytes = reader.read_entry(name).map_err(err)?;
        Ok(Some((bytes.to_vec(), reader.suite())))
    }

    fn save_protected_blob<T: Serialize>(
        &self,
        identity: &Identity,
        path: &Path,
        entry_name: &str,
        object_type: StateObjectType,
        object_id: &str,
        payload: &T,
    ) -> StoreResult<()> {
        let payload_bytes = filesec_core::codec::to_vec(payload).map_err(err)?;
        self.in_txn(object_type, object_id, || {
            let previous = self.current_anchor(identity.fingerprint(), object_type, object_id)?;
            let state = StateMetadata::next(
                identity.fingerprint(),
                object_type,
                object_id,
                self_suite(identity).to_u16(),
                previous.as_ref(),
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
            self.commit_state(&state)
        })
    }

    /// Read, decrypt and authenticate one protected record **without** any
    /// anchor check. A record bound to another identity/object/suite, or whose
    /// payload does not match its committed hash, is an error.
    fn read_protected_record<T: DeserializeOwned + Serialize>(
        &self,
        identity: &Identity,
        path: &Path,
        entry_name: &str,
        object_type: StateObjectType,
        object_id: &str,
    ) -> StoreResult<Option<ProtectedState<T>>> {
        let Some((bytes, suite)) = self.load_blob(identity, path, entry_name)? else {
            return Ok(None);
        };
        let record: ProtectedState<T> = match filesec_core::codec::from_slice(&bytes) {
            Ok(record) => record,
            Err(_) => {
                if filesec_core::codec::from_slice::<T>(&bytes).is_ok() {
                    return Err(format!(
                        "legacy {object_type} state requires explicit recovery"
                    ));
                }
                return Err(format!("malformed protected {object_type} state"));
            }
        };
        if record.version != PROTECTED_STATE_VERSION
            || record.state.identity_fingerprint != identity.fingerprint()
            || record.state.object_type != object_type
            || record.state.object_id != object_id
            || record.state.suite_id != suite.to_u16()
        {
            return Err(format!(
                "state-anchor mismatch for {object_type} {object_id}"
            ));
        }
        let payload_bytes = filesec_core::codec::to_vec(&record.payload).map_err(err)?;
        record.state.verify_payload(&payload_bytes).map_err(err)?;
        Ok(Some(record))
    }

    fn load_protected_blob<T: DeserializeOwned + Serialize>(
        &self,
        identity: &Identity,
        path: &Path,
        entry_name: &str,
        object_type: StateObjectType,
        object_id: &str,
    ) -> StoreResult<Option<T>> {
        self.in_txn(object_type, object_id, || {
            let record = match self.read_protected_record(
                identity,
                path,
                entry_name,
                object_type,
                object_id,
            ) {
                Ok(Some(record)) => record,
                Ok(None) => return Ok(None),
                Err(e) => {
                    if e.starts_with("state-anchor mismatch") {
                        let _ = self.quarantine(path);
                    }
                    return Err(e);
                }
            };
            self.accept_state(&record.state, path)?;
            Ok(Some(record.payload))
        })
    }

    /// Load the contact book (empty if none yet).
    pub fn load_contacts(&self, identity: &Identity) -> StoreResult<ContactBook> {
        Ok(self
            .load_protected_blob(
                identity,
                &self.contacts_path(),
                CONTACTS_BLOB,
                StateObjectType::Contacts,
                "contacts",
            )?
            .unwrap_or_default())
    }

    /// Persist the contact book.
    pub fn save_contacts(&self, identity: &Identity, book: &ContactBook) -> StoreResult<()> {
        self.save_protected_blob(
            identity,
            &self.contacts_path(),
            CONTACTS_BLOB,
            StateObjectType::Contacts,
            "contacts",
            book,
        )
    }

    /// Load the vault registry (empty if none yet).
    pub fn load_registry(&self, identity: &Identity) -> StoreResult<Registry> {
        Ok(self
            .load_protected_blob(
                identity,
                &self.index_path(),
                REGISTRY_BLOB,
                StateObjectType::Registry,
                "registry",
            )?
            .unwrap_or_default())
    }

    /// Persist the vault registry.
    pub fn save_registry(&self, identity: &Identity, registry: &Registry) -> StoreResult<()> {
        self.save_protected_blob(
            identity,
            &self.index_path(),
            REGISTRY_BLOB,
            StateObjectType::Registry,
            "registry",
            registry,
        )
    }

    /// Explicitly authenticate and migrate a legacy contact book, immediately
    /// writing it back as epoch-1 rollback-protected state.
    pub fn recover_legacy_contacts(&self, identity: &Identity) -> StoreResult<ContactBook> {
        let book = match self.load_blob(identity, &self.contacts_path(), CONTACTS_BLOB)? {
            Some((bytes, _)) => ContactBook::from_bytes(&bytes).map_err(err)?,
            None => ContactBook::default(),
        };
        self.save_contacts(identity, &book)?;
        Ok(book)
    }

    /// Explicitly authenticate and migrate a legacy vault registry, immediately
    /// writing it back as epoch-1 rollback-protected state.
    pub fn recover_legacy_registry(&self, identity: &Identity) -> StoreResult<Registry> {
        let registry = match self.load_blob(identity, &self.index_path(), REGISTRY_BLOB)? {
            Some((bytes, _)) => filesec_core::codec::from_slice(&bytes).map_err(err)?,
            None => Registry::default(),
        };
        self.save_registry(identity, &registry)?;
        Ok(registry)
    }

    /// Persist a (typically new) vault to its local v2 store directory, encrypted
    /// to the identity itself under the identity's at-rest suite.
    pub fn save_vault(&self, identity: &Identity, id: &str, vault: &Vault) -> StoreResult<()> {
        self.create_vault_dir(id, |partial| {
            VaultReaderV2::from_vault_with_object_id(
                partial,
                identity,
                self_suite(identity),
                vault,
                id,
            )
        })
    }

    /// Create a new vault directory as a staged transaction (FS-11): `build`
    /// writes the complete vault into `<id>.fsv2.partial`, which is renamed to
    /// `<id>.fsv2` (the commit point) and then anchored. A crash before the
    /// rename leaves only a `.partial` that the next unlock discards; a crash
    /// after it leaves a complete vault that [`Self::reconcile_vaults`] registers.
    /// An existing vault or tombstone at `id` is never overwritten.
    fn create_vault_dir(
        &self,
        id: &str,
        build: impl FnOnce(&Path) -> filesec_core::Result<VaultReaderV2>,
    ) -> StoreResult<()> {
        self.in_txn(StateObjectType::VaultManifest, id, || {
            let dir = self.vault_dir_v2(id);
            if dir.exists() || self.vault_tombstone(id).exists() {
                return Err("vault already exists; use the rollback-aware mutation APIs".into());
            }
            let partial = self.vaults_dir.join(format!("{id}.fsv2.partial"));
            wipe_vault_dir(&partial);
            let state = match build(&partial) {
                Ok(reader) => reader.state_metadata().cloned(),
                Err(e) => {
                    wipe_vault_dir(&partial);
                    return Err(err(e));
                }
            };
            let Some(state) = state else {
                wipe_vault_dir(&partial);
                return Err("new vault has no rollback-protection metadata".into());
            };
            if let Err(e) = std::fs::rename(&partial, &dir) {
                wipe_vault_dir(&partial);
                return Err(err(e));
            }
            let _ = filesec_core::safe_io::sync_dir(&self.vaults_dir);
            // A vault whose anchor could not be recorded was never created as
            // far as the caller knows; don't leave an unanchored directory.
            if let Err(e) = self.commit_state(&state) {
                wipe_vault_dir(&dir);
                return Err(e);
            }
            Ok(())
        })
    }

    /// Load a vault fully into memory (used by tests and any caller needing the
    /// whole plaintext). Legacy state must first pass the explicit recovery flow.
    pub fn load_vault(&self, identity: &Identity, id: &str) -> StoreResult<Vault> {
        self.open_vault(identity, id)?.to_vault().map_err(err)
    }

    /// Lazily open a rollback-protected vault (metadata only; file contents
    /// decrypt on demand). Legacy state returns a recovery-required error.
    pub fn open_vault(&self, identity: &Identity, id: &str) -> StoreResult<VaultReaderV2> {
        self.in_txn(StateObjectType::VaultManifest, id, || {
            self.open_vault_locked(identity, id)
        })
    }

    fn open_vault_locked(&self, identity: &Identity, id: &str) -> StoreResult<VaultReaderV2> {
        let v2 = self.vault_dir_v2(id);
        if v2.exists() {
            // A crash after the migration commit but before the old file was
            // wiped can leave the v1 container behind; the v2 dir wins.
            let mut reader = VaultReaderV2::open(&v2, identity).map_err(err)?;
            let state = reader
                .state_metadata()
                .ok_or_else(|| "vault has no rollback-protection metadata".to_string())?;
            if state.object_id != id {
                let _ = self.quarantine(&v2);
                return Err("vault object id does not match its registry/path id".into());
            }
            self.accept_state(state, &v2)?;
            let v1 = self.vault_path(id);
            if v1.exists() {
                let _ = secure_wipe(&v1);
            }
            // Reclaim blobs left unreferenced by a crash or by a commit whose
            // durability was never confirmed (FS-10). Safe here: the vault's
            // transaction lock is held, so no writer has a blob in flight, and
            // the collector itself refuses to run unless the directory syncs.
            let _ = reader.collect_garbage();
            return Ok(reader);
        }
        if self.vault_path(id).exists() {
            return Err(
                "legacy local vault requires explicit recovery before it can be opened".to_string(),
            );
        }
        Err(format!("vault not found: {id}"))
    }

    /// Crash-safe explicit migration of a legacy v1 `.fsec` vault to the v2 directory
    /// format. The fully-written `<id>.fsv2.partial` dir is renamed to `<id>.fsv2`
    /// (the atomic commit point) before the old `.fsec` is wiped, so a crash
    /// before the rename keeps the v1 file intact (and the stray `.partial` is
    /// cleaned on the next unlock), and a crash after it makes the v2 dir
    /// authoritative. Data is never lost.
    fn migrate_vault_v1_to_v2(&self, identity: &Identity, id: &str) -> StoreResult<()> {
        let v1 = self.vault_path(id);
        let final_dir = self.vault_dir_v2(id);
        let partial = self.vaults_dir.join(format!("{id}.fsv2.partial"));
        let _ = std::fs::remove_dir_all(&partial);
        let (reader, sender) = format::verify_and_open(&v1, identity).map_err(err)?;
        if sender.fingerprint != identity.fingerprint() {
            return Err("legacy local vault was not signed by this identity".into());
        }
        let migrated = match VaultReaderV2::from_reader_v1_with_object_id(
            &partial,
            identity,
            self_suite(identity),
            &reader,
            id,
        ) {
            Ok(reader) => reader,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&partial);
                return Err(err(e));
            }
        };
        let state = migrated
            .state_metadata()
            .cloned()
            .ok_or_else(|| "migrated vault has no rollback-protection metadata".to_string())?;
        drop(migrated);
        std::fs::rename(&partial, &final_dir).map_err(err)?;
        if let Ok(d) = std::fs::File::open(&self.vaults_dir) {
            let _ = d.sync_all();
        }
        let _ = secure_wipe(&v1);
        self.commit_state(&state)?;
        Ok(())
    }

    /// Explicit one-time recovery for a legacy local vault. A legacy v2 raw
    /// manifest is authenticated and re-enveloped in place; a signed local v1
    /// container is verified and transcoded to a protected v2 directory.
    pub fn recover_legacy_vault(
        &self,
        identity: &Identity,
        id: &str,
    ) -> StoreResult<VaultReaderV2> {
        self.in_txn(StateObjectType::VaultManifest, id, || {
            self.recover_legacy_vault_locked(identity, id)
        })
    }

    fn recover_legacy_vault_locked(
        &self,
        identity: &Identity,
        id: &str,
    ) -> StoreResult<VaultReaderV2> {
        let v2 = self.vault_dir_v2(id);
        if v2.exists() {
            let legacy = match VaultReaderV2::recover_legacy(&v2, identity) {
                Ok(reader) => reader,
                Err(filesec_core::Error::Format(
                    "vault manifest is already rollback protected",
                )) => VaultReaderV2::open(&v2, identity).map_err(err)?,
                Err(e) => return Err(err(e)),
            };
            let partial = self.vaults_dir.join(format!("{id}.fsv2.partial"));
            let old = self.vaults_dir.join(format!("{id}.fsv2.old"));
            let _ = std::fs::remove_dir_all(&partial);
            let _ = std::fs::remove_dir_all(&old);
            // Stream the re-key blob-by-blob straight from the opened source, so a
            // multi-GB vault never materializes in RAM (peak is a couple of chunks).
            // `legacy` must stay alive across the build; drop it before moving `v2`.
            let reader = VaultReaderV2::from_reader_v2_with_object_id(
                &partial,
                identity,
                self_suite(identity),
                &legacy,
                id,
            )
            .map_err(err)?;
            let state = reader
                .state_metadata()
                .cloned()
                .ok_or_else(|| "recovered vault has no rollback-protection metadata".to_string())?;
            drop(reader);
            drop(legacy);
            std::fs::rename(&v2, &old).map_err(err)?;
            if let Err(e) = std::fs::rename(&partial, &v2) {
                let _ = std::fs::rename(&old, &v2);
                return Err(err(e));
            }
            wipe_vault_dir(&old);
            self.commit_state(&state)?;
            return self.open_vault_locked(identity, id);
        }
        if self.vault_path(id).exists() {
            self.migrate_vault_v1_to_v2(identity, id)?;
            return self.open_vault_locked(identity, id);
        }
        Err(format!("vault not found: {id}"))
    }

    /// Every committed v2 vault directory, as `(vault id, path)`. Scratch and
    /// tombstone directories (`.partial`, `.old`, ...) are not vaults.
    fn v2_vaults(&self) -> Vec<(String, PathBuf)> {
        let mut vaults = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&self.vaults_dir) {
            for entry in rd.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some(id) = name.strip_suffix(".fsv2") {
                    if entry.path().is_dir() {
                        vaults.push((id.to_string(), entry.path()));
                    }
                }
            }
        }
        vaults.sort();
        vaults
    }

    /// Best-effort cleanup, on unlock, of interrupted vault-migration scratch
    /// directories: a `*.fsv2.partial` (an aborted write) is removed; a
    /// `*.fsv2.old` (an interrupted suite re-key) is removed when its final dir
    /// committed, else rolled back into place.
    pub fn clean_partial_dirs(&self) {
        if let Ok(rd) = std::fs::read_dir(&self.vaults_dir) {
            for entry in rd.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with(".fsv2.partial") {
                    let _ = std::fs::remove_dir_all(&path);
                } else if let Some(stem) = name.strip_suffix(".old") {
                    let final_dir = self.vaults_dir.join(stem);
                    if final_dir.exists() {
                        let _ = std::fs::remove_dir_all(&path);
                    } else {
                        let _ = std::fs::rename(&path, &final_dir);
                    }
                }
            }
        }
    }

    /// Add files (from disk) and empty directories to an existing v2 vault. Each
    /// new file becomes its own encrypted blob and the manifest is resealed —
    /// O(the change), not a whole-vault rewrite, and other files are never read.
    pub fn append_files_to_vault(
        &self,
        _identity: &Identity,
        _id: &str,
        reader: &VaultReaderV2,
        added: &[format::AddedFile],
        added_dirs: &[String],
    ) -> StoreResult<()> {
        // v2 is O(change): each new file becomes its own blob and the manifest is
        // resealed — no whole-vault rewrite. The reader is cloned (it carries the
        // manifest key); the caller re-opens afterwards to pick up the new state.
        let object_id = reader
            .state_metadata()
            .map(|state| state.object_id.clone())
            .ok_or_else(|| "vault has no rollback-protection metadata".to_string())?;
        self.in_txn(StateObjectType::VaultManifest, &object_id, || {
            self.ensure_current_vault(reader)?;
            let mut writer = reader.clone();
            for d in added_dirs {
                writer.mkdir(d).map_err(err)?;
                self.commit_vault_reader(&writer)?;
            }
            for f in added {
                writer
                    .put_file(&f.vault_path, &f.source, f.mtime, f.mode)
                    .map_err(err)?;
                self.commit_vault_reader(&writer)?;
            }
            Ok(())
        })
    }

    /// Remove paths (each entry plus, for a directory, its subtree) from an
    /// existing v2 vault: each removal unlinks only that file's blob and reseals
    /// the manifest — other files are untouched.
    pub fn remove_paths_from_vault(
        &self,
        _identity: &Identity,
        _id: &str,
        reader: &VaultReaderV2,
        remove: &[String],
    ) -> StoreResult<()> {
        self.mutate_vault(reader, |writer| {
            for p in remove {
                writer.remove_path(p).map_err(err)?;
                self.commit_vault_reader(writer)?;
            }
            Ok(())
        })
    }

    /// Apply a batch of manifest-only renames (`from` -> `to`) to an existing v2
    /// vault. No blob is read or rewritten — only the manifest tree changes — so
    /// this is the cheap engine behind moving, renaming, soft-delete (move into
    /// the trash) and restore (move back out). Each pair is applied in order; a
    /// later pair sees the tree left by the earlier ones.
    pub fn rename_in_vault(
        &self,
        _identity: &Identity,
        _id: &str,
        reader: &VaultReaderV2,
        pairs: &[(String, String)],
    ) -> StoreResult<()> {
        self.mutate_vault(reader, |writer| {
            for (from, to) in pairs {
                writer.rename(from, to).map_err(err)?;
                self.commit_vault_reader(writer)?;
            }
            Ok(())
        })
    }

    /// Write `bytes` to `vault_path` inside an existing v2 vault (creating or
    /// overwriting that one file as a fresh blob + manifest reseal). Backs the
    /// in-app text editor's "new file" and "save".
    pub fn put_bytes_in_vault(
        &self,
        _identity: &Identity,
        _id: &str,
        reader: &VaultReaderV2,
        vault_path: &str,
        bytes: &[u8],
        mtime: Option<i64>,
    ) -> StoreResult<()> {
        self.mutate_vault(reader, |writer| {
            writer
                .put_file_bytes(vault_path, bytes, mtime, None)
                .map_err(err)
        })
    }

    /// Replace a single file's contents inside an existing v2 vault: the new file
    /// is written as a fresh blob, the old blob is unlinked, and the manifest is
    /// resealed. Only that one file's storage changes.
    #[allow(clippy::too_many_arguments)]
    pub fn replace_file_in_vault(
        &self,
        _identity: &Identity,
        _id: &str,
        reader: &VaultReaderV2,
        vault_path: &str,
        new_source: &Path,
        mtime: Option<i64>,
        mode: Option<u32>,
    ) -> StoreResult<()> {
        // Overwrite is just a `put_file`: a fresh blob replaces the old one and
        // the manifest is resealed (the old blob is unlinked).
        self.mutate_vault(reader, |writer| {
            writer
                .put_file(vault_path, new_source, mtime, mode)
                .map_err(err)
        })
    }

    /// Transcode a just-verified incoming v1 container into a fresh local v2 store
    /// directory (encrypted to self), one file at a time so a huge imported file
    /// is never fully held in memory. Cleans up the directory on failure.
    pub fn import_reader_to_vault(
        &self,
        identity: &Identity,
        id: &str,
        reader: &format::VaultReader,
    ) -> StoreResult<()> {
        self.create_vault_dir(id, |partial| {
            VaultReaderV2::from_reader_v1_with_object_id(
                partial,
                identity,
                self_suite(identity),
                reader,
                id,
            )
        })
    }

    fn vault_tombstone(&self, id: &str) -> PathBuf {
        self.vaults_dir.join(format!("{id}.fsv2.deleted"))
    }

    fn legacy_vault_tombstone(&self, id: &str) -> PathBuf {
        self.vaults_dir.join(format!("{id}.fsec.deleted"))
    }

    /// Delete a vault as a recoverable transaction (FS-11) and return the
    /// updated registry.
    ///
    /// 1. The vault's directory (and any legacy `.fsec`) is renamed to a
    ///    `.deleted` **tombstone** — the encrypted data is still intact.
    /// 2. The registry without the vault is saved: the commit point. If that
    ///    fails the tombstone is renamed back and nothing changed.
    /// 3. The vault's anchor is set to a terminal "deleted" high-water mark, so
    ///    a restored copy of the deleted vault is never accepted again, and the
    ///    tombstone is securely wiped.
    ///
    /// A crash after step 1 is resolved by [`Self::reconcile_vaults`] on the
    /// next unlock: a tombstone the registry still lists is restored, one it no
    /// longer lists is retired.
    pub fn delete_vault(
        &self,
        identity: &Identity,
        registry: &Registry,
        id: &str,
    ) -> StoreResult<Registry> {
        let mut updated = registry.clone();
        updated.remove(id);
        self.in_txn(StateObjectType::VaultManifest, id, || {
            self.tombstone_vault(id)
        })?;
        if let Err(e) = self.save_registry(identity, &updated) {
            return Err(
                match self.in_txn(StateObjectType::VaultManifest, id, || {
                    self.restore_tombstone(id)
                }) {
                    Ok(()) => e,
                    Err(restore) => format!(
                        "{e} (the vault is kept as a tombstone and will be restored on the next unlock: {restore})"
                    ),
                },
            );
        }
        // Committed. Finishing is retried by the next unlock if it fails here.
        let _ = self.in_txn(StateObjectType::VaultManifest, id, || {
            self.retire_tombstone(identity, id)
        });
        Ok(updated)
    }

    fn tombstone_vault(&self, id: &str) -> StoreResult<()> {
        let live = self.vault_dir_v2(id);
        if live.exists() {
            std::fs::rename(&live, self.vault_tombstone(id)).map_err(err)?;
        }
        let legacy = self.vault_path(id);
        if legacy.exists() {
            std::fs::rename(&legacy, self.legacy_vault_tombstone(id)).map_err(err)?;
        }
        let _ = filesec_core::safe_io::sync_dir(&self.vaults_dir);
        Ok(())
    }

    fn restore_tombstone(&self, id: &str) -> StoreResult<()> {
        let tomb = self.vault_tombstone(id);
        if tomb.exists() {
            std::fs::rename(&tomb, self.vault_dir_v2(id)).map_err(err)?;
        }
        let legacy = self.legacy_vault_tombstone(id);
        if legacy.exists() {
            std::fs::rename(&legacy, self.vault_path(id)).map_err(err)?;
        }
        let _ = filesec_core::safe_io::sync_dir(&self.vaults_dir);
        Ok(())
    }

    /// Finish a committed deletion: record the terminal anchor, then wipe.
    fn retire_tombstone(&self, identity: &Identity, id: &str) -> StoreResult<()> {
        {
            let _guard = self
                .lock
                .anchors
                .lock()
                .map_err(|_| "state anchor lock is unavailable".to_string())?;
            self.put_anchor_locked(&deleted_vault_anchor(identity, id))?;
        }
        let tomb = self.vault_tombstone(id);
        if tomb.exists() {
            wipe_vault_dir(&tomb);
        }
        let _ = secure_wipe(&self.legacy_vault_tombstone(id));
        Ok(())
    }

    /// Bring the registry and the vault directories back into agreement after
    /// an interruption (FS-11). Run on every unlock, before the session starts.
    ///
    /// * A `.deleted` tombstone the registry still lists is **restored** (its
    ///   deletion never committed); one it no longer lists is **retired**.
    /// * A committed vault directory the registry does not list (a create or
    ///   import whose registry update failed or was interrupted) is opened —
    ///   which authenticates it and checks its anchor — and registered again.
    ///   Anything that does not open is left in place (or quarantined by the
    ///   anchor check), never deleted.
    ///
    /// Returns the reconciled registry (saved if it changed) and human-readable
    /// notes about what was repaired.
    pub fn reconcile_vaults(
        &self,
        identity: &Identity,
        registry: Registry,
    ) -> StoreResult<(Registry, Vec<String>)> {
        let mut registry = registry;
        let mut notes = Vec::new();
        let mut changed = false;
        for id in self.tombstoned_vaults() {
            if registry.vaults.iter().any(|v| v.id == id) {
                self.in_txn(StateObjectType::VaultManifest, &id, || {
                    self.restore_tombstone(&id)
                })?;
                let name = registry
                    .vaults
                    .iter()
                    .find(|v| v.id == id)
                    .map(|v| v.name.clone())
                    .unwrap_or_default();
                notes.push(format!(
                    "Kept vault \"{name}\": its deletion was interrupted before it completed."
                ));
            } else {
                self.in_txn(StateObjectType::VaultManifest, &id, || {
                    self.retire_tombstone(identity, &id)
                })?;
            }
        }
        for (id, _) in self.v2_vaults() {
            if registry.vaults.iter().any(|v| v.id == id) {
                continue;
            }
            let Ok(reader) = self.open_vault(identity, &id) else {
                continue;
            };
            notes.push(format!(
                "Recovered vault \"{}\", which was saved but missing from the vault list.",
                reader.name()
            ));
            registry.upsert(VaultMeta {
                id,
                name: reader.name().to_string(),
                created_at: reader.created_at(),
                modified_at: now_unix(),
                file_count: reader.file_count() as u64,
                total_size: reader.total_size(),
            });
            changed = true;
        }
        if changed {
            self.save_registry(identity, &registry)?;
        }
        Ok((registry, notes))
    }

    /// Vault ids with a `.deleted` tombstone (v2 directory or legacy file).
    fn tombstoned_vaults(&self) -> Vec<String> {
        let mut ids = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&self.vaults_dir) {
            for entry in rd.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let id = name
                    .strip_suffix(".fsv2.deleted")
                    .or_else(|| name.strip_suffix(".fsec.deleted"));
                if let Some(id) = id {
                    ids.push(id.to_string());
                }
            }
        }
        ids.sort();
        ids.dedup();
        ids
    }

    /// The hardened directory holding checked-out plaintext temp files.
    pub fn checkout_dir(&self) -> &Path {
        &self.checkout_dir
    }

    /// Create an empty checkout temp file under the hardened `checkout/` dir and
    /// return its path. On Unix the file is created with mode 0600 from the
    /// outset (via [`open_private_truncating`]) so decrypted plaintext never
    /// exists with loose permissions.
    ///
    /// The name is a random hex stem plus, at most, `leaf`'s extension — the
    /// vault's own filename is **never** written to disk. The name outlives the
    /// file (recent-items lists, index caches, backups), so leaking it would
    /// leak vault contents; the extension survives only because the OS launchers
    /// need it to pick the right application. See [`temp_extension`].
    pub fn create_private_checkout_file(&self, leaf: &str) -> StoreResult<PathBuf> {
        let stem = random_hex::<8>()?;
        let name = match temp_extension(leaf) {
            Some(ext) => format!("{stem}.{ext}"),
            None => stem,
        };
        let path = self.checkout_dir.join(name);
        open_private_truncating(&path)?;
        Ok(path)
    }

    /// Best-effort secure-wipe of any leftover checkout temp files (e.g. from a
    /// prior crash that bypassed check-in/discard). Called on unlock.
    pub fn clean_checkout_dir(&self) {
        if let Ok(rd) = std::fs::read_dir(&self.checkout_dir) {
            for entry in rd.flatten() {
                let _ = secure_wipe(&entry.path());
            }
        }
    }
}

/// What the OS secure storage says about a store's anchor namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecureProbe {
    /// It answered and holds this store's anchor record: the store is
    /// secure-anchored, whatever the data directory claims.
    Established,
    /// It answered and holds nothing for this store.
    Empty,
    /// It is absent from this build, unreachable, or failed.
    Unreachable,
}

fn probe_secure(secure: Option<&dyn SecureAnchorStorage>, account: &str) -> SecureProbe {
    match secure.map(|s| s.load(account)) {
        Some(Ok(Some(_))) => SecureProbe::Established,
        Some(Ok(None)) => SecureProbe::Empty,
        Some(Err(_)) | None => SecureProbe::Unreachable,
    }
}

/// The unauthenticated `.state-anchor-backend` hint, as found on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BackendMarker {
    Secure,
    Degraded,
    Malformed,
}

fn read_backend_marker(path: &Path) -> Option<BackendMarker> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_BACKEND_MARKER_LEN {
        return Some(BackendMarker::Malformed);
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return Some(BackendMarker::Malformed);
    };
    Some(match text.trim() {
        BACKEND_MARKER_SECURE => BackendMarker::Secure,
        BACKEND_MARKER_DEGRADED => BackendMarker::Degraded,
        _ => BackendMarker::Malformed,
    })
}

fn write_backend_marker(data_dir: &Path, backend: AnchorBackend) -> StoreResult<()> {
    let value = match backend {
        AnchorBackend::SecureStorage => BACKEND_MARKER_SECURE,
        AnchorBackend::DegradedFile => BACKEND_MARKER_DEGRADED,
    };
    let tmp = data_dir.join(".state-anchor-backend.tmp");
    write_private_atomic(
        &tmp,
        &data_dir.join(ANCHORS_BACKEND_FILE),
        format!("{value}\n").as_bytes(),
    )
}

/// Decide where this store's rollback anchors live.
///
/// The `.state-anchor-backend` marker sits in the very directory an attacker is
/// assumed able to roll back, so it is only ever a **hint**. The rules (FS-01):
///
/// * If OS secure storage answers and holds this store's anchor record, the
///   store is secure-anchored — full stop. A marker claiming `degraded`, a
///   missing marker, a malformed one, or a planted `.state-anchors` file cannot
///   downgrade it to file anchors; the marker is repaired instead.
/// * A store that selects secure storage **establishes** its record there
///   immediately (an empty anchor set), so the provenance lives outside the
///   tamperable directory from the very first launch, before any state exists.
/// * A `degraded` marker is honored only when secure storage either holds
///   nothing for this store (it was deliberately file-backed from creation) or
///   cannot be consulted at all. In the latter case the marker cannot be
///   authenticated; that is the documented limit of degraded mode, and the GUI
///   keeps showing the degraded-mode warning.
/// * Every other ambiguity with protected state already on disk fails closed
///   with [`ANCHOR_RECOVERY_REQUIRED`]; moving an established store to another
///   backend takes the explicit, passphrase-authenticated
///   [`Store::recover_rollback_anchors`].
fn select_anchor_backend(
    data_dir: &Path,
    account: &str,
    secure: Option<&dyn SecureAnchorStorage>,
) -> StoreResult<AnchorBackend> {
    let marker = read_backend_marker(&data_dir.join(ANCHORS_BACKEND_FILE));
    let protected_state = keystore_is_v3(&data_dir.join(KEYSTORE_FILE));
    let file_anchors = data_dir.join(ANCHORS_FILE).exists();
    let probe = probe_secure(secure, account);
    let backend = match (probe, marker) {
        (SecureProbe::Established, _) => AnchorBackend::SecureStorage,
        (_, Some(BackendMarker::Malformed)) => {
            return Err(format!(
                "{ANCHOR_RECOVERY_REQUIRED}: the anchor backend marker is malformed"
            ))
        }
        (SecureProbe::Empty, Some(BackendMarker::Secure)) if protected_state => {
            return Err(format!(
                "{ANCHOR_RECOVERY_REQUIRED}: the anchors are missing from OS secure storage; refusing to trust existing protected state"
            ))
        }
        (SecureProbe::Unreachable, Some(BackendMarker::Secure)) => {
            return Err(format!(
                "{ANCHOR_RECOVERY_REQUIRED}: OS secure storage holding this store's anchors is unavailable"
            ))
        }
        (SecureProbe::Empty, Some(BackendMarker::Secure)) => AnchorBackend::SecureStorage,
        (_, Some(BackendMarker::Degraded)) => AnchorBackend::DegradedFile,
        // No marker: only a store's very first launch writes one, so protected
        // state without it means the marker was lost or removed.
        (_, None) if file_anchors => AnchorBackend::DegradedFile,
        (SecureProbe::Empty, None) => AnchorBackend::SecureStorage,
        (SecureProbe::Unreachable, None) if protected_state => {
            return Err(format!(
                "{ANCHOR_RECOVERY_REQUIRED}: the anchor backend marker is missing and OS secure storage is unavailable"
            ))
        }
        (SecureProbe::Unreachable, None) => AnchorBackend::DegradedFile,
    };
    let backend = if backend == AnchorBackend::SecureStorage && probe == SecureProbe::Empty {
        establish_secure_anchor_record(secure, account, protected_state)?
    } else {
        backend
    };
    let wanted = match backend {
        AnchorBackend::SecureStorage => BackendMarker::Secure,
        AnchorBackend::DegradedFile => BackendMarker::Degraded,
    };
    if marker != Some(wanted) {
        write_backend_marker(data_dir, backend)?;
    }
    Ok(backend)
}

/// Write the root record to secure storage so the store's backend is
/// recorded outside the data directory before any protected state exists. A
/// fresh store whose secure storage refuses the write falls back to degraded
/// file anchors (exactly as if secure storage were absent); with protected
/// state already present that fallback would be a silent downgrade, so it fails.
fn establish_secure_anchor_record(
    secure: Option<&dyn SecureAnchorStorage>,
    account: &str,
    protected_state: bool,
) -> StoreResult<AnchorBackend> {
    let bytes = encode_root_record()?;
    match secure.map(|s| s.save(account, &bytes)) {
        Some(Ok(())) => Ok(AnchorBackend::SecureStorage),
        Some(Err(_)) | None if !protected_state => Ok(AnchorBackend::DegradedFile),
        Some(Err(e)) => Err(format!(
            "{ANCHOR_RECOVERY_REQUIRED}: could not record anchors in OS secure storage: {e}"
        )),
        None => Err(format!(
            "{ANCHOR_RECOVERY_REQUIRED}: OS secure storage is not available"
        )),
    }
}

fn keystore_is_v3(path: &Path) -> bool {
    use std::io::Read;
    let mut prefix = [0u8; 6];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut prefix))
        .is_ok()
        && &prefix[..4] == b"FSK\x1a"
        && u16::from_be_bytes([prefix[4], prefix[5]]) == 3
}

/// Write `contents` to a user-chosen `path` with owner-only permissions (0600
/// where the OS supports it) from the outset, so an exported secret (e.g. an
/// identity backup) never briefly exists with loose permissions.
///
/// Routed through [`filesec_core::safe_io::SafeFileWriter`], so the write is
/// atomic (a private temp is fsync'd and renamed into place — a crash leaves the
/// old file or the new one, never a half-written secret) and refuses to write
/// through a symlink planted at `path`.
pub fn write_private_export(path: &Path, contents: &[u8]) -> StoreResult<()> {
    use std::io::Write;
    let mut w = filesec_core::safe_io::SafeFileWriter::create(path).map_err(err)?;
    w.write_all(contents).map_err(err)?;
    w.commit().map_err(err)?;
    Ok(())
}

fn reject_oversized_file(path: &Path, max_len: u64, label: &'static str) -> StoreResult<()> {
    let meta = std::fs::metadata(path).map_err(err)?;
    if !meta.is_file() {
        return Err(format!("{label} is not a file"));
    }
    if meta.len() > max_len {
        return Err(format!("{label} is too large"));
    }
    Ok(())
}

fn read_bounded_file(path: &Path, max_len: u64, label: &'static str) -> StoreResult<Vec<u8>> {
    filesec_core::safe_io::read_bounded_file(path, max_len).map_err(|e| format!("{label}: {e}"))
}

/// Generate a fresh random vault id (hex of 16 random bytes).
pub fn new_vault_id() -> StoreResult<String> {
    random_hex::<16>()
}

fn random_hex<const N: usize>() -> StoreResult<String> {
    random_hex_from(filesec_core::secret::random_array::<N>)
}

fn random_hex_from<const N: usize>(
    rng: impl FnOnce() -> filesec_core::error::Result<[u8; N]>,
) -> StoreResult<String> {
    let bytes = rng().map_err(err)?;
    Ok(filesec_core::util::hex(&bytes))
}

/// The longest tail we will accept as a file extension. Anything longer is far
/// more likely to be part of the name than a real extension, and carrying it
/// onto a temp file would leak exactly what we are hiding.
const MAX_TEMP_EXT: usize = 8;

/// The extension to give a checkout temp file, or `None` for no extension.
///
/// Only a short, purely alphanumeric ASCII tail survives — everything that could
/// carry a recognisable name is dropped — so the temp reveals the file's *type*
/// and nothing more. The OS launchers (`open`, `start`, `xdg-open`) dispatch on
/// the extension, which is the only reason to keep any of the name at all.
fn temp_extension(leaf: &str) -> Option<String> {
    let (stem, ext) = leaf.rsplit_once('.')?;
    // A leading dot is a hidden file (`.bashrc`), not an extension — keeping the
    // tail there would put the whole filename on disk.
    if stem.is_empty() || ext.is_empty() || ext.len() > MAX_TEMP_EXT {
        return None;
    }
    if !ext.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// Write a decrypted vault's contents into `dest` on the real filesystem.
///
/// Refused before anything is written if two entries would alias on a case- or
/// normalization-insensitive destination or a file already exists there
/// ([`filesec_core::vault::preflight_extraction`]).
///
/// Each path is re-validated with [`normalize_path`] (rejecting absolute or
/// traversal paths) and written through [`extract_file_hardened`], so a malicious
/// vault can neither escape `dest` nor make FileSec write plaintext through a
/// symlink planted inside it; a write that fails leaves no partial file.
pub fn extract_vault(vault: &Vault, dest: &Path) -> StoreResult<()> {
    use filesec_core::manifest::EntryKind;
    filesec_core::vault::preflight_extraction(
        dest,
        vault.entries().iter().map(|e| (e.path.as_str(), e.kind)),
    )
    .map_err(err)?;
    for e in vault.entries() {
        match e.kind {
            EntryKind::Dir => extract_dir_hardened(dest, &e.path)?,
            EntryKind::File => extract_file_hardened(dest, &e.path, |w| {
                use std::io::Write;
                w.write_all(&e.content)
                    .map_err(filesec_core::error::Error::from)
            })?,
        }
    }
    Ok(())
}

/// Decrypt/write one vault entry to `root`/`rel` through the hardened
/// [`filesec_core::safe_io::SafeFileWriter`]: `rel` is re-validated as a relative
/// path, parent directories are created without following planted symlinks, a
/// symlinked target is refused, and `fill` streams the plaintext into a private
/// temp that is fsync'd and atomically renamed into place only on success. If
/// `fill` errors (e.g. authentication failed), the temp is discarded and nothing
/// lands at the target.
pub fn extract_file_hardened<F>(root: &Path, rel: &str, fill: F) -> StoreResult<()>
where
    F: FnOnce(&mut filesec_core::safe_io::SafeFileWriter) -> filesec_core::error::Result<()>,
{
    use filesec_core::safe_io::{create_dirs_no_symlink, SafeFileWriter};
    let norm = filesec_core::vault::normalize_path(rel).map_err(err)?;
    let target = root.join(&norm);
    if let Some(parent) = target.parent() {
        create_dirs_no_symlink(root, parent).map_err(err)?;
    }
    let mut w = SafeFileWriter::create(&target).map_err(err)?;
    fill(&mut w).map_err(err)?;
    w.commit().map_err(err)?;
    Ok(())
}

/// Create a (possibly nested) directory subtree for `rel` under `root` through the
/// symlink-rejecting helper. `rel` is re-validated as a relative path first.
pub fn extract_dir_hardened(root: &Path, rel: &str) -> StoreResult<()> {
    let norm = filesec_core::vault::normalize_path(rel).map_err(err)?;
    filesec_core::safe_io::create_dirs_no_symlink(root, &root.join(norm)).map_err(err)
}

/// Best-effort: restore owner write permission on a file that was marked
/// read-only, so it can be overwritten. On Unix this sets mode `0600` (owner-only)
/// rather than clearing the read-only bit globally (which would be world-writable).
#[cfg(unix)]
fn restore_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restore_writable(path: &Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        let _ = std::fs::set_permissions(path, perms);
    }
}

/// Best-effort secure deletion of a v2 vault directory: wipe the header, the
/// manifest, and every blob, then remove the directory tree.
fn wipe_vault_dir(dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(dir.join("blobs")) {
        for e in rd.flatten() {
            let _ = secure_wipe(&e.path());
        }
    }
    let _ = secure_wipe(&dir.join("manifest"));
    let _ = secure_wipe(&dir.join("header"));
    let _ = std::fs::remove_dir_all(dir);
}

/// Best-effort secure deletion: overwrite the file's current length with random
/// bytes, fsync, then unlink. A no-op if the file is absent.
///
/// LIMITATIONS — this is best-effort, **not** forensic-grade. On flash/SSD
/// storage (wear leveling, block remapping, over-provisioning), copy-on-write
/// filesystems (APFS, Btrfs, ZFS), and journaling filesystems, an in-place
/// overwrite is **not guaranteed** to land on the same physical blocks that held
/// the plaintext, so remnants may survive. It also cannot reach editor swap or
/// backup files created elsewhere. This matches the README threat model
/// (endpoint compromise and OS-level remnants are out of scope); it raises the
/// bar against casual recovery only.
pub fn secure_wipe(path: &Path) -> StoreResult<()> {
    use std::io::{Seek, SeekFrom, Write};
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(err(e)),
    };
    // A cleanup sweep must never overwrite a symlink's target or a special file.
    if meta.file_type().is_symlink() {
        return std::fs::remove_file(path).map_err(err);
    }
    if !meta.is_file() {
        return Err("refusing to wipe a non-regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() > 1 {
            return std::fs::remove_file(path).map_err(err);
        }
    }
    let len = meta.len();
    // Read-only files (e.g. view temps) can't be opened for writing; restore
    // owner write first so we can overwrite before unlinking.
    if meta.permissions().readonly() {
        restore_writable(path);
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(err)?;
    f.seek(SeekFrom::Start(0)).map_err(err)?;
    let block = 64 * 1024u64;
    let mut written = 0u64;
    while written < len {
        let n = (len - written).min(block) as usize;
        let buf = filesec_core::secret::random_vec(n).map_err(err)?;
        f.write_all(&buf).map_err(err)?;
        written += n as u64;
    }
    f.flush().map_err(err)?;
    f.sync_all().map_err(err)?;
    drop(f);
    std::fs::remove_file(path).map_err(err)?;
    Ok(())
}

/// Best-effort: mark `path` read-only, signalling "look, don't edit" for a
/// view temp. Advisory only — many apps ignore it, and [`secure_wipe`] restores
/// writability before overwriting.
pub fn make_readonly(path: &Path) -> StoreResult<()> {
    let mut perms = std::fs::metadata(path).map_err(err)?.permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(path, perms).map_err(err)
}

/// Open (creating, truncating) a file for writing with owner-only permissions
/// from the outset where the OS supports it, so secret bytes never exist with
/// loose perms. Returns the open handle.
#[cfg(unix)]
fn open_private_create(path: &Path) -> StoreResult<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(err)
}

#[cfg(not(unix))]
fn open_private_create(path: &Path) -> StoreResult<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(err)
}

/// Create an empty private (0600 where supported) file at `path`.
fn open_private_truncating(path: &Path) -> StoreResult<()> {
    open_private_create(path).map(drop)
}

/// Atomically write `bytes` to `final_path` via a private temp file that is
/// fsync'd and renamed into place, then best-effort fsync the directory so the
/// rename is durable. A crash can leave the old file or the new one, never a
/// half-written one. The temp is cleaned up on any failure.
fn write_private_atomic(_tmp: &Path, final_path: &Path, bytes: &[u8]) -> StoreResult<()> {
    write_private_export(final_path, bytes)
}

#[cfg(unix)]
fn harden_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(unix)]
fn harden_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn harden_file(_path: &Path) {}

#[cfg(not(unix))]
fn harden_dir(_path: &Path) {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn random_hex_propagates_rng_failure() {
        let result = random_hex_from::<16>(|| Err(filesec_core::error::Error::Rng));
        assert!(result
            .unwrap_err()
            .contains("secure random number generation failed"));
    }

    #[test]
    fn random_hex_encodes_successful_rng_output() {
        let result = random_hex_from::<4>(|| Ok([0xab, 0xcd, 0x01, 0x23])).unwrap();
        assert_eq!(result, "abcd0123");
    }

    #[test]
    fn temp_extension_keeps_a_short_alphanumeric_tail() {
        assert_eq!(temp_extension("report.pdf").as_deref(), Some("pdf"));
        assert_eq!(temp_extension("archive.tar.gz").as_deref(), Some("gz"));
        assert_eq!(temp_extension("PHOTO.JPG").as_deref(), Some("jpg"));
        assert_eq!(
            temp_extension("Q4 salary report.pdf").as_deref(),
            Some("pdf")
        );
    }

    #[test]
    fn temp_extension_rejects_anything_that_could_carry_a_name() {
        // No extension at all.
        assert_eq!(temp_extension("no-extension"), None);
        // Hidden files: the tail is the whole name.
        assert_eq!(temp_extension(".bashrc"), None);
        assert_eq!(temp_extension(".env"), None);
        // Trailing dot.
        assert_eq!(temp_extension("weird."), None);
        // Non-alphanumeric or unicode tails.
        assert_eq!(temp_extension("weird.p df"), None);
        assert_eq!(temp_extension("notes.rés"), None);
        // Implausibly long tail — probably part of the name.
        assert_eq!(temp_extension("x.VERYLONGSUFFIX"), None);
    }

    #[test]
    fn checkout_temp_name_leaks_nothing_but_the_extension() {
        let dir = tmp("checkout-name");
        let store = Store::at(&dir).unwrap();
        let leaf = "Q4 salary report.pdf";
        let path = store.create_private_checkout_file(leaf).unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.ends_with(".pdf"), "extension must survive: {name}");
        for word in ["Q4", "salary", "report"] {
            assert!(
                !name
                    .to_ascii_lowercase()
                    .contains(&word.to_ascii_lowercase()),
                "temp name {name} leaks {word:?} from {leaf:?}"
            );
        }
        // 16 hex chars + '.' + "pdf"
        assert_eq!(name.len(), 20, "unexpected temp name shape: {name}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn checkout_temp_name_omits_the_dot_when_there_is_no_extension() {
        let dir = tmp("checkout-noext");
        let store = Store::at(&dir).unwrap();
        let path = store.create_private_checkout_file("Minutes 2026").unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(name.len(), 16, "expected a bare hex stem: {name}");
        assert!(name.chars().all(|c| c.is_ascii_hexdigit()), "{name}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tmp(name: &str) -> PathBuf {
        let suffix = filesec_core::util::hex(&filesec_core::secret::random_array::<8>().unwrap());
        std::env::temp_dir().join(format!("filesec-store-bounds-{suffix}-{name}"))
    }

    #[test]
    fn load_keystore_rejects_oversized_file_before_read() {
        let dir = tmp("keystore");
        let store = Store::at(&dir).unwrap();
        std::fs::File::create(store.keystore_path())
            .unwrap()
            .set_len(MAX_KEYSTORE_FILE_LEN + 1)
            .unwrap();
        match store.load_keystore() {
            Ok(_) => panic!("oversized keystore unexpectedly loaded"),
            Err(e) => assert!(e.contains("too large")),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_registry_rejects_oversized_local_blob_before_read() {
        let dir = tmp("registry");
        let store = Store::at(&dir).unwrap();
        let identity = Identity::generate("Alice", 0).unwrap();
        std::fs::File::create(store.index_path())
            .unwrap()
            .set_len(MAX_SELF_BLOB_CONTAINER_LEN + 1)
            .unwrap();
        assert!(store
            .load_registry(&identity)
            .unwrap_err()
            .contains("too large"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_contacts_and_registry_require_explicit_recovery() {
        let dir = tmp("legacy-metadata");
        let store = Store::at(&dir).unwrap();
        let identity = Identity::generate("Alice", 0).unwrap();
        let mut contacts = ContactBook::default();
        contacts.upsert(Identity::generate("Bob", 0).unwrap().public(), 1);
        store
            .save_blob(
                &identity,
                &store.contacts_path(),
                CONTACTS_BLOB,
                &contacts.to_bytes().unwrap(),
            )
            .unwrap();
        let mut registry = Registry::default();
        registry.upsert(VaultMeta {
            id: "legacy".into(),
            name: "Legacy".into(),
            created_at: 1,
            modified_at: 1,
            file_count: 0,
            total_size: 0,
        });
        store
            .save_blob(
                &identity,
                &store.index_path(),
                REGISTRY_BLOB,
                &filesec_core::codec::to_vec(&registry).unwrap(),
            )
            .unwrap();

        assert!(store
            .load_contacts(&identity)
            .unwrap_err()
            .contains("legacy"));
        assert!(store
            .load_registry(&identity)
            .unwrap_err()
            .contains("legacy"));
        assert_eq!(
            store
                .recover_legacy_contacts(&identity)
                .unwrap()
                .contacts
                .len(),
            1
        );
        assert_eq!(
            store
                .recover_legacy_registry(&identity)
                .unwrap()
                .vaults
                .len(),
            1
        );
        assert_eq!(store.load_contacts(&identity).unwrap().contacts.len(), 1);
        assert_eq!(store.load_registry(&identity).unwrap().vaults.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[cfg(unix)]
    #[test]
    fn cleanup_unlinks_symlinks_and_hardlinks_without_overwriting_targets() {
        let dir = tmp("wipe-links");
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("original");
        std::fs::write(&victim, b"keep this file").unwrap();
        let symlink = dir.join("symlink");
        std::os::unix::fs::symlink(&victim, &symlink).unwrap();
        secure_wipe(&symlink).unwrap();
        let hardlink = dir.join("hardlink");
        std::fs::hard_link(&victim, &hardlink).unwrap();
        secure_wipe(&hardlink).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep this file");
        assert!(std::fs::symlink_metadata(&symlink).is_err());
        assert!(!hardlink.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
