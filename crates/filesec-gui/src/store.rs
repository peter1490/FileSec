//! On-disk persistence for the desktop app.
//!
//! Everything except the passphrase-protected keystore is stored as a FileSec
//! container encrypted to the user's own identity, so vault names, the contact
//! list, and the vault registry are all confidential at rest — not just file
//! contents. Files are created with restrictive permissions where the OS
//! supports it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use filesec_core::contacts::ContactBook;
use filesec_core::format::{self, ExportOptions};
use filesec_core::format_v2::VaultReaderV2;
use filesec_core::identity::Identity;
use filesec_core::keystore::KeystoreFile;
use filesec_core::util::now_unix;
use filesec_core::vault::Vault;
use filesec_core::SuiteId;

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
}

impl Store {
    /// Discover (and create) the per-OS application data directory.
    ///
    /// Honors the `FILESEC_DATA_DIR` environment variable as an override
    /// (useful for portable installs and tests); otherwise uses the standard
    /// per-OS location via `directories`.
    pub fn discover() -> StoreResult<Self> {
        if let Some(dir) = std::env::var_os("FILESEC_DATA_DIR") {
            return Self::at(PathBuf::from(dir));
        }
        let pd = directories::ProjectDirs::from("dev", "FileSec", "FileSec")
            .ok_or_else(|| "could not determine the application data directory".to_string())?;
        Self::at(pd.data_dir().to_path_buf())
    }

    /// Open (and create) a store rooted at a specific directory.
    pub fn at(data_dir: impl Into<PathBuf>) -> StoreResult<Self> {
        let data_dir = data_dir.into();
        let vaults_dir = data_dir.join("vaults");
        let checkout_dir = data_dir.join("checkout");
        std::fs::create_dir_all(&vaults_dir).map_err(err)?;
        std::fs::create_dir_all(&checkout_dir).map_err(err)?;
        harden_dir(&data_dir);
        harden_dir(&vaults_dir);
        harden_dir(&checkout_dir);
        Ok(Self {
            data_dir,
            vaults_dir,
            checkout_dir,
        })
    }

    /// The application data directory (shown in the UI).
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
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
        let bytes = ks.to_bytes().map_err(err)?;
        let final_path = self.keystore_path();
        let tmp = self.data_dir.join("keystore.fsk.tmp");
        write_private_atomic(&tmp, &final_path, &bytes)?;
        harden_file(&final_path);
        Ok(())
    }

    /// Load the keystore (still encrypted — call `unlock`).
    pub fn load_keystore(&self) -> StoreResult<KeystoreFile> {
        let bytes = std::fs::read(self.keystore_path()).map_err(err)?;
        KeystoreFile::from_bytes(&bytes).map_err(err)
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
    ) -> StoreResult<Option<Vec<u8>>> {
        if !path.exists() {
            return Ok(None);
        }
        let imported = format::import_vault_from_path(path, identity).map_err(err)?;
        match imported.vault.get(name) {
            Some(e) => Ok(Some(e.content.to_vec())),
            None => Err("stored blob is missing its entry".to_string()),
        }
    }

    /// Load the contact book (empty if none yet).
    pub fn load_contacts(&self, identity: &Identity) -> StoreResult<ContactBook> {
        match self.load_blob(identity, &self.contacts_path(), CONTACTS_BLOB)? {
            Some(bytes) => ContactBook::from_bytes(&bytes).map_err(err),
            None => Ok(ContactBook::default()),
        }
    }

    /// Persist the contact book.
    pub fn save_contacts(&self, identity: &Identity, book: &ContactBook) -> StoreResult<()> {
        let bytes = book.to_bytes().map_err(err)?;
        self.save_blob(identity, &self.contacts_path(), CONTACTS_BLOB, &bytes)
    }

    /// Load the vault registry (empty if none yet).
    pub fn load_registry(&self, identity: &Identity) -> StoreResult<Registry> {
        match self.load_blob(identity, &self.index_path(), REGISTRY_BLOB)? {
            Some(bytes) => filesec_core::codec::from_slice(&bytes).map_err(err),
            None => Ok(Registry::default()),
        }
    }

    /// Persist the vault registry.
    pub fn save_registry(&self, identity: &Identity, registry: &Registry) -> StoreResult<()> {
        let bytes = filesec_core::codec::to_vec(registry).map_err(err)?;
        self.save_blob(identity, &self.index_path(), REGISTRY_BLOB, &bytes)
    }

    /// Persist a (typically new) vault to its local v2 store directory, encrypted
    /// to the identity itself under the identity's at-rest suite.
    pub fn save_vault(&self, identity: &Identity, id: &str, vault: &Vault) -> StoreResult<()> {
        let dir = self.vault_dir_v2(id);
        // Start from a clean directory: vault ids are random so this is normally a
        // no-op, but it makes an overwrite well-defined (no stale blobs linger).
        let _ = std::fs::remove_dir_all(&dir);
        VaultReaderV2::from_vault(&dir, identity, self_suite(identity), vault).map_err(err)?;
        Ok(())
    }

    /// Load a vault fully into memory (used by tests and any caller needing the
    /// whole plaintext). Opens the vault — migrating a legacy v1 container to v2
    /// if needed — and decrypts every file.
    pub fn load_vault(&self, identity: &Identity, id: &str) -> StoreResult<Vault> {
        self.open_vault(identity, id)?.to_vault().map_err(err)
    }

    /// Lazily open a vault (metadata only; file contents decrypt on demand). A
    /// legacy v1 `.fsec` container is transparently migrated to the v2 directory
    /// format on first open (crash-safe; see [`Self::migrate_vault_v1_to_v2`]).
    pub fn open_vault(&self, identity: &Identity, id: &str) -> StoreResult<VaultReaderV2> {
        let v2 = self.vault_dir_v2(id);
        if v2.exists() {
            // A crash after the migration commit but before the old file was
            // wiped can leave the v1 container behind; the v2 dir wins.
            let v1 = self.vault_path(id);
            if v1.exists() {
                let _ = secure_wipe(&v1);
            }
            return VaultReaderV2::open(&v2, identity).map_err(err);
        }
        if self.vault_path(id).exists() {
            self.migrate_vault_v1_to_v2(identity, id)?;
            return VaultReaderV2::open(&v2, identity).map_err(err);
        }
        Err(format!("vault not found: {id}"))
    }

    /// Crash-safe lazy migration of a legacy v1 `.fsec` vault to the v2 directory
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
        let reader = format::open_vault_from_path(&v1, identity).map_err(err)?;
        if let Err(e) =
            VaultReaderV2::from_reader_v1(&partial, identity, self_suite(identity), &reader)
        {
            let _ = std::fs::remove_dir_all(&partial);
            return Err(err(e));
        }
        std::fs::rename(&partial, &final_dir).map_err(err)?;
        if let Ok(d) = std::fs::File::open(&self.vaults_dir) {
            let _ = d.sync_all();
        }
        let _ = secure_wipe(&v1);
        Ok(())
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
        let mut writer = reader.clone();
        for d in added_dirs {
            writer.mkdir(d).map_err(err)?;
        }
        for f in added {
            writer
                .put_file(&f.vault_path, &f.source, f.mtime, f.mode)
                .map_err(err)?;
        }
        Ok(())
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
        let mut writer = reader.clone();
        for p in remove {
            writer.remove_path(p).map_err(err)?;
        }
        Ok(())
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
        let mut writer = reader.clone();
        writer
            .put_file(vault_path, new_source, mtime, mode)
            .map_err(err)?;
        Ok(())
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
        let dir = self.vault_dir_v2(id);
        let _ = std::fs::remove_dir_all(&dir);
        if let Err(e) = VaultReaderV2::from_reader_v1(&dir, identity, self_suite(identity), reader)
        {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(err(e));
        }
        Ok(())
    }

    /// Delete a vault's encrypted store, securely wiping its contents. Handles
    /// both the v2 directory and any leftover legacy v1 `.fsec` file.
    pub fn delete_vault_file(&self, id: &str) -> StoreResult<()> {
        let dir = self.vault_dir_v2(id);
        if dir.exists() {
            wipe_vault_dir(&dir);
        }
        let v1 = self.vault_path(id);
        if v1.exists() {
            let _ = secure_wipe(&v1);
        }
        Ok(())
    }

    /// The hardened directory holding checked-out plaintext temp files.
    pub fn checkout_dir(&self) -> &Path {
        &self.checkout_dir
    }

    /// Create an empty checkout temp file under the hardened `checkout/` dir and
    /// return its path. On Unix the file is created with mode 0600 from the
    /// outset (via [`open_private_truncating`]) so decrypted plaintext never
    /// exists with loose permissions. A random hex prefix guarantees uniqueness;
    /// `leaf` (a sanitized display name, extension intact) is appended so the OS
    /// opens it with the right application.
    pub fn create_private_checkout_file(&self, leaf: &str) -> StoreResult<PathBuf> {
        let stem = filesec_core::util::hex(
            &filesec_core::secret::random_vec(8).unwrap_or_else(|_| vec![0u8; 8]),
        );
        let name = if leaf.is_empty() {
            stem
        } else {
            format!("{stem}-{leaf}")
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

    /// Every self-encrypted store file that currently exists: the registry, the
    /// contact book, and each vault container. (The keystore is *not* one of
    /// these — it is passphrase-sealed, not encrypted to the identity.)
    #[cfg(feature = "pqc")]
    fn self_encrypted_files(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        for p in [self.index_path(), self.contacts_path()] {
            if p.exists() {
                paths.push(p);
            }
        }
        if let Ok(rd) = std::fs::read_dir(&self.vaults_dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                // Only finished `.fsec` vaults — never a stray `*.tmp` from an
                // interrupted write or migration.
                if p.extension().and_then(|s| s.to_str()) == Some("fsec") {
                    paths.push(p);
                }
            }
        }
        paths
    }

    /// Re-encrypt every self-encrypted store file so it is signed by `opener` and
    /// addressed to `recipients` under `options`. Each file is rewritten atomically
    /// (temp + rename).
    #[cfg(feature = "pqc")]
    fn reencrypt_all(
        &self,
        opener: &Identity,
        recipients: &[filesec_core::PublicIdentity],
        options: &ExportOptions,
    ) -> StoreResult<()> {
        for path in self.self_encrypted_files() {
            let reader = format::open_vault_from_path(&path, opener).map_err(err)?;
            let tmp = path.with_extension("migrate-tmp");
            if let Err(e) = reader.reexport_to_path(opener, recipients, options, &tmp) {
                let _ = std::fs::remove_file(&tmp);
                return Err(err(e));
            }
            std::fs::rename(&tmp, &path).map_err(err)?;
            harden_file(&path);
        }
        Ok(())
    }

    /// List every v2 vault directory in the store.
    #[cfg(feature = "pqc")]
    fn v2_vault_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&self.vaults_dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() && p.extension().and_then(|s| s.to_str()) == Some("fsv2") {
                    dirs.push(p);
                }
            }
        }
        dirs
    }

    /// Re-key every v2 vault to `suite`, addressed to `opener` — the post-quantum
    /// migration's harden phase. Crash-safe per vault: the new directory is built
    /// in `<dir>.partial`, the current dir is moved aside to `<dir>.old`, the new
    /// dir is renamed into place, then `.old` is removed. `clean_partial_dirs`
    /// rolls back an interruption. Idempotent — a vault already on `suite` is left
    /// alone. (`opener` shares the pre-migration X25519 key, so it can still open a
    /// classical vault here; hardening to the hybrid suite is what re-establishes
    /// confidentiality from the old fingerprint.)
    #[cfg(feature = "pqc")]
    fn reencrypt_v2_vaults(&self, opener: &Identity, suite: SuiteId) -> StoreResult<()> {
        for dir in self.v2_vault_dirs() {
            let current = VaultReaderV2::open(&dir, opener).map_err(err)?;
            if current.suite() == suite {
                continue;
            }
            let vault = current.to_vault().map_err(err)?;
            drop(current);
            let mut partial = dir.clone().into_os_string();
            partial.push(".partial");
            let partial = PathBuf::from(partial);
            let mut old = dir.clone().into_os_string();
            old.push(".old");
            let old = PathBuf::from(old);
            let _ = std::fs::remove_dir_all(&partial);
            if let Err(e) = VaultReaderV2::from_vault(&partial, opener, suite, &vault) {
                let _ = std::fs::remove_dir_all(&partial);
                return Err(err(e));
            }
            std::fs::rename(&dir, &old).map_err(err)?;
            std::fs::rename(&partial, &dir).map_err(err)?;
            let _ = std::fs::remove_dir_all(&old);
        }
        Ok(())
    }

    /// Migrate a classical identity to a hybrid (post-quantum) one, re-encrypting
    /// the entire local store to the new identity. Returns the new identity.
    ///
    /// **Crash-safe by construction.** Re-sealing the keystore is the atomic
    /// commit point; before it every store file is readable by *both* identities,
    /// and after it by the *new* one — so an interruption at any step never locks
    /// you out:
    ///
    /// 1. **Bridge** — re-encrypt every store file to `[old, new]` under the
    ///    classical suite. Both identities can open it, and the keystore still
    ///    holds `old`, so a crash here leaves everything openable by `old`
    ///    (re-running the migration is safe).
    /// 2. **Commit** — re-seal the keystore to `new`. After this the app is hybrid
    ///    and the bridged files (which list `new` as a recipient) all open.
    /// 3. **Harden** — re-encrypt every store file to `[new]` only under the
    ///    hybrid suite, giving post-quantum protection at rest. If interrupted
    ///    here, `new` still opens every file and a later normal save (which uses
    ///    [`self_options`]) finishes upgrading any stragglers.
    ///
    /// The new identity has a **new fingerprint** — the caller must re-share its
    /// public key and have contacts re-verify the new safety number. Any `.fsec`
    /// addressed to the *old* fingerprint that has not been imported yet should be
    /// imported before migrating.
    #[cfg(feature = "pqc")]
    pub fn migrate_to_hybrid(
        &self,
        old: &Identity,
        passphrase: &[u8],
        kdf: filesec_core::kdf::KdfParams,
    ) -> StoreResult<Identity> {
        if old.is_hybrid_capable() {
            return Err("this identity is already post-quantum".to_string());
        }
        let new = old.upgraded_to_hybrid().map_err(err)?;

        // 1. Bridge: classical suite, addressed to both identities.
        let bridge = [old.public(), new.public()];
        let classic = ExportOptions {
            suite: SuiteId::Classic,
            ..ExportOptions::default()
        };
        self.reencrypt_all(old, &bridge, &classic)?;

        // 2. Commit: the keystore now holds the hybrid identity.
        let ks = KeystoreFile::create(&new, passphrase, kdf).map_err(err)?;
        self.save_keystore(&ks)?;

        // 3. Harden: hybrid suite, addressed to the new identity only.
        let new_only = [new.public()];
        let hybrid = ExportOptions {
            suite: SuiteId::Hybrid,
            ..ExportOptions::default()
        };
        self.reencrypt_all(&new, &new_only, &hybrid)?;
        // v2 vault directories aren't `.fsec` files, so `reencrypt_all` skipped
        // them; re-key each to the new hybrid suite (addressed to `new`).
        self.reencrypt_v2_vaults(&new, SuiteId::Hybrid)?;

        Ok(new)
    }
}

/// Generate a fresh random vault id (hex of 16 random bytes).
pub fn new_vault_id() -> String {
    let bytes = filesec_core::secret::random_vec(16).unwrap_or_else(|_| vec![0u8; 16]);
    filesec_core::util::hex(&bytes)
}

/// Write a decrypted vault's contents into `dest` on the real filesystem.
///
/// Every entry path is already normalized (relative, no `..`), so joining it
/// under `dest` cannot escape the destination directory.
pub fn extract_vault(vault: &Vault, dest: &Path) -> StoreResult<()> {
    use filesec_core::manifest::EntryKind;
    for e in vault.entries() {
        let target = dest.join(&e.path);
        match e.kind {
            EntryKind::Dir => {
                std::fs::create_dir_all(&target).map_err(err)?;
            }
            EntryKind::File => {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(err)?;
                }
                std::fs::write(&target, &e.content).map_err(err)?;
            }
        }
    }
    Ok(())
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
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(()), // absent (or unreadable) — nothing to wipe
    };
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
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(err)
}

#[cfg(not(unix))]
fn open_private_create(path: &Path) -> StoreResult<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
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
fn write_private_atomic(tmp: &Path, final_path: &Path, bytes: &[u8]) -> StoreResult<()> {
    use std::io::Write;
    let mut f = open_private_create(tmp)?;
    let write = (|| {
        f.write_all(bytes)?;
        f.flush()?;
        f.sync_all()
    })();
    drop(f);
    if let Err(e) = write {
        let _ = std::fs::remove_file(tmp);
        return Err(err(e));
    }
    if let Err(e) = std::fs::rename(tmp, final_path) {
        let _ = std::fs::remove_file(tmp);
        return Err(err(e));
    }
    // Best-effort: fsync the containing directory so the rename itself survives a
    // crash. Not all platforms/filesystems support directory fsync; ignore errors.
    if let Some(parent) = final_path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
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
