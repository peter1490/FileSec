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
use filesec_core::identity::Identity;
use filesec_core::keystore::KeystoreFile;
use filesec_core::util::now_unix;
use filesec_core::vault::Vault;

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

    /// Whether an identity has already been created.
    pub fn keystore_exists(&self) -> bool {
        self.keystore_path().exists()
    }

    /// Persist the passphrase-protected keystore.
    pub fn save_keystore(&self, ks: &KeystoreFile) -> StoreResult<()> {
        let bytes = ks.to_bytes().map_err(err)?;
        std::fs::write(self.keystore_path(), bytes).map_err(err)?;
        harden_file(&self.keystore_path());
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
            &ExportOptions::default(),
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

    /// Persist a vault to its local encrypted file.
    pub fn save_vault(&self, identity: &Identity, id: &str, vault: &Vault) -> StoreResult<()> {
        format::export_vault_to_path(
            vault,
            identity,
            &[identity.public()],
            &ExportOptions::default(),
            &self.vault_path(id),
        )
        .map_err(err)?;
        harden_file(&self.vault_path(id));
        Ok(())
    }

    /// Load a vault fully into memory (used for mutation and re-export, which
    /// need the entire plaintext).
    pub fn load_vault(&self, identity: &Identity, id: &str) -> StoreResult<Vault> {
        let imported =
            format::import_vault_from_path(&self.vault_path(id), identity).map_err(err)?;
        Ok(imported.vault)
    }

    /// Lazily open a vault: authenticate and load only the manifest (metadata),
    /// decrypting file contents on demand. Cheap even for very large vaults.
    pub fn open_vault(&self, identity: &Identity, id: &str) -> StoreResult<format::VaultReader> {
        format::open_vault_from_path(&self.vault_path(id), identity).map_err(err)
    }

    /// Add files (streamed from disk) and empty directories to an existing vault
    /// **without** decrypting it into memory: the new container is written from
    /// `reader` (which streams the existing data) plus the new files, to a temp
    /// file that atomically replaces the vault. Peak memory is a couple of chunks
    /// regardless of vault or file size.
    pub fn append_files_to_vault(
        &self,
        identity: &Identity,
        id: &str,
        reader: &format::VaultReader,
        added: &[format::AddedFile],
        added_dirs: &[String],
    ) -> StoreResult<()> {
        let final_path = self.vault_path(id);
        let tmp = self.vaults_dir.join(format!("{id}.fsec.tmp"));
        if let Err(e) = reader.append_files_to_path(
            identity,
            &[identity.public()],
            &ExportOptions::default(),
            added,
            added_dirs,
            &tmp,
        ) {
            let _ = std::fs::remove_file(&tmp); // don't leave a partial temp behind
            return Err(err(e));
        }
        std::fs::rename(&tmp, &final_path).map_err(err)?;
        harden_file(&final_path);
        Ok(())
    }

    /// Remove paths (each entry plus, for a directory, its subtree) from an
    /// existing vault **without** decrypting it into memory: the new container is
    /// streamed from `reader` minus the removed files, to a temp file that
    /// atomically replaces the vault.
    pub fn remove_paths_from_vault(
        &self,
        identity: &Identity,
        id: &str,
        reader: &format::VaultReader,
        remove: &[String],
    ) -> StoreResult<()> {
        let final_path = self.vault_path(id);
        let tmp = self.vaults_dir.join(format!("{id}.fsec.tmp"));
        if let Err(e) = reader.remove_paths_to_path(
            identity,
            &[identity.public()],
            &ExportOptions::default(),
            remove,
            &tmp,
        ) {
            let _ = std::fs::remove_file(&tmp);
            return Err(err(e));
        }
        std::fs::rename(&tmp, &final_path).map_err(err)?;
        harden_file(&final_path);
        Ok(())
    }

    /// Replace a single file's contents inside an existing vault **without**
    /// decrypting it into memory: the new container is streamed from `reader`
    /// (the old file's bytes dropped, the new file appended from disk) to a temp
    /// file that atomically replaces the vault. Peak memory is a couple of chunks.
    #[allow(clippy::too_many_arguments)]
    pub fn replace_file_in_vault(
        &self,
        identity: &Identity,
        id: &str,
        reader: &format::VaultReader,
        vault_path: &str,
        new_source: &Path,
        mtime: Option<i64>,
        mode: Option<u32>,
    ) -> StoreResult<()> {
        let final_path = self.vault_path(id);
        let tmp = self.vaults_dir.join(format!("{id}.fsec.tmp"));
        if let Err(e) = reader.replace_file_to_path(
            identity,
            &[identity.public()],
            &ExportOptions::default(),
            vault_path,
            new_source,
            mtime,
            mode,
            &tmp,
        ) {
            let _ = std::fs::remove_file(&tmp);
            return Err(err(e));
        }
        std::fs::rename(&tmp, &final_path).map_err(err)?;
        harden_file(&final_path);
        Ok(())
    }

    /// Transcode a just-verified incoming container straight into the local
    /// self-encrypted store, **streaming** from `reader` so a huge imported file
    /// is never held in memory. Writes to the (new) vault path directly — there is
    /// no existing file to preserve — and cleans up on failure.
    pub fn import_reader_to_vault(
        &self,
        identity: &Identity,
        id: &str,
        reader: &format::VaultReader,
    ) -> StoreResult<()> {
        let path = self.vault_path(id);
        if let Err(e) = reader.reexport_to_path(
            identity,
            &[identity.public()],
            &ExportOptions::default(),
            &path,
        ) {
            let _ = std::fs::remove_file(&path);
            return Err(err(e));
        }
        harden_file(&path);
        Ok(())
    }

    /// Delete a vault's encrypted file.
    pub fn delete_vault_file(&self, id: &str) -> StoreResult<()> {
        let p = self.vault_path(id);
        if p.exists() {
            std::fs::remove_file(&p).map_err(err)?;
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

/// Create (truncating) a file for writing with owner-only permissions from the
/// outset where the OS supports it, so plaintext never exists with loose perms.
#[cfg(unix)]
fn open_private_truncating(path: &Path) -> StoreResult<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(err)?;
    Ok(())
}

#[cfg(not(unix))]
fn open_private_truncating(path: &Path) -> StoreResult<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(err)?;
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
