//! The `.fsv2` **at-rest vault format**: a directory of independently encrypted
//! per-file blobs, so adding, editing, deleting, renaming, or re-permissioning a
//! single file rewrites only that file's blob plus the (small) manifest — O(the
//! change), never O(the whole vault) as the single-stream [`crate::format`]
//! container requires.
//!
//! This format is used **only for the local working store** (encrypted to
//! yourself). Cross-party transport keeps using the signed single-stream `.fsec`
//! v1 container unchanged: [`VaultReaderV2::to_vault`] reconstructs an in-memory
//! [`Vault`] for export, and [`VaultReaderV2::from_reader_v1`] unpacks an
//! imported v1 container into a fresh v2 directory.
//!
//! # On-disk layout
//! ```text
//! <vault>.fsv2/
//!   header           CBOR(VaultHeaderV2), plaintext — bound as AAD everywhere
//!   manifest         nonce ‖ AEAD(CBOR(ManifestV2)), AAD = header bytes
//!   blobs/<file_id>  per-file STREAM ciphertext (chunk-aligned), AAD = header bytes
//! ```
//!
//! # Keys & integrity
//! A random **manifest key** is wrapped once to the owning identity via
//! [`crate::envelope`] (so a hybrid identity gets ML-KEM-at-rest for free) and
//! stored in the header's stanza. The sealed manifest then holds, per file, a
//! **fresh random blob key + nonce**; every blob write draws new ones, so STREAM
//! nonce uniqueness is structural — there are no counters to keep. The plaintext
//! `header` (suite id + vault id + stanza) is fed as AAD into the manifest AEAD
//! and every blob STREAM, so a tampered/downgraded suite fails authentication.
//! The header is stable for the vault's life (only the manifest nonce and blob
//! keys rotate), so a normal mutation never invalidates other files' blobs.
//!
//! [`VaultReaderV2::read_entry_to_writer`] reads every chunk and verifies the
//! file's whole-file BLAKE3 as it streams.

use std::io::{BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::envelope::{self, RecipientStanza};
use crate::error::{Error, Result};
use crate::format::{hash_path, ContainerPlan, ExportOptions, VaultReader};
use crate::identity::{Identity, PublicIdentity};
use crate::manifest::{Entry, EntryKind, Manifest};
use crate::secret::{ct_eq, random_array, SymKey};
use crate::suite::SuiteId;
use crate::vault::{normalize_path, Vault};
use crate::{aead, codec};

const HEADER_FILE: &str = "header";
const MANIFEST_FILE: &str = "manifest";
const BLOBS_DIR: &str = "blobs";
/// Reserved top-level directory holding soft-deleted ("trashed") entries. It is a
/// **local-only** convention: trashed entries are still real, encrypted blobs in
/// the manifest (so they can be restored), but they are deliberately excluded
/// from anything that leaves the vault — [`VaultReaderV2::to_vault_for_export`]
/// (and therefore [`export_v2_to_path`]) skips this subtree, so a file you put in
/// the trash never travels inside a `.fsec` you send to someone else.
pub const TRASH_DIR: &str = ".trash";

/// Whether a normalized vault path is the trash root or sits anywhere inside it.
/// The `".trash/"` literal mirrors [`TRASH_DIR`] (kept in sync by the test below).
pub fn is_trashed(path: &str) -> bool {
    path == TRASH_DIR || path.starts_with(".trash/")
}
/// Current at-rest directory format version.
const FORMAT_VERSION_V2: u16 = 2;
/// Upper bound on the plaintext header / sealed manifest reads (untrusted-input guard).
const MAX_HEADER_LEN: u64 = 16 * 1024 * 1024;
const MAX_MANIFEST_LEN: u64 = 512 * 1024 * 1024;

/// Plaintext header file. Stable for the vault's lifetime; fed as AAD into the
/// manifest AEAD and every blob STREAM (anti-downgrade binding).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct VaultHeaderV2 {
    format_version: u16,
    suite_id: u16,
    vault_id: [u8; 16],
    /// The manifest key wrapped to the owning identity (one recipient: self).
    manifest_stanza: RecipientStanza,
}

/// One manifest entry. For directories `file_id`/`key`/`nonce` are `None`.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct EntryV2 {
    path: String,
    kind: EntryKind,
    size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mtime: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mode: Option<u32>,
    blake3: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<Vec<u8>>,
    #[serde(default)]
    chunk_size: u32,
}

/// The sealed manifest: the folder tree, per-file metadata, and per-blob keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ManifestV2 {
    vault_name: String,
    created_at: i64,
    entries: Vec<EntryV2>,
}

fn dir_entry(path: String) -> EntryV2 {
    EntryV2 {
        path,
        kind: EntryKind::Dir,
        size: 0,
        mtime: None,
        mode: None,
        blake3: [0u8; 32],
        file_id: None,
        key: None,
        nonce: None,
        chunk_size: 0,
    }
}

/// Number of STREAM chunks for a plaintext of `size` (an empty file still has one
/// tag-only chunk, matching [`aead::encrypt_stream_with`]).
fn num_chunks(size: u64, chunk: u64) -> u64 {
    if size == 0 {
        1
    } else {
        size.div_ceil(chunk)
    }
}

/// A lazily-opened v2 vault: only the header + manifest are read on open; file
/// content decrypts on demand from per-file blobs. The same surface as
/// [`VaultReader`], plus O(change) mutations.
///
/// `Clone` is cheap-ish (metadata only: paths, the manifest, and the wrapped
/// keys — never blob content); the store clones a reader to apply a mutation off
/// to the side while the session keeps its own.
#[derive(Clone)]
pub struct VaultReaderV2 {
    dir: PathBuf,
    suite: SuiteId,
    /// Exact on-disk header bytes — the AAD for the manifest and every blob.
    header_bytes: Vec<u8>,
    manifest_key: SymKey,
    manifest: ManifestV2,
    /// v1-shaped view of `manifest.entries` (kept in sync), so callers see the
    /// same [`Entry`] type a [`VaultReader`] exposes.
    view: Vec<Entry>,
}

fn view_of(manifest: &ManifestV2) -> Vec<Entry> {
    manifest
        .entries
        .iter()
        .map(|e| Entry {
            path: e.path.clone(),
            kind: e.kind,
            size: e.size,
            mtime: e.mtime,
            mode: e.mode,
            blake3: e.blake3,
            // v2 locates content by per-file blob, not a stream offset.
            data_offset: 0,
        })
        .collect()
}

impl VaultReaderV2 {
    /// Create a fresh, empty v2 vault directory.
    pub fn create(
        dir: &Path,
        identity: &Identity,
        suite: SuiteId,
        vault_name: &str,
        created_at: i64,
    ) -> Result<Self> {
        if !suite.is_supported() {
            return Err(Error::UnsupportedSuite(suite.to_u16()));
        }
        fs_err::create_dir_all(dir.join(BLOBS_DIR))?;
        harden_dir(dir);
        harden_dir(&dir.join(BLOBS_DIR));

        let manifest_key = SymKey::random()?;
        let manifest_stanza =
            envelope::wrap_for_recipient(&manifest_key, &identity.public(), suite)?;
        let header = VaultHeaderV2 {
            format_version: FORMAT_VERSION_V2,
            suite_id: suite.to_u16(),
            vault_id: random_array::<16>()?,
            manifest_stanza,
        };
        let header_bytes = codec::to_vec(&header)?;
        write_atomic(&dir.join(HEADER_FILE), &header_bytes)?;

        let manifest = ManifestV2 {
            vault_name: vault_name.to_string(),
            created_at,
            entries: Vec::new(),
        };
        let mut me = Self {
            dir: dir.to_path_buf(),
            suite,
            header_bytes,
            manifest_key,
            manifest,
            view: Vec::new(),
        };
        me.reseal_manifest()?;
        Ok(me)
    }

    /// Open an existing v2 vault directory, unwrapping the manifest key with
    /// `identity` and authenticating the manifest. No blob content is read.
    pub fn open(dir: &Path, identity: &Identity) -> Result<Self> {
        let header_bytes = read_bounded(&dir.join(HEADER_FILE), MAX_HEADER_LEN)?;
        let header: VaultHeaderV2 = codec::from_slice(&header_bytes)?;
        if header.format_version != FORMAT_VERSION_V2 {
            return Err(Error::Format("unsupported v2 format version"));
        }
        let suite = SuiteId::from_u16(header.suite_id)?;
        let manifest_key = envelope::unwrap_with_identity(&header.manifest_stanza, identity)?;

        let raw = read_bounded(&dir.join(MANIFEST_FILE), MAX_MANIFEST_LEN)?;
        let nlen = suite.aead_alg().nonce_len();
        if raw.len() < nlen {
            return Err(Error::Format("truncated v2 manifest"));
        }
        let (nonce, ct) = raw.split_at(nlen);
        let pt = Zeroizing::new(aead::open_with(
            suite.aead_alg(),
            &manifest_key,
            nonce,
            &header_bytes,
            ct,
        )?);
        let manifest: ManifestV2 = codec::from_slice(&pt)?;
        let view = view_of(&manifest);
        Ok(Self {
            dir: dir.to_path_buf(),
            suite,
            header_bytes,
            manifest_key,
            manifest,
            view,
        })
    }

    /// The vault's display name.
    pub fn name(&self) -> &str {
        &self.manifest.vault_name
    }
    /// The vault's Unix creation time.
    pub fn created_at(&self) -> i64 {
        self.manifest.created_at
    }
    /// All entries (files and directories), v1-shaped.
    pub fn entries(&self) -> &[Entry] {
        &self.view
    }
    /// Whether the vault has no entries.
    pub fn is_empty(&self) -> bool {
        self.manifest.entries.is_empty()
    }
    /// Number of file entries (directories excluded).
    pub fn file_count(&self) -> usize {
        self.manifest
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .count()
    }
    /// Total plaintext size of all files.
    pub fn total_size(&self) -> u64 {
        self.manifest
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .map(|e| e.size)
            .sum()
    }
    /// The vault's cryptographic suite.
    pub fn suite(&self) -> SuiteId {
        self.suite
    }

    fn blob_path(&self, file_id: &str) -> PathBuf {
        self.dir.join(BLOBS_DIR).join(file_id)
    }

    fn file_entry(&self, path: &str) -> Result<&EntryV2> {
        let norm = normalize_path(path)?;
        let e = self
            .manifest
            .entries
            .iter()
            .find(|e| e.path == norm)
            .ok_or_else(|| Error::Vault("entry not found".into()))?;
        if e.kind != EntryKind::File {
            return Err(Error::Vault("not a file".into()));
        }
        Ok(e)
    }

    /// Decrypt one chunk `c` of `entry`'s blob (random access). Peak memory is
    /// one chunk; a tampered chunk fails with [`Error::Auth`].
    fn decrypt_blob_chunk(
        &self,
        file: &mut fs_err::File,
        entry: &EntryV2,
        key: &SymKey,
        nonce: &[u8],
        c: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let chunk = u64::from(entry.chunk_size);
        let last_index = num_chunks(entry.size, chunk) - 1;
        let is_last = c == last_index;
        let pt_len = if is_last {
            entry.size - last_index * chunk
        } else {
            chunk
        };
        let ct_len = (pt_len + aead::TAG_LEN as u64) as usize;
        let ct_off = c * (chunk + aead::TAG_LEN as u64);
        file.seek(SeekFrom::Start(ct_off))?;
        let mut ct = vec![0u8; ct_len];
        file.read_exact(&mut ct)?;
        Ok(Zeroizing::new(aead::decrypt_chunk_with(
            self.suite.aead_alg(),
            key,
            nonce,
            &self.header_bytes,
            c as u32,
            is_last,
            &ct,
        )?))
    }

    /// Decrypt the whole file at `path` into `out`, one chunk at a time, verifying
    /// its BLAKE3 as it streams. Peak memory is a single chunk.
    pub fn read_entry_to_writer<W: Write>(&self, path: &str, out: &mut W) -> Result<()> {
        let entry = self.file_entry(path)?;
        if entry.size == 0 {
            if !ct_eq(blake3::hash(&[]).as_bytes(), &entry.blake3) {
                return Err(Error::Auth);
            }
            return Ok(());
        }
        let chunk = u64::from(entry.chunk_size);
        if chunk == 0 {
            return Err(Error::Format("bad chunk size"));
        }
        let key = SymKey::from_bytes(entry.key.ok_or(Error::Format("missing blob key"))?);
        let nonce = entry
            .nonce
            .as_ref()
            .ok_or(Error::Format("missing blob nonce"))?;
        let mut file = fs_err::File::open(self.blob_path(blob_id(entry)?))?;
        let last_index = num_chunks(entry.size, chunk) - 1;
        let mut hasher = blake3::Hasher::new();
        for c in 0..=last_index {
            let pt = self.decrypt_blob_chunk(&mut file, entry, &key, nonce, c)?;
            hasher.update(&pt);
            out.write_all(&pt)?;
        }
        if !ct_eq(hasher.finalize().as_bytes(), &entry.blake3) {
            return Err(Error::Auth);
        }
        Ok(())
    }

    /// Decrypt and return a whole file's content (buffers the file).
    pub fn read_entry(&self, path: &str) -> Result<Zeroizing<Vec<u8>>> {
        let entry = self.file_entry(path)?;
        let mut buf = Zeroizing::new(Vec::with_capacity(entry.size as usize));
        self.read_entry_to_writer(path, &mut *buf)?;
        Ok(buf)
    }

    /// Decrypt every file to `dest` on the real filesystem, streaming each file
    /// chunk-by-chunk (peak memory is one chunk).
    pub fn extract_to(&self, dest: &Path) -> Result<()> {
        for e in &self.manifest.entries {
            let target = dest.join(normalize_path(&e.path)?);
            match e.kind {
                EntryKind::Dir => {
                    fs_err::create_dir_all(&target)?;
                }
                EntryKind::File => {
                    if let Some(parent) = target.parent() {
                        fs_err::create_dir_all(parent)?;
                    }
                    let mut out = std::io::BufWriter::new(fs_err::File::create(&target)?);
                    self.read_entry_to_writer(&e.path, &mut out)?;
                    out.flush()?;
                }
            }
        }
        Ok(())
    }

    /// Fully decrypt into an in-memory [`Vault`]. A faithful materialization of
    /// *every* entry — including the local [`TRASH_DIR`] subtree — so it is the
    /// right call for re-keying / round-tripping the whole store. For producing a
    /// container to hand to someone else, use [`Self::to_vault_for_export`].
    pub fn to_vault(&self) -> Result<Vault> {
        self.materialize(|_| true)
    }

    /// Like [`Self::to_vault`] but **omits the trash**: soft-deleted entries are
    /// never decrypted and never make it into the exported container. This is what
    /// [`export_v2_to_path`] uses, so "delete then send" can't leak the file.
    pub fn to_vault_for_export(&self) -> Result<Vault> {
        self.materialize(|path| !is_trashed(path))
    }

    /// Shared body of [`Self::to_vault`] / [`Self::to_vault_for_export`]: decrypt
    /// the entries for which `keep` returns `true` into a fresh [`Vault`].
    fn materialize(&self, keep: impl Fn(&str) -> bool) -> Result<Vault> {
        let mut vault = Vault::new(self.manifest.vault_name.clone(), self.manifest.created_at);
        for e in &self.manifest.entries {
            if !keep(&e.path) {
                continue;
            }
            match e.kind {
                EntryKind::Dir => vault.add_dir(&e.path)?,
                EntryKind::File => {
                    let content = self.read_entry(&e.path)?;
                    vault.add_file(&e.path, content.to_vec(), e.mtime, e.mode)?;
                }
            }
        }
        Ok(vault)
    }

    // ----- mutations (O(change): touch one blob + reseal the manifest) -----

    /// Re-serialize, re-seal (fresh nonce), and atomically rewrite the manifest,
    /// then refresh the v1-shaped view. The single commit point of any mutation.
    fn reseal_manifest(&mut self) -> Result<()> {
        let pt = Zeroizing::new(codec::to_vec(&self.manifest)?);
        let nonce = crate::secret::random_vec(self.suite.aead_alg().nonce_len())?;
        let ct = aead::seal_with(
            self.suite.aead_alg(),
            &self.manifest_key,
            &nonce,
            &self.header_bytes,
            &pt,
        )?;
        let mut buf = Vec::with_capacity(nonce.len() + ct.len());
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&ct);
        write_atomic(&self.dir.join(MANIFEST_FILE), &buf)?;
        self.view = view_of(&self.manifest);
        Ok(())
    }

    /// Push directory entries for each missing ancestor of `norm` (in memory).
    fn ensure_dirs(&mut self, norm: &str) {
        let comps: Vec<&str> = norm.split('/').collect();
        let mut acc = String::new();
        for comp in comps.iter().take(comps.len().saturating_sub(1)) {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(comp);
            if !self.manifest.entries.iter().any(|e| e.path == acc) {
                self.manifest.entries.push(dir_entry(acc.clone()));
            }
        }
    }

    /// Encrypt a new blob and stage the entry **in memory** (no reseal). Returns
    /// the old blob's `file_id` if this overwrote an existing file, so the caller
    /// can delete it after the manifest commit. Errors (leaving memory unchanged)
    /// if a directory already occupies `norm`.
    fn stage_file<R: Read>(
        &mut self,
        norm: String,
        blake3: [u8; 32],
        size: u64,
        source: R,
        mtime: Option<i64>,
        mode: Option<u32>,
    ) -> Result<Option<String>> {
        if let Some(e) = self.manifest.entries.iter().find(|e| e.path == norm) {
            if e.kind == EntryKind::Dir {
                return Err(Error::Vault(format!("a directory exists at {norm}")));
            }
        }
        let file_id = new_file_id()?;
        let key = SymKey::random()?;
        let nonce = crate::secret::random_vec(self.suite.aead_alg().stream_nonce_len())?;
        encrypt_blob(
            &self.blob_path(&file_id),
            self.suite.aead_alg(),
            &key,
            &nonce,
            &self.header_bytes,
            source,
            aead::DEFAULT_CHUNK_SIZE,
        )?;
        // Disk write succeeded; now mutate the in-memory manifest.
        let old = match self.manifest.entries.iter().position(|e| e.path == norm) {
            Some(pos) => self.manifest.entries.remove(pos).file_id,
            None => None,
        };
        self.ensure_dirs(&norm);
        self.manifest.entries.push(EntryV2 {
            path: norm,
            kind: EntryKind::File,
            size,
            mtime,
            mode,
            blake3,
            file_id: Some(file_id),
            key: Some(*key.as_bytes()),
            nonce: Some(nonce),
            chunk_size: aead::DEFAULT_CHUNK_SIZE as u32,
        });
        Ok(old)
    }

    /// Add or replace the file at `vault_path` from a file on disk. Rewrites only
    /// that blob and the manifest.
    pub fn put_file(
        &mut self,
        vault_path: &str,
        source: &Path,
        mtime: Option<i64>,
        mode: Option<u32>,
    ) -> Result<()> {
        let norm = normalize_path(vault_path)?;
        let (blake3, size) = hash_path(source)?;
        let reader = BufReader::new(fs_err::File::open(source)?);
        let old = self.stage_file(norm, blake3, size, reader, mtime, mode)?;
        self.reseal_manifest()?;
        if let Some(old_id) = old {
            let _ = fs_err::remove_file(self.blob_path(&old_id));
        }
        Ok(())
    }

    /// Add or replace the file at `vault_path` from an in-memory buffer.
    pub fn put_file_bytes(
        &mut self,
        vault_path: &str,
        bytes: &[u8],
        mtime: Option<i64>,
        mode: Option<u32>,
    ) -> Result<()> {
        let norm = normalize_path(vault_path)?;
        let blake3 = *blake3::hash(bytes).as_bytes();
        let old = self.stage_file(
            norm,
            blake3,
            bytes.len() as u64,
            Cursor::new(bytes),
            mtime,
            mode,
        )?;
        self.reseal_manifest()?;
        if let Some(old_id) = old {
            let _ = fs_err::remove_file(self.blob_path(&old_id));
        }
        Ok(())
    }

    /// Create an (empty) directory, plus any missing ancestors. A no-op if the
    /// directory already exists; errors if a file occupies the path.
    pub fn mkdir(&mut self, vault_path: &str) -> Result<()> {
        let norm = normalize_path(vault_path)?;
        if let Some(e) = self.manifest.entries.iter().find(|e| e.path == norm) {
            return if e.kind == EntryKind::Dir {
                Ok(())
            } else {
                Err(Error::Vault(format!("a file exists at {norm}")))
            };
        }
        self.ensure_dirs(&norm);
        self.manifest.entries.push(dir_entry(norm));
        self.reseal_manifest()
    }

    /// Remove the entry at `vault_path` and, if it is a directory, its whole
    /// subtree. Deletes the affected blobs. A no-op if nothing matches.
    pub fn remove_path(&mut self, vault_path: &str) -> Result<()> {
        let norm = normalize_path(vault_path)?;
        let prefix = format!("{norm}/");
        let before = self.manifest.entries.len();
        let mut removed_ids = Vec::new();
        let mut kept = Vec::with_capacity(before);
        for e in std::mem::take(&mut self.manifest.entries) {
            if e.path == norm || e.path.starts_with(&prefix) {
                if let Some(id) = e.file_id {
                    removed_ids.push(id);
                }
            } else {
                kept.push(e);
            }
        }
        let changed = kept.len() != before;
        self.manifest.entries = kept;
        if changed {
            self.reseal_manifest()?;
            for id in removed_ids {
                let _ = fs_err::remove_file(self.blob_path(&id));
            }
        }
        Ok(())
    }

    /// Rename/move `from` to `to` (a file, or a directory with its whole subtree).
    /// Manifest-only — blobs are untouched. Errors if `to` already exists or `to`
    /// is inside `from`.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        let from = normalize_path(from)?;
        let to = normalize_path(to)?;
        if from == to {
            return Ok(());
        }
        let from_prefix = format!("{from}/");
        if to == from || to.starts_with(&from_prefix) {
            return Err(Error::Vault("cannot move a directory into itself".into()));
        }
        if !self.manifest.entries.iter().any(|e| e.path == from) {
            return Err(Error::Vault(format!("not found: {from}")));
        }
        if self.manifest.entries.iter().any(|e| e.path == to) {
            return Err(Error::Vault(format!("path already exists: {to}")));
        }
        self.ensure_dirs(&to);
        for e in &mut self.manifest.entries {
            if e.path == from {
                e.path = to.clone();
            } else if let Some(rest) = e.path.strip_prefix(&from_prefix) {
                e.path = format!("{to}/{rest}");
            }
        }
        self.reseal_manifest()
    }

    /// Update an entry's advisory mtime/mode (manifest-only).
    pub fn set_attr(
        &mut self,
        vault_path: &str,
        mtime: Option<i64>,
        mode: Option<u32>,
    ) -> Result<()> {
        let norm = normalize_path(vault_path)?;
        let e = self
            .manifest
            .entries
            .iter_mut()
            .find(|e| e.path == norm)
            .ok_or_else(|| Error::Vault(format!("not found: {norm}")))?;
        e.mtime = mtime;
        e.mode = mode;
        self.reseal_manifest()
    }

    /// Build a fresh v2 vault at `dir` from an opened, verified v1 [`VaultReader`]
    /// (the import / migration path), **streaming** the data straight from the
    /// source container into the per-file blobs. The v1 data section is one
    /// contiguous plaintext stream in entry order, so each file is re-encrypted on
    /// the fly from the next `size` bytes — a multi-gigabyte file is never buffered
    /// whole (peak memory is a couple of chunks). Reseals the manifest once at the
    /// end.
    pub fn from_reader_v1(
        dir: &Path,
        identity: &Identity,
        suite: SuiteId,
        reader: &VaultReader,
    ) -> Result<Self> {
        let mut me = Self::create(dir, identity, suite, reader.name(), reader.created_at())?;
        let mut plaintext = reader.plaintext_stream()?;
        let mut offset: u64 = 0;
        for e in reader.entries() {
            match e.kind {
                EntryKind::Dir => {
                    if !me.manifest.entries.iter().any(|x| x.path == e.path) {
                        me.ensure_dirs(&e.path);
                        me.manifest.entries.push(dir_entry(e.path.clone()));
                    }
                }
                EntryKind::File => {
                    // Files are laid out contiguously in entry order; the next
                    // `e.size` bytes of the stream are exactly this file's content.
                    if e.data_offset != offset {
                        return Err(Error::Format("non-contiguous data offset"));
                    }
                    let mut src = HashingReader::new((&mut plaintext).take(e.size));
                    // Fresh vault, so this never overwrites (no old blob to drop).
                    me.stage_file(e.path.clone(), e.blake3, e.size, &mut src, e.mtime, e.mode)?;
                    // Defense in depth atop the already-verified container signature.
                    if !ct_eq(src.finalize().as_bytes(), &e.blake3) {
                        return Err(Error::Auth);
                    }
                    offset = offset
                        .checked_add(e.size)
                        .ok_or(Error::Format("size overflow"))?;
                }
            }
        }
        // The stream must end exactly at the last file — no trailing plaintext.
        let mut extra = [0u8; 1];
        match plaintext.read(&mut extra) {
            Ok(0) => {}
            Ok(_) => return Err(Error::Format("trailing data after last entry")),
            Err(e) => return Err(Error::Io(e)),
        }
        me.reseal_manifest()?;
        Ok(me)
    }

    /// Build a fresh v2 vault at `dir` from an in-memory [`Vault`] (the create /
    /// save path); reseals the manifest once at the end.
    pub fn from_vault(
        dir: &Path,
        identity: &Identity,
        suite: SuiteId,
        vault: &Vault,
    ) -> Result<Self> {
        let mut me = Self::create(dir, identity, suite, &vault.name, vault.created_at)?;
        for e in vault.entries() {
            match e.kind {
                EntryKind::Dir => {
                    if !me.manifest.entries.iter().any(|x| x.path == e.path) {
                        me.ensure_dirs(&e.path);
                        me.manifest.entries.push(dir_entry(e.path.clone()));
                    }
                }
                EntryKind::File => {
                    let digest = *blake3::hash(e.content.as_slice()).as_bytes();
                    me.stage_file(
                        e.path.clone(),
                        digest,
                        e.content.len() as u64,
                        Cursor::new(e.content.as_slice()),
                        e.mtime,
                        e.mode,
                    )?;
                }
            }
        }
        me.reseal_manifest()?;
        Ok(me)
    }

    /// Prepare a streaming export of this vault as a signed `.fsec` v1 transport
    /// container, **without** materializing the plaintext. The returned plan knows
    /// the exact container size up front ([`V2ExportPlan::container_size`]) and
    /// streams each blob chunk-by-chunk when written ([`V2ExportPlan::write_to`]),
    /// so peak memory is a couple of chunks regardless of vault size.
    ///
    /// The local [`TRASH_DIR`] subtree is excluded, exactly like
    /// [`Self::to_vault_for_export`], so a soft-deleted file never rides along.
    pub fn export_plan<'a>(
        &'a self,
        sender: &'a Identity,
        recipients: &[PublicIdentity],
        options: &ExportOptions,
    ) -> Result<V2ExportPlan<'a>> {
        // Build the v1 manifest from v2 metadata (no blob content is read) and the
        // ordered list of blobs to stream, assigning each file a contiguous data
        // offset in the same order the plaintext reader will yield them.
        let mut entries = Vec::with_capacity(self.manifest.entries.len());
        let mut files = Vec::new();
        let mut offset: u64 = 0;
        for e in &self.manifest.entries {
            if is_trashed(&e.path) {
                continue;
            }
            match e.kind {
                EntryKind::Dir => entries.push(Entry {
                    path: e.path.clone(),
                    kind: EntryKind::Dir,
                    size: 0,
                    mtime: e.mtime,
                    mode: e.mode,
                    blake3: [0u8; 32],
                    data_offset: 0,
                }),
                EntryKind::File => {
                    entries.push(Entry {
                        path: e.path.clone(),
                        kind: EntryKind::File,
                        size: e.size,
                        mtime: e.mtime,
                        mode: e.mode,
                        blake3: e.blake3,
                        data_offset: offset,
                    });
                    files.push(ExportFile {
                        file_id: blob_id(e)?.to_string(),
                        key: e.key.ok_or(Error::Format("missing blob key"))?,
                        nonce: e.nonce.clone().ok_or(Error::Format("missing blob nonce"))?,
                        blake3: e.blake3,
                        size: e.size,
                        chunk_size: e.chunk_size,
                    });
                    offset = offset
                        .checked_add(e.size)
                        .ok_or(Error::Format("size overflow"))?;
                }
            }
        }
        let manifest = Manifest {
            vault_name: self.manifest.vault_name.clone(),
            created_at: self.manifest.created_at,
            entries,
        };
        let plan = ContainerPlan::new(&manifest, offset, sender, recipients, options)?;
        Ok(V2ExportPlan {
            reader: self,
            files,
            plan,
        })
    }
}

/// The `file_id` of a file entry (errors if absent — a corrupt manifest).
fn blob_id(entry: &EntryV2) -> Result<&str> {
    entry
        .file_id
        .as_deref()
        .ok_or(Error::Format("file entry missing blob id"))
}

fn new_file_id() -> Result<String> {
    Ok(crate::util::hex(&random_array::<16>()?))
}

/// Read a whole file, rejecting anything larger than `max` (untrusted-input guard).
fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let meta = fs_err::metadata(path)?;
    if !meta.is_file() {
        return Err(Error::Format("metadata path is not a file"));
    }
    if meta.len() > max {
        return Err(Error::Format("file too large"));
    }
    let bytes = fs_err::read(path)?;
    if bytes.len() as u64 > max {
        return Err(Error::Format("file too large"));
    }
    Ok(bytes)
}

/// A temp sibling path (`<path>.tmp`) that tolerates names containing dots.
fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Atomically write `bytes` to `path`: temp + fsync + rename (+ best-effort dir
/// fsync), hardened to 0600 on Unix.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = tmp_path(path);
    {
        let mut f = fs_err::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    harden_file(&tmp);
    fs_err::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        if let Ok(d) = fs_err::File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Encrypt `source` into a fresh blob at `path` (temp + fsync + rename), 0600.
fn encrypt_blob<R: Read>(
    path: &Path,
    alg: aead::AeadAlg,
    key: &SymKey,
    nonce: &[u8],
    aad: &[u8],
    source: R,
    chunk_size: usize,
) -> Result<()> {
    let tmp = tmp_path(path);
    {
        let mut f = fs_err::File::create(&tmp)?;
        aead::encrypt_stream_with(alg, key, nonce, aad, source, &mut f, chunk_size)?;
        f.sync_all()?;
    }
    harden_file(&tmp);
    fs_err::rename(&tmp, path)?;
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

/// Re-export a v2 vault as the signed single-stream `.fsec` v1 transport
/// container (unchanged format), **streaming** straight from the per-file blobs so
/// the whole vault is never held in memory. The local trash is excluded.
pub fn export_v2_to_path(
    reader: &VaultReaderV2,
    sender: &Identity,
    recipients: &[PublicIdentity],
    options: &ExportOptions,
    path: &Path,
) -> Result<()> {
    let plan = reader.export_plan(sender, recipients, options)?;
    let file = fs_err::File::create(path)?;
    plan.write_to(file)
}

/// One blob to stream during an export: the metadata needed to open and decrypt
/// it. Owned (not borrowed from the manifest) so the export plan and its reader
/// have a simple lifetime.
struct ExportFile {
    file_id: String,
    key: [u8; 32],
    nonce: Vec<u8>,
    blake3: [u8; 32],
    size: u64,
    chunk_size: u32,
}

/// A prepared streaming export of a v2 vault into a signed `.fsec` container.
///
/// Building the plan reads only metadata, so [`Self::container_size`] is known
/// before any blob is touched — a direct transfer declares that exact size to the
/// receiver up front. [`Self::write_to`] then decrypts each blob chunk-by-chunk on
/// the fly; peak memory is a couple of chunks regardless of vault size.
pub struct V2ExportPlan<'a> {
    reader: &'a VaultReaderV2,
    files: Vec<ExportFile>,
    plan: ContainerPlan<'a>,
}

impl V2ExportPlan<'_> {
    /// The exact number of bytes [`Self::write_to`] will produce.
    pub fn container_size(&self) -> u64 {
        self.plan.container_len()
    }

    /// Stream the signed, recipient-encrypted container into `out`.
    pub fn write_to<W: Write>(self, out: W) -> Result<()> {
        let data = V2PlaintextReader {
            reader: self.reader,
            files: self.files.into_iter(),
            current: None,
        };
        self.plan.write(data, out)
    }
}

/// A [`Read`] that BLAKE3-hashes every byte as it passes through, so a streamed
/// file's whole-file digest can be checked once it has been fully consumed. Used
/// by [`VaultReaderV2::from_reader_v1`] to verify each file as it re-encrypts it
/// without holding the file in memory.
struct HashingReader<R: Read> {
    inner: R,
    hasher: blake3::Hasher,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
        }
    }

    fn finalize(&self) -> blake3::Hash {
        self.hasher.finalize()
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// The currently-streaming blob: its decrypting reader plus a running hash of the
/// plaintext, checked against the manifest digest at the blob's end.
struct CurrentBlob {
    dec: aead::StreamDecryptReader<BufReader<fs_err::File>>,
    hasher: blake3::Hasher,
    expected: [u8; 32],
}

/// A [`Read`] that yields a v2 vault's plaintext, concatenated in manifest order,
/// by decrypting each per-file blob chunk-by-chunk. The whole-file BLAKE3 is
/// verified as each blob streams (defense in depth atop the per-chunk AEAD).
struct V2PlaintextReader<'a> {
    reader: &'a VaultReaderV2,
    files: std::vec::IntoIter<ExportFile>,
    current: Option<CurrentBlob>,
}

/// An [`std::io::Error`] standing in for an authentication failure mid-stream.
fn auth_io_err() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, Error::Auth)
}

/// The outcome of advancing [`V2PlaintextReader`] to the next manifest file.
enum Advance {
    /// A blob was opened into `current` and is ready to stream.
    Opened,
    /// An empty file was verified and skipped (it yields no plaintext).
    SkippedEmpty,
    /// No files remain.
    Done,
}

impl V2PlaintextReader<'_> {
    /// Move to the next file: open its blob into `current`, skip an empty file
    /// (after checking its digest is the hash of nothing), or report completion.
    fn advance(&mut self) -> std::io::Result<Advance> {
        let f = match self.files.next() {
            Some(f) => f,
            None => return Ok(Advance::Done),
        };
        if f.size == 0 {
            if !ct_eq(blake3::hash(&[]).as_bytes(), &f.blake3) {
                return Err(auth_io_err());
            }
            return Ok(Advance::SkippedEmpty);
        }
        let file = BufReader::new(fs_err::File::open(self.reader.blob_path(&f.file_id))?);
        let dec = aead::StreamDecryptReader::new_with(
            self.reader.suite.aead_alg(),
            &SymKey::from_bytes(f.key),
            &f.nonce,
            &self.reader.header_bytes,
            file,
            f.chunk_size as usize,
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.current = Some(CurrentBlob {
            dec,
            hasher: blake3::Hasher::new(),
            expected: f.blake3,
        });
        Ok(Advance::Opened)
    }
}

impl Read for V2PlaintextReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.current.is_none() {
                match self.advance()? {
                    Advance::Opened => {}
                    Advance::SkippedEmpty => continue,
                    Advance::Done => return Ok(0),
                }
            }
            let cur = match self.current.as_mut() {
                Some(c) => c,
                None => continue, // unreachable after `advance` returned `Opened`
            };
            let n = cur.dec.read(buf)?;
            if n == 0 {
                // Blob fully streamed: verify the whole-file digest before moving on.
                if !ct_eq(cur.hasher.finalize().as_bytes(), &cur.expected) {
                    return Err(auth_io_err());
                }
                self.current = None;
                continue;
            }
            cur.hasher.update(&buf[..n]);
            return Ok(n);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let suffix = crate::util::hex(&crate::secret::random_array::<8>().unwrap());
        std::env::temp_dir().join(format!("filesec-v2-bounds-{suffix}-{name}"))
    }

    #[test]
    fn read_bounded_rejects_oversized_header_before_read() {
        let dir = tmp("header");
        fs_err::create_dir_all(&dir).unwrap();
        let header = dir.join(HEADER_FILE);
        fs_err::File::create(&header)
            .unwrap()
            .set_len(MAX_HEADER_LEN + 1)
            .unwrap();
        assert!(matches!(
            read_bounded(&header, MAX_HEADER_LEN),
            Err(Error::Format("file too large"))
        ));
        let _ = fs_err::remove_dir_all(&dir);
    }

    #[test]
    fn read_bounded_rejects_oversized_manifest_before_read() {
        let dir = tmp("manifest");
        fs_err::create_dir_all(&dir).unwrap();
        let manifest = dir.join(MANIFEST_FILE);
        fs_err::File::create(&manifest)
            .unwrap()
            .set_len(MAX_MANIFEST_LEN + 1)
            .unwrap();
        assert!(matches!(
            read_bounded(&manifest, MAX_MANIFEST_LEN),
            Err(Error::Format("file too large"))
        ));
        let _ = fs_err::remove_dir_all(&dir);
    }
}
