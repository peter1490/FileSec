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
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::envelope::{self, RecipientStanza};
use crate::error::{Error, Result};
use crate::format::{hash_path, ContainerPlan, ExportOptions, VaultReader};
use crate::identity::{Identity, PublicIdentity};
use crate::manifest::{Entry, EntryKind, Manifest};
use crate::secret::{ct_eq, random_array, SymKey};
use crate::state::{StateAnchor, StateMetadata, StateObjectType};
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
/// Version of the rollback-protected manifest envelope stored inside the v2
/// directory format. The header remains v2 so existing blob AAD stays stable
/// during explicit in-place recovery.
const MANIFEST_ENVELOPE_VERSION: u16 = 3;
/// Upper bound on the plaintext header / sealed manifest reads (untrusted-input guard).
const MAX_HEADER_LEN: u64 = 16 * 1024 * 1024;
const MAX_MANIFEST_LEN: u64 = 512 * 1024 * 1024;
/// Upper bound on the number of entries a decrypted manifest may declare, so a
/// manifest that fits inside [`MAX_MANIFEST_LEN`] still cannot drive unbounded
/// per-entry work. Mirrors the v1 [`crate::format`] limit.
const MAX_MANIFEST_ENTRIES: usize = 10_000_000;
/// Exact length of a blob `file_id`: 32 lowercase-hex characters (16 random bytes).
const BLOB_ID_LEN: usize = 32;

/// Validate a blob `file_id` as **exactly** 32 lowercase-hex characters and
/// nothing else — no path separators, dots, uppercase, or other bytes — so it can
/// never be interpreted as a path, an absolute path, or a `..` traversal
/// component when joined under `blobs/`. The manifest is authenticated (sealed to
/// the owner), so this is defense in depth: even a manifest forged with the
/// owner's own key cannot turn a blob id into a path that escapes the vault dir.
fn validate_blob_id(id: &str) -> Result<()> {
    if id.len() != BLOB_ID_LEN {
        return Err(Error::Format("blob id must be 32 hex chars"));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Format("blob id must be lowercase hex"));
    }
    Ok(())
}

/// Validate a freshly decrypted manifest before any per-entry processing: bound
/// the entry count, reject duplicate/invalid paths, and — for each file — confirm
/// the blob id is a single hex path component, the chunk size is within
/// [`aead::MAX_CHUNK_SIZE`], the blob nonce length matches the suite, and the blob
/// key is present. Runs once on open/recover so later blob reads can trust the
/// metadata they act on.
fn validate_manifest_v2(manifest: &ManifestV2, alg: aead::AeadAlg) -> Result<()> {
    if manifest.entries.len() > MAX_MANIFEST_ENTRIES {
        return Err(Error::Format("too many manifest entries"));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut total_size = 0u64;
    for e in &manifest.entries {
        let norm = normalize_path(&e.path)?;
        if !seen.insert(norm) {
            return Err(Error::Format("duplicate path in manifest"));
        }
        if e.kind == EntryKind::File {
            validate_blob_id(
                e.file_id
                    .as_deref()
                    .ok_or(Error::Format("missing blob id"))?,
            )?;
            if e.chunk_size == 0 || e.chunk_size as usize > aead::MAX_CHUNK_SIZE {
                return Err(Error::Format("bad chunk size"));
            }
            if num_chunks(e.size, u64::from(e.chunk_size)) > u64::from(u32::MAX) {
                return Err(Error::Format("too many blob chunks"));
            }
            total_size = total_size
                .checked_add(e.size)
                .ok_or(Error::Format("size overflow"))?;
            if e.key.is_none() {
                return Err(Error::Format("missing blob key"));
            }
            match &e.nonce {
                Some(n) if n.len() == alg.stream_nonce_len() => {}
                _ => return Err(Error::Format("bad blob nonce length")),
            }
        }
    }
    Ok(())
}

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

// Preserve the existing CBOR array representation while wiping every owned key
// on drop, including cloned readers and export plans. Never format key bytes.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
struct BlobKey([u8; 32]);

impl std::fmt::Debug for BlobKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlobKey(***redacted***)")
    }
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
    key: Option<BlobKey>,
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

/// Plaintext framing around the encrypted manifest. `state` is authenticated as
/// AEAD associated data, while its current hash commits to the decrypted
/// [`ManifestV2`] bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ManifestEnvelopeV3 {
    version: u16,
    state: StateMetadata,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
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
    // `Arc` so a reader clone shares one manifest-key copy by refcount rather
    // than duplicating the secret bytes (F17); zeroized on the last `Arc` drop.
    manifest_key: Arc<SymKey>,
    manifest: ManifestV2,
    owner_fingerprint: [u8; 32],
    state: Option<StateMetadata>,
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

fn vault_object_id(header_bytes: &[u8]) -> Result<String> {
    let header: VaultHeaderV2 = codec::from_slice(header_bytes)?;
    Ok(crate::util::hex(&header.vault_id))
}

fn manifest_aad(header_bytes: &[u8], state: &StateMetadata) -> Vec<u8> {
    let state_aad = state.authenticated_data();
    let mut aad = Vec::with_capacity(16 + header_bytes.len() + state_aad.len());
    aad.extend_from_slice(&(header_bytes.len() as u64).to_le_bytes());
    aad.extend_from_slice(header_bytes);
    aad.extend_from_slice(&(state_aad.len() as u64).to_le_bytes());
    aad.extend_from_slice(&state_aad);
    aad
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
        Self::create_inner(
            dir,
            identity,
            suite,
            vault_name,
            created_at,
            random_array::<16>()?,
        )
    }

    /// Create a fresh vault whose authenticated object id is the exact
    /// lowercase-hex `object_id` used by the local registry/path. This prevents a
    /// different otherwise-valid vault directory from being substituted at that
    /// path. Direct core users may use [`Self::create`] for a random id instead.
    pub fn create_with_object_id(
        dir: &Path,
        identity: &Identity,
        suite: SuiteId,
        vault_name: &str,
        created_at: i64,
        object_id: &str,
    ) -> Result<Self> {
        let decoded = data_encoding::HEXLOWER
            .decode(object_id.as_bytes())
            .map_err(|_| Error::Format("vault object id must be lowercase hex"))?;
        let vault_id: [u8; 16] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| Error::Format("vault object id must encode 16 bytes"))?;
        Self::create_inner(dir, identity, suite, vault_name, created_at, vault_id)
    }

    fn create_inner(
        dir: &Path,
        identity: &Identity,
        suite: SuiteId,
        vault_name: &str,
        created_at: i64,
        vault_id: [u8; 16],
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
            vault_id,
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
            manifest_key: Arc::new(manifest_key),
            manifest,
            owner_fingerprint: identity.fingerprint(),
            state: None,
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
        let envelope: ManifestEnvelopeV3 =
            codec::from_slice(&raw).map_err(|_| Error::LegacyState("v2 vault manifest"))?;
        if envelope.version != MANIFEST_ENVELOPE_VERSION
            || envelope.state.object_type != StateObjectType::VaultManifest
            || envelope.state.object_id != crate::util::hex(&header.vault_id)
            || envelope.state.suite_id != suite.to_u16()
            || envelope.state.identity_fingerprint != identity.fingerprint()
            || envelope.nonce.len() != suite.aead_alg().nonce_len()
        {
            return Err(Error::StateMismatch(envelope.state.label()));
        }
        let aad = manifest_aad(&header_bytes, &envelope.state);
        let pt = Zeroizing::new(aead::open_with(
            suite.aead_alg(),
            &manifest_key,
            &envelope.nonce,
            &aad,
            &envelope.ciphertext,
        )?);
        envelope.state.verify_payload(&pt)?;
        let manifest: ManifestV2 = codec::from_slice(&pt)?;
        validate_manifest_v2(&manifest, suite.aead_alg())?;
        let view = view_of(&manifest);
        Ok(Self {
            dir: dir.to_path_buf(),
            suite,
            header_bytes,
            manifest_key: Arc::new(manifest_key),
            manifest,
            owner_fingerprint: identity.fingerprint(),
            state: Some(envelope.state),
            view,
        })
    }

    /// Explicitly upgrade an authenticated legacy raw manifest to the
    /// rollback-protected envelope, in place. Blob bytes and the v2 header remain
    /// untouched, so their existing AEAD associated data remains valid.
    pub fn recover_legacy(dir: &Path, identity: &Identity) -> Result<Self> {
        let header_bytes = read_bounded(&dir.join(HEADER_FILE), MAX_HEADER_LEN)?;
        let header: VaultHeaderV2 = codec::from_slice(&header_bytes)?;
        if header.format_version != FORMAT_VERSION_V2 {
            return Err(Error::Format("unsupported v2 format version"));
        }
        let suite = SuiteId::from_u16(header.suite_id)?;
        let manifest_key = envelope::unwrap_with_identity(&header.manifest_stanza, identity)?;
        let raw = read_bounded(&dir.join(MANIFEST_FILE), MAX_MANIFEST_LEN)?;
        if codec::from_slice::<ManifestEnvelopeV3>(&raw).is_ok() {
            return Err(Error::Format(
                "vault manifest is already rollback protected",
            ));
        }
        let nlen = suite.aead_alg().nonce_len();
        if raw.len() < nlen {
            return Err(Error::Format("truncated legacy v2 manifest"));
        }
        let (nonce, ciphertext) = raw.split_at(nlen);
        let pt = Zeroizing::new(aead::open_with(
            suite.aead_alg(),
            &manifest_key,
            nonce,
            &header_bytes,
            ciphertext,
        )?);
        let manifest: ManifestV2 = codec::from_slice(&pt)?;
        validate_manifest_v2(&manifest, suite.aead_alg())?;
        let view = view_of(&manifest);
        let mut reader = Self {
            dir: dir.to_path_buf(),
            suite,
            header_bytes,
            manifest_key: Arc::new(manifest_key),
            manifest,
            owner_fingerprint: identity.fingerprint(),
            state: None,
            view,
        };
        reader.reseal_manifest()?;
        Ok(reader)
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

    /// Rollback-protection metadata for the currently opened manifest.
    #[must_use]
    pub fn state_metadata(&self) -> Option<&StateMetadata> {
        self.state.as_ref()
    }

    fn blob_path(&self, file_id: &str) -> PathBuf {
        self.dir.join(BLOBS_DIR).join(file_id)
    }

    fn open_blob(&self, file_id: &str, size: u64, chunk_size: u32) -> Result<fs_err::File> {
        if chunk_size == 0 {
            return Err(Error::Format("bad chunk size"));
        }
        let chunks = num_chunks(size, u64::from(chunk_size));
        if chunks > u64::from(u32::MAX) {
            return Err(Error::Format("too many blob chunks"));
        }
        let expected = size
            .checked_add(chunks * aead::TAG_LEN as u64)
            .ok_or(Error::Format("blob length overflow"))?;
        let file = fs_err::File::open(self.blob_path(file_id))?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.len() != expected {
            return Err(Error::Format("blob length mismatch"));
        }
        Ok(file)
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
        let chunk = u64::from(entry.chunk_size);
        if chunk == 0 {
            return Err(Error::Format("bad chunk size"));
        }
        let key = SymKey::from_bytes(
            entry
                .key
                .as_ref()
                .ok_or(Error::Format("missing blob key"))?
                .0,
        );
        let nonce = entry
            .nonce
            .as_ref()
            .ok_or(Error::Format("missing blob nonce"))?;
        let mut file = self.open_blob(blob_id(entry)?, entry.size, entry.chunk_size)?;
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
        let capacity =
            usize::try_from(entry.size).map_err(|_| Error::Format("file too large to buffer"))?;
        let mut buf = Zeroizing::new(Vec::new());
        buf.try_reserve_exact(capacity)
            .map_err(|_| Error::Format("file too large to buffer"))?;
        self.read_entry_to_writer(path, &mut *buf)?;
        Ok(buf)
    }

    /// Decrypt every file to `dest` on the real filesystem, streaming each file
    /// chunk-by-chunk (peak memory is one chunk).
    ///
    /// Each file is written through [`crate::safe_io::SafeFileWriter`]:
    /// [`Self::read_entry_to_writer`] authenticates the plaintext (per-chunk AEAD
    /// plus a full-file BLAKE3 check) as it streams into a private temp, and only
    /// a verified file is atomically renamed into place — so a tampered blob never
    /// leaves partial plaintext behind. Parent directories are created without
    /// descending through planted symlinks, and a symlinked target is refused.
    pub fn extract_to(&self, dest: &Path) -> Result<()> {
        for e in &self.manifest.entries {
            let target = dest.join(normalize_path(&e.path)?);
            match e.kind {
                EntryKind::Dir => {
                    crate::safe_io::create_dirs_no_symlink(dest, &target)?;
                }
                EntryKind::File => {
                    if let Some(parent) = target.parent() {
                        crate::safe_io::create_dirs_no_symlink(dest, parent)?;
                    }
                    let mut out = crate::safe_io::SafeFileWriter::create(&target)?;
                    self.read_entry_to_writer(&e.path, &mut out)?;
                    out.commit()?;
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
        let previous = self.state.as_ref().map(StateAnchor::from_metadata);
        let object_id = vault_object_id(&self.header_bytes)?;
        let state = StateMetadata::next(
            self.owner_fingerprint,
            StateObjectType::VaultManifest,
            object_id,
            self.suite.to_u16(),
            previous.as_ref(),
            &pt,
        )?;
        let nonce = crate::secret::random_vec(self.suite.aead_alg().nonce_len())?;
        let aad = manifest_aad(&self.header_bytes, &state);
        let ct = aead::seal_with(self.suite.aead_alg(), &self.manifest_key, &nonce, &aad, &pt)?;
        let buf = codec::to_vec(&ManifestEnvelopeV3 {
            version: MANIFEST_ENVELOPE_VERSION,
            state: state.clone(),
            nonce,
            ciphertext: ct,
        })?;
        write_atomic(&self.dir.join(MANIFEST_FILE), &buf)?;
        self.state = Some(state);
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
        let mut source = HashingReader::new(source);
        encrypt_blob(
            &self.blob_path(&file_id),
            self.suite.aead_alg(),
            &key,
            &nonce,
            &self.header_bytes,
            &mut source,
            aead::DEFAULT_CHUNK_SIZE,
        )?;
        // A source on disk can change between the initial hash and this read.
        // Preserve the old entry/blob unless the bytes actually encrypted match
        // the metadata that will be committed to the manifest.
        if source.bytes_read != size || !ct_eq(source.finalize().as_bytes(), &blake3) {
            let _ = fs_err::remove_file(self.blob_path(&file_id));
            return Err(Error::Auth);
        }
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
            key: Some(BlobKey(*key.as_bytes())),
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
        Self::from_reader_v1_inner(dir, identity, suite, reader, None)
    }

    /// Like [`Self::from_reader_v1`], but binds the new manifest to the local
    /// registry/path `object_id`.
    pub fn from_reader_v1_with_object_id(
        dir: &Path,
        identity: &Identity,
        suite: SuiteId,
        reader: &VaultReader,
        object_id: &str,
    ) -> Result<Self> {
        Self::from_reader_v1_inner(dir, identity, suite, reader, Some(object_id))
    }

    fn from_reader_v1_inner(
        dir: &Path,
        identity: &Identity,
        suite: SuiteId,
        reader: &VaultReader,
        object_id: Option<&str>,
    ) -> Result<Self> {
        let mut me = match object_id {
            Some(object_id) => Self::create_with_object_id(
                dir,
                identity,
                suite,
                reader.name(),
                reader.created_at(),
                object_id,
            )?,
            None => Self::create(dir, identity, suite, reader.name(), reader.created_at())?,
        };
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
                    let mut src = (&mut plaintext).take(e.size);
                    // Fresh vault, so this never overwrites (no old blob to drop).
                    me.stage_file(e.path.clone(), e.blake3, e.size, &mut src, e.mtime, e.mode)?;
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

    /// Build a fresh v2 vault at `dir` by **streaming** every file from an
    /// already-opened, verified v2 vault `source` — the in-place re-key path used
    /// by legacy recovery and the post-quantum upgrade. Each blob is decrypted and
    /// re-encrypted one chunk at a time (peak memory is a couple of chunks per
    /// file), so a multi-gigabyte vault is never materialized in RAM the way
    /// [`Self::to_vault`] + [`Self::from_vault`] would. The whole manifest —
    /// including the local [`TRASH_DIR`] subtree — is reproduced faithfully, so
    /// this is a true round-trip, not an export. Reseals the manifest once at the
    /// end.
    pub fn from_reader_v2(
        dir: &Path,
        identity: &Identity,
        suite: SuiteId,
        source: &VaultReaderV2,
    ) -> Result<Self> {
        Self::from_reader_v2_inner(dir, identity, suite, source, None)
    }

    /// Like [`Self::from_reader_v2`], but binds the new manifest to the local
    /// registry/path `object_id`.
    pub fn from_reader_v2_with_object_id(
        dir: &Path,
        identity: &Identity,
        suite: SuiteId,
        source: &VaultReaderV2,
        object_id: &str,
    ) -> Result<Self> {
        Self::from_reader_v2_inner(dir, identity, suite, source, Some(object_id))
    }

    fn from_reader_v2_inner(
        dir: &Path,
        identity: &Identity,
        suite: SuiteId,
        source: &VaultReaderV2,
        object_id: Option<&str>,
    ) -> Result<Self> {
        let mut me = match object_id {
            Some(object_id) => Self::create_with_object_id(
                dir,
                identity,
                suite,
                &source.manifest.vault_name,
                source.manifest.created_at,
                object_id,
            )?,
            None => Self::create(
                dir,
                identity,
                suite,
                &source.manifest.vault_name,
                source.manifest.created_at,
            )?,
        };
        // Each v2 blob is self-contained (its own key/nonce), so — unlike the v1
        // importer — there are no data offsets or contiguity to track: just walk
        // the manifest and re-stage each entry. Trash is included (a re-key is a
        // faithful round-trip), matching `to_vault`/`materialize(|_| true)`.
        for e in &source.manifest.entries {
            match e.kind {
                EntryKind::Dir => {
                    if !me.manifest.entries.iter().any(|x| x.path == e.path) {
                        me.ensure_dirs(&e.path);
                        me.manifest.entries.push(dir_entry(e.path.clone()));
                    }
                }
                EntryKind::File => {
                    // Stream this one blob's plaintext straight into a fresh blob,
                    // re-hashing as we go. Fresh vault, so this never overwrites
                    // (no old blob to drop).
                    let mut src = source.entry_plaintext(e)?;
                    me.stage_file(e.path.clone(), e.blake3, e.size, &mut src, e.mtime, e.mode)?;
                }
            }
        }
        me.reseal_manifest()?;
        Ok(me)
    }

    /// A pull-[`Read`] over one file entry's decrypted plaintext, streamed a chunk
    /// at a time from its blob (peak memory is a couple of chunks). Empty files
    /// authenticate their tag-only blob. Feeds [`Self::stage_file`] from
    /// [`Self::from_reader_v2_inner`] without buffering the whole file.
    fn entry_plaintext(&self, e: &EntryV2) -> Result<EntryPlaintext> {
        if e.chunk_size == 0 {
            return Err(Error::Format("bad chunk size"));
        }
        let key = SymKey::from_bytes(e.key.as_ref().ok_or(Error::Format("missing blob key"))?.0);
        let nonce = e
            .nonce
            .as_ref()
            .ok_or(Error::Format("missing blob nonce"))?;
        let file = BufReader::new(self.open_blob(blob_id(e)?, e.size, e.chunk_size)?);
        Ok(EntryPlaintext::Blob(aead::StreamDecryptReader::new_with(
            self.suite.aead_alg(),
            &key,
            nonce,
            &self.header_bytes,
            file,
            e.chunk_size as usize,
        )?))
    }

    /// Build a fresh v2 vault at `dir` from an in-memory [`Vault`] (the create /
    /// save path); reseals the manifest once at the end.
    pub fn from_vault(
        dir: &Path,
        identity: &Identity,
        suite: SuiteId,
        vault: &Vault,
    ) -> Result<Self> {
        Self::from_vault_inner(dir, identity, suite, vault, None)
    }

    /// Like [`Self::from_vault`], but binds the new manifest to the local
    /// registry/path `object_id`.
    pub fn from_vault_with_object_id(
        dir: &Path,
        identity: &Identity,
        suite: SuiteId,
        vault: &Vault,
        object_id: &str,
    ) -> Result<Self> {
        Self::from_vault_inner(dir, identity, suite, vault, Some(object_id))
    }

    fn from_vault_inner(
        dir: &Path,
        identity: &Identity,
        suite: SuiteId,
        vault: &Vault,
        object_id: Option<&str>,
    ) -> Result<Self> {
        let mut me = match object_id {
            Some(object_id) => Self::create_with_object_id(
                dir,
                identity,
                suite,
                &vault.name,
                vault.created_at,
                object_id,
            )?,
            None => Self::create(dir, identity, suite, &vault.name, vault.created_at)?,
        };
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
                        key: e.key.clone().ok_or(Error::Format("missing blob key"))?,
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

/// The `file_id` of a file entry, validated as a single lowercase-hex path
/// component (errors if absent or malformed — a corrupt manifest). Every path
/// that turns a `file_id` into an on-disk blob path routes through here.
fn blob_id(entry: &EntryV2) -> Result<&str> {
    let id = entry
        .file_id
        .as_deref()
        .ok_or(Error::Format("file entry missing blob id"))?;
    validate_blob_id(id)?;
    Ok(id)
}

fn new_file_id() -> Result<String> {
    Ok(crate::util::hex(&random_array::<16>()?))
}

/// Read a whole file, rejecting anything larger than `max` (untrusted-input guard).
fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    crate::safe_io::read_bounded_file(path, max)
}

/// Atomically write `bytes` to `path`: temp + fsync + rename (+ best-effort dir
/// fsync), hardened to 0600 on Unix.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut writer = crate::safe_io::SafeFileWriter::create(path)?;
    writer.write_all(bytes)?;
    writer.commit()
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
    let mut writer = crate::safe_io::SafeFileWriter::create(path)?;
    aead::encrypt_stream_with(alg, key, nonce, aad, source, &mut writer, chunk_size)?;
    writer.commit()
}

#[cfg(unix)]
fn harden_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

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
    let mut file = crate::safe_io::SafeFileWriter::create(path)?;
    plan.write_to(&mut file)?;
    file.commit()
}

/// One blob to stream during an export: the metadata needed to open and decrypt
/// it. Owned (not borrowed from the manifest) so the export plan and its reader
/// have a simple lifetime.
struct ExportFile {
    file_id: String,
    key: BlobKey,
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
    bytes_read: u64,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
            bytes_read: 0,
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
        self.bytes_read = self
            .bytes_read
            .checked_add(n as u64)
            .ok_or_else(|| std::io::Error::other("source length overflow"))?;
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

/// A pull-[`Read`] over a single v2 file entry's plaintext, including the
/// authenticated tag-only blob for an empty file. Lets
/// [`VaultReaderV2::from_reader_v2_inner`] hand [`VaultReaderV2::stage_file`] one
/// concrete reader per file without buffering the whole file.
enum EntryPlaintext {
    Blob(aead::StreamDecryptReader<BufReader<fs_err::File>>),
}

impl Read for EntryPlaintext {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            EntryPlaintext::Blob(r) => r.read(buf),
        }
    }
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
    /// No files remain.
    Done,
}

impl V2PlaintextReader<'_> {
    /// Open the next blob, including empty files, or report completion.
    fn advance(&mut self) -> std::io::Result<Advance> {
        let f = match self.files.next() {
            Some(f) => f,
            None => return Ok(Advance::Done),
        };
        let file = BufReader::new(
            self.reader
                .open_blob(&f.file_id, f.size, f.chunk_size)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        );
        let dec = aead::StreamDecryptReader::new_with(
            self.reader.suite.aead_alg(),
            &SymKey::from_bytes(f.key.0),
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
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.current.is_none() {
                match self.advance()? {
                    Advance::Opened => {}
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

    #[test]
    fn blob_keys_keep_wire_compatibility_and_redact_debug() {
        let bytes = [42; 32];
        let key = BlobKey(bytes);
        assert_eq!(codec::to_vec(&key).unwrap(), codec::to_vec(&bytes).unwrap());
        assert_eq!(
            codec::from_slice::<BlobKey>(&codec::to_vec(&bytes).unwrap())
                .unwrap()
                .0,
            bytes
        );
        assert_eq!(format!("{key:?}"), "BlobKey(***redacted***)");
    }

    #[test]
    fn changed_source_does_not_replace_the_previous_file() {
        let dir = tmp("changed-source");
        let identity = Identity::generate("Owner", 0).unwrap();
        let mut reader = VaultReaderV2::create(&dir, &identity, SuiteId::Classic, "V", 1).unwrap();
        reader
            .put_file_bytes("file.txt", b"old content", None, None)
            .unwrap();
        let before = fs_err::read(dir.join(MANIFEST_FILE)).unwrap();
        let result = reader.stage_file(
            "file.txt".into(),
            *blake3::hash(b"expected").as_bytes(),
            8,
            &b"modified"[..],
            None,
            None,
        );
        assert!(matches!(result, Err(Error::Auth)));
        assert_eq!(&*reader.read_entry("file.txt").unwrap(), b"old content");
        assert_eq!(fs_err::read(dir.join(MANIFEST_FILE)).unwrap(), before);
        assert_eq!(fs_err::read_dir(dir.join(BLOBS_DIR)).unwrap().count(), 1);
        fs_err::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn manifest_rejects_blob_counter_overflow() {
        let dir = tmp("counter-overflow");
        let identity = Identity::generate("Owner", 0).unwrap();
        let mut reader = VaultReaderV2::create(&dir, &identity, SuiteId::Classic, "V", 1).unwrap();
        reader.put_file_bytes("file.txt", b"x", None, None).unwrap();
        reader.manifest.entries[0].size = u64::MAX;
        reader.manifest.entries[0].chunk_size = 1;
        assert!(matches!(
            validate_manifest_v2(&reader.manifest, reader.suite.aead_alg()),
            Err(Error::Format("too many blob chunks"))
        ));
        fs_err::remove_dir_all(dir).unwrap();
    }

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

    #[test]
    fn legacy_raw_manifest_requires_explicit_recovery_and_is_reanchored() {
        let dir = tmp("legacy-manifest");
        let identity = Identity::generate("Legacy", 0).unwrap();
        let reader = VaultReaderV2::create(&dir, &identity, SuiteId::Classic, "Legacy", 1).unwrap();

        // Replace the v3 envelope with the historical nonce||ciphertext layout.
        let plaintext = Zeroizing::new(codec::to_vec(&reader.manifest).unwrap());
        let nonce = crate::secret::random_vec(reader.suite.aead_alg().nonce_len()).unwrap();
        let ciphertext = aead::seal_with(
            reader.suite.aead_alg(),
            &reader.manifest_key,
            &nonce,
            &reader.header_bytes,
            &plaintext,
        )
        .unwrap();
        let mut legacy = nonce;
        legacy.extend_from_slice(&ciphertext);
        fs_err::write(dir.join(MANIFEST_FILE), legacy).unwrap();
        drop(reader);

        assert!(matches!(
            VaultReaderV2::open(&dir, &identity),
            Err(Error::LegacyState("v2 vault manifest"))
        ));
        let recovered = VaultReaderV2::recover_legacy(&dir, &identity).unwrap();
        assert_eq!(recovered.state_metadata().unwrap().epoch, 1);
        drop(recovered);
        assert!(VaultReaderV2::open(&dir, &identity).is_ok());
        let _ = fs_err::remove_dir_all(&dir);
    }

    #[test]
    fn validate_blob_id_accepts_generated_ids() {
        for _ in 0..64 {
            let id = new_file_id().unwrap();
            assert!(validate_blob_id(&id).is_ok(), "generated id {id} rejected");
        }
    }

    #[test]
    fn validate_blob_id_rejects_malformed_components() {
        assert!(validate_blob_id("0123456789abcdef0123456789abcdef").is_ok());
        // Each is exactly the kind of value a blob id must never be, and — except
        // the length cases — each is 32 bytes so the *character* rule is what
        // rejects it (not a length shortcut).
        for bad in [
            "",                                  // empty
            "0123456789abcdef0123456789abcde",   // 31 chars (too short)
            "0123456789abcdef0123456789abcdef0", // 33 chars (too long)
            "0123456789ABCDEF0123456789abcdef",  // uppercase
            "0123456789abcdef0123456789abcde/",  // slash (traversal component)
            "0123456789abcdef.123456789abcdef",  // dot
            "/123456789abcdef0123456789abcdef",  // leading slash (absolute-ish)
            "..2456789abcdef0123456789abcdef0",  // starts with ..
            "0123456789abcdef0123456789abcdeg",  // non-hex char
        ] {
            assert!(validate_blob_id(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn open_rejects_blob_id_with_path_traversal() {
        // A manifest re-sealed with the owner's own key but carrying a traversal
        // blob id must still be refused on open — the id is validated as a single
        // hex component before it is ever joined to a path.
        let dir = tmp("evil-blob-id");
        let identity = Identity::generate("Owner", 0).unwrap();
        let mut reader = VaultReaderV2::create(&dir, &identity, SuiteId::Classic, "V", 1).unwrap();
        reader
            .put_file_bytes("secret.txt", b"hi", None, None)
            .unwrap();
        let idx = reader
            .manifest
            .entries
            .iter()
            .position(|e| e.kind == EntryKind::File)
            .unwrap();
        reader.manifest.entries[idx].file_id = Some("../../etc/evil".into());
        reader.reseal_manifest().unwrap();
        drop(reader);
        assert!(matches!(
            VaultReaderV2::open(&dir, &identity),
            Err(Error::Format(_))
        ));
        let _ = fs_err::remove_dir_all(&dir);
    }

    proptest::proptest! {
        #[test]
        fn validate_blob_id_matches_spec(s in ".*") {
            let got = validate_blob_id(&s).is_ok();
            let want = s.len() == BLOB_ID_LEN
                && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            proptest::prop_assert_eq!(got, want);
        }
    }
}
