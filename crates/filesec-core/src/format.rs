//! The `.fsec` container format: export (write) and import (read).
//!
//! On-disk layout, front to back:
//!
//! ```text
//! preamble   : "FSEC\x1A" | format_version (u16 BE) | header_len (u32 BE)
//! header     : CBOR(Header)  — plaintext, but bound as AAD into all AEAD and
//!              covered by the sender signature
//! manifest   : XChaCha20-Poly1305(CBOR(Manifest)), AAD = header bytes
//! data       : STREAM of fixed chunks (per-chunk AEAD), AAD = header bytes
//! trailer    : Ed25519 signature over BLAKE3(preamble || header || manifest || data)
//! ```
//!
//! The same container is used both for transport (export to other parties) and
//! for the local at-rest vault store (export to yourself).
//!
//! Import order is strictly **verify-before-decrypt**: parse and bound-check the
//! preamble and header, verify the sender signature over the entire body, then
//! unwrap the content key and decrypt. Nothing is decrypted, and no plaintext is
//! produced, until the signature and every authentication tag check out.

use std::collections::BTreeSet;
use std::io::{BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use serde::{Deserialize, Serialize};

use crate::envelope::{self, RecipientStanza};
use crate::error::{Error, Result};
use crate::identity::{Identity, PublicIdentity};
use crate::manifest::{Entry, EntryKind, Manifest};
use crate::secret::{ct_eq, random_array, random_vec, SymKey};
use crate::suite::SuiteId;
use crate::vault::{normalize_path, Vault, VaultEntry};
use crate::{aead, codec, kem, sign};

/// Magic bytes identifying a FileSec container.
const MAGIC: &[u8; 5] = b"FSEC\x1a";
/// Current container format version.
const FORMAT_VERSION: u16 = 1;
/// Fixed preamble length: magic(5) + version(2) + header_len(4).
const PREAMBLE_LEN: usize = 11;
/// Upper bound on the CBOR header size (defends untrusted parsing).
const MAX_HEADER_LEN: usize = 32 * 1024 * 1024;
/// Upper bound on the encrypted manifest size.
const MAX_MANIFEST_LEN: u64 = 512 * 1024 * 1024;

/// Plaintext header. Everything here is bound as AAD and signed.
///
/// For a hybrid container the sender's ML-DSA-65 and ML-KEM-768 public keys are
/// carried here too (so an importer can verify the post-quantum signature and
/// recompute the hybrid fingerprint). They are serialized only when present, so
/// a classical header is byte-for-byte identical to before.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Header {
    suite_id: u16,
    vault_id: [u8; 16],
    sender_sign_public: [u8; sign::PUBLIC_LEN],
    sender_kem_public: [u8; kem::PUBLIC_LEN],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sender_mldsa_public: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sender_mlkem_public: Option<Vec<u8>>,
    sender_fpr: [u8; 32],
    recipients: Vec<RecipientStanza>,
    manifest_nonce: Vec<u8>,
    manifest_len: u64,
    data_stream_nonce: Vec<u8>,
    data_chunk_size: u32,
    data_len: u64,
}

/// Length of an ML-DSA-65 signature appended to a hybrid container's trailer.
/// Zero in builds without the `pqc` feature (where no hybrid suite exists).
#[cfg(feature = "pqc")]
const fn hybrid_sig_len() -> usize {
    crate::mldsa::SIGNATURE_LEN
}
#[cfg(not(feature = "pqc"))]
const fn hybrid_sig_len() -> usize {
    0
}

/// Total signature-trailer length for a suite: the Ed25519 signature, plus the
/// ML-DSA-65 signature for a hybrid suite.
fn trailer_len(suite: SuiteId) -> usize {
    if suite.is_hybrid() {
        sign::SIGNATURE_LEN + hybrid_sig_len()
    } else {
        sign::SIGNATURE_LEN
    }
}

/// Options controlling how a vault is exported.
#[derive(Clone, Copy, Debug)]
pub struct ExportOptions {
    /// Algorithm suite to use.
    pub suite: SuiteId,
    /// Plaintext chunk size for the data stream.
    pub chunk_size: usize,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            suite: SuiteId::Classic,
            chunk_size: aead::DEFAULT_CHUNK_SIZE,
        }
    }
}

/// A file to add to a vault, with its content **streamed from disk** rather than
/// held in memory. Used by [`VaultReader::append_files`] so adding a large file
/// never loads it (or the rest of the vault) into RAM.
#[derive(Clone, Debug)]
pub struct AddedFile {
    /// Destination path inside the vault (will be normalized).
    pub vault_path: String,
    /// Source file on the real filesystem.
    pub source: PathBuf,
    /// Optional modification time to record (Unix seconds).
    pub mtime: Option<i64>,
    /// Optional advisory Unix permission bits to record.
    pub mode: Option<u32>,
}

/// The result of importing a container: the decrypted vault plus the
/// (cryptographically verified) sender's public key material.
pub struct ImportedVault {
    /// The decrypted, reconstructed vault.
    pub vault: Vault,
    /// Suite the container used.
    pub suite: SuiteId,
    /// Sender's identity fingerprint (verified; match against contacts).
    pub sender_fingerprint: [u8; 32],
    /// Sender's Ed25519 verifying key.
    pub sender_sign_public: [u8; sign::PUBLIC_LEN],
    /// Sender's X25519 agreement public key.
    pub sender_kem_public: [u8; kem::PUBLIC_LEN],
    /// Sender's ML-DSA-65 verifying key (hybrid containers only).
    pub sender_mldsa_public: Option<Vec<u8>>,
    /// Sender's ML-KEM-768 encapsulation key (hybrid containers only).
    pub sender_mlkem_public: Option<Vec<u8>>,
}

impl ImportedVault {
    /// Reconstruct the sender as a [`PublicIdentity`] (with an empty name — the
    /// trustworthy name comes from the importer's own contact book, keyed by
    /// [`Self::sender_fingerprint`]).
    #[must_use]
    pub fn sender_public(&self) -> PublicIdentity {
        PublicIdentity {
            name: String::new(),
            created_at: 0,
            sign_public: self.sender_sign_public,
            kem_public: self.sender_kem_public,
            mldsa_public: self.sender_mldsa_public.clone(),
            mlkem_public: self.sender_mlkem_public.clone(),
        }
    }
}

/// A `Write` adapter that BLAKE3-hashes everything written through it.
struct HashingWriter<W: Write> {
    inner: W,
    hasher: blake3::Hasher,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
        }
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Build the manifest (folder tree, per-entry metadata, per-file BLAKE3 hash,
/// and running data offsets) from a vault **without copying any file content**.
/// The plaintext data stream is produced separately and lazily by
/// [`VaultContentReader`], so the whole vault is never concatenated into one
/// buffer just to be streamed through the AEAD.
fn build_manifest(vault: &Vault) -> Manifest {
    let mut entries = Vec::with_capacity(vault.entries().len());
    let mut offset: u64 = 0;
    for e in vault.entries() {
        match e.kind {
            EntryKind::File => {
                let size = e.size();
                entries.push(Entry {
                    path: e.path.clone(),
                    kind: EntryKind::File,
                    size,
                    mtime: e.mtime,
                    mode: e.mode,
                    blake3: *blake3::hash(&e.content).as_bytes(),
                    data_offset: offset,
                });
                offset = offset.saturating_add(size);
            }
            EntryKind::Dir => entries.push(Entry {
                path: e.path.clone(),
                kind: EntryKind::Dir,
                size: 0,
                mtime: e.mtime,
                mode: e.mode,
                blake3: [0u8; 32],
                data_offset: 0,
            }),
        }
    }
    Manifest {
        vault_name: vault.name.clone(),
        created_at: vault.created_at,
        entries,
    }
}

/// A [`Read`] over a vault's file contents, concatenated in entry order. Lets
/// [`export_vault`] stream plaintext straight into the AEAD without first
/// copying every file into one big buffer. Borrows the vault and copies nothing
/// beyond the bytes handed to each `read` call.
struct VaultContentReader<'a> {
    entries: &'a [VaultEntry],
    idx: usize,
    pos: usize,
}

impl<'a> VaultContentReader<'a> {
    fn new(vault: &'a Vault) -> Self {
        Self {
            entries: vault.entries(),
            idx: 0,
            pos: 0,
        }
    }
}

impl Read for VaultContentReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.idx < self.entries.len() {
            let e = &self.entries[self.idx];
            if e.kind != EntryKind::File || self.pos >= e.content.len() {
                self.idx += 1;
                self.pos = 0;
                continue;
            }
            let src = &e.content[self.pos..];
            let n = src.len().min(buf.len());
            buf[..n].copy_from_slice(&src[..n]);
            self.pos += n;
            return Ok(n);
        }
        Ok(0)
    }
}

/// Reads several boxed sources back-to-back as one continuous stream. Used to
/// concatenate a vault's existing (decrypted) data with newly added files, all
/// streamed, so [`VaultReader::append_files`] never buffers a whole file.
struct ChainReader {
    rest: std::vec::IntoIter<Box<dyn Read>>,
    current: Option<Box<dyn Read>>,
}

impl ChainReader {
    fn new(sources: Vec<Box<dyn Read>>) -> Self {
        let mut rest = sources.into_iter();
        let current = rest.next();
        Self { rest, current }
    }
}

impl Read for ChainReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while let Some(r) = self.current.as_mut() {
            let n = r.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            self.current = self.rest.next();
        }
        Ok(0)
    }
}

/// Reads a plaintext stream made of consecutive fixed-size segments (one per
/// existing file, in order) and forwards only the *kept* segments' bytes,
/// silently consuming and discarding the removed ones. Used by
/// [`VaultReader::remove_paths`] to drop files without buffering anything beyond
/// a scratch chunk.
struct SelectReader<R: Read> {
    inner: R,
    segments: std::vec::IntoIter<(u64, bool)>,
    /// Bytes left in the current segment, and whether to keep them.
    remaining: u64,
    keep: bool,
    /// Reusable buffer for discarding removed segments' bytes.
    scratch: Zeroizing<Vec<u8>>,
}

impl<R: Read> SelectReader<R> {
    fn new(inner: R, segments: Vec<(u64, bool)>) -> Self {
        Self {
            inner,
            segments: segments.into_iter(),
            remaining: 0,
            keep: false,
            scratch: Zeroizing::new(vec![0u8; aead::DEFAULT_CHUNK_SIZE]),
        }
    }
}

impl<R: Read> Read for SelectReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.remaining == 0 {
                match self.segments.next() {
                    Some((size, keep)) => {
                        self.remaining = size;
                        self.keep = keep;
                    }
                    None => return Ok(0),
                }
                continue;
            }
            if self.keep {
                let want = self.remaining.min(buf.len() as u64) as usize;
                if want == 0 {
                    return Ok(0); // caller passed an empty buffer
                }
                let n = self.inner.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "source stream ended early",
                    ));
                }
                self.remaining -= n as u64;
                return Ok(n);
            }
            // Discard this (removed) segment's bytes, then move on.
            while self.remaining > 0 {
                let want = self.remaining.min(self.scratch.len() as u64) as usize;
                let n = self.inner.read(&mut self.scratch[..want])?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "source stream ended early",
                    ));
                }
                self.remaining -= n as u64;
            }
        }
    }
}

/// BLAKE3-hash a file by streaming it from disk in chunks, returning its hash and
/// byte length without ever holding the whole file in memory. The read buffer is
/// zeroizing because it briefly holds plaintext.
fn hash_file(path: &Path) -> Result<([u8; 32], u64)> {
    let mut f = BufReader::new(fs_err::File::open(path)?);
    let mut hasher = blake3::Hasher::new();
    let mut buf = Zeroizing::new(vec![0u8; aead::DEFAULT_CHUNK_SIZE]);
    let mut total: u64 = 0;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total
            .checked_add(n as u64)
            .ok_or(Error::Format("size overflow"))?;
    }
    Ok((*hasher.finalize().as_bytes(), total))
}

/// BLAKE3-hash a file on disk by path, returning its hash and byte length.
///
/// Streams the file in chunks (peak memory is one chunk); the read buffer is
/// zeroizing because it briefly holds plaintext. Exposed so callers can cheaply
/// detect whether an extracted-then-edited file actually changed before paying
/// to re-encrypt it.
pub fn hash_path(path: &Path) -> Result<([u8; 32], u64)> {
    hash_file(path)
}

/// Append a directory entry (if not already present) to `entries`, tracking
/// `seen` to avoid duplicates.
fn push_dir_entry(path: String, seen: &mut BTreeSet<String>, entries: &mut Vec<Entry>) {
    if seen.insert(path.clone()) {
        entries.push(Entry {
            path,
            kind: EntryKind::Dir,
            size: 0,
            mtime: None,
            mode: None,
            blake3: [0u8; 32],
            data_offset: 0,
        });
    }
}

/// Add directory entries for each missing ancestor of a normalized path (mirrors
/// [`crate::vault::Vault`]'s implicit-parent behavior).
fn push_ancestor_dirs(norm_path: &str, seen: &mut BTreeSet<String>, entries: &mut Vec<Entry>) {
    let comps: Vec<&str> = norm_path.split('/').collect();
    let mut acc = String::new();
    for comp in comps.iter().take(comps.len().saturating_sub(1)) {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(comp);
        push_dir_entry(acc.clone(), seen, entries);
    }
}

/// Ciphertext length of the data stream for `plaintext_len` bytes at
/// `chunk_size` (each chunk adds a tag; an empty input still yields one chunk).
fn data_ciphertext_len(plaintext_len: u64, chunk_size: u64) -> u64 {
    let chunks = if plaintext_len == 0 {
        1
    } else {
        plaintext_len.div_ceil(chunk_size)
    };
    plaintext_len + chunks * (aead::TAG_LEN as u64)
}

/// Export `vault`, signed by `sender`, readable by each of `recipients`.
pub fn export_vault<W: Write>(
    vault: &Vault,
    sender: &Identity,
    recipients: &[PublicIdentity],
    options: &ExportOptions,
    out: W,
) -> Result<()> {
    let manifest = build_manifest(vault);
    write_container(
        &manifest,
        vault.total_size(),
        VaultContentReader::new(vault),
        sender,
        recipients,
        options,
        out,
    )
}

/// Serialize and encrypt `manifest`, stream the `data` plaintext (whose
/// decrypted length is `data_plaintext_len`) through the AEAD into `out`, sign
/// the whole body, and append the trailer.
///
/// This is the single place the on-disk framing is produced; both the in-memory
/// [`export_vault`] and the streaming [`VaultReader::reexport`] funnel through it
/// so they cannot drift. The data is consumed from a [`Read`], so neither caller
/// needs to hold the whole plaintext at once.
fn write_container<R: Read, W: Write>(
    manifest: &Manifest,
    data_plaintext_len: u64,
    data: R,
    sender: &Identity,
    recipients: &[PublicIdentity],
    options: &ExportOptions,
    out: W,
) -> Result<()> {
    if recipients.is_empty() {
        return Err(Error::Vault(
            "a container needs at least one recipient".into(),
        ));
    }
    if !options.suite.is_supported() {
        return Err(Error::UnsupportedSuite(options.suite.to_u16()));
    }
    if options.chunk_size == 0 {
        return Err(Error::Format("chunk size"));
    }
    let suite = options.suite;
    let alg = suite.aead_alg();

    // A hybrid sender always advertises its post-quantum keys in the header,
    // even in a classical/AES container: its canonical fingerprint commits to
    // them, so an importer must recompute the same fingerprint to match the
    // sender against its contacts. The Ed25519 signature covers the whole header
    // (including these keys), so they are authenticated regardless of suite. A
    // hybrid *suite* additionally requires them (to dual-sign), so fail early and
    // explicitly if they are absent.
    let sender_mldsa_public = sender.mldsa_public().map(<[u8]>::to_vec);
    let sender_mlkem_public = sender.mlkem_public().map(<[u8]>::to_vec);
    if suite.is_hybrid() && (sender_mldsa_public.is_none() || sender_mlkem_public.is_none()) {
        return Err(Error::MissingPqcKey(
            "hybrid container requires a sender with post-quantum keys",
        ));
    }

    // 1. Serialize the manifest and compute the on-disk section lengths.
    let manifest_plaintext = Zeroizing::new(codec::to_vec(manifest)?);
    let manifest_len = (manifest_plaintext.len() + aead::TAG_LEN) as u64;
    let data_len = data_ciphertext_len(data_plaintext_len, options.chunk_size as u64);

    // 2. Fresh secrets. Nonce sizes follow the suite's bulk AEAD.
    let cek = SymKey::random()?;
    let manifest_nonce = random_vec(alg.nonce_len())?;
    let data_stream_nonce = random_vec(alg.stream_nonce_len())?;
    let vault_id = random_array::<16>()?;

    // 3. Wrap the content key to every recipient (hybrid suites also ML-KEM-
    //    encapsulate to each recipient inside `wrap_for_recipient`).
    let mut stanzas = Vec::with_capacity(recipients.len());
    for r in recipients {
        stanzas.push(envelope::wrap_for_recipient(&cek, r, suite)?);
    }

    // 4. Header, then bind it everywhere as AAD.
    let header = Header {
        suite_id: suite.to_u16(),
        vault_id,
        sender_sign_public: sender.sign_public(),
        sender_kem_public: sender.kem_public(),
        sender_mldsa_public,
        sender_mlkem_public,
        sender_fpr: sender.fingerprint(),
        recipients: stanzas,
        manifest_nonce: manifest_nonce.clone(),
        manifest_len,
        data_stream_nonce: data_stream_nonce.clone(),
        data_chunk_size: options.chunk_size as u32,
        data_len,
    };
    let header_bytes = codec::to_vec(&header)?;
    if header_bytes.len() > MAX_HEADER_LEN || header_bytes.len() > u32::MAX as usize {
        return Err(Error::Format("header too large"));
    }

    // 5. Stream everything out through a hashing writer (except the trailer).
    let mut hw = HashingWriter::new(BufWriter::new(out));
    hw.write_all(MAGIC)?;
    hw.write_all(&FORMAT_VERSION.to_be_bytes())?;
    hw.write_all(&(header_bytes.len() as u32).to_be_bytes())?;
    hw.write_all(&header_bytes)?;

    let enc_manifest = aead::seal_with(
        alg,
        &cek,
        &manifest_nonce,
        &header_bytes,
        &manifest_plaintext,
    )?;
    if enc_manifest.len() as u64 != manifest_len {
        return Err(Error::Format("manifest length mismatch"));
    }
    hw.write_all(&enc_manifest)?;

    let written = aead::encrypt_stream_with(
        alg,
        &cek,
        &data_stream_nonce,
        &header_bytes,
        data,
        &mut hw,
        options.chunk_size,
    )?;
    if written != data_len {
        return Err(Error::Format("data length mismatch"));
    }

    // 6. Sign the hash of everything written, then append the trailer: the
    //    Ed25519 signature, plus the ML-DSA-65 signature for a hybrid container.
    //    Requiring both on import means forging needs breaking *both* schemes.
    let hash = hw.hasher.finalize();
    let signature = sender.sign(hash.as_bytes());
    let mut inner = hw.inner;
    inner.write_all(&signature)?;
    #[cfg(feature = "pqc")]
    if suite.is_hybrid() {
        let pq_signature = sender.sign_pqc(hash.as_bytes())?;
        inner.write_all(&pq_signature)?;
    }
    inner.flush()?;
    Ok(())
}

/// Export a vault directly to a file path.
pub fn export_vault_to_path(
    vault: &Vault,
    sender: &Identity,
    recipients: &[PublicIdentity],
    options: &ExportOptions,
    path: &Path,
) -> Result<()> {
    let file = fs_err::File::create(path)?;
    export_vault(vault, sender, recipients, options, file)
}

/// Import (verify + decrypt) a container from its raw bytes.
pub fn import_vault(bytes: &[u8], identity: &Identity) -> Result<ImportedVault> {
    let len = bytes.len();
    if len < PREAMBLE_LEN {
        return Err(Error::Format("truncated preamble"));
    }
    if &bytes[0..5] != MAGIC.as_slice() {
        return Err(Error::Format("not a FileSec container"));
    }
    let version = u16::from_be_bytes([bytes[5], bytes[6]]);
    if version != FORMAT_VERSION {
        return Err(Error::Format("unsupported format version"));
    }
    let header_len = u32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]) as usize;
    if header_len > MAX_HEADER_LEN {
        return Err(Error::Format("header too large"));
    }
    let manifest_start = PREAMBLE_LEN
        .checked_add(header_len)
        .ok_or(Error::Format("length overflow"))?;
    if len < manifest_start {
        return Err(Error::Format("truncated header"));
    }
    let header_bytes = &bytes[PREAMBLE_LEN..manifest_start];
    let header: Header = codec::from_slice(header_bytes)?;

    // Validate header fields before trusting any length.
    let suite = SuiteId::from_u16(header.suite_id)?;
    let alg = suite.aead_alg();
    if header.manifest_nonce.len() != alg.nonce_len()
        || header.data_stream_nonce.len() != alg.stream_nonce_len()
    {
        return Err(Error::Format("bad nonce length"));
    }
    if header.data_chunk_size == 0 {
        return Err(Error::Format("bad chunk size"));
    }
    if header.manifest_len < aead::TAG_LEN as u64 || header.manifest_len > MAX_MANIFEST_LEN {
        return Err(Error::Format("bad manifest length"));
    }
    if header.data_len < aead::TAG_LEN as u64 || header.data_len > len as u64 {
        return Err(Error::Format("bad data length"));
    }
    let manifest_len = header.manifest_len as usize;
    let data_len = header.data_len as usize;

    let manifest_end = manifest_start
        .checked_add(manifest_len)
        .ok_or(Error::Format("length overflow"))?;
    let data_end = manifest_end
        .checked_add(data_len)
        .ok_or(Error::Format("length overflow"))?;
    let sig_end = data_end
        .checked_add(trailer_len(suite))
        .ok_or(Error::Format("length overflow"))?;
    if len != sig_end {
        return Err(Error::Format("container length does not match header"));
    }

    // Verify the sender signature(s) over the entire body BEFORE decrypting. A
    // hybrid container is dual-signed; both the Ed25519 and the ML-DSA signature
    // must verify.
    let signed = &bytes[0..data_end];
    let body_hash = blake3::hash(signed);
    let mut signature = [0u8; sign::SIGNATURE_LEN];
    signature.copy_from_slice(&bytes[data_end..data_end + sign::SIGNATURE_LEN]);
    sign::verify(&header.sender_sign_public, body_hash.as_bytes(), &signature)?;
    verify_hybrid_signature(
        suite,
        &header,
        body_hash.as_bytes(),
        &bytes[data_end..sig_end],
    )?;

    // The sender fingerprint in the header must match the signed public keys
    // (including the post-quantum ones for a hybrid sender).
    let sender = PublicIdentity {
        name: String::new(),
        created_at: 0,
        sign_public: header.sender_sign_public,
        kem_public: header.sender_kem_public,
        mldsa_public: header.sender_mldsa_public.clone(),
        mlkem_public: header.sender_mlkem_public.clone(),
    };
    if !ct_eq(&sender.fingerprint(), &header.sender_fpr) {
        return Err(Error::Format("sender fingerprint mismatch"));
    }

    // Locate our recipient stanza and recover the content key.
    let my_fpr = identity.fingerprint();
    let stanza = header
        .recipients
        .iter()
        .find(|s| ct_eq(&s.recipient_fpr, &my_fpr))
        .ok_or(Error::NotARecipient)?;
    let cek = envelope::unwrap_with_identity(stanza, identity)?;

    // Decrypt + authenticate the manifest (AAD = header bytes).
    let enc_manifest = &bytes[manifest_start..manifest_end];
    let manifest_plaintext = Zeroizing::new(aead::open_with(
        alg,
        &cek,
        &header.manifest_nonce,
        header_bytes,
        enc_manifest,
    )?);
    let manifest: Manifest = codec::from_slice(&manifest_plaintext)?;

    // Validate the plaintext layout (contiguity, sizes, total) BEFORE allocating
    // any file buffer, so a malformed manifest cannot request a huge allocation.
    validate_manifest_layout(&manifest, header.data_chunk_size as u64, header.data_len)?;

    // Stream-decrypt the data section straight into the reconstructed vault: each
    // file's bytes are read on demand, so the whole plaintext is never held in a
    // second buffer alongside the per-entry copies.
    let enc_data = &bytes[manifest_end..data_end];
    let plaintext = aead::StreamDecryptReader::new_with(
        alg,
        &cek,
        &header.data_stream_nonce,
        header_bytes,
        Cursor::new(enc_data),
        header.data_chunk_size as usize,
    )?;
    let vault = reconstruct_vault_streaming(&manifest, plaintext)?;

    Ok(ImportedVault {
        vault,
        suite,
        sender_fingerprint: header.sender_fpr,
        sender_sign_public: header.sender_sign_public,
        sender_kem_public: header.sender_kem_public,
        sender_mldsa_public: header.sender_mldsa_public,
        sender_mlkem_public: header.sender_mlkem_public,
    })
}

/// Verify the post-quantum half of a hybrid container's dual signature. For a
/// classical suite this is a no-op (the Ed25519 signature is the whole trailer).
/// `trailer` is the full signature trailer (`Ed25519 || ML-DSA`).
fn verify_hybrid_signature(
    suite: SuiteId,
    header: &Header,
    body_hash: &[u8],
    trailer: &[u8],
) -> Result<()> {
    if !suite.is_hybrid() {
        return Ok(());
    }
    #[cfg(feature = "pqc")]
    {
        let mldsa_public = header
            .sender_mldsa_public
            .as_deref()
            .ok_or(Error::Format("hybrid container missing ML-DSA sender key"))?;
        let pq_signature = trailer
            .get(sign::SIGNATURE_LEN..)
            .ok_or(Error::Format("truncated hybrid signature"))?;
        crate::mldsa::verify(mldsa_public, body_hash, pq_signature)
    }
    // Unreachable without `pqc` (no hybrid suite exists), but keeps the function
    // total and side-effect free.
    #[cfg(not(feature = "pqc"))]
    {
        let _ = (header, body_hash, trailer);
        Err(Error::UnsupportedSuite(suite.to_u16()))
    }
}

/// Validate a decrypted manifest's plaintext layout against the declared
/// ciphertext data length, **without** decrypting or allocating any file
/// content. Checks that every path is well-formed and unique, that files are
/// contiguous in ascending offset order (exactly as the writer emits them), and
/// that the resulting plaintext total — plus one AEAD tag per chunk — equals the
/// declared `data_len_ciphertext`.
///
/// Running this before reconstruction means a hostile manifest cannot trick us
/// into a giant allocation: every later `entry.size` is bounded by a total that
/// has been reconciled with the real on-disk data length. Returns the validated
/// `(total_plaintext, num_chunks)`.
fn validate_manifest_layout(
    manifest: &Manifest,
    chunk_size: u64,
    data_len_ciphertext: u64,
) -> Result<(u64, u32)> {
    if chunk_size == 0 {
        return Err(Error::Format("bad chunk size"));
    }
    let mut total_plaintext: u64 = 0;
    let mut seen = BTreeSet::new();
    for entry in &manifest.entries {
        let p = normalize_path(&entry.path)?;
        if !seen.insert(p) {
            return Err(Error::Format("duplicate path in manifest"));
        }
        if entry.kind == EntryKind::File {
            if entry.data_offset != total_plaintext {
                return Err(Error::Format("non-contiguous data offset"));
            }
            total_plaintext = total_plaintext
                .checked_add(entry.size)
                .ok_or(Error::Format("size overflow"))?;
        }
    }
    let num_chunks = if total_plaintext == 0 {
        1
    } else {
        total_plaintext.div_ceil(chunk_size)
    };
    if num_chunks > u32::MAX as u64 {
        return Err(Error::Format("too many chunks"));
    }
    let expected = total_plaintext
        .checked_add(num_chunks.saturating_mul(aead::TAG_LEN as u64))
        .ok_or(Error::Format("length overflow"))?;
    if expected != data_len_ciphertext {
        return Err(Error::Format("data length mismatch"));
    }
    Ok((total_plaintext, num_chunks as u32))
}

/// Reconstruct a [`Vault`] by reading the decrypted data stream **sequentially**
/// from `plaintext` (the concatenated file contents in entry order), re-checking
/// every path and per-file BLAKE3 hash. Only one copy of each file's bytes is
/// ever held — the copy that ends up owned by the returned vault.
///
/// The caller must have validated the manifest layout with
/// [`validate_manifest_layout`] first, which bounds every `entry.size` and
/// guarantees files are contiguous and in order.
fn reconstruct_vault_streaming<R: Read>(manifest: &Manifest, mut plaintext: R) -> Result<Vault> {
    let mut vault = Vault::new(manifest.vault_name.clone(), manifest.created_at);
    let mut offset: u64 = 0;
    for entry in &manifest.entries {
        let path = normalize_path(&entry.path)?;
        match entry.kind {
            EntryKind::File => {
                if entry.data_offset != offset {
                    return Err(Error::Format("non-contiguous data offset"));
                }
                let mut content = Zeroizing::new(vec![0u8; entry.size as usize]);
                plaintext.read_exact(&mut content)?;
                if !ct_eq(blake3::hash(&content).as_bytes(), &entry.blake3) {
                    return Err(Error::Auth);
                }
                offset = offset
                    .checked_add(entry.size)
                    .ok_or(Error::Format("size overflow"))?;
                vault.push_entry(VaultEntry {
                    path,
                    kind: EntryKind::File,
                    mtime: entry.mtime,
                    mode: entry.mode,
                    content,
                });
            }
            EntryKind::Dir => vault.push_entry(VaultEntry {
                path,
                kind: EntryKind::Dir,
                mtime: entry.mtime,
                mode: entry.mode,
                content: Zeroizing::new(Vec::new()),
            }),
        }
    }
    // The stream must end exactly at the last file — no trailing plaintext.
    let mut extra = [0u8; 1];
    match plaintext.read(&mut extra) {
        Ok(0) => Ok(vault),
        Ok(_) => Err(Error::Format("trailing data after last entry")),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Import a container directly from a file path.
pub fn import_vault_from_path(path: &Path, identity: &Identity) -> Result<ImportedVault> {
    let bytes = fs_err::read(path)?;
    import_vault(&bytes, identity)
}

/// A lazily-opened vault.
///
/// Holds only the small, authenticated manifest (the folder tree and per-entry
/// metadata) plus the content key — **not** the file data. Opening one reads
/// and decrypts only the header and manifest, so opening a multi-gigabyte vault
/// is cheap and uses negligible memory. Individual file contents are decrypted
/// from disk on demand via random-access chunk decryption.
///
/// Security note: this path is for the local, self-encrypted store. The manifest
/// is AEAD-authenticated on open and every chunk is AEAD-authenticated on read
/// (both keyed by the per-vault content key, which is wrapped to the opener's
/// private key). The end-to-end sender *signature* is verified by
/// [`import_vault`] when a container first enters the system from another party;
/// it is not re-hashed on every local open (which would require reading the
/// whole file).
#[derive(Clone)]
pub struct VaultReader {
    path: PathBuf,
    manifest: Manifest,
    cek: SymKey,
    header_bytes: Vec<u8>,
    data_stream_nonce: Vec<u8>,
    data_chunk_size: u64,
    data_section_offset: u64,
    total_plaintext: u64,
    num_chunks: u32,
    suite: SuiteId,
}

impl VaultReader {
    /// Vault display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.manifest.vault_name
    }

    /// Unix creation time.
    #[must_use]
    pub fn created_at(&self) -> i64 {
        self.manifest.created_at
    }

    /// The (metadata-only) entries: paths, kinds, sizes — no content.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.manifest.entries
    }

    /// Whether the vault has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.manifest.entries.is_empty()
    }

    /// Number of file entries (excludes directories).
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.manifest
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .count()
    }

    /// Total plaintext byte size of all files.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.total_plaintext
    }

    /// The algorithm suite the container uses.
    #[must_use]
    pub fn suite(&self) -> SuiteId {
        self.suite
    }

    /// Decrypt and return a single file's content **on demand**, reading and
    /// decrypting only the chunks that cover it.
    ///
    /// This buffers the whole file (the bytes are the return value); for writing
    /// a file straight to disk prefer [`Self::read_entry_to_writer`], which holds
    /// only one chunk at a time.
    pub fn read_entry(&self, path: &str) -> Result<Zeroizing<Vec<u8>>> {
        let entry = self.file_entry(path)?;
        let mut file = fs_err::File::open(&self.path)?;
        let mut buf = Zeroizing::new(Vec::with_capacity(entry.size as usize));
        self.decrypt_entry_to_writer(&mut file, entry, &mut *buf)?;
        Ok(buf)
    }

    /// Decrypt a single file straight into `out`, one chunk at a time, so peak
    /// memory is a single chunk regardless of the file's size. The per-file hash
    /// is verified as the bytes stream through.
    pub fn read_entry_to_writer<W: Write>(&self, path: &str, out: &mut W) -> Result<()> {
        let entry = self.file_entry(path)?;
        let mut file = fs_err::File::open(&self.path)?;
        self.decrypt_entry_to_writer(&mut file, entry, out)
    }

    /// Look up a file entry by path, erroring if it is missing or is a directory.
    fn file_entry(&self, path: &str) -> Result<&Entry> {
        let norm = normalize_path(path)?;
        let entry = self
            .manifest
            .entries
            .iter()
            .find(|e| e.path == norm)
            .ok_or_else(|| Error::Vault("entry not found".into()))?;
        if entry.kind != EntryKind::File {
            return Err(Error::Vault("not a file".into()));
        }
        Ok(entry)
    }

    /// Decrypt every file to `dest` on the real filesystem, **streaming** each
    /// file chunk-by-chunk straight to disk. Peak memory is a single chunk — not
    /// the size of the largest file, and never the whole vault.
    pub fn extract_to(&self, dest: &Path) -> Result<()> {
        let mut file = fs_err::File::open(&self.path)?;
        for entry in &self.manifest.entries {
            let norm = normalize_path(&entry.path)?;
            let target = dest.join(&norm);
            match entry.kind {
                EntryKind::Dir => {
                    fs_err::create_dir_all(&target)?;
                }
                EntryKind::File => {
                    if let Some(parent) = target.parent() {
                        fs_err::create_dir_all(parent)?;
                    }
                    let mut out = BufWriter::new(fs_err::File::create(&target)?);
                    self.decrypt_entry_to_writer(&mut file, entry, &mut out)?;
                    out.flush()?;
                }
            }
        }
        Ok(())
    }

    /// Fully decrypt the vault into an in-memory [`Vault`] (used for mutation,
    /// where the entire plaintext is needed). Streams the data section straight
    /// into the reconstructed vault, so peak memory is one chunk plus the result
    /// — never a second full copy of the plaintext. Meant to run on a worker
    /// thread.
    pub fn to_vault(&self) -> Result<Vault> {
        reconstruct_vault_streaming(&self.manifest, self.plaintext_reader()?)
    }

    /// Re-encrypt this vault to a new set of `recipients`, signed by `sender`,
    /// **streaming** the data straight from the encrypted source into the new
    /// container without ever materializing the whole plaintext.
    ///
    /// The already-authenticated manifest (paths, sizes, per-file hashes, and
    /// offsets) is reused verbatim; each data chunk is decrypted on the fly only
    /// to be immediately re-encrypted under a fresh content key. Peak memory is a
    /// couple of chunks regardless of vault size. Per-chunk AEAD authentication
    /// guards integrity on the read side (the same trust model as any other local
    /// open), so the body is not re-hashed end to end.
    pub fn reexport<W: Write>(
        &self,
        sender: &Identity,
        recipients: &[PublicIdentity],
        options: &ExportOptions,
        out: W,
    ) -> Result<()> {
        write_container(
            &self.manifest,
            self.total_plaintext,
            self.plaintext_reader()?,
            sender,
            recipients,
            options,
            out,
        )
    }

    /// Re-export directly to a file path. See [`Self::reexport`].
    pub fn reexport_to_path(
        &self,
        sender: &Identity,
        recipients: &[PublicIdentity],
        options: &ExportOptions,
        path: &Path,
    ) -> Result<()> {
        let file = fs_err::File::create(path)?;
        self.reexport(sender, recipients, options, file)
    }

    /// Write a **new** container that is this vault plus `added` files (streamed
    /// from disk) and `added_dirs` empty directories.
    ///
    /// Nothing is materialized: the existing data is decrypted-then-re-encrypted
    /// chunk-by-chunk straight from the source, and each new file is hashed and
    /// then streamed from its path on disk. Peak memory is a couple of chunks
    /// regardless of how large the vault or the added files are — the whole point
    /// of this path over decrypting to an in-memory [`Vault`], mutating, and
    /// re-exporting.
    ///
    /// Existing file offsets are preserved and new files are appended after them.
    /// Errors if an added path collides with an existing entry. New files are
    /// read twice (once to hash, once to encrypt); if a source changes size in
    /// between, the length check in [`write_container`] fails.
    pub fn append_files<W: Write>(
        &self,
        sender: &Identity,
        recipients: &[PublicIdentity],
        options: &ExportOptions,
        added: &[AddedFile],
        added_dirs: &[String],
        out: W,
    ) -> Result<()> {
        // Start from the existing entries; their data offsets stay valid because
        // new files are appended strictly after the existing data.
        let mut entries = self.manifest.entries.clone();
        let mut seen: BTreeSet<String> = entries.iter().map(|e| e.path.clone()).collect();
        let mut offset = self.total_plaintext;

        for d in added_dirs {
            let norm = normalize_path(d)?;
            push_ancestor_dirs(&norm, &mut seen, &mut entries);
            push_dir_entry(norm, &mut seen, &mut entries);
        }

        for f in added {
            let norm = normalize_path(&f.vault_path)?;
            if seen.contains(&norm) {
                return Err(Error::Vault(format!("path already exists: {norm}")));
            }
            push_ancestor_dirs(&norm, &mut seen, &mut entries);
            let (blake3, size) = hash_file(&f.source)?;
            entries.push(Entry {
                path: norm.clone(),
                kind: EntryKind::File,
                size,
                mtime: f.mtime,
                mode: f.mode,
                blake3,
                data_offset: offset,
            });
            seen.insert(norm);
            offset = offset
                .checked_add(size)
                .ok_or(Error::Format("size overflow"))?;
        }

        let manifest = Manifest {
            vault_name: self.manifest.vault_name.clone(),
            created_at: self.manifest.created_at,
            entries,
        };

        // Data stream = existing plaintext (streamed from the source) followed by
        // each new file (streamed from disk), in the same order the file entries
        // were appended above.
        let mut sources: Vec<Box<dyn Read>> = Vec::with_capacity(added.len() + 1);
        sources.push(Box::new(self.plaintext_reader()?));
        for f in added {
            sources.push(Box::new(BufReader::new(fs_err::File::open(&f.source)?)));
        }
        write_container(
            &manifest,
            offset,
            ChainReader::new(sources),
            sender,
            recipients,
            options,
            out,
        )
    }

    /// Append files directly to a new file path. See [`Self::append_files`].
    pub fn append_files_to_path(
        &self,
        sender: &Identity,
        recipients: &[PublicIdentity],
        options: &ExportOptions,
        added: &[AddedFile],
        added_dirs: &[String],
        path: &Path,
    ) -> Result<()> {
        let file = fs_err::File::create(path)?;
        self.append_files(sender, recipients, options, added, added_dirs, file)
    }

    /// Write a **new** container that is this vault minus every path in `remove`
    /// (each removes that entry and, for a directory, its whole subtree).
    ///
    /// Like [`Self::append_files`], nothing is materialized: the existing data is
    /// streamed from the encrypted source, kept files are re-encrypted on the
    /// fly, and removed files' bytes are decrypted-then-discarded. Surviving file
    /// offsets are recomputed so the new data stream stays contiguous. Peak
    /// memory is a couple of chunks regardless of vault size. Removing a path
    /// that is not present is a no-op (the vault is simply rewritten).
    pub fn remove_paths<W: Write>(
        &self,
        sender: &Identity,
        recipients: &[PublicIdentity],
        options: &ExportOptions,
        remove: &[String],
        out: W,
    ) -> Result<()> {
        // Precompute exact-match and subtree-prefix matchers.
        let mut matchers: Vec<(String, String)> = Vec::with_capacity(remove.len());
        for p in remove {
            let norm = normalize_path(p)?;
            let prefix = format!("{norm}/");
            matchers.push((norm, prefix));
        }
        let is_removed = |path: &str| {
            matchers
                .iter()
                .any(|(exact, prefix)| path == exact || path.starts_with(prefix.as_str()))
        };

        // Build the surviving manifest (file offsets recomputed) and the per-file
        // keep-flags for the data stream, in existing data-stream order.
        let mut entries = Vec::new();
        let mut segments: Vec<(u64, bool)> = Vec::new();
        let mut offset: u64 = 0;
        for e in &self.manifest.entries {
            let removed = is_removed(&e.path);
            if e.kind == EntryKind::File {
                segments.push((e.size, !removed));
            }
            if removed {
                continue;
            }
            let mut ne = e.clone();
            if ne.kind == EntryKind::File {
                ne.data_offset = offset;
                offset = offset
                    .checked_add(ne.size)
                    .ok_or(Error::Format("size overflow"))?;
            } else {
                ne.data_offset = 0;
            }
            entries.push(ne);
        }

        let manifest = Manifest {
            vault_name: self.manifest.vault_name.clone(),
            created_at: self.manifest.created_at,
            entries,
        };
        let data = SelectReader::new(self.plaintext_reader()?, segments);
        write_container(&manifest, offset, data, sender, recipients, options, out)
    }

    /// Remove paths directly to a new file path. See [`Self::remove_paths`].
    pub fn remove_paths_to_path(
        &self,
        sender: &Identity,
        recipients: &[PublicIdentity],
        options: &ExportOptions,
        remove: &[String],
        path: &Path,
    ) -> Result<()> {
        let file = fs_err::File::create(path)?;
        self.remove_paths(sender, recipients, options, remove, file)
    }

    /// Write a **new** container identical to this vault except that the file at
    /// `path` is replaced by the contents of `new_source` (streamed from disk).
    ///
    /// This is the fused form of [`Self::remove_paths`] + [`Self::append_files`]
    /// in a single streaming pass: surviving files are decrypted-then-re-encrypted
    /// on the fly, the old file's bytes are decrypted-then-discarded, and the new
    /// file is hashed then streamed from disk. The replaced file moves to the end
    /// of the data stream, so every surviving file's offset is recomputed to keep
    /// the stream contiguous. Peak memory is a couple of chunks regardless of size.
    ///
    /// Errors if `path` is absent or names a directory (unlike `append_files`,
    /// which collides, and `remove_paths`, which no-ops). The new source is read
    /// twice (once to hash, once to encrypt); if it changes size in between, the
    /// length check in [`write_container`] fails. The given `mtime`/`mode` are
    /// recorded on the new entry.
    #[allow(clippy::too_many_arguments)]
    pub fn replace_file<W: Write>(
        &self,
        sender: &Identity,
        recipients: &[PublicIdentity],
        options: &ExportOptions,
        path: &str,
        new_source: &Path,
        mtime: Option<i64>,
        mode: Option<u32>,
        out: W,
    ) -> Result<()> {
        let target = normalize_path(path)?;

        // Confirm the target is an existing file before changing anything.
        let is_file = self
            .manifest
            .entries
            .iter()
            .any(|e| e.path == target && e.kind == EntryKind::File);
        if !is_file {
            return Err(Error::Vault(format!("not a file in vault: {target}")));
        }

        // Hash the replacement up front (also yields its byte length).
        let (new_blake3, new_size) = hash_file(new_source)?;

        // Build the surviving manifest (all file offsets recomputed) and the
        // keep/drop segment list over the existing data stream, in existing
        // order. The replaced file is dropped here and re-appended at the end.
        let mut entries = Vec::with_capacity(self.manifest.entries.len());
        let mut segments: Vec<(u64, bool)> = Vec::new();
        let mut offset: u64 = 0;
        for e in &self.manifest.entries {
            let is_target = e.kind == EntryKind::File && e.path == target;
            if e.kind == EntryKind::File {
                segments.push((e.size, !is_target));
            }
            if is_target {
                continue; // dropped here, re-appended below
            }
            let mut ne = e.clone();
            if ne.kind == EntryKind::File {
                ne.data_offset = offset;
                offset = offset
                    .checked_add(ne.size)
                    .ok_or(Error::Format("size overflow"))?;
            } else {
                ne.data_offset = 0;
            }
            entries.push(ne);
        }

        // Re-append the replaced path as a new file entry at the end. Its
        // ancestor dirs already exist (the path was present before), so there is
        // no need to push them.
        entries.push(Entry {
            path: target,
            kind: EntryKind::File,
            size: new_size,
            mtime,
            mode,
            blake3: new_blake3,
            data_offset: offset,
        });
        offset = offset
            .checked_add(new_size)
            .ok_or(Error::Format("size overflow"))?;

        let manifest = Manifest {
            vault_name: self.manifest.vault_name.clone(),
            created_at: self.manifest.created_at,
            entries,
        };

        // Data = surviving plaintext (the old target's bytes discarded by
        // SelectReader) followed by the new file streamed from disk.
        let kept = SelectReader::new(self.plaintext_reader()?, segments);
        let sources: Vec<Box<dyn Read>> = vec![
            Box::new(kept),
            Box::new(BufReader::new(fs_err::File::open(new_source)?)),
        ];
        write_container(
            &manifest,
            offset,
            ChainReader::new(sources),
            sender,
            recipients,
            options,
            out,
        )
    }

    /// Replace a file directly to a new file path. See [`Self::replace_file`].
    #[allow(clippy::too_many_arguments)]
    pub fn replace_file_to_path(
        &self,
        sender: &Identity,
        recipients: &[PublicIdentity],
        options: &ExportOptions,
        path: &str,
        new_source: &Path,
        mtime: Option<i64>,
        mode: Option<u32>,
        out_path: &Path,
    ) -> Result<()> {
        let file = fs_err::File::create(out_path)?;
        self.replace_file(
            sender, recipients, options, path, new_source, mtime, mode, file,
        )
    }

    /// A [`Read`] that yields this vault's full decrypted plaintext, streamed
    /// chunk-by-chunk from disk. Shared by [`Self::to_vault`] and
    /// [`Self::reexport`].
    fn plaintext_reader(
        &self,
    ) -> Result<aead::StreamDecryptReader<std::io::Take<BufReader<fs_err::File>>>> {
        let mut file = fs_err::File::open(&self.path)?;
        file.seek(SeekFrom::Start(self.data_section_offset))?;
        let limited = BufReader::new(file).take(self.data_len());
        aead::StreamDecryptReader::new_with(
            self.suite.aead_alg(),
            &self.cek,
            &self.data_stream_nonce,
            &self.header_bytes,
            limited,
            self.data_chunk_size as usize,
        )
    }

    fn data_len(&self) -> u64 {
        self.total_plaintext + u64::from(self.num_chunks) * aead::TAG_LEN as u64
    }

    /// Decrypt the chunks covering `entry` and write **only** that file's exact
    /// bytes to `out`, one chunk at a time. Peak memory is a single decrypted
    /// chunk; nothing the size of the file is ever held. The per-file BLAKE3 hash
    /// is verified incrementally as the bytes stream through.
    ///
    /// Each chunk is independently AEAD-authenticated by [`aead::decrypt_chunk`]
    /// before any of its bytes are written, so tampered ciphertext is rejected
    /// chunk-by-chunk rather than after buffering the whole file.
    fn decrypt_entry_to_writer<W: Write>(
        &self,
        file: &mut fs_err::File,
        entry: &Entry,
        out: &mut W,
    ) -> Result<()> {
        if entry.size == 0 {
            if !ct_eq(blake3::hash(&[]).as_bytes(), &entry.blake3) {
                return Err(Error::Auth);
            }
            return Ok(());
        }
        let chunk = self.data_chunk_size;
        let last_index = u64::from(self.num_chunks) - 1;
        let file_start = entry.data_offset;
        let file_end = file_start
            .checked_add(entry.size)
            .ok_or(Error::Format("entry range overflow"))?;
        let first = file_start / chunk;
        let last = (file_end - 1) / chunk;
        if last > last_index {
            return Err(Error::Format("entry range out of bounds"));
        }
        let mut hasher = blake3::Hasher::new();
        for c in first..=last {
            let is_last = c == last_index;
            let pt_len = if is_last {
                self.total_plaintext - last_index * chunk
            } else {
                chunk
            };
            let ct_len = (pt_len + aead::TAG_LEN as u64) as usize;
            let ct_off = self.data_section_offset + c * (chunk + aead::TAG_LEN as u64);
            file.seek(SeekFrom::Start(ct_off))?;
            let mut ct = vec![0u8; ct_len];
            file.read_exact(&mut ct)?;
            let pt = Zeroizing::new(aead::decrypt_chunk_with(
                self.suite.aead_alg(),
                &self.cek,
                &self.data_stream_nonce,
                &self.header_bytes,
                c as u32,
                is_last,
                &ct,
            )?);
            // Write only the part of this chunk that overlaps the wanted file.
            let chunk_start = c * chunk;
            let lo = file_start.saturating_sub(chunk_start) as usize;
            let hi = (file_end.min(chunk_start + pt_len) - chunk_start) as usize;
            if hi > pt.len() || lo > hi {
                return Err(Error::Format("chunk range mismatch"));
            }
            hasher.update(&pt[lo..hi]);
            out.write_all(&pt[lo..hi])?;
        }
        if !ct_eq(hasher.finalize().as_bytes(), &entry.blake3) {
            return Err(Error::Auth);
        }
        Ok(())
    }
}

/// Lazily open a container from a file path: authenticate the header and
/// manifest, recover the content key, and return a [`VaultReader`] **without**
/// reading or decrypting the file data.
pub fn open_vault_from_path(path: &Path, identity: &Identity) -> Result<VaultReader> {
    let file_len = fs_err::metadata(path)?.len();
    if file_len < PREAMBLE_LEN as u64 {
        return Err(Error::Format("truncated preamble"));
    }
    let mut file = BufReader::new(fs_err::File::open(path)?);
    let (reader, _sender) = open_reader_inner(path, &mut file, file_len, identity, None)?;
    Ok(reader)
}

/// Sender identity material recovered from a container and **cryptographically
/// verified** against the end-to-end signature by [`verify_and_open`].
pub struct VerifiedSender {
    /// Sender fingerprint — match this against your contact book.
    pub fingerprint: [u8; 32],
    /// Sender Ed25519 verifying key.
    pub sign_public: [u8; sign::PUBLIC_LEN],
    /// Sender X25519 agreement key.
    pub kem_public: [u8; kem::PUBLIC_LEN],
    /// Sender ML-DSA-65 verifying key (hybrid containers only).
    pub mldsa_public: Option<Vec<u8>>,
    /// Sender ML-KEM-768 encapsulation key (hybrid containers only).
    pub mlkem_public: Option<Vec<u8>>,
}

impl VerifiedSender {
    /// Reconstruct the sender as a [`PublicIdentity`] (with an empty name — the
    /// trustworthy name comes from the importer's own contact book).
    #[must_use]
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            name: String::new(),
            created_at: 0,
            sign_public: self.sign_public,
            kem_public: self.kem_public,
            mldsa_public: self.mldsa_public.clone(),
            mlkem_public: self.mlkem_public.clone(),
        }
    }
}

/// Open a container **and verify the sender's end-to-end signature**, streaming
/// the whole body through a hasher so the data section is never loaded into
/// memory.
///
/// Use this when a container first enters the system from another party: the
/// signature proves who sent it. The returned [`VaultReader`] then streams file
/// data on demand, so importing a multi-gigabyte container — even one holding a
/// single huge file — uses only a few chunks of memory. Pair it with
/// [`VaultReader::reexport`] to transcode straight into the local store without
/// ever materializing the plaintext.
///
/// Verify-before-decrypt: the signature is checked over the entire body here,
/// before the caller decrypts or transcodes any file content.
pub fn verify_and_open(path: &Path, identity: &Identity) -> Result<(VaultReader, VerifiedSender)> {
    let file_len = fs_err::metadata(path)?.len();
    if file_len < PREAMBLE_LEN as u64 {
        return Err(Error::Format("truncated preamble"));
    }
    let mut file = BufReader::new(fs_err::File::open(path)?);
    let mut hasher = blake3::Hasher::new();
    let (reader, sender) =
        open_reader_inner(path, &mut file, file_len, identity, Some(&mut hasher))?;

    // The cursor now sits at the start of the data section. Stream the ciphertext
    // through the hasher (one chunk at a time — never buffered), then read and
    // verify the signature trailer over the whole body. A hybrid container is
    // dual-signed (Ed25519 + ML-DSA); both signatures must verify.
    let mut remaining = reader.data_len();
    let mut buf = vec![0u8; aead::DEFAULT_CHUNK_SIZE];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        file.read_exact(&mut buf[..want])?;
        hasher.update(&buf[..want]);
        remaining -= want as u64;
    }
    let mut trailer = vec![0u8; trailer_len(reader.suite)];
    file.read_exact(&mut trailer)?;
    let body_hash = hasher.finalize();
    let mut signature = [0u8; sign::SIGNATURE_LEN];
    signature.copy_from_slice(&trailer[..sign::SIGNATURE_LEN]);
    sign::verify(&sender.sign_public, body_hash.as_bytes(), &signature)?;
    verify_verified_sender_hybrid(reader.suite, &sender, body_hash.as_bytes(), &trailer)?;

    Ok((reader, sender))
}

/// The post-quantum half of [`verify_and_open`]'s signature check, mirroring
/// [`verify_hybrid_signature`] but against a [`VerifiedSender`].
fn verify_verified_sender_hybrid(
    suite: SuiteId,
    sender: &VerifiedSender,
    body_hash: &[u8],
    trailer: &[u8],
) -> Result<()> {
    if !suite.is_hybrid() {
        return Ok(());
    }
    #[cfg(feature = "pqc")]
    {
        let mldsa_public = sender
            .mldsa_public
            .as_deref()
            .ok_or(Error::Format("hybrid container missing ML-DSA sender key"))?;
        let pq_signature = trailer
            .get(sign::SIGNATURE_LEN..)
            .ok_or(Error::Format("truncated hybrid signature"))?;
        crate::mldsa::verify(mldsa_public, body_hash, pq_signature)
    }
    #[cfg(not(feature = "pqc"))]
    {
        let _ = (sender, body_hash, trailer);
        Err(Error::UnsupportedSuite(suite.to_u16()))
    }
}

/// Shared container parser: read the preamble, header, and encrypted manifest
/// from `file` (positioned at the start), recover the content key, validate the
/// layout, and build a [`VaultReader`]. Leaves `file` positioned at the start of
/// the data section. When `hasher` is supplied, the preamble, header, and
/// encrypted manifest are fed into it so the caller can finish hashing the data
/// section and verify the signature.
fn open_reader_inner(
    path: &Path,
    file: &mut BufReader<fs_err::File>,
    file_len: u64,
    identity: &Identity,
    mut hasher: Option<&mut blake3::Hasher>,
) -> Result<(VaultReader, VerifiedSender)> {
    let mut preamble = [0u8; PREAMBLE_LEN];
    file.read_exact(&mut preamble)?;
    if &preamble[0..5] != MAGIC.as_slice() {
        return Err(Error::Format("not a FileSec container"));
    }
    let version = u16::from_be_bytes([preamble[5], preamble[6]]);
    if version != FORMAT_VERSION {
        return Err(Error::Format("unsupported format version"));
    }
    let header_len =
        u32::from_be_bytes([preamble[7], preamble[8], preamble[9], preamble[10]]) as usize;
    if header_len > MAX_HEADER_LEN {
        return Err(Error::Format("header too large"));
    }
    if let Some(h) = hasher.as_mut() {
        h.update(&preamble);
    }

    let mut header_bytes = vec![0u8; header_len];
    file.read_exact(&mut header_bytes)?;
    if let Some(h) = hasher.as_mut() {
        h.update(&header_bytes);
    }
    let header: Header = codec::from_slice(&header_bytes)?;
    let suite = SuiteId::from_u16(header.suite_id)?;
    let alg = suite.aead_alg();
    if header.manifest_nonce.len() != alg.nonce_len()
        || header.data_stream_nonce.len() != alg.stream_nonce_len()
    {
        return Err(Error::Format("bad nonce length"));
    }
    if header.data_chunk_size == 0 {
        return Err(Error::Format("bad chunk size"));
    }
    if header.manifest_len < aead::TAG_LEN as u64 || header.manifest_len > MAX_MANIFEST_LEN {
        return Err(Error::Format("bad manifest length"));
    }
    if header.data_len < aead::TAG_LEN as u64 {
        return Err(Error::Format("bad data length"));
    }

    let manifest_start = PREAMBLE_LEN as u64 + header_len as u64;
    let data_section_offset = manifest_start
        .checked_add(header.manifest_len)
        .ok_or(Error::Format("length overflow"))?;
    let sig_end = data_section_offset
        .checked_add(header.data_len)
        .and_then(|x| x.checked_add(trailer_len(suite) as u64))
        .ok_or(Error::Format("length overflow"))?;
    if file_len != sig_end {
        return Err(Error::Format("container length does not match header"));
    }

    // Read and authenticate the manifest (we are positioned at manifest_start).
    let mut enc_manifest = vec![0u8; header.manifest_len as usize];
    file.read_exact(&mut enc_manifest)?;
    if let Some(h) = hasher.as_mut() {
        h.update(&enc_manifest);
    }

    // The sender fingerprint in the header must match its signed public keys
    // (including the post-quantum ones for a hybrid sender).
    let sender = VerifiedSender {
        fingerprint: header.sender_fpr,
        sign_public: header.sender_sign_public,
        kem_public: header.sender_kem_public,
        mldsa_public: header.sender_mldsa_public.clone(),
        mlkem_public: header.sender_mlkem_public.clone(),
    };
    if !ct_eq(&sender.public().fingerprint(), &header.sender_fpr) {
        return Err(Error::Format("sender fingerprint mismatch"));
    }

    let my_fpr = identity.fingerprint();
    let stanza = header
        .recipients
        .iter()
        .find(|s| ct_eq(&s.recipient_fpr, &my_fpr))
        .ok_or(Error::NotARecipient)?;
    let cek = envelope::unwrap_with_identity(stanza, identity)?;

    let manifest_plaintext = Zeroizing::new(aead::open_with(
        alg,
        &cek,
        &header.manifest_nonce,
        &header_bytes,
        &enc_manifest,
    )?);
    let manifest: Manifest = codec::from_slice(&manifest_plaintext)?;

    // Validate the tree and the plaintext layout against the declared data
    // length. Our writer emits files contiguously in entry order, so offsets must
    // form a running total that reconciles with `header.data_len`.
    let chunk = header.data_chunk_size as u64;
    let (total_plaintext, num_chunks) =
        validate_manifest_layout(&manifest, chunk, header.data_len)?;

    let reader = VaultReader {
        path: path.to_path_buf(),
        manifest,
        cek,
        header_bytes,
        data_stream_nonce: header.data_stream_nonce,
        data_chunk_size: chunk,
        data_section_offset,
        total_plaintext,
        num_chunks,
        suite,
    };
    Ok((reader, sender))
}
