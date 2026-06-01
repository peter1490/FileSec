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

use std::io::{BufWriter, Cursor, Write};
use std::path::Path;

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
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Header {
    suite_id: u16,
    vault_id: [u8; 16],
    sender_sign_public: [u8; sign::PUBLIC_LEN],
    sender_kem_public: [u8; kem::PUBLIC_LEN],
    sender_fpr: [u8; 32],
    recipients: Vec<RecipientStanza>,
    manifest_nonce: Vec<u8>,
    manifest_len: u64,
    data_stream_nonce: Vec<u8>,
    data_chunk_size: u32,
    data_len: u64,
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

/// Build the manifest and the concatenated plaintext data stream from a vault.
fn build_manifest_and_data(vault: &Vault) -> (Manifest, Zeroizing<Vec<u8>>) {
    let mut data = Zeroizing::new(Vec::with_capacity(vault.total_size() as usize));
    let mut entries = Vec::with_capacity(vault.entries().len());
    for e in vault.entries() {
        match e.kind {
            EntryKind::File => {
                let offset = data.len() as u64;
                let hash = *blake3::hash(&e.content).as_bytes();
                data.extend_from_slice(&e.content);
                entries.push(Entry {
                    path: e.path.clone(),
                    kind: EntryKind::File,
                    size: e.size(),
                    mtime: e.mtime,
                    mode: e.mode,
                    blake3: hash,
                    data_offset: offset,
                });
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
    (
        Manifest {
            vault_name: vault.name.clone(),
            created_at: vault.created_at,
            entries,
        },
        data,
    )
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

    // 1. Manifest + concatenated plaintext.
    let (manifest, data) = build_manifest_and_data(vault);
    let manifest_plaintext = Zeroizing::new(codec::to_vec(&manifest)?);
    let manifest_len = (manifest_plaintext.len() + aead::TAG_LEN) as u64;
    let data_len = data_ciphertext_len(data.len() as u64, options.chunk_size as u64);

    // 2. Fresh secrets.
    let cek = SymKey::random()?;
    let manifest_nonce = random_vec(aead::NONCE_LEN)?;
    let data_stream_nonce = random_vec(aead::STREAM_NONCE_LEN)?;
    let vault_id = random_array::<16>()?;

    // 3. Wrap the content key to every recipient.
    let mut stanzas = Vec::with_capacity(recipients.len());
    for r in recipients {
        stanzas.push(envelope::wrap_for_recipient(&cek, r)?);
    }

    // 4. Header, then bind it everywhere as AAD.
    let header = Header {
        suite_id: options.suite.to_u16(),
        vault_id,
        sender_sign_public: sender.sign_public(),
        sender_kem_public: sender.kem_public(),
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

    let enc_manifest = aead::seal(&cek, &manifest_nonce, &header_bytes, &manifest_plaintext)?;
    if enc_manifest.len() as u64 != manifest_len {
        return Err(Error::Format("manifest length mismatch"));
    }
    hw.write_all(&enc_manifest)?;

    let written = aead::encrypt_stream(
        &cek,
        &data_stream_nonce,
        &header_bytes,
        Cursor::new(data.as_slice()),
        &mut hw,
        options.chunk_size,
    )?;
    if written != data_len {
        return Err(Error::Format("data length mismatch"));
    }

    // 6. Sign the hash of everything written, then append the signature.
    let hash = hw.hasher.finalize();
    let signature = sender.sign(hash.as_bytes());
    let mut inner = hw.inner;
    inner.write_all(&signature)?;
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
    if header.manifest_nonce.len() != aead::NONCE_LEN
        || header.data_stream_nonce.len() != aead::STREAM_NONCE_LEN
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
        .checked_add(sign::SIGNATURE_LEN)
        .ok_or(Error::Format("length overflow"))?;
    if len != sig_end {
        return Err(Error::Format("container length does not match header"));
    }

    // Verify the sender signature over the entire body BEFORE decrypting.
    let signed = &bytes[0..data_end];
    let mut signature = [0u8; sign::SIGNATURE_LEN];
    signature.copy_from_slice(&bytes[data_end..sig_end]);
    let body_hash = blake3::hash(signed);
    sign::verify(&header.sender_sign_public, body_hash.as_bytes(), &signature)?;

    // The sender fingerprint in the header must match the signed public keys.
    let sender = PublicIdentity {
        name: String::new(),
        created_at: 0,
        sign_public: header.sender_sign_public,
        kem_public: header.sender_kem_public,
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
    let manifest_plaintext = Zeroizing::new(aead::open(
        &cek,
        &header.manifest_nonce,
        header_bytes,
        enc_manifest,
    )?);
    let manifest: Manifest = codec::from_slice(&manifest_plaintext)?;

    // Stream-decrypt the data section.
    let enc_data = &bytes[manifest_end..data_end];
    let mut data = Zeroizing::new(Vec::new());
    aead::decrypt_stream(
        &cek,
        &header.data_stream_nonce,
        header_bytes,
        Cursor::new(enc_data),
        &mut *data,
        header.data_chunk_size as usize,
    )?;

    // Reconstruct the vault, re-validating every path and per-file hash.
    let mut vault = Vault::new(manifest.vault_name, manifest.created_at);
    let mut seen = std::collections::BTreeSet::new();
    for entry in &manifest.entries {
        let path = normalize_path(&entry.path)?;
        if !seen.insert(path.clone()) {
            return Err(Error::Format("duplicate path in manifest"));
        }
        match entry.kind {
            EntryKind::File => {
                let start = entry.data_offset as usize;
                let end = start
                    .checked_add(entry.size as usize)
                    .ok_or(Error::Format("entry range overflow"))?;
                if end > data.len() {
                    return Err(Error::Format("entry range out of bounds"));
                }
                let content = Zeroizing::new(data[start..end].to_vec());
                if !ct_eq(blake3::hash(&content).as_bytes(), &entry.blake3) {
                    return Err(Error::Auth);
                }
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

    Ok(ImportedVault {
        vault,
        suite,
        sender_fingerprint: header.sender_fpr,
        sender_sign_public: header.sender_sign_public,
        sender_kem_public: header.sender_kem_public,
    })
}

/// Import a container directly from a file path.
pub fn import_vault_from_path(path: &Path, identity: &Identity) -> Result<ImportedVault> {
    let bytes = fs_err::read(path)?;
    import_vault(&bytes, identity)
}
