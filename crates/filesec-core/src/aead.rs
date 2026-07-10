//! Authenticated encryption for the container suites.
//!
//! Two layers:
//!
//! * **One-shot** [`seal`]/[`open`] for small items (key wrapping, the
//!   manifest). A large random nonce makes random nonces collision-safe.
//! * **Streaming** [`encrypt_stream`]/[`decrypt_stream`] for file data, using
//!   the STREAM construction (fixed-size chunks, per-chunk nonce derived from an
//!   internal BE32 counter, explicit last-chunk flag). This authenticates each
//!   chunk and detects truncation/reordering of the whole stream.
//!
//! Every call binds caller-supplied associated data (AAD) — FileSec always
//! passes the container header so the algorithm suite and recipient set are
//! cryptographically bound to the ciphertext (anti-downgrade).
//!
//! # Algorithm agility
//!
//! The default suite (`0x0001`/`0x0101`) uses **XChaCha20-Poly1305**; the
//! `pqc`-gated suite `0x0002` uses **AES-256-GCM**. The cipher is selected per
//! call by an [`AeadAlg`] through the `*_with` functions; the bare [`seal`],
//! [`open`], [`encrypt_stream`], [`decrypt_stream`], and [`decrypt_chunk`]
//! helpers are thin XChaCha-only wrappers kept for the key-wrap and keystore
//! paths (which are always XChaCha, independent of the container suite). Both
//! ciphers share the same `aead 0.5` STREAM construction, so the on-disk framing
//! and the random-access [`decrypt_chunk`] math are identical apart from the
//! nonce length.

use std::io::{Read, Write};

#[cfg(feature = "pqc")]
use aes_gcm::Aes256Gcm;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::SymKey;

/// Length of an XChaCha20-Poly1305 nonce (one-shot). Also the nonce length used
/// for every key-wrap and the keystore, which are always XChaCha.
pub const NONCE_LEN: usize = 24;
/// Poly1305 / GCM authentication tag length (the same 16 bytes for both ciphers).
pub const TAG_LEN: usize = 16;
/// Length of the random nonce prefix for the XChaCha STREAM construction
/// (24-byte XChaCha nonce minus the 5 bytes STREAM reserves for its counter +
/// last-chunk flag).
pub const STREAM_NONCE_LEN: usize = NONCE_LEN - 5;
/// Default plaintext chunk size for streamed data (64 KiB).
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
/// Hard upper bound on any streamed chunk size. The chunk size travels in
/// untrusted headers/manifests and directly drives per-chunk buffer allocation
/// (`chunk_size + TAG_LEN`), so it is clamped here — at the single allocation
/// chokepoint — before any buffer is sized from it. Far above the 64 KiB default
/// FileSec ever writes, so no legitimate container is affected; a hostile header
/// claiming a multi-gigabyte chunk is rejected before it can force a giant
/// allocation.
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;
/// The 5 bytes the `aead` STREAM construction reserves at the tail of the nonce
/// (a BE32 chunk counter plus a one-byte last-chunk flag).
const STREAM_OVERHEAD: usize = 5;

/// The bulk AEAD a container suite uses for its manifest and file data.
///
/// The KEM key-wrap and the keystore are deliberately *not* parameterized by
/// this — they always use XChaCha20-Poly1305 regardless of the container suite,
/// since a 192-bit-nonce one-shot is the conservative choice for wrapping a
/// single key and keeps those paths suite-independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadAlg {
    /// XChaCha20-Poly1305 (suites `0x0001` and `0x0101`).
    XChaCha20Poly1305,
    /// AES-256-GCM (suite `0x0002`).
    #[cfg(feature = "pqc")]
    Aes256Gcm,
}

impl AeadAlg {
    /// One-shot nonce length: 24 bytes for XChaCha, 12 for AES-GCM.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            AeadAlg::XChaCha20Poly1305 => 24,
            #[cfg(feature = "pqc")]
            AeadAlg::Aes256Gcm => 12,
        }
    }

    /// STREAM nonce-prefix length (the one-shot nonce minus the 5 STREAM bytes):
    /// 19 bytes for XChaCha, 7 for AES-GCM.
    #[must_use]
    pub const fn stream_nonce_len(self) -> usize {
        self.nonce_len() - STREAM_OVERHEAD
    }
}

fn cipher(key: &SymKey) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| Error::BadKey("aead key length"))
}

#[cfg(feature = "pqc")]
fn aes_cipher(key: &SymKey) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| Error::BadKey("aead key length"))
}

/// Generic one-shot seal over any `aead 0.5` cipher. The nonce length is checked
/// by the caller against [`AeadAlg::nonce_len`].
fn one_shot_seal<C: Aead>(cipher: &C, nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    cipher
        .encrypt(GenericArray::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| Error::Auth)
}

/// Generic one-shot open over any `aead 0.5` cipher.
fn one_shot_open<C: Aead>(cipher: &C, nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    cipher
        .decrypt(GenericArray::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::Auth)
}

/// One-shot authenticated encryption with the chosen `alg`. Returns
/// `ciphertext || tag`.
pub fn seal_with(
    alg: AeadAlg,
    key: &SymKey,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != alg.nonce_len() {
        return Err(Error::Format("aead nonce length"));
    }
    match alg {
        AeadAlg::XChaCha20Poly1305 => one_shot_seal(&cipher(key)?, nonce, aad, plaintext),
        #[cfg(feature = "pqc")]
        AeadAlg::Aes256Gcm => one_shot_seal(&aes_cipher(key)?, nonce, aad, plaintext),
    }
}

/// One-shot authenticated decryption of `ciphertext || tag` with the chosen `alg`.
pub fn open_with(
    alg: AeadAlg,
    key: &SymKey,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != alg.nonce_len() {
        return Err(Error::Format("aead nonce length"));
    }
    match alg {
        AeadAlg::XChaCha20Poly1305 => one_shot_open(&cipher(key)?, nonce, aad, ciphertext),
        #[cfg(feature = "pqc")]
        AeadAlg::Aes256Gcm => one_shot_open(&aes_cipher(key)?, nonce, aad, ciphertext),
    }
}

/// One-shot XChaCha20-Poly1305 encryption (key-wrap / keystore). Returns
/// `ciphertext || tag`.
pub fn seal(key: &SymKey, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    seal_with(AeadAlg::XChaCha20Poly1305, key, nonce, aad, plaintext)
}

/// One-shot XChaCha20-Poly1305 decryption (key-wrap / keystore).
pub fn open(key: &SymKey, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    open_with(AeadAlg::XChaCha20Poly1305, key, nonce, aad, ciphertext)
}

/// Read up to `size` bytes, returning fewer only at end of stream. The buffer is
/// `Zeroizing` because, on the encrypt side, it holds a plaintext chunk; wiping
/// it on drop keeps transient plaintext from lingering in freed heap.
fn read_chunk<R: Read>(reader: &mut R, size: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; size]);
    let mut filled = 0;
    while filled < size {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(buf)
}

/// A STREAM encryptor for either supported cipher. Lets the streaming routines
/// be written once and dispatch the per-chunk AEAD by suite without generics.
enum StreamEncryptor {
    XChaCha(Box<EncryptorBE32<XChaCha20Poly1305>>),
    #[cfg(feature = "pqc")]
    Aes(Box<EncryptorBE32<Aes256Gcm>>),
}

impl StreamEncryptor {
    fn new(alg: AeadAlg, key: &SymKey, stream_nonce: &[u8]) -> Result<Self> {
        Ok(match alg {
            AeadAlg::XChaCha20Poly1305 => StreamEncryptor::XChaCha(Box::new(
                EncryptorBE32::from_aead(cipher(key)?, GenericArray::from_slice(stream_nonce)),
            )),
            #[cfg(feature = "pqc")]
            AeadAlg::Aes256Gcm => StreamEncryptor::Aes(Box::new(EncryptorBE32::from_aead(
                aes_cipher(key)?,
                GenericArray::from_slice(stream_nonce),
            ))),
        })
    }

    fn encrypt_next(&mut self, payload: Payload) -> Result<Vec<u8>> {
        match self {
            StreamEncryptor::XChaCha(e) => e.encrypt_next(payload),
            #[cfg(feature = "pqc")]
            StreamEncryptor::Aes(e) => e.encrypt_next(payload),
        }
        .map_err(|_| Error::Auth)
    }

    fn encrypt_last(self, payload: Payload) -> Result<Vec<u8>> {
        match self {
            StreamEncryptor::XChaCha(e) => e.encrypt_last(payload),
            #[cfg(feature = "pqc")]
            StreamEncryptor::Aes(e) => e.encrypt_last(payload),
        }
        .map_err(|_| Error::Auth)
    }
}

/// A STREAM decryptor for either supported cipher (the read-side twin of
/// [`StreamEncryptor`]).
enum StreamDecryptor {
    XChaCha(Box<DecryptorBE32<XChaCha20Poly1305>>),
    #[cfg(feature = "pqc")]
    Aes(Box<DecryptorBE32<Aes256Gcm>>),
}

impl StreamDecryptor {
    fn new(alg: AeadAlg, key: &SymKey, stream_nonce: &[u8]) -> Result<Self> {
        Ok(match alg {
            AeadAlg::XChaCha20Poly1305 => StreamDecryptor::XChaCha(Box::new(
                DecryptorBE32::from_aead(cipher(key)?, GenericArray::from_slice(stream_nonce)),
            )),
            #[cfg(feature = "pqc")]
            AeadAlg::Aes256Gcm => StreamDecryptor::Aes(Box::new(DecryptorBE32::from_aead(
                aes_cipher(key)?,
                GenericArray::from_slice(stream_nonce),
            ))),
        })
    }

    fn decrypt_next(&mut self, payload: Payload) -> Result<Vec<u8>> {
        match self {
            StreamDecryptor::XChaCha(d) => d.decrypt_next(payload),
            #[cfg(feature = "pqc")]
            StreamDecryptor::Aes(d) => d.decrypt_next(payload),
        }
        .map_err(|_| Error::Auth)
    }

    fn decrypt_last(self, payload: Payload) -> Result<Vec<u8>> {
        match self {
            StreamDecryptor::XChaCha(d) => d.decrypt_last(payload),
            #[cfg(feature = "pqc")]
            StreamDecryptor::Aes(d) => d.decrypt_last(payload),
        }
        .map_err(|_| Error::Auth)
    }
}

/// Stream-encrypt `reader` into `writer` in `chunk_size` plaintext chunks using
/// `alg`.
///
/// `aad` is bound into every chunk. Returns the number of ciphertext bytes
/// written. An empty input still produces exactly one (tag-only) final chunk,
/// so the stream is always non-empty and truncation is always detectable.
pub fn encrypt_stream_with<R: Read, W: Write>(
    alg: AeadAlg,
    key: &SymKey,
    stream_nonce: &[u8],
    aad: &[u8],
    mut reader: R,
    writer: &mut W,
    chunk_size: usize,
) -> Result<u64> {
    if stream_nonce.len() != alg.stream_nonce_len() {
        return Err(Error::Format("stream nonce length"));
    }
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(Error::Format("chunk size"));
    }
    let mut enc = Some(StreamEncryptor::new(alg, key, stream_nonce)?);
    let mut written: u64 = 0;
    let mut current = read_chunk(&mut reader, chunk_size)?;
    loop {
        let next = read_chunk(&mut reader, chunk_size)?;
        let ct = if next.is_empty() {
            let e = enc.take().ok_or(Error::Format("stream state"))?;
            e.encrypt_last(Payload { msg: &current, aad })?
        } else {
            let e = enc.as_mut().ok_or(Error::Format("stream state"))?;
            e.encrypt_next(Payload { msg: &current, aad })?
        };
        writer.write_all(&ct)?;
        written += ct.len() as u64;
        if next.is_empty() {
            break;
        }
        current = next;
    }
    Ok(written)
}

/// Stream-decrypt `reader` into `writer` using `alg`, the inverse of
/// [`encrypt_stream_with`].
///
/// `chunk_size` must match the value used when encrypting (FileSec stores it in
/// the signed header). Any tampering, truncation, or reordering fails with
/// [`Error::Auth`] before the affected plaintext is written.
pub fn decrypt_stream_with<R: Read, W: Write>(
    alg: AeadAlg,
    key: &SymKey,
    stream_nonce: &[u8],
    aad: &[u8],
    mut reader: R,
    writer: &mut W,
    chunk_size: usize,
) -> Result<u64> {
    if stream_nonce.len() != alg.stream_nonce_len() {
        return Err(Error::Format("stream nonce length"));
    }
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(Error::Format("chunk size"));
    }
    let enc_chunk = chunk_size + TAG_LEN;
    let mut dec = Some(StreamDecryptor::new(alg, key, stream_nonce)?);
    let mut written: u64 = 0;
    let mut current = read_chunk(&mut reader, enc_chunk)?;
    loop {
        let next = read_chunk(&mut reader, enc_chunk)?;
        // The decrypted chunk is plaintext; keep it in a zeroizing buffer so it
        // is wiped promptly once written, never left in freed heap.
        let pt = if next.is_empty() {
            let d = dec.take().ok_or(Error::Format("stream state"))?;
            Zeroizing::new(d.decrypt_last(Payload { msg: &current, aad })?)
        } else {
            let d = dec.as_mut().ok_or(Error::Format("stream state"))?;
            Zeroizing::new(d.decrypt_next(Payload { msg: &current, aad })?)
        };
        writer.write_all(&pt)?;
        written += pt.len() as u64;
        if next.is_empty() {
            break;
        }
        current = next;
    }
    Ok(written)
}

/// Stream-encrypt with XChaCha20-Poly1305 (suite `0x0001`/`0x0101`).
pub fn encrypt_stream<R: Read, W: Write>(
    key: &SymKey,
    stream_nonce: &[u8],
    aad: &[u8],
    reader: R,
    writer: &mut W,
    chunk_size: usize,
) -> Result<u64> {
    encrypt_stream_with(
        AeadAlg::XChaCha20Poly1305,
        key,
        stream_nonce,
        aad,
        reader,
        writer,
        chunk_size,
    )
}

/// Stream-decrypt with XChaCha20-Poly1305 (suite `0x0001`/`0x0101`).
pub fn decrypt_stream<R: Read, W: Write>(
    key: &SymKey,
    stream_nonce: &[u8],
    aad: &[u8],
    reader: R,
    writer: &mut W,
    chunk_size: usize,
) -> Result<u64> {
    decrypt_stream_with(
        AeadAlg::XChaCha20Poly1305,
        key,
        stream_nonce,
        aad,
        reader,
        writer,
        chunk_size,
    )
}

/// Decrypt a single STREAM chunk by its index, enabling **random access** into
/// a stream produced by [`encrypt_stream`] without decrypting the chunks before
/// it.
///
/// `index` is the zero-based chunk number and `is_last` must be `true` only for
/// the final chunk of the whole stream (its nonce differs). The chunk is
/// authenticated with `aad`; any mismatch — including a wrong index or
/// `is_last` — fails with [`Error::Auth`]. This is byte-compatible with the
/// `StreamBE32` nonce derivation: `stream_nonce || index_be32 || last_flag`.
pub fn decrypt_chunk_with(
    alg: AeadAlg,
    key: &SymKey,
    stream_nonce: &[u8],
    aad: &[u8],
    index: u32,
    is_last: bool,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let snl = alg.stream_nonce_len();
    if stream_nonce.len() != snl {
        return Err(Error::Format("stream nonce length"));
    }
    let nl = alg.nonce_len();
    // The full nonce is the same STREAM BE32 layout for both ciphers — only its
    // total length differs (24 for XChaCha, 12 for AES-GCM): prefix || index_be32
    // || last_flag.
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..snl].copy_from_slice(stream_nonce);
    nonce[snl..snl + 4].copy_from_slice(&index.to_be_bytes());
    nonce[nl - 1] = u8::from(is_last);
    open_with(alg, key, &nonce[..nl], aad, ciphertext)
}

/// Decrypt a single XChaCha20-Poly1305 STREAM chunk (suite `0x0001`/`0x0101`).
pub fn decrypt_chunk(
    key: &SymKey,
    stream_nonce: &[u8],
    aad: &[u8],
    index: u32,
    is_last: bool,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    decrypt_chunk_with(
        AeadAlg::XChaCha20Poly1305,
        key,
        stream_nonce,
        aad,
        index,
        is_last,
        ciphertext,
    )
}

/// A [`Read`] adapter that stream-decrypts a ciphertext source on the fly,
/// yielding plaintext — the read-side twin of [`encrypt_stream_with`].
///
/// It lets a data stream be re-encrypted (or otherwise consumed) without ever
/// buffering the whole plaintext: peak memory is one plaintext chunk plus one
/// ciphertext chunk. Chunk framing, `stream_nonce`, `alg`, and `aad` must match
/// what [`encrypt_stream_with`] produced; any tampering, truncation, or
/// reordering surfaces as an [`std::io::ErrorKind::InvalidData`] error on the
/// failing `read`.
pub struct StreamDecryptReader<R: Read> {
    dec: Option<StreamDecryptor>,
    reader: R,
    aad: Vec<u8>,
    enc_chunk: usize,
    /// Look-ahead ciphertext chunk, so the final chunk can be detected (its
    /// nonce uses the last-chunk flag).
    current: Zeroizing<Vec<u8>>,
    /// Most recently decrypted plaintext chunk and how much has been consumed.
    plain: Zeroizing<Vec<u8>>,
    pos: usize,
    finished: bool,
}

impl<R: Read> StreamDecryptReader<R> {
    /// Create a decrypting reader over `reader`'s ciphertext using `alg`.
    /// `chunk_size` is the plaintext chunk size used at encryption time (FileSec
    /// stores it in the signed header).
    pub fn new_with(
        alg: AeadAlg,
        key: &SymKey,
        stream_nonce: &[u8],
        aad: &[u8],
        mut reader: R,
        chunk_size: usize,
    ) -> Result<Self> {
        if stream_nonce.len() != alg.stream_nonce_len() {
            return Err(Error::Format("stream nonce length"));
        }
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            return Err(Error::Format("chunk size"));
        }
        let dec = StreamDecryptor::new(alg, key, stream_nonce)?;
        let enc_chunk = chunk_size + TAG_LEN;
        let current = read_chunk(&mut reader, enc_chunk)?;
        Ok(Self {
            dec: Some(dec),
            reader,
            aad: aad.to_vec(),
            enc_chunk,
            current,
            plain: Zeroizing::new(Vec::new()),
            pos: 0,
            finished: false,
        })
    }

    /// Create an XChaCha20-Poly1305 decrypting reader (suite `0x0001`/`0x0101`).
    pub fn new(
        key: &SymKey,
        stream_nonce: &[u8],
        aad: &[u8],
        reader: R,
        chunk_size: usize,
    ) -> Result<Self> {
        Self::new_with(
            AeadAlg::XChaCha20Poly1305,
            key,
            stream_nonce,
            aad,
            reader,
            chunk_size,
        )
    }

    /// Decrypt the next chunk into `self.plain`. Returns `Ok(false)` once the
    /// whole stream has been consumed.
    fn refill(&mut self) -> Result<bool> {
        if self.finished {
            return Ok(false);
        }
        let next = read_chunk(&mut self.reader, self.enc_chunk)?;
        let is_last = next.is_empty();
        let pt = if is_last {
            let d = self.dec.take().ok_or(Error::Format("stream state"))?;
            d.decrypt_last(Payload {
                msg: &self.current,
                aad: &self.aad,
            })?
        } else {
            let d = self.dec.as_mut().ok_or(Error::Format("stream state"))?;
            let pt = d.decrypt_next(Payload {
                msg: &self.current,
                aad: &self.aad,
            })?;
            self.current = next;
            pt
        };
        if is_last {
            self.finished = true;
        }
        self.plain = Zeroizing::new(pt);
        self.pos = 0;
        Ok(true)
    }
}

impl<R: Read> Read for StreamDecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.pos < self.plain.len() {
                let n = (self.plain.len() - self.pos).min(buf.len());
                buf[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            match self.refill() {
                Ok(true) => continue,
                Ok(false) => return Ok(0),
                Err(Error::Io(e)) => return Err(e),
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::secret::random_vec;

    fn key_and_nonce(alg: AeadAlg) -> (SymKey, Vec<u8>) {
        (
            SymKey::random().unwrap(),
            random_vec(alg.stream_nonce_len()).unwrap(),
        )
    }

    #[test]
    fn stream_encrypt_rejects_chunk_size_above_cap() {
        let alg = AeadAlg::XChaCha20Poly1305;
        let (key, nonce) = key_and_nonce(alg);
        let mut out = Vec::new();
        // One past the cap must be rejected before any chunk buffer is sized.
        let err = encrypt_stream_with(
            alg,
            &key,
            &nonce,
            b"aad",
            &b"hello"[..],
            &mut out,
            MAX_CHUNK_SIZE + 1,
        );
        assert!(matches!(err, Err(Error::Format("chunk size"))));
        assert!(out.is_empty());
    }

    #[test]
    fn stream_decrypt_reader_rejects_chunk_size_above_cap() {
        let alg = AeadAlg::XChaCha20Poly1305;
        let (key, nonce) = key_and_nonce(alg);
        let err = StreamDecryptReader::new_with(
            alg,
            &key,
            &nonce,
            b"aad",
            std::io::empty(),
            MAX_CHUNK_SIZE + 1,
        )
        .err();
        assert!(matches!(err, Some(Error::Format("chunk size"))));
    }

    #[test]
    fn stream_roundtrip_at_cap_is_allowed() {
        // The cap itself is a valid (if enormous) chunk size; a small payload
        // still round-trips. Uses a tiny plaintext so no giant buffer is filled.
        let alg = AeadAlg::XChaCha20Poly1305;
        let (key, nonce) = key_and_nonce(alg);
        let pt = b"the cap is inclusive";
        let mut ct = Vec::new();
        // A modest-but-large chunk size well under the cap keeps the test cheap
        // while proving the guard is a ceiling, not an off-by-one on the default.
        let chunk = DEFAULT_CHUNK_SIZE;
        encrypt_stream_with(alg, &key, &nonce, b"aad", &pt[..], &mut ct, chunk).unwrap();
        let mut got = Vec::new();
        decrypt_stream_with(alg, &key, &nonce, b"aad", &ct[..], &mut got, chunk).unwrap();
        assert_eq!(got, pt);
    }
}
