//! Authenticated encryption for suite `0x0001`: XChaCha20-Poly1305.
//!
//! Two layers:
//!
//! * **One-shot** [`seal`]/[`open`] for small items (key wrapping, the
//!   manifest). XChaCha's 192-bit nonce makes random nonces collision-safe.
//! * **Streaming** [`encrypt_stream`]/[`decrypt_stream`] for file data, using
//!   the STREAM construction (fixed-size chunks, per-chunk nonce derived from an
//!   internal BE32 counter, explicit last-chunk flag). This authenticates each
//!   chunk and detects truncation/reordering of the whole stream.
//!
//! Every call binds caller-supplied associated data (AAD) — FileSec always
//! passes the container header so the algorithm suite and recipient set are
//! cryptographically bound to the ciphertext (anti-downgrade).

use std::io::{Read, Write};

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::SymKey;

/// Length of an XChaCha20-Poly1305 nonce (one-shot).
pub const NONCE_LEN: usize = 24;
/// Poly1305 authentication tag length.
pub const TAG_LEN: usize = 16;
/// Length of the random nonce prefix for the STREAM construction
/// (24-byte XChaCha nonce minus the 5 bytes STREAM reserves for its counter +
/// last-chunk flag).
pub const STREAM_NONCE_LEN: usize = NONCE_LEN - 5;
/// Default plaintext chunk size for streamed data (64 KiB).
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

fn cipher(key: &SymKey) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| Error::BadKey("aead key length"))
}

/// One-shot authenticated encryption. Returns `ciphertext || tag`.
pub fn seal(key: &SymKey, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        return Err(Error::Format("aead nonce length"));
    }
    cipher(key)?
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Auth)
}

/// One-shot authenticated decryption of `ciphertext || tag`.
pub fn open(key: &SymKey, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        return Err(Error::Format("aead nonce length"));
    }
    cipher(key)?
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Auth)
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

/// Stream-encrypt `reader` into `writer` in `chunk_size` plaintext chunks.
///
/// `aad` is bound into every chunk. Returns the number of ciphertext bytes
/// written. An empty input still produces exactly one (tag-only) final chunk,
/// so the stream is always non-empty and truncation is always detectable.
pub fn encrypt_stream<R: Read, W: Write>(
    key: &SymKey,
    stream_nonce: &[u8],
    aad: &[u8],
    mut reader: R,
    writer: &mut W,
    chunk_size: usize,
) -> Result<u64> {
    if stream_nonce.len() != STREAM_NONCE_LEN {
        return Err(Error::Format("stream nonce length"));
    }
    if chunk_size == 0 {
        return Err(Error::Format("chunk size"));
    }
    let nonce = GenericArray::from_slice(stream_nonce);
    let mut enc = Some(EncryptorBE32::from_aead(cipher(key)?, nonce));
    let mut written: u64 = 0;
    let mut current = read_chunk(&mut reader, chunk_size)?;
    loop {
        let next = read_chunk(&mut reader, chunk_size)?;
        let ct = if next.is_empty() {
            let e = enc.take().ok_or(Error::Format("stream state"))?;
            e.encrypt_last(Payload { msg: &current, aad })
                .map_err(|_| Error::Auth)?
        } else {
            let e = enc.as_mut().ok_or(Error::Format("stream state"))?;
            e.encrypt_next(Payload { msg: &current, aad })
                .map_err(|_| Error::Auth)?
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

/// Stream-decrypt `reader` into `writer`, the inverse of [`encrypt_stream`].
///
/// `chunk_size` must match the value used when encrypting (FileSec stores it in
/// the signed header). Any tampering, truncation, or reordering fails with
/// [`Error::Auth`] before the affected plaintext is written.
pub fn decrypt_stream<R: Read, W: Write>(
    key: &SymKey,
    stream_nonce: &[u8],
    aad: &[u8],
    mut reader: R,
    writer: &mut W,
    chunk_size: usize,
) -> Result<u64> {
    if stream_nonce.len() != STREAM_NONCE_LEN {
        return Err(Error::Format("stream nonce length"));
    }
    if chunk_size == 0 {
        return Err(Error::Format("chunk size"));
    }
    let enc_chunk = chunk_size + TAG_LEN;
    let nonce = GenericArray::from_slice(stream_nonce);
    let mut dec = Some(DecryptorBE32::from_aead(cipher(key)?, nonce));
    let mut written: u64 = 0;
    let mut current = read_chunk(&mut reader, enc_chunk)?;
    loop {
        let next = read_chunk(&mut reader, enc_chunk)?;
        // The decrypted chunk is plaintext; keep it in a zeroizing buffer so it
        // is wiped promptly once written, never left in freed heap.
        let pt = if next.is_empty() {
            let d = dec.take().ok_or(Error::Format("stream state"))?;
            Zeroizing::new(
                d.decrypt_last(Payload { msg: &current, aad })
                    .map_err(|_| Error::Auth)?,
            )
        } else {
            let d = dec.as_mut().ok_or(Error::Format("stream state"))?;
            Zeroizing::new(
                d.decrypt_next(Payload { msg: &current, aad })
                    .map_err(|_| Error::Auth)?,
            )
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

/// Decrypt a single STREAM chunk by its index, enabling **random access** into
/// a stream produced by [`encrypt_stream`] without decrypting the chunks before
/// it.
///
/// `index` is the zero-based chunk number and `is_last` must be `true` only for
/// the final chunk of the whole stream (its nonce differs). The chunk is
/// authenticated with `aad`; any mismatch — including a wrong index or
/// `is_last` — fails with [`Error::Auth`]. This is byte-compatible with the
/// `StreamBE32` nonce derivation: `stream_nonce || index_be32 || last_flag`.
pub fn decrypt_chunk(
    key: &SymKey,
    stream_nonce: &[u8],
    aad: &[u8],
    index: u32,
    is_last: bool,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if stream_nonce.len() != STREAM_NONCE_LEN {
        return Err(Error::Format("stream nonce length"));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..STREAM_NONCE_LEN].copy_from_slice(stream_nonce);
    nonce[STREAM_NONCE_LEN..STREAM_NONCE_LEN + 4].copy_from_slice(&index.to_be_bytes());
    nonce[NONCE_LEN - 1] = u8::from(is_last);
    open(key, &nonce, aad, ciphertext)
}

/// A [`Read`] adapter that stream-decrypts a ciphertext source on the fly,
/// yielding plaintext — the read-side twin of [`encrypt_stream`].
///
/// It lets a data stream be re-encrypted (or otherwise consumed) without ever
/// buffering the whole plaintext: peak memory is one plaintext chunk plus one
/// ciphertext chunk. Chunk framing, `stream_nonce`, and `aad` must match what
/// [`encrypt_stream`] produced; any tampering, truncation, or reordering surfaces
/// as an [`std::io::ErrorKind::InvalidData`] error on the failing `read`.
pub struct StreamDecryptReader<R: Read> {
    dec: Option<DecryptorBE32<XChaCha20Poly1305>>,
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
    /// Create a decrypting reader over `reader`'s ciphertext. `chunk_size` is the
    /// plaintext chunk size used at encryption time (FileSec stores it in the
    /// signed header).
    pub fn new(
        key: &SymKey,
        stream_nonce: &[u8],
        aad: &[u8],
        mut reader: R,
        chunk_size: usize,
    ) -> Result<Self> {
        if stream_nonce.len() != STREAM_NONCE_LEN {
            return Err(Error::Format("stream nonce length"));
        }
        if chunk_size == 0 {
            return Err(Error::Format("chunk size"));
        }
        let nonce = GenericArray::from_slice(stream_nonce);
        let dec = DecryptorBE32::from_aead(cipher(key)?, nonce);
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
            })
            .map_err(|_| Error::Auth)?
        } else {
            let d = self.dec.as_mut().ok_or(Error::Format("stream state"))?;
            let pt = d
                .decrypt_next(Payload {
                    msg: &self.current,
                    aad: &self.aad,
                })
                .map_err(|_| Error::Auth)?;
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
