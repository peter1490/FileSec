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

/// Read up to `size` bytes, returning fewer only at end of stream.
fn read_chunk<R: Read>(reader: &mut R, size: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
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
        let pt = if next.is_empty() {
            let d = dec.take().ok_or(Error::Format("stream state"))?;
            d.decrypt_last(Payload { msg: &current, aad })
                .map_err(|_| Error::Auth)?
        } else {
            let d = dec.as_mut().ok_or(Error::Format("stream state"))?;
            d.decrypt_next(Payload { msg: &current, aad })
                .map_err(|_| Error::Auth)?
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
