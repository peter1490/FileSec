//! Envelope encryption: a random per-vault content key (CEK) wrapped to each
//! recipient's public key.
//!
//! For each recipient the sender performs an ephemeral-static X25519 agreement,
//! derives a key-wrapping key (KWK) by binding the shared secret to the
//! ephemeral and recipient public keys via BLAKE3, and seals the CEK under the
//! KWK. Only a holder of the recipient private key can recompute the KWK and
//! recover the CEK — that is what makes the container confidential.
//!
//! # Hybrid post-quantum wrap (suite `0x0101`)
//!
//! For a hybrid container the sender *additionally* ML-KEM-768-encapsulates a
//! shared secret to the recipient's ML-KEM key and stores the ciphertext in the
//! stanza. The KWK is then derived from **both** shared secrets, the ephemeral
//! and recipient X25519 keys, the ML-KEM ciphertext, and the recipient ML-KEM
//! key — a concatenation-KDF combiner. Because the KWK only stays secret if an
//! attacker recovers *both* shared secrets, breaking ML-KEM cannot weaken the
//! X25519 baseline, and breaking X25519 cannot weaken the ML-KEM contribution:
//! the hybrid is at least as strong as the stronger of its two halves.
//!
//! The CEK wrap itself always uses XChaCha20-Poly1305 (a 192-bit random nonce),
//! independent of the container's bulk-data suite.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::identity::{Identity, PublicIdentity};
use crate::secret::{SymKey, SYM_KEY_LEN};
use crate::suite::SuiteId;
use crate::{aead, kdf, kem};

const WRAP_CONTEXT: &str = "FileSec x25519 key-wrap v1";
#[cfg(feature = "pqc")]
const HYBRID_WRAP_CONTEXT: &str = "FileSec x25519+ml-kem-768 hybrid key-wrap v1";
const WRAP_AAD: &[u8] = b"FileSec CEK wrap v1";

/// A per-recipient stanza embedding the wrapped content key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecipientStanza {
    /// Fingerprint of the recipient identity this stanza is addressed to (lets
    /// an importer locate its own stanza without trial-decryption).
    pub recipient_fpr: [u8; 32],
    /// Sender's one-time ephemeral X25519 public key.
    pub ephemeral_public: [u8; kem::PUBLIC_LEN],
    /// ML-KEM-768 ciphertext encapsulating the post-quantum shared secret
    /// (present only for hybrid suite `0x0101`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mlkem_ciphertext: Option<Vec<u8>>,
    /// Nonce used to seal the content key.
    pub wrap_nonce: Vec<u8>,
    /// The content key sealed under the key-wrapping key (`CEK || tag`).
    pub wrapped_cek: Vec<u8>,
}

/// Derive the classical key-wrapping key from the agreed shared secret and the
/// bound public keys.
fn derive_kwk(
    shared: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
) -> SymKey {
    let mut ikm = Zeroizing::new(Vec::with_capacity(96));
    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(ephemeral_public);
    ikm.extend_from_slice(recipient_public);
    kdf::derive_subkey(WRAP_CONTEXT, &ikm)
}

/// Derive the hybrid key-wrapping key (the concatenation-KDF combiner). Binds
/// both shared secrets and the full transcript so the KWK is secure unless
/// *both* KEMs are broken.
#[cfg(feature = "pqc")]
fn derive_hybrid_kwk(
    classical_shared: &[u8; 32],
    pq_shared: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_kem_public: &[u8; 32],
    mlkem_ciphertext: &[u8],
    recipient_mlkem_public: &[u8],
) -> SymKey {
    let mut ikm = Zeroizing::new(Vec::new());
    ikm.extend_from_slice(classical_shared);
    ikm.extend_from_slice(pq_shared);
    ikm.extend_from_slice(ephemeral_public);
    ikm.extend_from_slice(recipient_kem_public);
    ikm.extend_from_slice(mlkem_ciphertext);
    ikm.extend_from_slice(recipient_mlkem_public);
    kdf::derive_subkey(HYBRID_WRAP_CONTEXT, &ikm)
}

/// Sender side of the hybrid wrap: ML-KEM-encapsulate to the recipient and
/// return the ciphertext plus the combined KWK.
#[cfg(feature = "pqc")]
fn wrap_hybrid_kwk(
    classical_shared: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient: &PublicIdentity,
) -> Result<(Option<Vec<u8>>, SymKey)> {
    let recip_mlkem = recipient
        .mlkem_public
        .as_deref()
        .ok_or(Error::MissingPqcKey("recipient has no ML-KEM key"))?;
    let (ciphertext, pq_shared) = crate::mlkem::encapsulate(recip_mlkem)?;
    let kwk = derive_hybrid_kwk(
        classical_shared,
        &pq_shared,
        ephemeral_public,
        &recipient.kem_public,
        &ciphertext,
        recip_mlkem,
    );
    Ok((Some(ciphertext), kwk))
}

/// Stub for builds without the `pqc` feature. Never reached, because a non-pqc
/// build has no hybrid [`SuiteId`] so [`SuiteId::is_hybrid`] is always `false`.
#[cfg(not(feature = "pqc"))]
fn wrap_hybrid_kwk(
    _classical_shared: &[u8; 32],
    _ephemeral_public: &[u8; 32],
    _recipient: &PublicIdentity,
) -> Result<(Option<Vec<u8>>, SymKey)> {
    Err(Error::UnsupportedSuite(SuiteId::Classic.to_u16()))
}

/// Recipient side of the hybrid unwrap: ML-KEM-decapsulate and rebuild the
/// combined KWK.
#[cfg(feature = "pqc")]
fn unwrap_hybrid_kwk(
    classical_shared: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_kem_public: &[u8; 32],
    mlkem_ciphertext: &[u8],
    identity: &Identity,
) -> Result<SymKey> {
    let recip_mlkem = identity
        .mlkem_public()
        .ok_or(Error::MissingPqcKey("identity has no ML-KEM key"))?;
    let pq_shared = identity.mlkem_decapsulate(mlkem_ciphertext)?;
    Ok(derive_hybrid_kwk(
        classical_shared,
        &pq_shared,
        ephemeral_public,
        recipient_kem_public,
        mlkem_ciphertext,
        recip_mlkem,
    ))
}

/// Stub for builds without the `pqc` feature (unreachable; see [`wrap_hybrid_kwk`]).
#[cfg(not(feature = "pqc"))]
fn unwrap_hybrid_kwk(
    _classical_shared: &[u8; 32],
    _ephemeral_public: &[u8; 32],
    _recipient_kem_public: &[u8; 32],
    _mlkem_ciphertext: &[u8],
    _identity: &Identity,
) -> Result<SymKey> {
    Err(Error::UnsupportedSuite(SuiteId::Classic.to_u16()))
}

/// Sender side: wrap `cek` for `recipient` under the given `suite`.
///
/// For a hybrid suite the recipient must carry an ML-KEM key, else this fails
/// with [`Error::MissingPqcKey`].
pub fn wrap_for_recipient(
    cek: &SymKey,
    recipient: &PublicIdentity,
    suite: SuiteId,
) -> Result<RecipientStanza> {
    let (shared, ephemeral_public) = kem::ephemeral_agree(&recipient.kem_public)?;
    let wrap_nonce = crate::secret::random_vec(aead::NONCE_LEN)?;
    let (mlkem_ciphertext, kwk) = if suite.is_hybrid() {
        wrap_hybrid_kwk(&shared, &ephemeral_public, recipient)?
    } else {
        (
            None,
            derive_kwk(&shared, &ephemeral_public, &recipient.kem_public),
        )
    };
    let wrapped_cek = aead::seal(&kwk, &wrap_nonce, WRAP_AAD, cek.as_bytes())?;
    Ok(RecipientStanza {
        recipient_fpr: recipient.fingerprint(),
        ephemeral_public,
        mlkem_ciphertext,
        wrap_nonce,
        wrapped_cek,
    })
}

/// Recipient side: recover the content key from a stanza using `identity`.
///
/// A stanza carrying an ML-KEM ciphertext is unwrapped with the hybrid combiner;
/// the identity must hold the matching ML-KEM key, else this fails with
/// [`Error::MissingPqcKey`].
pub fn unwrap_with_identity(stanza: &RecipientStanza, identity: &Identity) -> Result<SymKey> {
    let shared = identity.agree(&stanza.ephemeral_public)?;
    let recipient_kem_public = identity.kem_public();
    let kwk = match &stanza.mlkem_ciphertext {
        Some(ciphertext) => unwrap_hybrid_kwk(
            &shared,
            &stanza.ephemeral_public,
            &recipient_kem_public,
            ciphertext,
            identity,
        )?,
        None => derive_kwk(&shared, &stanza.ephemeral_public, &recipient_kem_public),
    };
    let mut cek_bytes = Zeroizing::new(aead::open(
        &kwk,
        &stanza.wrap_nonce,
        WRAP_AAD,
        &stanza.wrapped_cek,
    )?);
    if cek_bytes.len() != SYM_KEY_LEN {
        return Err(Error::Format("wrapped content key length"));
    }
    let mut arr = [0u8; SYM_KEY_LEN];
    arr.copy_from_slice(&cek_bytes);
    cek_bytes.zeroize();
    let key = SymKey::from_bytes(arr);
    arr.zeroize();
    Ok(key)
}
