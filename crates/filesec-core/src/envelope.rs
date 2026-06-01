//! Envelope encryption: a random per-vault content key (CEK) wrapped to each
//! recipient's public key.
//!
//! For each recipient the sender performs an ephemeral-static X25519 agreement,
//! derives a key-wrapping key (KWK) by binding the shared secret to the
//! ephemeral and recipient public keys via BLAKE3, and seals the CEK under the
//! KWK. Only a holder of the recipient private key can recompute the KWK and
//! recover the CEK — that is what makes the container confidential.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::identity::{Identity, PublicIdentity};
use crate::secret::{SymKey, SYM_KEY_LEN};
use crate::{aead, kdf, kem};

const WRAP_CONTEXT: &str = "FileSec x25519 key-wrap v1";
const WRAP_AAD: &[u8] = b"FileSec CEK wrap v1";

/// A per-recipient stanza embedding the wrapped content key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecipientStanza {
    /// Fingerprint of the recipient identity this stanza is addressed to (lets
    /// an importer locate its own stanza without trial-decryption).
    pub recipient_fpr: [u8; 32],
    /// Sender's one-time ephemeral X25519 public key.
    pub ephemeral_public: [u8; kem::PUBLIC_LEN],
    /// Nonce used to seal the content key.
    pub wrap_nonce: Vec<u8>,
    /// The content key sealed under the key-wrapping key (`CEK || tag`).
    pub wrapped_cek: Vec<u8>,
}

/// Derive the key-wrapping key from the agreed shared secret and the bound
/// public keys.
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

/// Sender side: wrap `cek` for `recipient`.
pub fn wrap_for_recipient(cek: &SymKey, recipient: &PublicIdentity) -> Result<RecipientStanza> {
    let (shared, ephemeral_public) = kem::ephemeral_agree(&recipient.kem_public)?;
    let kwk = derive_kwk(&shared, &ephemeral_public, &recipient.kem_public);
    let wrap_nonce = crate::secret::random_vec(aead::NONCE_LEN)?;
    let wrapped_cek = aead::seal(&kwk, &wrap_nonce, WRAP_AAD, cek.as_bytes())?;
    Ok(RecipientStanza {
        recipient_fpr: recipient.fingerprint(),
        ephemeral_public,
        wrap_nonce,
        wrapped_cek,
    })
}

/// Recipient side: recover the content key from a stanza using `identity`.
pub fn unwrap_with_identity(stanza: &RecipientStanza, identity: &Identity) -> Result<SymKey> {
    let shared = identity.agree(&stanza.ephemeral_public)?;
    let kwk = derive_kwk(&shared, &stanza.ephemeral_public, &identity.kem_public());
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
