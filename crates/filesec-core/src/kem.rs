//! X25519 key agreement (suite `0x0001`).
//!
//! Provides raw ephemeral-static Diffie-Hellman used by [`crate::envelope`] to
//! wrap the per-vault content key to each recipient. Shared secrets are checked
//! for contributory behaviour to reject low-order/identity public keys, and all
//! secret bytes are held in zeroizing buffers.

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::random_array;

/// Length of an X25519 public key.
pub const PUBLIC_LEN: usize = 32;
/// Length of an X25519 secret scalar.
pub const SECRET_LEN: usize = 32;

/// An X25519 key-agreement keypair. The secret is zeroized on drop by the
/// underlying `StaticSecret`.
pub struct KemKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KemKeyPair {
    /// Generate a fresh keypair from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_secret_bytes(random_array::<SECRET_LEN>()?))
    }

    /// Reconstruct a keypair from stored secret bytes.
    pub fn from_secret_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// The public key bytes (safe to share).
    pub fn public_bytes(&self) -> [u8; PUBLIC_LEN] {
        self.public.to_bytes()
    }

    /// The secret scalar bytes, in a zeroizing buffer (for keystore persistence).
    pub fn secret_bytes(&self) -> Zeroizing<[u8; SECRET_LEN]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// Recipient side: agree on the shared secret given a sender's ephemeral
    /// public key.
    pub fn agree(&self, ephemeral_public: &[u8; PUBLIC_LEN]) -> Result<Zeroizing<[u8; 32]>> {
        let peer = PublicKey::from(*ephemeral_public);
        let shared = self.secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(Error::BadKey("non-contributory X25519 agreement"));
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }
}

/// Sender side: perform a one-time ephemeral agreement with `recipient_public`.
///
/// Returns the shared secret plus the ephemeral public key to embed in the
/// recipient stanza.
pub fn ephemeral_agree(
    recipient_public: &[u8; PUBLIC_LEN],
) -> Result<(Zeroizing<[u8; 32]>, [u8; PUBLIC_LEN])> {
    let ephemeral = StaticSecret::from(random_array::<SECRET_LEN>()?);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let peer = PublicKey::from(*recipient_public);
    let shared = ephemeral.diffie_hellman(&peer);
    if !shared.was_contributory() {
        return Err(Error::BadKey("non-contributory X25519 agreement"));
    }
    Ok((
        Zeroizing::new(shared.to_bytes()),
        ephemeral_public.to_bytes(),
    ))
}
