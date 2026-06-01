//! Ed25519 digital signatures (suite `0x0001`).
//!
//! Used to authenticate the sender of a container: the sender signs a BLAKE3
//! hash spanning the whole container and the importer verifies it *before*
//! decrypting anything. Verification uses `verify_strict` to reject malleable
//! signatures and weak (small-order) public keys.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::random_array;

/// Length of an Ed25519 public (verifying) key.
pub const PUBLIC_LEN: usize = 32;
/// Length of an Ed25519 secret seed.
pub const SECRET_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// An Ed25519 signing keypair. The secret is zeroized on drop by the underlying
/// `SigningKey`.
pub struct SignKeyPair {
    signing: SigningKey,
}

impl SignKeyPair {
    /// Generate a fresh keypair from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_secret_bytes(random_array::<SECRET_LEN>()?))
    }

    /// Reconstruct a keypair from a stored 32-byte seed.
    pub fn from_secret_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&bytes),
        }
    }

    /// The public (verifying) key bytes (safe to share).
    pub fn public_bytes(&self) -> [u8; PUBLIC_LEN] {
        self.signing.verifying_key().to_bytes()
    }

    /// The secret seed bytes, in a zeroizing buffer (for keystore persistence).
    pub fn secret_bytes(&self) -> Zeroizing<[u8; SECRET_LEN]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// Sign a message, returning the detached signature.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(message).to_bytes()
    }
}

/// Verify a detached signature against a public key. Returns
/// [`Error::BadSignature`] on any failure.
pub fn verify(
    public: &[u8; PUBLIC_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    let vk = VerifyingKey::from_bytes(public).map_err(|_| Error::BadKey("ed25519 public key"))?;
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(message, &sig)
        .map_err(|_| Error::BadSignature)
}
