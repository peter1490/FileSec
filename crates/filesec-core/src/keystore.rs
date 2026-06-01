//! Passphrase-protected keystore for the user's private identity.
//!
//! The private keys are serialized to CBOR and sealed with XChaCha20-Poly1305
//! under a master key derived from the user's passphrase via Argon2id. The
//! resulting [`KeystoreFile`] is portable, OS-independent, and the single source
//! of truth for the identity. An optional OS-keychain auto-unlock is a deferred
//! convenience and is not part of this module.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::kdf::{self, KdfParams};
use crate::{aead, codec, kem, secret, sign};

/// Keystore format version.
const VERSION: u16 = 1;
/// Salt length for Argon2id.
const SALT_LEN: usize = 16;
/// AEAD associated data binding the keystore purpose/version.
const AAD: &[u8] = b"FileSec keystore v1";

/// The decrypted private identity bundle. Zeroized on drop.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SecretBundle {
    name: String,
    created_at: i64,
    sign_secret: [u8; sign::SECRET_LEN],
    kem_secret: [u8; kem::SECRET_LEN],
}

/// On-disk keystore: public envelope around the encrypted [`SecretBundle`].
#[derive(Serialize, Deserialize)]
pub struct KeystoreFile {
    version: u16,
    kdf: KdfParams,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl KeystoreFile {
    /// Create an encrypted keystore wrapping `identity` under `passphrase`.
    pub fn create(identity: &Identity, passphrase: &[u8], params: KdfParams) -> Result<Self> {
        let salt = secret::random_vec(SALT_LEN)?;
        let master = kdf::derive_master_key(passphrase, &salt, params)?;
        let nonce = secret::random_vec(aead::NONCE_LEN)?;

        let bundle = SecretBundle {
            name: identity.name.clone(),
            created_at: identity.created_at,
            sign_secret: *identity.sign_secret(),
            kem_secret: *identity.kem_secret(),
        };
        let plaintext = Zeroizing::new(codec::to_vec(&bundle)?);
        let ciphertext = aead::seal(&master, &nonce, AAD, &plaintext)?;

        Ok(Self {
            version: VERSION,
            kdf: params,
            salt,
            nonce,
            ciphertext,
        })
    }

    /// Serialize to bytes for storage on disk.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        codec::to_vec(self)
    }

    /// Parse keystore bytes (does not yet decrypt — call [`Self::unlock`]).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let file: KeystoreFile = codec::from_slice(bytes)?;
        if file.version != VERSION {
            return Err(Error::Format("unsupported keystore version"));
        }
        Ok(file)
    }

    /// Decrypt and reconstruct the [`Identity`] with the supplied passphrase.
    /// A wrong passphrase surfaces as [`Error::BadPassphrase`].
    pub fn unlock(&self, passphrase: &[u8]) -> Result<Identity> {
        let master = kdf::derive_master_key(passphrase, &self.salt, self.kdf)?;
        let plaintext = Zeroizing::new(
            aead::open(&master, &self.nonce, AAD, &self.ciphertext)
                .map_err(|_| Error::BadPassphrase)?,
        );
        let mut bundle: SecretBundle = codec::from_slice(&plaintext)?;
        let identity = Identity::from_secrets(
            bundle.name.clone(),
            bundle.created_at,
            bundle.sign_secret,
            bundle.kem_secret,
        );
        bundle.zeroize();
        Ok(identity)
    }
}
