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
///
/// The post-quantum fields are present only for a hybrid identity and are
/// serialized only when set (`skip_serializing_if`), so a classical keystore is
/// byte-for-byte unchanged and older keystores still unlock. Each PQC keypair is
/// stored as its compact seed (re-expanded on use) plus the cached public key.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SecretBundle {
    name: String,
    created_at: i64,
    sign_secret: [u8; sign::SECRET_LEN],
    kem_secret: [u8; kem::SECRET_LEN],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mldsa_seed: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mldsa_public: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mlkem_seed: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mlkem_public: Option<Vec<u8>>,
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
            mldsa_seed: identity.mldsa_secret().map(<[u8]>::to_vec),
            mldsa_public: identity.mldsa_public().map(<[u8]>::to_vec),
            mlkem_seed: identity.mlkem_secret().map(<[u8]>::to_vec),
            mlkem_public: identity.mlkem_public().map(<[u8]>::to_vec),
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
        // Re-pair each PQC public with its seed; a half-present pair (which a
        // well-formed keystore never produces) degrades to a classical identity.
        let pair = |public: &Option<Vec<u8>>, seed: &Option<Vec<u8>>| match (public, seed) {
            (Some(p), Some(s)) => Some((p.clone(), s.clone())),
            _ => None,
        };
        let mldsa = pair(&bundle.mldsa_public, &bundle.mldsa_seed);
        let mlkem = pair(&bundle.mlkem_public, &bundle.mlkem_seed);
        let identity = Identity::from_parts(
            bundle.name.clone(),
            bundle.created_at,
            bundle.sign_secret,
            bundle.kem_secret,
            mldsa,
            mlkem,
        );
        bundle.zeroize();
        Ok(identity)
    }
}
