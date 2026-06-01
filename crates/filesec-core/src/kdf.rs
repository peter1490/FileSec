//! Key derivation: Argon2id for passphrases, BLAKE3 for sub-key derivation.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::secret::{SymKey, SYM_KEY_LEN};

/// Argon2id parameters, persisted in the keystore so it can always be reopened
/// with the parameters it was created with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Number of iterations (time cost).
    pub t_cost: u32,
    /// Degree of parallelism (lanes).
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // ~64 MiB, 3 passes, 1 lane: memory-hard yet interactive on a desktop.
        Self {
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// Derive a 256-bit master key from a passphrase and salt using Argon2id.
pub fn derive_master_key(passphrase: &[u8], salt: &[u8], params: KdfParams) -> Result<SymKey> {
    let p = Params::new(
        params.m_cost,
        params.t_cost,
        params.p_cost,
        Some(SYM_KEY_LEN),
    )
    .map_err(|_| Error::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = [0u8; SYM_KEY_LEN];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|_| Error::Kdf)?;
    let key = SymKey::from_bytes(out);
    out.zeroize();
    Ok(key)
}

/// Derive a domain-separated 256-bit sub-key from input keying material with
/// BLAKE3. `context` must be a unique, hard-coded label per use site.
pub fn derive_subkey(context: &str, ikm: &[u8]) -> SymKey {
    let mut bytes = blake3::derive_key(context, ikm);
    let key = SymKey::from_bytes(bytes);
    bytes.zeroize();
    key
}
