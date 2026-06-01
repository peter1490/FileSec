//! Secret material handling: zeroizing key types, secure RNG, constant-time eq.
//!
//! All long-lived secrets in FileSec flow through types defined here so they
//! are wiped from memory on drop and compared without timing leaks.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

/// Length in bytes of all symmetric keys in FileSec.
pub const SYM_KEY_LEN: usize = 32;

/// A 256-bit symmetric key — used as the content key (CEK), a key-wrapping key
/// (KWK), or the keystore master key. Zeroized on drop; `Debug` never reveals it.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymKey([u8; SYM_KEY_LEN]);

impl SymKey {
    /// Wrap raw key bytes (the caller is responsible for their provenance).
    pub fn from_bytes(bytes: [u8; SYM_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh random key from the OS CSPRNG.
    pub fn random() -> Result<Self> {
        Ok(Self(random_array()?))
    }

    /// Borrow the raw key bytes. Handle with care; do not copy needlessly.
    pub fn as_bytes(&self) -> &[u8; SYM_KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SymKey(***redacted***)")
    }
}

/// Fill a fixed-size array with cryptographically secure random bytes.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|_| Error::Rng)?;
    Ok(buf)
}

/// Allocate `n` cryptographically secure random bytes (for public values such
/// as nonces and salts).
pub fn random_vec(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|_| Error::Rng)?;
    Ok(buf)
}

/// Allocate `n` random bytes wrapped so they are zeroized on drop.
pub fn random_secret(n: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; n]);
    getrandom::getrandom(buf.as_mut_slice()).map_err(|_| Error::Rng)?;
    Ok(buf)
}

/// Constant-time byte-slice equality. Returns `false` immediately on a length
/// mismatch (length is not itself secret in any FileSec comparison).
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
