//! Algorithm-suite identifier and dispatch.
//!
//! A `.fsec` container names its *entire* cryptographic suite with a single
//! atomic [`SuiteId`] — there is no per-primitive in-band negotiation, which is
//! where downgrade bugs live. The id lives in the header, which is fed as AAD
//! into every AEAD operation and covered by the sender signature, so an
//! attacker cannot substitute a weaker suite without invalidating the
//! container. Importers additionally enforce [`SuiteId::is_supported`].

use crate::error::{Error, Result};

/// The cryptographic suite used by a container.
///
/// The MVP ships exactly one suite. The numeric values reserve space for
/// future suites so older readers reject newer containers cleanly rather than
/// misinterpreting them:
///
/// | value    | AEAD               | KEM               | signature        |
/// |----------|--------------------|-------------------|------------------|
/// | `0x0001` | XChaCha20-Poly1305 | X25519            | Ed25519          |
/// | `0x0002` | *reserved* AES-256-GCM | X25519        | Ed25519          |
/// | `0x0101` | *reserved* XChaCha20-Poly1305 | X25519+ML-KEM-768 | Ed25519+ML-DSA-65 |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SuiteId {
    /// XChaCha20-Poly1305 / X25519 / Ed25519 / Argon2id + BLAKE3. The classical
    /// default and the only suite implemented in the MVP.
    #[default]
    Classic = 0x0001,
}

impl SuiteId {
    /// Numeric on-the-wire value stored in the header.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        self as u16
    }

    /// Parse a numeric suite id, rejecting anything this build cannot perform.
    pub fn from_u16(value: u16) -> Result<Self> {
        match value {
            0x0001 => Ok(SuiteId::Classic),
            other => Err(Error::UnsupportedSuite(other)),
        }
    }

    /// Whether this build can read/write the suite.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, SuiteId::Classic)
    }

    /// Human-readable description for the UI.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            SuiteId::Classic => "Classic (XChaCha20-Poly1305 · X25519 · Ed25519)",
        }
    }
}
