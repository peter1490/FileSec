//! Algorithm-suite identifier and dispatch.
//!
//! A `.fsec` container names its *entire* cryptographic suite with a single
//! atomic [`SuiteId`] — there is no per-primitive in-band negotiation, which is
//! where downgrade bugs live. The id lives in the header, which is fed as AAD
//! into every AEAD operation and covered by the sender signature, so an
//! attacker cannot substitute a weaker suite without invalidating the
//! container. Importers additionally enforce [`SuiteId::is_supported`].

use crate::aead::AeadAlg;
use crate::error::{Error, Result};

/// The cryptographic suite used by a container.
///
/// The classical default (`0x0001`) is always available. The post-quantum
/// suites are compiled in only with the `pqc` feature; a build without it
/// rejects them at [`SuiteId::from_u16`] so an old reader refuses a newer
/// container cleanly rather than misinterpreting it:
///
/// | value    | AEAD               | KEM               | signature        |
/// |----------|--------------------|-------------------|------------------|
/// | `0x0001` | XChaCha20-Poly1305 | X25519            | Ed25519          |
/// | `0x0002` | AES-256-GCM        | X25519            | Ed25519          |
/// | `0x0101` | XChaCha20-Poly1305 | X25519+ML-KEM-768 | Ed25519+ML-DSA-65 |
///
/// The `0x01__` high byte marks a hybrid post-quantum suite; the low byte then
/// selects the bulk AEAD, mirroring the classical range.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SuiteId {
    /// XChaCha20-Poly1305 / X25519 / Ed25519 / Argon2id + BLAKE3. The classical
    /// default, always available.
    #[default]
    Classic = 0x0001,
    /// AES-256-GCM / X25519 / Ed25519. Same classical KEM and signature as
    /// [`SuiteId::Classic`], swapping the bulk cipher to AES-256-GCM for callers
    /// who want a NIST/FIPS-aligned, hardware-accelerated AEAD. Requires `pqc`.
    #[cfg(feature = "pqc")]
    Aes256Gcm = 0x0002,
    /// Hybrid post-quantum: XChaCha20-Poly1305 bulk cipher, a **combined**
    /// X25519+ML-KEM-768 KEM, and a **dual** Ed25519+ML-DSA-65 signature. The
    /// hybrid combiner guarantees the suite is no weaker than the classical
    /// baseline even if one of the two KEMs (or signatures) is broken. Requires
    /// `pqc`.
    #[cfg(feature = "pqc")]
    Hybrid = 0x0101,
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
            #[cfg(feature = "pqc")]
            0x0002 => Ok(SuiteId::Aes256Gcm),
            #[cfg(feature = "pqc")]
            0x0101 => Ok(SuiteId::Hybrid),
            other => Err(Error::UnsupportedSuite(other)),
        }
    }

    /// Whether this build can read/write the suite. Every variant that exists in
    /// this build is, by construction, supported.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        true
    }

    /// The bulk AEAD this suite uses for its manifest and file data.
    #[must_use]
    pub const fn aead_alg(self) -> AeadAlg {
        match self {
            SuiteId::Classic => AeadAlg::XChaCha20Poly1305,
            #[cfg(feature = "pqc")]
            SuiteId::Aes256Gcm => AeadAlg::Aes256Gcm,
            #[cfg(feature = "pqc")]
            SuiteId::Hybrid => AeadAlg::XChaCha20Poly1305,
        }
    }

    /// Whether this is a hybrid post-quantum suite — i.e. it combines a
    /// post-quantum KEM/signature with the classical ones. Drives the envelope
    /// (combined KEM) and the container trailer (dual signature).
    #[must_use]
    pub const fn is_hybrid(self) -> bool {
        match self {
            SuiteId::Classic => false,
            #[cfg(feature = "pqc")]
            SuiteId::Aes256Gcm => false,
            #[cfg(feature = "pqc")]
            SuiteId::Hybrid => true,
        }
    }

    /// Human-readable description for the UI.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            SuiteId::Classic => "Classic (XChaCha20-Poly1305 · X25519 · Ed25519)",
            #[cfg(feature = "pqc")]
            SuiteId::Aes256Gcm => "AES-256-GCM (AES-256-GCM · X25519 · Ed25519)",
            #[cfg(feature = "pqc")]
            SuiteId::Hybrid => {
                "Hybrid PQC (XChaCha20-Poly1305 · X25519+ML-KEM-768 · Ed25519+ML-DSA-65)"
            }
        }
    }
}
