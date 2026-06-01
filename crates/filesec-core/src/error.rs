//! Typed error handling.
//!
//! Errors never embed secret material (keys, plaintext, passphrases) in their
//! `Display`/`Debug` output, and the crate never panics on untrusted input —
//! every fallible path returns [`Result`].

/// Convenience alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// All errors that `filesec-core` can produce.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The OS random number generator failed.
    #[error("secure random number generation failed")]
    Rng,

    /// AEAD authentication failed: data was tampered with, truncated, or the
    /// wrong key was used. Deliberately does not distinguish the cause.
    #[error("authentication failed: data is corrupt, tampered, or the wrong key was used")]
    Auth,

    /// The supplied passphrase did not unlock the keystore.
    #[error("incorrect passphrase")]
    BadPassphrase,

    /// A container or stored file was structurally malformed.
    #[error("malformed data: {0}")]
    Format(&'static str),

    /// The container declares an algorithm suite this build does not support.
    #[error("unsupported algorithm suite: {0:#06x}")]
    UnsupportedSuite(u16),

    /// The sender signature over a container did not verify.
    #[error("sender signature verification failed")]
    BadSignature,

    /// No recipient stanza in the container matches the current identity.
    #[error("this container is not addressed to your identity")]
    NotARecipient,

    /// Key material was structurally invalid (wrong length, not on curve, ...).
    #[error("invalid key material: {0}")]
    BadKey(&'static str),

    /// CBOR (de)serialization failed.
    #[error("serialization failure")]
    Serialization,

    /// Argon2 / KDF parameters were invalid or derivation failed.
    #[error("key derivation failed")]
    Kdf,

    /// A filesystem operation failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A vault-level invariant was violated (e.g. duplicate or escaping path).
    #[error("vault error: {0}")]
    Vault(String),
}
