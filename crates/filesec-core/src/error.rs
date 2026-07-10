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

    /// Persisted or imported Argon2id parameters exceeded the local open policy.
    #[error("key derivation parameters rejected: {0}")]
    KdfParams(&'static str),

    /// An authenticated state object is older than the locally anchored
    /// high-water mark. The caller should quarantine it rather than opening it.
    #[error("rollback detected for {0}: the stored state is older than the trusted anchor")]
    RollbackDetected(String),

    /// An authenticated state object conflicts with the trusted state at the
    /// same epoch, changes identity/object binding, or breaks the hash chain.
    #[error("state-anchor mismatch for {0}: the stored state conflicts with trusted history")]
    StateMismatch(String),

    /// A valid pre-anchor state format was encountered on a normal open. Legacy
    /// state is accepted only by an explicit recovery/migration entry point.
    #[error("legacy state requires explicit recovery: {0}")]
    LegacyState(&'static str),

    /// A hardened filesystem write refused to proceed: the destination or one of
    /// its parent components is a symlink, an extraction path escaped its root, or
    /// a path component collided with a non-directory. Sensitive plaintext is
    /// never written through such a path.
    #[error("unsafe filesystem path: {0}")]
    UnsafePath(&'static str),

    /// A filesystem operation failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A vault-level invariant was violated (e.g. duplicate or escaping path).
    #[error("vault error: {0}")]
    Vault(String),

    /// A post-quantum (hybrid) operation was requested but the required key
    /// material is missing — e.g. exporting suite `0x0101` to a recipient whose
    /// identity carries no ML-KEM key, or opening a hybrid container with a
    /// classical-only identity.
    #[error("post-quantum key material is missing: {0}")]
    MissingPqcKey(&'static str),

    /// During a direct network transfer, the peer that answered proved a
    /// long-term identity whose fingerprint did not match the contact we meant
    /// to reach ("right address, wrong identity"). The transfer is aborted.
    #[error("the peer's identity does not match the expected contact")]
    PeerIdentityMismatch,

    /// During a direct network transfer, the dialing peer failed to prove
    /// knowledge of the per-transfer 128-bit transfer secret. The responder
    /// aborts *before* disclosing any identity or signature material, so an
    /// attacker who does not hold the secret learns nothing and gets no offline
    /// oracle against it.
    #[error("the transfer code does not match")]
    TransferSecretMismatch,

    /// A transport handshake message was malformed, arrived out of order, or
    /// named an unsupported protocol version/suite.
    #[error("handshake protocol error: {0}")]
    HandshakeProtocol(&'static str),
}
