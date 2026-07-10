//! FileSec core: cryptography and the `.fsec` container format.
//!
//! This crate contains the entire security story for FileSec and intentionally
//! has **no GUI or dialog dependencies** so it can be unit-tested, fuzzed, and
//! audited in isolation.
//!
//! # Layout
//! * [`secret`], [`aead`], [`kem`], [`sign`], [`kdf`] — cryptographic primitives.
//! * [`suite`] — the algorithm-suite identifier and dispatch.
//! * [`identity`], [`keystore`], [`contacts`] — key/identity management.
//! * [`envelope`], [`manifest`], [`vault`], [`format`] — the `.fsec` container.
//! * [`safe_io`] — hardened, atomic, symlink-rejecting writes for plaintext.
//!
//! See `THREAT_MODEL.md` at the repo root for the authoritative threat model
//! (what is protected, against whom, and what is out of scope) and the workspace
//! plan for the container format specification.

// Deny the most dangerous footguns. Crypto code must not silently panic on
// untrusted input or unwrap fallible results.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(missing_docs)]

pub mod aead;
pub mod codec;
pub mod contacts;
pub mod envelope;
pub mod error;
pub mod format;
pub mod format_v2;
pub mod identity;
pub mod kdf;
pub mod kem;
pub mod keystore;
pub mod manifest;
#[cfg(feature = "pqc")]
pub mod mldsa;
#[cfg(feature = "pqc")]
pub mod mlkem;
pub mod safe_io;
pub mod secret;
pub mod sign;
pub mod state;
pub mod suite;
#[cfg(feature = "net")]
pub mod transport;
pub mod util;
pub mod vault;

pub use error::{Error, Result};
pub use format::{AddedFile, ExportOptions, ImportedVault, VaultReader, VerifiedSender};
pub use format_v2::VaultReaderV2;
pub use identity::{sanitize_display_name, Identity, PublicIdentity};
pub use suite::SuiteId;
#[cfg(feature = "net")]
pub use transport::{Initiator, PeerAuth, RecordType, Responder, Session};
pub use vault::Vault;
