//! Desktop resource budgets for container and vault metadata (audit O-04).
//!
//! Bulk file content is always streamed a chunk at a time, but metadata is
//! not: opening a container or vault holds its header, the encrypted and the
//! decrypted manifest, the decoded entries, and (in the app) an index of them
//! at once. These limits are sized so that worst case stays inside what a
//! desktop process can reasonably spend, rather than merely below what the
//! formats can express.
//!
//! Rough peak for a manifest at the limits below: ciphertext + plaintext
//! (2 × 256 MiB) plus about 300 bytes per decoded entry (≈ 300 MiB for a
//! million entries) plus the app's browser index — on the order of 1 GiB. A
//! realistic vault (thousands to tens of thousands of entries) uses a few MiB.
//!
//! Deliberately in-memory APIs (`Vault`, `VaultReader::to_vault`,
//! `import_vault_from_path`, `read_entry`) scale with the plaintext they
//! materialize; [`MAX_IN_MEMORY_CONTAINER_LEN`] bounds the one that reads a
//! whole untrusted file.

/// Largest v1 container header accepted. A hybrid recipient stanza is about
/// 1.2 KiB, so this admits several thousand recipients.
pub const MAX_CONTAINER_HEADER_LEN: usize = 4 * 1024 * 1024;

/// Largest local v2 vault header accepted (it holds a single recipient stanza).
pub const MAX_VAULT_HEADER_LEN: u64 = 1024 * 1024;

/// Largest encrypted manifest accepted, v1 or v2.
pub const MAX_MANIFEST_LEN: u64 = 256 * 1024 * 1024;

/// Most entries a manifest may declare, v1 or v2.
pub const MAX_MANIFEST_ENTRIES: usize = 1_000_000;

/// Largest container read fully into memory by the deliberately
/// non-streaming import. The streaming open/verify paths have no such limit.
pub const MAX_IN_MEMORY_CONTAINER_LEN: u64 = 2 * 1024 * 1024 * 1024;
