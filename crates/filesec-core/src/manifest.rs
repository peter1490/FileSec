//! The encrypted manifest: the folder tree and per-entry metadata.
//!
//! The manifest is serialized to CBOR and encrypted with the content key, so
//! filenames, structure, sizes, and per-file hashes are all confidential — not
//! just file contents.

use serde::{Deserialize, Serialize};

/// Whether a manifest entry is a file or a directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    /// A regular file with content in the data section.
    File,
    /// A directory (no content; preserves empty folders and structure).
    Dir,
}

/// One entry in the vault's tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    /// Relative POSIX path (normalized; never absolute, never contains `..`).
    pub path: String,
    /// File or directory.
    pub kind: EntryKind,
    /// Plaintext byte length (0 for directories).
    pub size: u64,
    /// Optional modification time (Unix seconds).
    pub mtime: Option<i64>,
    /// Optional advisory Unix permission bits.
    pub mode: Option<u32>,
    /// BLAKE3 hash of the plaintext content (all-zero for directories).
    pub blake3: [u8; 32],
    /// Byte offset of this file's content within the decrypted data stream
    /// (0 for directories).
    pub data_offset: u64,
}

/// The full manifest.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
    /// Human-readable vault name (confidential — lives here, not in the header).
    pub vault_name: String,
    /// Unix creation time of the vault.
    pub created_at: i64,
    /// All entries, in data-stream order for files.
    pub entries: Vec<Entry>,
}
