//! The in-app vault model: the logical tree of files and folders the user
//! manages. This is the plaintext, in-memory representation; persistence and
//! transport happen through the [`crate::format`] container.
//!
//! File contents are held in zeroizing buffers while a vault is open.

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::manifest::EntryKind;

/// Maximum number of path components, to bound untrusted input.
const MAX_PATH_DEPTH: usize = 64;
/// Maximum byte length of a single path.
const MAX_PATH_LEN: usize = 4096;

/// A single file or directory in a vault.
pub struct VaultEntry {
    /// Normalized relative POSIX path.
    pub path: String,
    /// File or directory.
    pub kind: EntryKind,
    /// Optional modification time (Unix seconds).
    pub mtime: Option<i64>,
    /// Optional advisory Unix permission bits.
    pub mode: Option<u32>,
    /// Plaintext content (empty for directories). Zeroized on drop.
    pub content: Zeroizing<Vec<u8>>,
}

impl VaultEntry {
    /// Content length in bytes (0 for directories).
    #[must_use]
    pub fn size(&self) -> u64 {
        self.content.len() as u64
    }
}

/// An open vault: a name plus an ordered set of entries with unique paths.
pub struct Vault {
    /// Human-readable name.
    pub name: String,
    /// Unix creation time.
    pub created_at: i64,
    entries: Vec<VaultEntry>,
}

impl Vault {
    /// Create an empty vault.
    #[must_use]
    pub fn new(name: impl Into<String>, created_at: i64) -> Self {
        Self {
            name: name.into(),
            created_at,
            entries: Vec::new(),
        }
    }

    /// Borrow the entries (read-only).
    #[must_use]
    pub fn entries(&self) -> &[VaultEntry] {
        &self.entries
    }

    /// Number of file entries (excludes directories).
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .count()
    }

    /// Total plaintext byte size of all files.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.entries.iter().map(VaultEntry::size).sum()
    }

    /// Whether a normalized path already exists.
    #[must_use]
    pub fn contains(&self, path: &str) -> bool {
        self.entries.iter().any(|e| e.path == path)
    }

    /// Look up an entry by normalized path.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&VaultEntry> {
        let norm = normalize_path(path).ok()?;
        self.entries.iter().find(|e| e.path == norm)
    }

    /// Add a file, creating any implied parent directories. Fails if the path
    /// is invalid or already present.
    pub fn add_file(
        &mut self,
        path: &str,
        content: Vec<u8>,
        mtime: Option<i64>,
        mode: Option<u32>,
    ) -> Result<()> {
        let norm = normalize_path(path)?;
        if self.contains(&norm) {
            return Err(Error::Vault(format!("path already exists: {norm}")));
        }
        self.ensure_parents(&norm);
        self.entries.push(VaultEntry {
            path: norm,
            kind: EntryKind::File,
            mtime,
            mode,
            content: Zeroizing::new(content),
        });
        Ok(())
    }

    /// Add an explicit (possibly empty) directory.
    pub fn add_dir(&mut self, path: &str) -> Result<()> {
        let norm = normalize_path(path)?;
        if self.contains(&norm) {
            return Ok(());
        }
        self.ensure_parents(&norm);
        self.entries.push(VaultEntry {
            path: norm,
            kind: EntryKind::Dir,
            mtime: None,
            mode: None,
            content: Zeroizing::new(Vec::new()),
        });
        Ok(())
    }

    /// Remove an entry (and, if it is a directory, everything beneath it).
    /// Returns the number of entries removed.
    pub fn remove(&mut self, path: &str) -> usize {
        let norm = match normalize_path(path) {
            Ok(n) => n,
            Err(_) => return 0,
        };
        let prefix = format!("{norm}/");
        let before = self.entries.len();
        self.entries
            .retain(|e| e.path != norm && !e.path.starts_with(&prefix));
        before - self.entries.len()
    }

    /// Push directory entries for each missing ancestor of `path`.
    fn ensure_parents(&mut self, path: &str) {
        let mut acc = String::new();
        let comps: Vec<&str> = path.split('/').collect();
        for comp in comps.iter().take(comps.len().saturating_sub(1)) {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(comp);
            if !self.entries.iter().any(|e| e.path == acc) {
                self.entries.push(VaultEntry {
                    path: acc.clone(),
                    kind: EntryKind::Dir,
                    mtime: None,
                    mode: None,
                    content: Zeroizing::new(Vec::new()),
                });
            }
        }
    }

    /// Internal: append a pre-validated entry (used by the importer, which has
    /// already normalized paths).
    pub(crate) fn push_entry(&mut self, entry: VaultEntry) {
        self.entries.push(entry);
    }
}

/// Normalize and validate an untrusted relative path.
///
/// Returns a clean POSIX path with single `/` separators and no leading slash.
/// Rejects empty paths, `.`/`..` components, NUL/control bytes, and
/// pathologically deep or long paths.
///
/// Absolute inputs are **rejected outright** rather than silently rewritten to
/// relative form (F19): a leading `/`, a leading `\` or `\\` UNC prefix, and a
/// Windows drive prefix (`C:\`, `C:/`, or drive-relative `C:foo`) all error
/// instead of being stripped down to a relative path. Already-valid relative
/// paths — including ones that merely use `\` as a mid-path separator or contain
/// redundant `.`/`//` — are still normalized for backward compatibility. This is
/// the single chokepoint that keeps a malicious container from escaping its
/// extraction directory or naming an absolute destination.
pub fn normalize_path(path: &str) -> Result<String> {
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return Err(Error::Vault("invalid path length".into()));
    }
    // Treat both separators as separators so neither OS can be tricked.
    let unified = path.replace('\\', "/");
    // A leading separator (Unix absolute `/x`, Windows `\x`, or a `\\host` UNC
    // share, both now `/...`) is absolute — refuse it rather than stripping it.
    if unified.starts_with('/') {
        return Err(Error::Vault("absolute paths are not allowed".into()));
    }
    // A Windows drive prefix (`C:` as the first two bytes) is absolute or
    // drive-relative; either way it must not be treated as a plain relative path.
    let bytes = unified.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(Error::Vault("drive-letter paths are not allowed".into()));
    }
    let mut components: Vec<&str> = Vec::new();
    for comp in unified.split('/') {
        match comp {
            "" | "." => continue, // collapse empty (from `//` or leading `/`) and `.`
            ".." => return Err(Error::Vault("path traversal ('..') is not allowed".into())),
            _ => {
                if comp.bytes().any(|b| b < 0x20 || b == 0x7f) {
                    return Err(Error::Vault("control characters in path".into()));
                }
                // Enforce the same portable namespace on every OS. Windows
                // interprets ':' as an alternate data stream and strips trailing
                // dots/spaces; device names remain special even with extensions.
                if comp.contains([':', '<', '>', '"', '|', '?', '*']) || comp.ends_with(['.', ' '])
                {
                    return Err(Error::Vault("non-portable path component".into()));
                }
                let stem = comp.split('.').next().unwrap_or(comp).to_uppercase();
                let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                    || ["COM", "LPT"].iter().any(|prefix| {
                        stem.strip_prefix(prefix).is_some_and(|n| {
                            matches!(
                                n,
                                "1" | "2"
                                    | "3"
                                    | "4"
                                    | "5"
                                    | "6"
                                    | "7"
                                    | "8"
                                    | "9"
                                    | "¹"
                                    | "²"
                                    | "³"
                            )
                        })
                    });
                if device {
                    return Err(Error::Vault("reserved device name in path".into()));
                }
                components.push(comp);
            }
        }
    }
    if components.is_empty() {
        return Err(Error::Vault("path resolves to nothing".into()));
    }
    if components.len() > MAX_PATH_DEPTH {
        return Err(Error::Vault("path is too deep".into()));
    }
    Ok(components.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_windows_devices_streams_and_aliases_on_every_platform() {
        for path in [
            "a/b:secret",
            "a/NUL.txt",
            "con",
            "a/COM1",
            "LPT³.log",
            "a/.. ",
            "a/file.",
            "a/file ",
            "a/*.txt",
            "a/b?",
            "a/b|c",
        ] {
            assert!(normalize_path(path).is_err(), "accepted {path}");
        }
        for path in [
            "report.txt",
            "a/COM10.txt",
            "console",
            "日本語/document.txt",
        ] {
            assert!(normalize_path(path).is_ok(), "rejected {path}");
        }
    }
}
