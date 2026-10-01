//! The in-app vault model: the logical tree of files and folders the user
//! manages. This is the plaintext, in-memory representation; persistence and
//! transport happen through the [`crate::format`] container.
//!
//! File contents are held in zeroizing buffers while a vault is open.

use std::collections::HashMap;
use std::path::Path;

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
        self.ensure_parents(&norm)?;
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
        match self.entries.iter().find(|e| e.path == norm) {
            Some(e) if e.kind == EntryKind::Dir => return Ok(()),
            Some(_) => return Err(Error::Vault(format!("a file exists at {norm}"))),
            None => {}
        }
        self.ensure_parents(&norm)?;
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

    /// Push directory entries for each missing ancestor of `path`, refusing
    /// to treat an existing file as a directory.
    fn ensure_parents(&mut self, path: &str) -> Result<()> {
        let mut acc = String::new();
        let comps: Vec<&str> = path.split('/').collect();
        for comp in comps.iter().take(comps.len().saturating_sub(1)) {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(comp);
            match self.entries.iter().find(|e| e.path == acc) {
                Some(e) if e.kind == EntryKind::Dir => {}
                Some(_) => {
                    return Err(Error::Vault(format!(
                        "a file exists at {acc}; it cannot contain other entries"
                    )))
                }
                None => self.entries.push(VaultEntry {
                    path: acc.clone(),
                    kind: EntryKind::Dir,
                    mtime: None,
                    mode: None,
                    content: Zeroizing::new(Vec::new()),
                }),
            }
        }
        Ok(())
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
///
/// Invisible and bidirectional formatting characters
/// ([`crate::util::is_spoofing_format_char`]) are rejected too (FS-16): they
/// let a name render as something else (`report\u{202E}gpj.exe` shows as
/// `reportexe.jpg`) in the app, in file managers, and in every program that
/// later opens the extracted file. A valid sender signature does not make a
/// file name truthful.
pub fn normalize_path(path: &str) -> Result<String> {
    let norm = normalize_stored_path(path)?;
    if norm.chars().any(crate::util::is_spoofing_format_char) {
        return Err(Error::Vault(
            "invisible or bidirectional formatting characters in path".into(),
        ));
    }
    Ok(norm)
}

/// [`normalize_path`] without the formatting-character rule, for paths that
/// are **already stored in the user's own local vault** (an older version
/// accepted them). Such a vault must keep opening so the entry can be seen —
/// rendered with [`visible_path`] — renamed, or removed; every path that is
/// created, renamed to, imported from someone else, or extracted to disk still
/// goes through the strict [`normalize_path`].
pub(crate) fn normalize_stored_path(path: &str) -> Result<String> {
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

/// Reject a tree in which a file is an ancestor of another entry (`a` a file
/// while `a/b` exists): such a manifest cannot be extracted faithfully and has
/// no consistent meaning in the browser. `entries` are normalized paths.
pub(crate) fn check_tree_shape(entries: &[(String, EntryKind)]) -> Result<()> {
    let files: std::collections::HashSet<&str> = entries
        .iter()
        .filter(|(_, kind)| *kind == EntryKind::File)
        .map(|(path, _)| path.as_str())
        .collect();
    for (path, _) in entries {
        let mut cur = path.as_str();
        while let Some((parent, _)) = cur.rsplit_once('/') {
            if files.contains(parent) {
                return Err(Error::Format("a file entry is used as a directory"));
            }
            cur = parent;
        }
    }
    Ok(())
}

/// Render a vault path for display with every invisible or bidirectional
/// formatting character made visible as `⟨U+XXXX⟩`, so what the user sees is
/// the actual sequence of characters (FS-16). Borrowed unchanged when there is
/// nothing to escape.
#[must_use]
pub fn visible_path(path: &str) -> std::borrow::Cow<'_, str> {
    if !path.chars().any(crate::util::is_spoofing_format_char) {
        return std::borrow::Cow::Borrowed(path);
    }
    let mut out = String::with_capacity(path.len() + 16);
    for c in path.chars() {
        if crate::util::is_spoofing_format_char(c) {
            out.push_str(&format!("\u{27E8}U+{:04X}\u{27E9}", c as u32));
        } else {
            out.push(c);
        }
    }
    std::borrow::Cow::Owned(out)
}

/// The identity of a normalized vault path on the most aliasing filesystems
/// FileSec extracts to: case-insensitive (NTFS, default APFS/HFS+) and
/// Unicode-normalization-insensitive (APFS, HFS+). Two different vault paths
/// with the same key would be written to one file there, the later silently
/// replacing the earlier (FS-09).
#[must_use]
pub fn portable_collision_key(normalized: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let folded = normalized.nfd().collect::<String>().to_lowercase();
    folded.nfc().collect()
}

/// How many conflicts an [`Error::ExtractionConflict`] message lists.
const MAX_REPORTED_CONFLICTS: usize = 8;

/// Refuse an extraction **before writing anything** if it could lose data.
///
/// `entries` are the vault paths about to be written under `dest`. The
/// extraction is refused if two distinct entries share a
/// [`portable_collision_key`] (they would alias on a case- or
/// normalization-insensitive destination, wherever that destination is), or
/// if a file entry's target already exists at the destination — FileSec never
/// replaces a file the user already has. Existing directories are fine to
/// extract into. Both source entries and the user's existing outputs are thus
/// preserved; the error names the conflicting paths.
pub fn preflight_extraction<'a, I>(dest: &Path, entries: I) -> Result<()>
where
    I: IntoIterator<Item = (&'a str, EntryKind)>,
{
    let mut seen: HashMap<String, String> = HashMap::new();
    let mut conflicts = Vec::new();
    for (path, kind) in entries {
        let norm = normalize_path(path)?;
        let key = portable_collision_key(&norm);
        match seen.get(&key) {
            Some(first) if *first != norm => {
                conflicts.push(format!("\"{first}\" and \"{norm}\" name the same file"));
            }
            Some(_) => {}
            None => {
                if kind == EntryKind::File {
                    if let Ok(meta) = std::fs::symlink_metadata(dest.join(&norm)) {
                        if !meta.is_dir() {
                            conflicts.push(format!("\"{norm}\" already exists at the destination"));
                        }
                    }
                }
                seen.insert(key, norm);
            }
        }
        if conflicts.len() >= MAX_REPORTED_CONFLICTS {
            break;
        }
    }
    if conflicts.is_empty() {
        Ok(())
    } else {
        Err(Error::ExtractionConflict(conflicts.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

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

    #[test]
    fn collision_key_folds_case_and_unicode_normalization() {
        assert_eq!(
            portable_collision_key("Report"),
            portable_collision_key("report")
        );
        assert_eq!(
            portable_collision_key("caf\u{e9}.txt"),
            portable_collision_key("cafe\u{301}.txt")
        );
        assert_eq!(
            portable_collision_key("DIR/\u{c9}t\u{c9}"),
            portable_collision_key("dir/e\u{301}te\u{301}")
        );
        assert_ne!(portable_collision_key("a/b"), portable_collision_key("a-b"));
    }

    #[test]
    fn preflight_reports_aliases_and_existing_files_without_writing() {
        let dest = std::env::temp_dir().join(format!(
            "filesec-preflight-{}",
            crate::util::hex(&crate::secret::random_array::<8>().unwrap())
        ));
        std::fs::create_dir_all(dest.join("docs")).unwrap();
        std::fs::write(dest.join("kept.txt"), b"mine").unwrap();
        let ok = [("docs", EntryKind::Dir), ("docs/new.txt", EntryKind::File)];
        preflight_extraction(&dest, ok).unwrap();

        let case = [("Report", EntryKind::File), ("report", EntryKind::File)];
        let error = preflight_extraction(&dest, case).unwrap_err().to_string();
        assert!(
            error.contains("Report") && error.contains("report"),
            "{error}"
        );

        let nfd = [
            ("caf\u{e9}.txt", EntryKind::File),
            ("cafe\u{301}.txt", EntryKind::File),
        ];
        assert!(matches!(
            preflight_extraction(&dest, nfd),
            Err(Error::ExtractionConflict(_))
        ));

        let existing = [("kept.txt", EntryKind::File)];
        let error = preflight_extraction(&dest, existing)
            .unwrap_err()
            .to_string();
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(std::fs::read(dest.join("kept.txt")).unwrap(), b"mine");
        std::fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn new_paths_reject_formatting_characters_but_stored_ones_stay_usable() {
        for path in [
            "report\u{202e}gpj.exe",
            "a/b\u{200b}c",
            "\u{2066}x\u{2069}",
            "soft\u{ad}hyphen",
            "tag\u{e0041}",
        ] {
            assert!(normalize_path(path).is_err(), "accepted {path:?}");
            assert!(normalize_stored_path(path).is_ok(), "stored {path:?}");
        }
        assert_eq!(visible_path("report.txt"), "report.txt");
        assert_eq!(
            visible_path("report\u{202e}gpj.exe"),
            "report\u{27e8}U+202E\u{27e9}gpj.exe"
        );
        // Ordinary non-ASCII names are untouched.
        assert!(normalize_path("caf\u{e9}/\u{65e5}\u{672c}.txt").is_ok());
    }

    #[test]
    fn a_file_cannot_be_used_as_a_directory() {
        let mut vault = Vault::new("V", 0);
        vault.add_file("a", b"file".to_vec(), None, None).unwrap();
        assert!(vault
            .add_file("a/b", b"child".to_vec(), None, None)
            .is_err());
        assert!(vault.add_dir("a").is_err(), "a file already occupies it");
        assert!(vault.add_dir("a/sub").is_err());
        vault.add_dir("d").unwrap();
        vault.add_dir("d").unwrap();
        vault
            .add_file("d/e.txt", b"ok".to_vec(), None, None)
            .unwrap();
        assert!(check_tree_shape(&[
            ("a".into(), EntryKind::File),
            ("a/b".into(), EntryKind::File),
        ])
        .is_err());
        assert!(check_tree_shape(&[
            ("d".into(), EntryKind::Dir),
            ("d/e".into(), EntryKind::File),
        ])
        .is_ok());
    }
}
