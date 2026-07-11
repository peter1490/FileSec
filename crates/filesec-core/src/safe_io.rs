//! Hardened filesystem writes for sensitive output (decrypted plaintext and
//! exported secrets).
//!
//! Every sensitive write goes through [`SafeFileWriter`]: bytes are streamed to a
//! **private** temp file (`create_new` + mode `0600` on Unix) created in the same
//! directory as the final destination, fsync'd, and only then atomically renamed
//! into place. A writer dropped without an explicit [`commit`](SafeFileWriter::commit)
//! — because decryption/authentication failed, or the process errored — removes
//! the temp file, so a failed extraction never leaves partial plaintext at the
//! destination, and because the temp uses `create_new` and the final target is
//! symlink-checked, a sensitive write is never made *through* a symlink an
//! attacker planted at the destination path.
//!
//! For multi-file extraction, [`create_dirs_no_symlink`] builds the parent
//! directories one component at a time, refusing to descend through any existing
//! symlink (an attacker-planted redirection out of the extraction root).
//!
//! LIMITATION: the symlink checks are `symlink_metadata` + `create_new`, not a
//! fully race-free `openat(O_NOFOLLOW)` walk (which would need a `libc`
//! dependency this MSRV-pinned, dependency-light build deliberately avoids).
//! `create_new`'s `O_EXCL` semantics already refuse to follow a symlink at the
//! *final* component, and the parent-component checks close the common
//! local-tampering window, but a narrow TOCTOU race against a concurrent
//! attacker who can write inside the destination directory remains — which the
//! project threat model already places out of scope (see `README.md`).

use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};
use crate::secret::random_array;
use crate::util::hex;

/// A hardened, atomic writer for sensitive output.
///
/// Construct with [`SafeFileWriter::create`], write the plaintext through the
/// [`Write`] impl, then finish with [`commit`](Self::commit). If the value is
/// dropped before `commit` (an error, an early return, a failed authentication
/// upstream), the private temp file is unlinked and the destination is left
/// untouched — the user sees either the previous complete file or nothing, never
/// a truncated half-decrypted one.
pub struct SafeFileWriter {
    dest: PathBuf,
    tmp: PathBuf,
    file: Option<std::fs::File>,
    committed: bool,
}

impl SafeFileWriter {
    /// Begin a hardened write to `dest`.
    ///
    /// Creates a private temp file (`create_new`, mode `0600` on Unix) in `dest`'s
    /// parent directory so the eventual rename is atomic on a single filesystem.
    /// Refuses immediately if `dest` already exists as a symlink. `dest`'s parent
    /// directory must already exist (extraction callers create it first through
    /// [`create_dirs_no_symlink`]).
    pub fn create(dest: &Path) -> Result<Self> {
        let parent = match dest.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        // Refuse to target an existing symlink. A later rename would replace the
        // link rather than write through it, but rejecting is the stricter
        // contract and catches the situation up front.
        reject_symlink(dest)?;
        let (tmp, file) = create_private_temp(&parent, dest)?;
        Ok(Self {
            dest: dest.to_path_buf(),
            tmp,
            file: Some(file),
            committed: false,
        })
    }

    /// Flush, fsync, re-check the destination for a symlink, then atomically
    /// rename the temp file into place, and best-effort fsync the containing
    /// directory so the rename itself survives a crash. On any failure the temp
    /// file is removed (via `Drop`) and the destination is left untouched.
    ///
    /// Callers writing decrypted plaintext are expected to have authenticated the
    /// content *as it streamed* (per-chunk AEAD + a full-file BLAKE3 check); this
    /// method deliberately does not re-hash, so an upstream authentication failure
    /// surfaces before `commit` is ever reached and the temp is discarded.
    pub fn commit(mut self) -> Result<()> {
        let mut file = self
            .file
            .take()
            .ok_or(Error::Format("safe writer already finished"))?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        // Guard against a symlink swapped in after creation (best-effort TOCTOU).
        reject_symlink(&self.dest)?;
        std::fs::rename(&self.tmp, &self.dest)?;
        if let Some(parent) = self.dest.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        self.committed = true;
        Ok(())
    }
}

impl Write for SafeFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.file {
            Some(f) => f.write(buf),
            None => Err(io::Error::other("safe writer already finished")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.file {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

impl Drop for SafeFileWriter {
    fn drop(&mut self) {
        if !self.committed {
            // Close the handle before unlinking so no writer keeps it alive.
            self.file.take();
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

/// Create every component of `dir` that lies beneath `root`, one level at a time,
/// refusing to descend through any existing component that is a symlink.
///
/// `root` is trusted (the caller — a user file dialog — chose it) and is not
/// itself checked; `dir` must equal `root` or be a descendant of it. Directories
/// created here are private (`0700`) on Unix. Existing real directories are left
/// as-is (the walk is idempotent across sibling entries that share a parent).
pub fn create_dirs_no_symlink(root: &Path, dir: &Path) -> Result<()> {
    let rel = dir
        .strip_prefix(root)
        .map_err(|_| Error::UnsafePath("extraction target escapes its root"))?;
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => cur.push(c),
            Component::CurDir => continue,
            // `normalize_path` guarantees only `Normal` components reach here;
            // refuse anything else rather than trust it.
            _ => return Err(Error::UnsafePath("unexpected path component")),
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(Error::UnsafePath(
                    "refusing to extract through a symlinked directory",
                ))
            }
            Ok(m) if m.is_dir() => {} // real directory — descend into it
            Ok(_) => {
                return Err(Error::UnsafePath(
                    "extraction path collides with a non-directory",
                ))
            }
            Err(_) => create_private_dir(&cur)?, // missing — create this one level
        }
    }
    Ok(())
}

/// Error if `path` currently exists and is a symlink. A missing path, a regular
/// file, or a directory are all fine (the caller will replace a regular file
/// atomically; a directory makes the later rename fail naturally).
fn reject_symlink(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(Error::UnsafePath(
            "refusing to write through an existing symlink",
        )),
        _ => Ok(()),
    }
}

/// Create a fresh, private, uniquely named temp file in `dir` for the write that
/// will become `dest`. Uses `create_new` (`O_EXCL`) so it never opens an existing
/// file or follows a symlink; the name carries a random suffix, retried on the
/// astronomically unlikely collision.
fn create_private_temp(dir: &Path, dest: &Path) -> Result<(PathBuf, std::fs::File)> {
    let base = dest
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("out");
    for _ in 0..8 {
        let suffix = hex(&random_array::<8>()?);
        let candidate = dir.join(format!(".{base}.{suffix}.fstmp"));
        match open_new_private(&candidate) {
            Ok(f) => return Ok((candidate, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Err(Error::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique temp file",
    )))
}

#[cfg(unix)]
fn open_new_private(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_new_private(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(Error::from)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> Result<()> {
    std::fs::DirBuilder::new().create(path).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    // Tests assert on concrete outcomes; the crate-level denies on
    // unwrap/expect/panic are relaxed here as in the other modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        // Unique per (pid, tag, counter) without needing `Date`/`rand` in tests.
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("filesec-safeio-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn commit_writes_content_atomically() {
        let dir = tmpdir("atomic");
        let dest = dir.join("out.txt");
        let mut w = SafeFileWriter::create(&dest).unwrap();
        w.write_all(b"hello world").unwrap();
        w.commit().unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello world");
        // No stray temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains("fstmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files leaked: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overwrites_existing_file_atomically() {
        let dir = tmpdir("overwrite");
        let dest = dir.join("out.txt");
        std::fs::write(&dest, b"old complete contents").unwrap();
        let mut w = SafeFileWriter::create(&dest).unwrap();
        w.write_all(b"new").unwrap();
        w.commit().unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drop_without_commit_leaves_no_partial_plaintext() {
        let dir = tmpdir("drop");
        let dest = dir.join("secret.txt");
        {
            let mut w = SafeFileWriter::create(&dest).unwrap();
            w.write_all(b"partial secret").unwrap();
            // dropped without commit
        }
        assert!(
            !dest.exists(),
            "destination must not exist after a failed write"
        );
        let leftovers: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
        assert!(leftovers.is_empty(), "temp file leaked: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn temp_and_final_are_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("perms");
        let dest = dir.join("out.txt");
        let mut w = SafeFileWriter::create(&dest).unwrap();
        w.write_all(b"x").unwrap();
        // While mid-write, the temp file must already be 0600.
        let tmp = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .find(|e| e.file_name().to_string_lossy().contains("fstmp"))
            .expect("temp file present");
        assert_eq!(tmp.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        w.commit().unwrap();
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_destination() {
        let dir = tmpdir("symlink-dest");
        let outside = dir.join("outside.txt");
        std::fs::write(&outside, b"do not touch").unwrap();
        let dest = dir.join("link.txt");
        std::os::unix::fs::symlink(&outside, &dest).unwrap();
        let err = SafeFileWriter::create(&dest);
        assert!(matches!(err, Err(Error::UnsafePath(_))));
        // The symlink target was never written through.
        assert_eq!(std::fs::read(&outside).unwrap(), b"do not touch");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_parent_component() {
        let dir = tmpdir("symlink-parent");
        let root = dir.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let elsewhere = dir.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        // root/sub is a symlink pointing outside the extraction root.
        std::os::unix::fs::symlink(&elsewhere, root.join("sub")).unwrap();
        let target_parent = root.join("sub").join("deeper");
        let err = create_dirs_no_symlink(&root, &target_parent);
        assert!(matches!(err, Err(Error::UnsafePath(_))));
        // Nothing was created under the symlink target.
        assert!(!elsewhere.join("deeper").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_dirs_is_idempotent_for_siblings() {
        let dir = tmpdir("dirs");
        let root = dir.join("root");
        std::fs::create_dir_all(&root).unwrap();
        create_dirs_no_symlink(&root, &root.join("a").join("b")).unwrap();
        // A sibling under the same parent must not fail on the existing dirs.
        create_dirs_no_symlink(&root, &root.join("a").join("c")).unwrap();
        assert!(root.join("a").join("b").is_dir());
        assert!(root.join("a").join("c").is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
