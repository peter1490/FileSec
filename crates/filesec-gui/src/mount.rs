//! Mount a vault as a virtual drive.
//!
//! This is the opt-in `mount` feature: it exposes an unlocked vault read-only
//! through a native filesystem driver so the user can browse and open files in
//! Finder / Explorer / a file manager, with content decrypted **on demand** (one
//! chunk at a time via [`filesec_core::format::VaultReader::read_at`]) and never
//! written to disk in the clear.
//!
//! Backends are target-gated, all behind the single `mount` Cargo feature:
//! * **Linux & macOS** — FUSE via the `fuser` crate (works with macFUSE or, on
//!   modern macOS, the kext-less FUSE-T). Implemented below.
//! * **Windows** — Dokany via `dokan` (pending; see [`mount_readonly`]).
//!
//! Like `passkey.rs` / `autounlock.rs`, the public surface is always present:
//! [`SUPPORTED`] reflects whether this build has the feature, and the entry
//! points return a [`MountError`] when unavailable. The default build pulls no
//! mount dependency at all.
//!
//! # Security
//! The mount is **read-only** in this phase and owner-only: FUSE is given
//! `MountOption::RO` + `DefaultPermissions` and the default `SessionACL::Owner`
//! (no `allow_other`), so only the mounting user can read it. On-disk bytes stay
//! ciphertext; plaintext exists only transiently in per-read `Zeroizing` chunk
//! buffers inside `read_at`. Reads are authenticated per chunk (a tampered chunk
//! fails with `Error::Auth`); a ranged read cannot verify a file's whole-file
//! BLAKE3, matching the trust model of any other lazy open.

use std::path::{Path, PathBuf};

use filesec_core::format_v2::VaultReaderV2;

/// Whether this build was compiled with mount support (`--features mount`).
pub const SUPPORTED: bool = cfg!(feature = "mount");

/// An error mounting or unmounting a vault.
#[derive(Debug)]
pub struct MountError(String);

impl MountError {
    /// Wrap a human-readable message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl std::fmt::Display for MountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MountError {}

/// A live mount. Holding it keeps the filesystem mounted; dropping it (or
/// calling [`ActiveMount::unmount`]) unmounts and tears the backend down.
///
/// On Unix the FUSE background session is owned here, so an `ActiveMount` that is
/// simply dropped — e.g. when the session is locked or the app exits — still
/// unmounts cleanly. The mount point directory itself is managed by the caller.
pub struct ActiveMount {
    mount_point: PathBuf,
    // Held only for its `Drop`, which unmounts the filesystem — never read
    // directly, so silence dead_code. `unmount()` (or dropping the `ActiveMount`)
    // runs that `Drop`.
    #[cfg(all(feature = "mount", any(target_os = "linux", target_os = "macos")))]
    #[allow(dead_code)]
    session: fuser::BackgroundSession,
}

impl ActiveMount {
    /// The directory the vault is mounted at.
    pub fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    /// Unmount the vault and tear down the backend. Consumes the handle; on Unix
    /// the owned FUSE session is dropped here, which performs the unmount.
    pub fn unmount(self) -> Result<(), MountError> {
        // `self` is dropped at the end of this scope; on Unix that drops the
        // owned `BackgroundSession`, which unmounts. Nothing else to do.
        Ok(())
    }
}

/// Mount `reader`'s vault read-only at `mount_point` (which must already exist as
/// an empty directory). Returns a handle that keeps the mount alive.
///
/// `reader` is moved into the mount; clone the session's cheap `VaultReader`
/// before calling. Errors if the platform backend is unavailable or the mount
/// syscall fails (e.g. no FUSE driver installed).
#[cfg(all(feature = "mount", any(target_os = "linux", target_os = "macos")))]
pub fn mount_readonly(
    reader: VaultReaderV2,
    mount_point: &Path,
) -> Result<ActiveMount, MountError> {
    let session = fuse_backend::mount(reader, mount_point)
        .map_err(|e| MountError::new(format!("could not mount the vault: {e}")))?;
    Ok(ActiveMount {
        mount_point: mount_point.to_path_buf(),
        session,
    })
}

/// Windows mounting (Dokany) is not yet implemented; see the module docs.
#[cfg(all(feature = "mount", target_os = "windows"))]
pub fn mount_readonly(
    _reader: VaultReaderV2,
    _mount_point: &Path,
) -> Result<ActiveMount, MountError> {
    Err(MountError::new(
        "mounting a vault on Windows is not yet implemented (the Dokany backend is pending)",
    ))
}

/// Stub when the `mount` feature is disabled.
#[cfg(not(feature = "mount"))]
pub fn mount_readonly(
    _reader: VaultReaderV2,
    _mount_point: &Path,
) -> Result<ActiveMount, MountError> {
    Err(MountError::new(
        "this build has no mount support (rebuild with --features mount)",
    ))
}

// ---------------------------------------------------------------------------
// Backend-agnostic node model: a stable inode tree over a VaultReader's
// manifest. Both the FUSE backend (below) and the future Dokany backend consume
// it, so the path/tree/read logic lives in one place, free of any driver types.
// ---------------------------------------------------------------------------
#[cfg(all(feature = "mount", any(target_os = "linux", target_os = "macos")))]
mod model {
    use std::collections::{BTreeSet, HashMap};
    use std::ffi::{OsStr, OsString};

    use filesec_core::format_v2::VaultReaderV2;
    use filesec_core::manifest::EntryKind;

    /// The root directory always has inode 1 (FUSE convention).
    pub(crate) const ROOT_INO: u64 = 1;

    /// A neutral error from a filesystem op, mapped to an `Errno` by the backend.
    pub(crate) enum FsError {
        NotFound,
        IsDir,
        Io,
    }

    /// One node in the mounted tree.
    pub(crate) struct Node {
        pub path: String,
        pub name: OsString,
        pub kind: EntryKind,
        pub size: u64,
        pub mtime: Option<i64>,
        pub mode: Option<u32>,
        pub parent: u64,
    }

    /// The whole tree plus the reader that decrypts file content on demand.
    pub(crate) struct VaultNodes {
        reader: VaultReaderV2,
        nodes: HashMap<u64, Node>,
        children: HashMap<u64, Vec<u64>>,
    }

    /// `(parent_path, final_component)` for a normalized non-root path.
    fn split_parent(path: &str) -> (&str, &str) {
        match path.rfind('/') {
            Some(i) => (&path[..i], &path[i + 1..]),
            None => ("", path),
        }
    }

    impl VaultNodes {
        /// Build the inode tree from the reader's manifest. Synthesizes any
        /// ancestor directory that is implied by a path but not an explicit
        /// entry, so the tree is always well-formed.
        pub(crate) fn build(reader: VaultReaderV2) -> Self {
            let mut nodes: HashMap<u64, Node> = HashMap::new();
            let mut children: HashMap<u64, Vec<u64>> = HashMap::new();
            let mut by_path: HashMap<String, u64> = HashMap::new();

            nodes.insert(
                ROOT_INO,
                Node {
                    path: String::new(),
                    name: OsString::new(),
                    kind: EntryKind::Dir,
                    size: 0,
                    mtime: Some(reader.created_at()),
                    mode: None,
                    parent: ROOT_INO,
                },
            );
            by_path.insert(String::new(), ROOT_INO);
            let mut next_ino: u64 = 2;

            // Every directory path: each strict ancestor of every entry, plus
            // explicit Dir entries. A BTreeSet iterates parents before children
            // (a prefix string sorts before any extension of it).
            let mut dir_paths: BTreeSet<String> = BTreeSet::new();
            for e in reader.entries() {
                let mut acc = String::new();
                for comp in e.path.split('/').filter(|c| !c.is_empty()) {
                    if !acc.is_empty() {
                        acc.push('/');
                    }
                    acc.push_str(comp);
                    if acc != e.path || e.kind == EntryKind::Dir {
                        dir_paths.insert(acc.clone());
                    }
                }
            }
            for dpath in &dir_paths {
                if by_path.contains_key(dpath) {
                    continue;
                }
                let (parent_path, name) = split_parent(dpath);
                let parent_ino = *by_path.get(parent_path).unwrap_or(&ROOT_INO);
                let ino = next_ino;
                next_ino += 1;
                nodes.insert(
                    ino,
                    Node {
                        path: dpath.clone(),
                        name: OsString::from(name),
                        kind: EntryKind::Dir,
                        size: 0,
                        mtime: None,
                        mode: None,
                        parent: parent_ino,
                    },
                );
                children.entry(parent_ino).or_default().push(ino);
                by_path.insert(dpath.clone(), ino);
            }

            for e in reader.entries() {
                if e.kind != EntryKind::File {
                    continue;
                }
                let (parent_path, name) = split_parent(&e.path);
                let parent_ino = *by_path.get(parent_path).unwrap_or(&ROOT_INO);
                let ino = next_ino;
                next_ino += 1;
                nodes.insert(
                    ino,
                    Node {
                        path: e.path.clone(),
                        name: OsString::from(name),
                        kind: EntryKind::File,
                        size: e.size,
                        mtime: e.mtime,
                        mode: e.mode,
                        parent: parent_ino,
                    },
                );
                children.entry(parent_ino).or_default().push(ino);
                by_path.insert(e.path.clone(), ino);
            }

            Self {
                reader,
                nodes,
                children,
            }
        }

        pub(crate) fn node(&self, ino: u64) -> Option<&Node> {
            self.nodes.get(&ino)
        }

        /// Resolve `name` within directory `parent` to a child inode.
        pub(crate) fn lookup(&self, parent: u64, name: &OsStr) -> Option<u64> {
            let kids = self.children.get(&parent)?;
            kids.iter().copied().find(|c| {
                self.nodes
                    .get(c)
                    .is_some_and(|n| n.name.as_os_str() == name)
            })
        }

        /// Children of a directory as `(ino, kind, name)`; `None` if `ino` is not
        /// a directory. An empty directory yields an empty list.
        pub(crate) fn readdir(&self, ino: u64) -> Option<Vec<(u64, EntryKind, OsString)>> {
            let n = self.nodes.get(&ino)?;
            if n.kind != EntryKind::Dir {
                return None;
            }
            Some(
                self.children
                    .get(&ino)
                    .map(|kids| {
                        kids.iter()
                            .filter_map(|c| self.nodes.get(c).map(|n| (*c, n.kind, n.name.clone())))
                            .collect()
                    })
                    .unwrap_or_default(),
            )
        }

        /// Decrypt up to `size` bytes of file `ino` starting at `offset`.
        pub(crate) fn read(&self, ino: u64, offset: u64, size: usize) -> Result<Vec<u8>, FsError> {
            let node = self.nodes.get(&ino).ok_or(FsError::NotFound)?;
            if node.kind != EntryKind::File {
                return Err(FsError::IsDir);
            }
            let mut buf = vec![0u8; size];
            let n = self
                .reader
                .read_at(&node.path, offset, &mut buf)
                .map_err(|_| FsError::Io)?;
            buf.truncate(n);
            Ok(buf)
        }
    }
}

// ---------------------------------------------------------------------------
// FUSE backend (Linux + macOS).
// ---------------------------------------------------------------------------
#[cfg(all(feature = "mount", any(target_os = "linux", target_os = "macos")))]
mod fuse_backend {
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    use fuser::{
        BackgroundSession, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, Generation,
        INodeNo, LockOwner, MountOption, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory,
        ReplyEntry, Request, SessionACL,
    };

    use filesec_core::format_v2::VaultReaderV2;
    use filesec_core::manifest::EntryKind;

    use super::model::{FsError, VaultNodes, ROOT_INO};

    /// Attribute/entry cache lifetime handed to the kernel. The vault is
    /// read-only, so a modest TTL is safe and cuts getattr traffic.
    const TTL: Duration = Duration::from_secs(1);

    struct FuseFs {
        nodes: VaultNodes,
    }

    fn sys_time(mtime: Option<i64>) -> SystemTime {
        match mtime {
            Some(s) if s >= 0 => SystemTime::UNIX_EPOCH + Duration::from_secs(s as u64),
            _ => SystemTime::UNIX_EPOCH,
        }
    }

    fn map_err(e: FsError) -> Errno {
        match e {
            FsError::NotFound => Errno::ENOENT,
            FsError::IsDir => Errno::EISDIR,
            FsError::Io => Errno::EIO,
        }
    }

    impl FuseFs {
        /// Build a `FileAttr` for `ino`, owned by the requesting uid/gid so the
        /// owner-only mount is actually accessible to the mounting user.
        fn attr(&self, ino: u64, uid: u32, gid: u32) -> Option<FileAttr> {
            let n = self.nodes.node(ino)?;
            let t = sys_time(n.mtime);
            let (kind, perm, nlink) = match n.kind {
                EntryKind::Dir => (
                    FileType::Directory,
                    n.mode.map_or(0o755, |m| (m & 0o7777) as u16),
                    2,
                ),
                EntryKind::File => (
                    FileType::RegularFile,
                    n.mode.map_or(0o644, |m| (m & 0o7777) as u16),
                    1,
                ),
            };
            Some(FileAttr {
                ino: INodeNo(ino),
                size: n.size,
                blocks: n.size.div_ceil(512),
                atime: t,
                mtime: t,
                ctime: t,
                crtime: t,
                kind,
                perm,
                nlink,
                uid,
                gid,
                rdev: 0,
                blksize: 4096,
                flags: 0,
            })
        }
    }

    impl Filesystem for FuseFs {
        fn lookup(
            &self,
            req: &Request,
            parent: INodeNo,
            name: &std::ffi::OsStr,
            reply: ReplyEntry,
        ) {
            match self.nodes.lookup(parent.0, name) {
                Some(ino) => match self.attr(ino, req.uid(), req.gid()) {
                    Some(attr) => reply.entry(&TTL, &attr, Generation(0)),
                    None => reply.error(Errno::ENOENT),
                },
                None => reply.error(Errno::ENOENT),
            }
        }

        fn getattr(&self, req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
            match self.attr(ino.0, req.uid(), req.gid()) {
                Some(attr) => reply.attr(&TTL, &attr),
                None => reply.error(Errno::ENOENT),
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn read(
            &self,
            _req: &Request,
            ino: INodeNo,
            _fh: FileHandle,
            offset: u64,
            size: u32,
            _flags: OpenFlags,
            _lock_owner: Option<LockOwner>,
            reply: ReplyData,
        ) {
            match self.nodes.read(ino.0, offset, size as usize) {
                Ok(bytes) => reply.data(&bytes),
                Err(e) => reply.error(map_err(e)),
            }
        }

        fn readdir(
            &self,
            _req: &Request,
            ino: INodeNo,
            _fh: FileHandle,
            offset: u64,
            mut reply: ReplyDirectory,
        ) {
            let kids = match self.nodes.readdir(ino.0) {
                Some(k) => k,
                None => {
                    reply.error(Errno::ENOTDIR);
                    return;
                }
            };
            // "." and ".." first, then the directory's children. `offset` is the
            // resume cookie: the index of the next entry to emit.
            let mut listing: Vec<(u64, FileType, std::ffi::OsString)> =
                Vec::with_capacity(2 + kids.len());
            let parent = self.nodes.node(ino.0).map_or(ROOT_INO, |n| n.parent);
            listing.push((ino.0, FileType::Directory, std::ffi::OsString::from(".")));
            listing.push((parent, FileType::Directory, std::ffi::OsString::from("..")));
            for (cino, kind, name) in kids {
                let ft = match kind {
                    EntryKind::Dir => FileType::Directory,
                    EntryKind::File => FileType::RegularFile,
                };
                listing.push((cino, ft, name));
            }
            for (i, (cino, kind, name)) in listing.into_iter().enumerate().skip(offset as usize) {
                // `add` returns true when the reply buffer is full.
                if reply.add(INodeNo(cino), (i as u64) + 1, kind, &name) {
                    break;
                }
            }
            reply.ok();
        }
    }

    /// Mount `reader` read-only at `mount_point` and return the background
    /// session. Owner-only (`SessionACL::Owner`, no `allow_other`) and read-only.
    // `Config` is `#[non_exhaustive]`, so it can only be built via `default()` +
    // field assignment — the functional-record-update the lint suggests is not
    // permitted for a foreign non-exhaustive struct.
    #[allow(clippy::field_reassign_with_default)]
    pub(crate) fn mount(
        reader: VaultReaderV2,
        mount_point: &Path,
    ) -> std::io::Result<BackgroundSession> {
        let fs = FuseFs {
            nodes: VaultNodes::build(reader),
        };
        let mut cfg = Config::default();
        cfg.mount_options = vec![
            MountOption::RO,
            MountOption::FSName("filesec".to_string()),
            MountOption::DefaultPermissions,
        ];
        cfg.acl = SessionACL::Owner;
        fuser::spawn_mount2(fs, mount_point, &cfg)
    }
}
