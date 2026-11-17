//! Pure, UI-independent helpers for the app: the file-browser model, trash
//! encoding, passphrase policy, formatting, launchers, and build details.
//!
//! Nothing here touches GPUI, so it is unit-tested directly (see the
//! `browse_tests` module at the bottom).

use std::collections::{HashMap, HashSet};
use std::time::UNIX_EPOCH;

use filesec_core::contacts::{ContactBook, Trust};
use filesec_core::format_v2::{is_trashed, VaultReaderV2, TRASH_DIR};
use filesec_core::manifest::EntryKind;
use filesec_core::util::hex;
#[cfg(feature = "pqc")]
use filesec_core::SuiteId;

use gpui_kit::Hsla;

use crate::repaint::Repaint;
use crate::store::StoreResult;
use crate::theme;
use crate::wipe::WipeHandle;

use filesec_core::format;

use super::{
    ExportForm, SortMode, COMMON_WEAK_PASSPHRASES, MIN_PASSPHRASE_CHARS, MIN_PASSPHRASE_SCORE,
    PASSPHRASE_STRENGTH_MESSAGE,
};

/// The cargo features this binary was compiled with, in manifest order.
///
/// Uses `cfg!` (an expression, so every branch is always type-checked) rather
/// than `#[cfg]` attributes, so all feature permutations compile the same code.
pub(super) fn compiled_features() -> Vec<&'static str> {
    let mut v = Vec::new();
    if cfg!(feature = "pqc") {
        v.push("pqc");
    }
    if cfg!(feature = "net") {
        v.push("net");
    }
    if cfg!(feature = "keyring") {
        v.push("keyring");
    }
    if cfg!(feature = "passkey") {
        v.push("passkey");
    }
    v
}

/// Which of the two shipped builds this is.
///
/// Both compile the post-quantum suites in and both default new identities to
/// classical; the functional difference is networking. See docs/RELEASE.md.
pub(super) fn build_variant() -> &'static str {
    if cfg!(feature = "net") {
        "Networking build — offline exchange plus direct peer-to-peer transfer"
    } else {
        "Standard build — offline container exchange"
    }
}

/// One-line build summary, for pasting into a bug report.
pub(super) fn build_info_line() -> String {
    let features = compiled_features();
    let features = if features.is_empty() {
        "none".to_string()
    } else {
        features.join(",")
    };
    format!(
        "FileSec {} ({}) target={} features={}",
        env!("CARGO_PKG_VERSION"),
        if cfg!(feature = "net") {
            "networking"
        } else {
            "standard"
        },
        env!("FILESEC_TARGET"),
        features,
    )
}

/// Open `dir` in the OS file manager.
///
/// Deliberately not [`start_view`]: that opens a *decrypted temp* and hands the
/// path to the shredder's close-watcher. Here there is nothing to wipe, so no
/// watcher thread and no blocking launcher. Returns `false` if the launcher
/// could not be spawned.
pub(super) fn reveal_in_file_manager(dir: &std::path::Path) -> bool {
    #[cfg(target_os = "macos")]
    let mut cmd = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut cmd = std::process::Command::new("explorer");
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = std::process::Command::new("xdg-open");
    // Windows' explorer.exe returns a non-zero exit code even when it succeeds,
    // so only the spawn itself is checked.
    cmd.arg(dir).spawn().is_ok()
}

/// Short suite name for the export picker chips.
#[cfg(feature = "pqc")]
pub(super) fn suite_short(s: SuiteId) -> &'static str {
    match s {
        SuiteId::Classic => "Classic",
        SuiteId::Aes256Gcm => "AES-256-GCM",
        SuiteId::Hybrid => "Hybrid PQC",
        _ => "Other",
    }
}

/// Display names of the selected recipients that are unverified and were not
/// explicitly confirmed for this export.
pub(super) fn unconfirmed_unverified(form: &ExportForm, contacts: &ContactBook) -> Vec<String> {
    contacts
        .contacts
        .iter()
        .filter(|c| c.trust == Trust::Unverified)
        .filter(|c| {
            let fpr = hex(&c.fingerprint());
            form.selected.contains(&fpr) && !form.confirmed_unverified.contains(&fpr)
        })
        .map(|c| c.identity.display_name())
        .collect()
}

/// How the user clicked a row's *body* (its trailing buttons / context menu emit
/// actions directly). The browser resolves this against the full row order + the
/// selection anchor, so shift / ⌘ / Ctrl behave like a real file explorer.
#[derive(Clone, Copy, Debug)]
pub(super) enum RowClick {
    /// A single primary click, with shift / command (Ctrl on Win/Linux, ⌘ on mac).
    Single { shift: bool, toggle: bool },
    /// A double primary click: open — enter a folder, view a file.
    Double,
}

/// The pure core of a single (non-double) click: update `selected` + `anchor` per
/// the explorer modifier rules — plain = select only; ⌘/Ctrl = toggle; Shift =
/// range from the anchor; Shift+⌘/Ctrl = add the range. Unit-tested below.
pub(super) fn resolve_single_click(
    selected: &mut HashSet<String>,
    anchor: &mut Option<String>,
    rows: &[Row],
    idx: usize,
    shift: bool,
    toggle: bool,
) {
    let path = rows[idx].path.clone();
    if shift {
        // Range from the anchor (or this row, if the anchor is gone). The anchor
        // stays put so the range can be re-adjusted by another shift-click.
        let anchor_idx = anchor
            .as_ref()
            .and_then(|a| rows.iter().position(|r| &r.path == a))
            .unwrap_or(idx);
        let (lo, hi) = (anchor_idx.min(idx), anchor_idx.max(idx));
        if !toggle {
            selected.clear();
        }
        for r in &rows[lo..=hi] {
            selected.insert(r.path.clone());
        }
    } else if toggle {
        if !selected.remove(&path) {
            selected.insert(path.clone());
        }
        *anchor = Some(path);
    } else {
        selected.clear();
        selected.insert(path.clone());
        *anchor = Some(path);
    }
}

/// Format a Unix timestamp (seconds) as a UTC `YYYY-MM-DD` date. Self-contained
/// (no chrono dependency) via Howard Hinnant's civil-from-days algorithm.
pub(super) fn fmt_date(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

pub(super) fn decode_fpr(hex_str: &str) -> Option<[u8; 32]> {
    if hex_str.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = hex_str.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out[i / 2] = (hi * 16 + lo) as u8;
        i += 2;
    }
    Some(out)
}

pub(super) fn file_mtime(path: &std::path::Path) -> Option<i64> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}

pub(super) fn passphrase_policy_error(passphrase: &str) -> Option<String> {
    let chars: Vec<char> = passphrase.chars().collect();
    if chars.len() < MIN_PASSPHRASE_CHARS {
        return Some(format!(
            "Passphrase must be at least {MIN_PASSPHRASE_CHARS} characters."
        ));
    }
    let lowered = passphrase.to_lowercase();
    if COMMON_WEAK_PASSPHRASES.contains(&lowered.as_str()) {
        return Some(PASSPHRASE_STRENGTH_MESSAGE.into());
    }
    let unique = chars.iter().copied().collect::<HashSet<_>>().len();
    if unique < 6 || has_long_repeated_run(&chars) {
        return Some(PASSPHRASE_STRENGTH_MESSAGE.into());
    }
    if passphrase_strength_score(passphrase, &chars, unique) < MIN_PASSPHRASE_SCORE {
        return Some(PASSPHRASE_STRENGTH_MESSAGE.into());
    }
    None
}

pub(super) fn has_long_repeated_run(chars: &[char]) -> bool {
    let mut last = None;
    let mut run = 0usize;
    for &ch in chars {
        if Some(ch) == last {
            run += 1;
        } else {
            last = Some(ch);
            run = 1;
        }
        if run >= 5 {
            return true;
        }
    }
    false
}

pub(super) fn passphrase_strength_score(passphrase: &str, chars: &[char], unique: usize) -> u32 {
    let len = chars.len();
    let mut score = 0u32;
    if len >= MIN_PASSPHRASE_CHARS {
        score += 2;
    }
    if len >= 16 {
        score += 1;
    }
    if len >= 20 {
        score += 1;
    }
    if len >= 28 {
        score += 1;
    }

    let has_lower = chars.iter().any(|c| c.is_ascii_lowercase());
    let has_upper = chars.iter().any(|c| c.is_ascii_uppercase());
    let has_digit = chars.iter().any(|c| c.is_ascii_digit());
    let has_space = chars.iter().any(|c| c.is_whitespace());
    let has_symbol = chars
        .iter()
        .any(|c| !c.is_alphanumeric() && !c.is_whitespace());
    score += [has_lower, has_upper, has_digit, has_space, has_symbol]
        .into_iter()
        .filter(|has| *has)
        .count() as u32;

    let word_count = passphrase
        .split_whitespace()
        .filter(|word| word.chars().count() >= 3)
        .count();
    if word_count >= 4 && len >= 20 {
        score += 2;
    }
    if unique >= 8 {
        score += 1;
    }
    score
}

pub(super) fn read_bounded_file(
    path: &std::path::Path,
    max_len: u64,
    label: &'static str,
) -> Result<Vec<u8>, String> {
    filesec_core::safe_io::read_bounded_file(path, max_len).map_err(|e| format!("{label}: {e}"))
}

pub(super) fn read_bounded_text_file(
    path: &std::path::Path,
    max_len: u64,
    label: &'static str,
) -> Result<String, String> {
    let bytes = read_bounded_file(path, max_len, label)?;
    String::from_utf8(bytes).map_err(|_| format!("{label} is not valid UTF-8."))
}

/// Pick a vault path for `base` that does not collide with any path in
/// `existing`, appending " (n)" before the extension if needed.
pub(super) fn unique_name_in(existing: &HashSet<String>, base: &str) -> String {
    if !existing.contains(base) {
        return base.to_string();
    }
    let (stem, ext) = match base.rsplit_once('.') {
        Some((s, e)) => (s.to_string(), format!(".{e}")),
        None => (base.to_string(), String::new()),
    };
    for i in 1..10_000 {
        let candidate = format!("{stem} ({i}){ext}");
        if !existing.contains(&candidate) {
            return candidate;
        }
    }
    base.to_string()
}

/// Plan the entries to add for a set of OS source paths placed under `into` (the
/// current folder; "" = vault root). A file becomes `into/leaf` (de-duplicated
/// against existing paths); a folder is walked and each member added under
/// `into/folder/rel`, skipping path collisions. Unreadable files are counted in
/// the returned `failed`. Reads metadata only — contents are streamed later by the
/// append worker. Shared by "Add files…", "Add folder…", and drag-and-drop.
pub(super) fn plan_additions(
    reader: &VaultReaderV2,
    into: &str,
    sources: &[std::path::PathBuf],
) -> (Vec<format::AddedFile>, Vec<String>, usize) {
    let mut existing: HashSet<String> = reader.entries().iter().map(|e| e.path.clone()).collect();
    let mut added: Vec<format::AddedFile> = Vec::new();
    let mut dirs: Vec<String> = Vec::new();
    let mut failed = 0usize;
    let under = |name: &str| {
        if into.is_empty() {
            name.to_string()
        } else {
            format!("{into}/{name}")
        }
    };
    for src in sources {
        let meta = match std::fs::metadata(src) {
            Ok(m) => m,
            Err(_) => {
                failed += 1;
                continue;
            }
        };
        if meta.is_dir() {
            let root = src
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "folder".into());
            for entry in walkdir::WalkDir::new(src).into_iter().flatten() {
                let rel = match entry.path().strip_prefix(src) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if rel.as_os_str().is_empty() {
                    continue;
                }
                let vault_path = under(&format!("{root}/{}", rel.to_string_lossy()));
                if existing.contains(&vault_path) {
                    continue; // skip collisions, as the in-memory path did
                }
                if entry.file_type().is_dir() {
                    existing.insert(vault_path.clone());
                    dirs.push(vault_path);
                } else if entry.file_type().is_file() && std::fs::File::open(entry.path()).is_ok() {
                    existing.insert(vault_path.clone());
                    added.push(format::AddedFile {
                        vault_path,
                        source: entry.path().to_path_buf(),
                        mtime: file_mtime(entry.path()),
                        mode: None,
                    });
                }
            }
        } else if std::fs::File::open(src).is_err() {
            failed += 1;
        } else {
            let base = src
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "file".into());
            let name = unique_name_in(&existing, &under(&base));
            existing.insert(name.clone());
            added.push(format::AddedFile {
                vault_path: name,
                source: src.clone(),
                mtime: file_mtime(src),
                mode: None,
            });
        }
    }
    (added, dirs, failed)
}

pub(super) fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "filesec".to_string()
    } else {
        cleaned
    }
}

/// `CREATE_NO_WINDOW` (winbase.h). The `cmd /C start …` launcher we use to open
/// files in their default app would otherwise flash an empty console window over
/// the GUI every time. This flag suppresses that console without affecting the
/// app `start` ultimately launches (it gets its own window).
#[cfg(target_os = "windows")]
pub(super) const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Best-effort: open `path` in the OS default application, detached (we do not
/// wait for it to close). Uses platform launchers via `std::process::Command`
/// to avoid pulling an extra dependency.
pub(super) fn open_in_default_app(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(path).spawn()?;
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        // The empty "" is the window title arg so a path with spaces isn't
        // swallowed as the title. `CREATE_NO_WINDOW` keeps `cmd` from popping up
        // a console window alongside the launched app.
        std::process::Command::new("cmd")
            .args(["/C", "start", ""])
            .arg(path)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open").arg(path).spawn()?;
    }
    Ok(())
}

/// Result of launching a read-only view. Which variants are constructed depends
/// on the target OS (e.g. `LaunchedNoWatch` only on Linux), so all are allowed
/// to be "unused" on any single platform.
#[allow(dead_code)]
pub(super) enum ViewLaunch {
    /// Launched, and a detached thread is waiting to wipe the temp on close.
    WatchingForClose,
    /// Launched, but this platform's launcher can't report when the app closes;
    /// the temp is wiped when the user leaves the vault instead.
    LaunchedNoWatch,
    /// The launcher could not be started at all.
    Failed,
}

/// Open `path` read-only in the OS default app for *viewing*. On platforms whose
/// launcher blocks until the app closes (macOS `open -W`, Windows `start /wait`),
/// spawn a detached thread that waits on that process and securely wipes the temp
/// the moment it returns. On platforms without a blocking launcher (Linux
/// `xdg-open`), there is no close signal, so cleanup falls to the leave-the-vault
/// backstop.
///
/// Caveat: a blocking launcher reports when the *application* exits, not when a
/// single document window closes — if the app was already running, the wipe waits
/// until that whole app quits. The leave-the-vault backstop covers that gap.
///
/// The watcher hands the temp to `wiper` rather than shredding it itself, so a
/// wipe that is still running is visible to the shutdown gate.
pub(super) fn start_view(
    path: &std::path::Path,
    wiper: &WipeHandle,
    repaint: &Repaint,
) -> ViewLaunch {
    let p = path.to_path_buf();
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let (wiper, repaint) = (wiper.clone(), repaint.clone());
    #[cfg(target_os = "macos")]
    {
        match std::process::Command::new("open").arg("-W").arg(&p).spawn() {
            Ok(mut child) => {
                std::thread::spawn(move || {
                    let _ = child.wait();
                    wiper.enqueue(&repaint, p);
                });
                ViewLaunch::WatchingForClose
            }
            Err(_) => ViewLaunch::Failed,
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        match std::process::Command::new("cmd")
            .args(["/C", "start", "/wait", ""])
            .arg(&p)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
        {
            Ok(mut child) => {
                std::thread::spawn(move || {
                    let _ = child.wait();
                    wiper.enqueue(&repaint, p);
                });
                ViewLaunch::WatchingForClose
            }
            Err(_) => ViewLaunch::Failed,
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // No blocking launcher here, so nothing to watch: the temp is wiped when
        // the user leaves the vault or quits.
        let _ = (wiper, repaint);
        match std::process::Command::new("xdg-open").arg(&p).spawn() {
            Ok(_) => ViewLaunch::LaunchedNoWatch,
            Err(_) => ViewLaunch::Failed,
        }
    }
}

pub(super) fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

// ---------------------------------------------------------------------------
// File-browser model: folder navigation, filtering, and sorting. These are pure
// functions over the vault's metadata (path / kind / plaintext size) — no
// decryption happens here — so they are unit-tested directly below.
// ---------------------------------------------------------------------------

/// A flattened snapshot of a reader's entries, taken once per frame so the UI can
/// mutate session state without holding the reader borrow.
pub(super) fn snapshot_entries(reader: &VaultReaderV2) -> Vec<(String, EntryKind, u64)> {
    reader
        .entries()
        .iter()
        .map(|e| (e.path.clone(), e.kind, e.size))
        .collect()
}

/// A short random hex tag that makes each trash token unique, so two deletions
/// of the same path (even in the same second) never collide.
pub(super) fn trash_tag() -> StoreResult<String> {
    let bytes = filesec_core::secret::random_array::<4>().map_err(|e| e.to_string())?;
    Ok(hex(&bytes))
}

/// The parent directory of a normalized vault path ("" for a top-level entry).
pub(super) fn parent_dir(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((parent, _)) => parent,
        None => "",
    }
}

/// The final path segment (the display name) of a vault path.
/// A vault path or name as the UI shows it: invisible and bidirectional
/// formatting characters are made visible (`⟨U+202E⟩`), so a name cannot render
/// as something it is not (FS-16). Entries created now cannot contain them; this
/// covers names an older version stored.
pub(super) fn shown(name: &str) -> String {
    filesec_core::vault::visible_path(name).into_owned()
}

pub(super) fn leaf_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Clamp `dir` to the nearest existing ancestor directory (or the root, ""), so a
/// folder removed/renamed out from under the browser never strands the view.
pub(super) fn clamp_dir(dirs: &HashSet<String>, dir: &str) -> String {
    let exists = |d: &str| d.is_empty() || dirs.contains(d);
    let mut cur = dir.to_string();
    while !cur.is_empty() && !exists(&cur) {
        cur = parent_dir(&cur).to_string();
    }
    cur
}

/// Identifies one committed revision of one vault: its id plus the epoch and
/// hash of its rollback-protected state (and the entry count as a guard).
pub(super) type ModelKey = (String, u64, [u8; 32], usize);

/// The file browser's view of one vault revision (O-02). Built once when the
/// vault's committed state changes — a mutation, or opening another vault —
/// and shared (`Arc`) by every frame until then, instead of cloning, indexing,
/// and scanning the whole manifest on every repaint.
pub(super) struct BrowserModel {
    pub(super) key: ModelKey,
    pub(super) entries: Vec<(String, EntryKind, u64)>,
    /// Every directory path, for O(1) "does this folder still exist".
    pub(super) dirs: HashSet<String>,
    /// Every non-trashed path, for pruning a stale selection in O(selected).
    pub(super) live: HashSet<String>,
    pub(super) has_live: bool,
    pub(super) trash: Vec<TrashItem>,
}

impl BrowserModel {
    pub(super) fn key_of(id: &str, reader: &VaultReaderV2) -> ModelKey {
        let (epoch, hash) = reader.state_metadata().map_or((0, [0u8; 32]), |state| {
            (state.epoch, state.current_state_hash)
        });
        (id.to_string(), epoch, hash, reader.entries().len())
    }

    pub(super) fn build(key: ModelKey, reader: &VaultReaderV2) -> Self {
        let entries = snapshot_entries(reader);
        let dirs = entries
            .iter()
            .filter(|(_, kind, _)| *kind == EntryKind::Dir)
            .map(|(path, _, _)| path.clone())
            .collect();
        let live: HashSet<String> = entries
            .iter()
            .filter(|(path, _, _)| !is_trashed(path))
            .map(|(path, _, _)| path.clone())
            .collect();
        let trash = trashed_items(&entries);
        Self {
            key,
            has_live: !live.is_empty(),
            entries,
            dirs,
            live,
            trash,
        }
    }
}

/// Everything the visible rows depend on.
#[derive(PartialEq)]
pub(super) struct RowsKey {
    pub(super) model: ModelKey,
    pub(super) dir: String,
    pub(super) search: String,
    pub(super) sort: SortMode,
}

/// A single browser row: a file or folder to display.
#[derive(Clone, Debug)]
pub(super) struct Row {
    pub(super) path: String,
    pub(super) kind: EntryKind,
    pub(super) size: u64,
    /// For a folder, the number of entries directly inside it (0 for files).
    pub(super) children: usize,
}

/// Build the ordered rows to show: either the direct children of `dir`, or — when
/// `search` is non-empty — every entry in the vault whose name matches, anywhere.
/// Directories always sort before files; `sort` orders within each group.
pub(super) fn visible_rows(
    entries: &[(String, EntryKind, u64)],
    dir: &str,
    search: &str,
    sort: SortMode,
) -> Vec<Row> {
    // Count all immediate children once, rather than rescanning the entire
    // vault for each folder rendered (quadratic for folder-heavy vaults).
    let mut child_counts = std::collections::HashMap::<&str, usize>::new();
    for (path, _, _) in entries {
        *child_counts.entry(parent_dir(path)).or_default() += 1;
    }
    let q = search.trim().to_lowercase();
    let mut rows: Vec<Row> = entries
        .iter()
        .filter(|(p, _, _)| {
            // The trash is a hidden, local-only subtree — never list it here (in
            // the folder view or a global search). It has its own panel.
            if is_trashed(p) {
                return false;
            }
            if q.is_empty() {
                parent_dir(p) == dir
            } else {
                leaf_name(p).to_lowercase().contains(&q)
            }
        })
        .map(|(p, k, sz)| Row {
            path: p.clone(),
            kind: *k,
            size: *sz,
            children: if *k == EntryKind::Dir {
                child_counts.get(p.as_str()).copied().unwrap_or(0)
            } else {
                0
            },
        })
        .collect();
    sort_rows(&mut rows, sort);
    rows
}

/// Sort rows in place: directories first, then by the chosen key. Names compare
/// case-insensitively by leaf; size ties break by name for a stable order.
pub(super) fn sort_rows(rows: &mut [Row], sort: SortMode) {
    use std::cmp::Reverse;
    // Cache each case-folded name once per sort, instead of allocating two new
    // strings for every comparison. Stable ties preserve the manifest order.
    match sort {
        SortMode::NameAsc => rows
            .sort_by_cached_key(|r| (r.kind != EntryKind::Dir, leaf_name(&r.path).to_lowercase())),
        SortMode::NameDesc => rows.sort_by_cached_key(|r| {
            (
                r.kind != EntryKind::Dir,
                Reverse(leaf_name(&r.path).to_lowercase()),
            )
        }),
        SortMode::SizeDesc => rows.sort_by_cached_key(|r| {
            (
                r.kind != EntryKind::Dir,
                Reverse(r.size),
                leaf_name(&r.path).to_lowercase(),
            )
        }),
        SortMode::SizeAsc => rows.sort_by_cached_key(|r| {
            (
                r.kind != EntryKind::Dir,
                r.size,
                leaf_name(&r.path).to_lowercase(),
            )
        }),
    }
}

/// A one-line summary of a browser view: "2 folders · 5 files · 4.2 MB", or
/// "N matches" while searching. Sizes count files only.
pub(super) fn view_summary(rows: &[Row], searching: bool) -> String {
    if searching {
        let n = rows.len();
        return format!("{n} match{}", if n == 1 { "" } else { "es" });
    }
    let dirs = rows.iter().filter(|r| r.kind == EntryKind::Dir).count();
    let files = rows.iter().filter(|r| r.kind == EntryKind::File).count();
    let bytes: u64 = rows
        .iter()
        .filter(|r| r.kind == EntryKind::File)
        .map(|r| r.size)
        .sum();
    let mut parts = Vec::new();
    if dirs > 0 {
        parts.push(format!("{dirs} folder{}", if dirs == 1 { "" } else { "s" }));
    }
    parts.push(format!("{files} file{}", if files == 1 { "" } else { "s" }));
    if files > 0 {
        parts.push(human_size(bytes));
    }
    parts.join(" · ")
}

/// Breadcrumb segments for `dir`, each `(label, navigation target)`. Always starts
/// with `("Home", "")`; e.g. "a/b" → [Home→"", a→"a", b→"a/b"].
pub(super) fn breadcrumb_segments(dir: &str) -> Vec<(String, String)> {
    let mut out = vec![("Home".to_string(), String::new())];
    let mut acc = String::new();
    for seg in dir.split('/').filter(|s| !s.is_empty()) {
        if acc.is_empty() {
            acc = seg.to_string();
        } else {
            acc = format!("{acc}/{seg}");
        }
        out.push((shown(seg), acc.clone()));
    }
    out
}

/// Broad file categories, used only to tint the file icon for quick scanning.
#[derive(PartialEq, Debug)]
pub(super) enum FileCat {
    Image,
    Media,
    Archive,
    Code,
    Other,
}

/// Classify a filename by extension into a coarse [`FileCat`].
pub(super) fn file_category(name: &str) -> FileCat {
    let ext = match name.rsplit_once('.') {
        Some((_, e)) => e.to_lowercase(),
        None => return FileCat::Other,
    };
    match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "svg" | "heic" | "tif" | "tiff"
        | "ico" => FileCat::Image,
        "mp3" | "wav" | "flac" | "aac" | "ogg" | "m4a" | "mp4" | "mov" | "mkv" | "avi" | "webm"
        | "wmv" | "m4v" => FileCat::Media,
        "zip" | "tar" | "gz" | "tgz" | "bz2" | "7z" | "rar" | "xz" | "zst" => FileCat::Archive,
        "rs" | "py" | "js" | "ts" | "tsx" | "jsx" | "c" | "h" | "cpp" | "hpp" | "java" | "go"
        | "rb" | "php" | "html" | "css" | "json" | "toml" | "yaml" | "yml" | "sh" => FileCat::Code,
        _ => FileCat::Other,
    }
}

/// The icon tint for a file, by category — subtle, palette-only differentiation.
pub(super) fn file_tint(name: &str, c: theme::Colors) -> Hsla {
    match file_category(name) {
        FileCat::Image => c.ok,
        FileCat::Media => c.accent_hi,
        FileCat::Archive => c.warn,
        FileCat::Code => c.accent,
        FileCat::Other => c.text_muted,
    }
}

/// The icon for a file, by category (plain documents get the text glyph).
pub(super) fn file_glyph(name: &str) -> theme::icon::Glyph {
    use theme::icon;
    match file_category(name) {
        FileCat::Image => icon::FILE_IMAGE,
        FileCat::Media => icon::FILE_MEDIA,
        FileCat::Archive => icon::FILE_ARCHIVE,
        FileCat::Code => icon::FILE_CODE,
        FileCat::Other => {
            let ext = name.rsplit_once('.').map(|(_, e)| e.to_lowercase());
            match ext.as_deref() {
                Some("txt" | "md" | "rtf" | "pdf" | "doc" | "docx" | "odt" | "csv" | "log") => {
                    icon::FILE_TEXT
                }
                _ => icon::FILE,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Trash model: soft delete. A "deleted" entry is *moved* (a manifest-only,
// O(1) rename — no blob is rewritten or decrypted) into the hidden `.trash/`
// subtree, where it stays fully encrypted and restorable until the user empties
// the trash. The single path segment under `.trash/` packs the deletion time, a
// random tag, and the percent-encoded original path, so restore knows exactly
// where the entry came from. These are pure functions, unit-tested below.
// ---------------------------------------------------------------------------

/// One soft-deleted entry, shown in the trash view.
pub(super) struct TrashItem {
    /// Its current (hidden) path under `.trash/`.
    pub(super) trashed_path: String,
    /// Where "Restore" will try to put it back (its original vault path).
    pub(super) orig_path: String,
    /// Unix seconds it was moved to the trash.
    pub(super) deleted_at: i64,
    pub(super) kind: EntryKind,
    /// A file's own size, or the total size of a folder's contents.
    pub(super) size: u64,
    /// For a folder, how many files it holds (0 for a file).
    pub(super) files: usize,
}

/// Percent-encode the only two characters that can't appear raw in a single
/// trash path segment: `%` (the escape itself) and `/` (a separator). Spaces,
/// dots, and unicode pass through untouched.
pub(super) fn pct_encode_seg(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '/' => out.push_str("%2F"),
            _ => out.push(ch),
        }
    }
    out
}

/// Reverse [`pct_encode_seg`]: decode `%XX` hex escapes left-to-right. We only
/// ever emit `%25` / `%2F`, but a general decoder keeps the round-trip robust.
pub(super) fn pct_decode_seg(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The hidden path a soft-deleted entry is moved to: `.trash/<at>-<rand>-<enc>`,
/// where `<at>` is the deletion time, `<rand>` a short tag (so two deletions of
/// the same path never collide), and `<enc>` the percent-encoded original path.
pub(super) fn trash_dest(deleted_at: i64, rand_hex: &str, orig: &str) -> String {
    format!(
        "{TRASH_DIR}/{deleted_at}-{rand_hex}-{}",
        pct_encode_seg(orig)
    )
}

/// Parse a top-level trash entry path (a direct child of `.trash`) back into its
/// `(deletion time, original path)`. Returns `None` for a malformed token, so a
/// hand-mangled manifest degrades gracefully instead of showing garbage.
pub(super) fn parse_trash_token(trashed_path: &str) -> Option<(i64, String)> {
    let token = trashed_path.strip_prefix(".trash/")?;
    // Exactly three parts: <deleted_at>-<rand>-<encoded original path>. The
    // original path may itself contain '-', so only the first two are split off.
    let mut parts = token.splitn(3, '-');
    let deleted_at: i64 = parts.next()?.parse().ok()?;
    let _rand = parts.next()?;
    let encoded = parts.next()?;
    Some((deleted_at, pct_decode_seg(encoded)))
}

/// (file count, total size) of everything inside each trashed folder, keyed by
/// the folder's top-level trash path, in **one pass** over the entries.
///
/// The previous per-folder rescan was O(n × t) for n entries and t trashed
/// folders and ran every frame — 0.6 s for 40,000 entries (O-01).
pub(super) fn trashed_subtree_totals(
    entries: &[(String, EntryKind, u64)],
) -> HashMap<&str, (usize, u64)> {
    let mut totals: HashMap<&str, (usize, u64)> = HashMap::new();
    for (path, kind, size) in entries {
        if *kind != EntryKind::File {
            continue;
        }
        let Some(rest) = path.strip_prefix(".trash/") else {
            continue;
        };
        // Only files *below* a top-level trash entry count toward it.
        let Some((top, _)) = rest.split_once('/') else {
            continue;
        };
        let top_path = &path[..".trash/".len() + top.len()];
        let slot = totals.entry(top_path).or_default();
        slot.0 += 1;
        slot.1 += size;
    }
    totals
}

/// The soft-deleted entries (the direct children of `.trash`), most-recent
/// first. Malformed tokens are skipped rather than shown wrong. Linear in the
/// number of entries (plus sorting the trash items themselves).
pub(super) fn trashed_items(entries: &[(String, EntryKind, u64)]) -> Vec<TrashItem> {
    let totals = trashed_subtree_totals(entries);
    let mut items: Vec<TrashItem> = entries
        .iter()
        .filter(|(p, _, _)| parent_dir(p) == TRASH_DIR)
        .filter_map(|(p, kind, size)| {
            let (deleted_at, orig_path) = parse_trash_token(p)?;
            let (files, total) = if *kind == EntryKind::Dir {
                totals.get(p.as_str()).copied().unwrap_or((0, 0))
            } else {
                (0, *size)
            };
            Some(TrashItem {
                trashed_path: p.clone(),
                orig_path,
                deleted_at,
                kind: *kind,
                size: total,
                files,
            })
        })
        .collect();
    items.sort_by(|a, b| {
        b.deleted_at
            .cmp(&a.deleted_at)
            .then_with(|| a.orig_path.cmp(&b.orig_path))
    });
    items
}

/// (live file count, live total size) — i.e. excluding the trash — so a vault's
/// card shrinks the moment a file is trashed.
pub(super) fn live_counts(entries: &[(String, EntryKind, u64)]) -> (u64, u64) {
    entries
        .iter()
        .filter(|(p, k, _)| *k == EntryKind::File && !is_trashed(p))
        .fold((0, 0), |(n, sz), (_, _, s)| (n + 1, sz + s))
}

/// Split a leaf into `(stem, extension-with-dot)`. A leading dot belongs to the
/// stem (`.bashrc` has no extension), matching common file-manager behaviour.
pub(super) fn split_ext(leaf: &str) -> (&str, &str) {
    match leaf.rfind('.') {
        Some(i) if i > 0 => (&leaf[..i], &leaf[i..]),
        _ => (leaf, ""),
    }
}

/// A free vault path to restore `desired` to: it is used as-is when nothing
/// lives there, else " (restored)", " (restored 2)", … is inserted before the
/// extension until the name is unused. `taken` is the set of existing paths.
pub(super) fn dedup_path(taken: &HashSet<String>, desired: &str) -> String {
    if !taken.contains(desired) {
        return desired.to_string();
    }
    let parent = parent_dir(desired);
    let (stem, ext) = split_ext(leaf_name(desired));
    let make = |suffix: &str| -> String {
        let leaf = format!("{stem}{suffix}{ext}");
        if parent.is_empty() {
            leaf
        } else {
            format!("{parent}/{leaf}")
        }
    };
    let mut candidate = make(" (restored)");
    let mut n = 2;
    while taken.contains(&candidate) {
        candidate = make(&format!(" (restored {n})"));
        n += 1;
    }
    candidate
}

/// Keep only the top-level entries of a selection: drop any path that is a
/// descendant of another selected path. (A global search can select both a folder
/// and a file inside it; trashing/moving both would act on the inner one twice.)
pub(super) fn prune_nested(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .filter(|p| {
            !paths
                .iter()
                .any(|other| other.as_str() != p.as_str() && p.starts_with(&format!("{other}/")))
        })
        .cloned()
        .collect()
}

/// The destination folders offered by the Move dialog: the vault root plus every
/// live folder, minus the folders being moved (and their subtrees, so a folder
/// can't be moved into itself). Each is `(path, display leaf, depth)` for an
/// indented tree-style picker.
pub(super) fn move_folder_options(
    entries: &[(String, EntryKind, u64)],
    moving: &[String],
) -> Vec<(String, String, usize)> {
    let blocked = |f: &str| {
        moving
            .iter()
            .any(|m| f == m || f.starts_with(&format!("{m}/")))
    };
    let mut dirs: Vec<&str> = entries
        .iter()
        .filter(|(p, k, _)| *k == EntryKind::Dir && !is_trashed(p) && !blocked(p))
        .map(|(p, _, _)| p.as_str())
        .collect();
    dirs.sort();
    let mut opts = vec![(String::new(), "Top level".to_string(), 0usize)];
    for d in dirs {
        let depth = d.split('/').count();
        opts.push((d.to_string(), shown(leaf_name(d)), depth));
    }
    opts
}

/// The secondary line of a trash card: what it is, where it came from, and when
/// it was deleted.
pub(super) fn trash_item_detail(item: &TrashItem) -> String {
    let loc = parent_dir(&item.orig_path);
    let where_from = if loc.is_empty() {
        "the top level".to_string()
    } else {
        format!("“{loc}”")
    };
    let what = if item.kind == EntryKind::Dir {
        format!(
            "folder · {} file{} · {}",
            item.files,
            if item.files == 1 { "" } else { "s" },
            human_size(item.size)
        )
    } else {
        human_size(item.size)
    };
    format!(
        "{what} · was in {where_from} · deleted {}",
        fmt_date(item.deleted_at)
    )
}

#[cfg(test)]
mod browse_tests {
    //! Unit tests for the pure file-browser model (navigation, filtering,
    //! sorting, classification) over synthetic vault metadata — no UI, no disk.
    use super::*;

    fn ent(path: &str, kind: EntryKind, size: u64) -> (String, EntryKind, u64) {
        (path.to_string(), kind, size)
    }

    /// docs/ {a.txt(10), b.txt(30), sub/ {deep.bin(5)}}, photo.png(100), notes.md(20)
    fn sample() -> Vec<(String, EntryKind, u64)> {
        vec![
            ent("docs", EntryKind::Dir, 0),
            ent("docs/a.txt", EntryKind::File, 10),
            ent("docs/b.txt", EntryKind::File, 30),
            ent("docs/sub", EntryKind::Dir, 0),
            ent("docs/sub/deep.bin", EntryKind::File, 5),
            ent("photo.png", EntryKind::File, 100),
            ent("notes.md", EntryKind::File, 20),
        ]
    }

    fn names(rows: &[Row]) -> Vec<&str> {
        rows.iter().map(|r| leaf_name(&r.path)).collect()
    }

    #[test]
    fn parent_and_leaf() {
        assert_eq!(parent_dir("a/b/c"), "a/b");
        assert_eq!(parent_dir("top"), "");
        assert_eq!(leaf_name("a/b/c.txt"), "c.txt");
        // FS-16: formatting characters are shown, not interpreted.
        assert_eq!(
            shown("report\u{202e}gpj.exe"),
            "report\u{27e8}U+202E\u{27e9}gpj.exe"
        );
        assert_eq!(shown("plain.txt"), "plain.txt");
        assert_eq!(leaf_name("solo"), "solo");
    }

    #[test]
    fn breadcrumbs() {
        assert_eq!(
            breadcrumb_segments(""),
            vec![("Home".to_string(), String::new())]
        );
        assert_eq!(
            breadcrumb_segments("a/b"),
            vec![
                ("Home".to_string(), String::new()),
                ("a".to_string(), "a".to_string()),
                ("b".to_string(), "a/b".to_string()),
            ]
        );
    }

    #[test]
    fn clamp_keeps_existing_drops_missing() {
        let e: HashSet<String> = sample()
            .into_iter()
            .filter(|(_, k, _)| *k == EntryKind::Dir)
            .map(|(p, _, _)| p)
            .collect();
        assert_eq!(clamp_dir(&e, "docs/sub"), "docs/sub");
        assert_eq!(clamp_dir(&e, ""), "");
        // A folder that no longer exists clamps to the nearest real ancestor.
        assert_eq!(clamp_dir(&e, "docs/gone"), "docs");
        assert_eq!(clamp_dir(&e, "gone/deeper"), "");
    }

    #[test]
    fn root_view_lists_direct_children_dirs_first() {
        let e = sample();
        let rows = visible_rows(&e, "", "", SortMode::NameAsc);
        // The folder before files; files alphabetical.
        assert_eq!(names(&rows), vec!["docs", "notes.md", "photo.png"]);
        // The folder reports its direct child count (a.txt, b.txt, sub = 3).
        let docs = rows.iter().find(|r| r.path == "docs").unwrap();
        assert_eq!(docs.children, 3);
    }

    #[test]
    fn subfolder_view_is_scoped() {
        let e = sample();
        let rows = visible_rows(&e, "docs", "", SortMode::NameAsc);
        assert_eq!(names(&rows), vec!["sub", "a.txt", "b.txt"]);
    }

    #[test]
    fn size_sort_orders_files_within_group() {
        let e = sample();
        let rows = visible_rows(&e, "docs", "", SortMode::SizeDesc);
        // Dir first, then files largest→smallest: b.txt(30), a.txt(10).
        assert_eq!(names(&rows), vec!["sub", "b.txt", "a.txt"]);
    }

    #[test]
    fn search_is_global_and_case_insensitive() {
        let e = sample();
        let rows = visible_rows(&e, "docs", "TXT", SortMode::NameAsc);
        let mut found = names(&rows);
        found.sort();
        assert_eq!(found, vec!["a.txt", "b.txt"]);
        // Matches reach into other folders, not just the current one.
        let deep = visible_rows(&e, "", "deep", SortMode::NameAsc);
        assert_eq!(deep.len(), 1);
        assert_eq!(deep[0].path, "docs/sub/deep.bin");
    }

    #[test]
    fn categories() {
        assert_eq!(file_category("a.PNG"), FileCat::Image);
        assert_eq!(file_category("song.mp3"), FileCat::Media);
        assert_eq!(file_category("bundle.tar.gz"), FileCat::Archive);
        assert_eq!(file_category("main.rs"), FileCat::Code);
        assert_eq!(file_category("README"), FileCat::Other);
        assert_eq!(file_category("data.unknownext"), FileCat::Other);
    }

    #[test]
    fn pct_roundtrips_paths_with_separators_and_escapes() {
        for orig in [
            "report.pdf",
            "docs/2026/q1 plan.xlsx",
            "weird %name%/a-b-c.txt",
            "100%/done/já.md",
        ] {
            assert_eq!(pct_decode_seg(&pct_encode_seg(orig)), orig);
        }
        // The encoding never leaves a raw separator in the segment.
        assert!(!pct_encode_seg("a/b/c").contains('/'));
    }

    #[test]
    fn trash_dest_and_token_roundtrip() {
        // A nested original path survives the move-to-trash → parse round-trip,
        // even though the destination is a single (slash-free) segment.
        let orig = "docs/2026/q1 plan-final.xlsx";
        let dest = trash_dest(1_717_000_000, "ab12cd34", orig);
        assert_eq!(parent_dir(&dest), TRASH_DIR);
        assert!(!leaf_name(&dest).contains('/'));
        let (at, decoded) = parse_trash_token(&dest).expect("parse");
        assert_eq!(at, 1_717_000_000);
        assert_eq!(decoded, orig);
        // A garbage token is rejected, not shown wrong.
        assert!(parse_trash_token(".trash/not-a-token").is_none());
        assert!(parse_trash_token("docs/file.txt").is_none());
    }

    /// docs/{a.txt} live, plus two trashed items (a file and a folder subtree).
    fn sample_with_trash() -> Vec<(String, EntryKind, u64)> {
        vec![
            ent("docs", EntryKind::Dir, 0),
            ent("docs/a.txt", EntryKind::File, 10),
            ent(TRASH_DIR, EntryKind::Dir, 0),
            ent(".trash/100-aa-old.txt", EntryKind::File, 7),
            ent(".trash/200-bb-photos", EntryKind::Dir, 0),
            ent(".trash/200-bb-photos/p1.jpg", EntryKind::File, 50),
            ent(".trash/200-bb-photos/p2.jpg", EntryKind::File, 30),
        ]
    }

    #[test]
    fn browser_hides_the_trash_subtree() {
        let e = sample_with_trash();
        // Neither the folder view nor a global search ever surfaces `.trash`.
        let root = visible_rows(&e, "", "", SortMode::NameAsc);
        assert_eq!(names(&root), vec!["docs"]);
        let search = visible_rows(&e, "", "p1", SortMode::NameAsc);
        assert!(search.is_empty(), "trashed files must not match search");
        // Live-only views of the vault.
        assert_eq!(live_counts(&e), (1, 10)); // docs/a.txt only
    }

    /// O-01: one-pass totals count every file at any depth under its own
    /// top-level trash entry, and nothing else.
    #[test]
    fn trashed_folder_totals_cover_nested_files_only() {
        let e = |p: &str, k: EntryKind, s: u64| (p.to_string(), k, s);
        let entries = vec![
            e(".trash", EntryKind::Dir, 0),
            e(".trash/20-aa-docs", EntryKind::Dir, 0),
            e(".trash/20-aa-docs/a.txt", EntryKind::File, 3),
            e(".trash/20-aa-docs/sub", EntryKind::Dir, 0),
            e(".trash/20-aa-docs/sub/b.txt", EntryKind::File, 4),
            e(".trash/10-bb-docs2", EntryKind::Dir, 0),
            e(".trash/10-bb-docs2-x/c.txt", EntryKind::File, 100),
            e(".trash/30-cc-loose.txt", EntryKind::File, 9),
            e("docs/live.txt", EntryKind::File, 50),
        ];
        let items = trashed_items(&entries);
        let by_path = |p: &str| items.iter().find(|i| i.trashed_path == p).unwrap();
        assert_eq!(
            (
                by_path(".trash/20-aa-docs").files,
                by_path(".trash/20-aa-docs").size
            ),
            (2, 7)
        );
        assert_eq!(
            (
                by_path(".trash/10-bb-docs2").files,
                by_path(".trash/10-bb-docs2").size
            ),
            (0, 0)
        );
        assert_eq!(by_path(".trash/30-cc-loose.txt").size, 9);
    }

    #[test]
    fn trashed_items_are_parsed_grouped_and_sorted() {
        let items = trashed_items(&sample_with_trash());
        assert_eq!(
            items.len(),
            2,
            "two top-level trashed items, not subtree files"
        );
        // Most-recent first (deleted_at 200 before 100).
        assert_eq!(items[0].orig_path, "photos");
        assert_eq!(items[0].kind, EntryKind::Dir);
        assert_eq!((items[0].files, items[0].size), (2, 80));
        assert_eq!(items[1].orig_path, "old.txt");
        assert_eq!(items[1].kind, EntryKind::File);
        assert_eq!(items[1].size, 7);
    }

    #[test]
    fn restore_dedups_against_a_live_collision() {
        let mut taken = HashSet::new();
        taken.insert("docs/a.txt".to_string());
        // Free path is returned unchanged.
        assert_eq!(dedup_path(&taken, "docs/b.txt"), "docs/b.txt");
        // A collision gets " (restored)" before the extension.
        assert_eq!(dedup_path(&taken, "docs/a.txt"), "docs/a (restored).txt");
        taken.insert("docs/a (restored).txt".to_string());
        assert_eq!(dedup_path(&taken, "docs/a.txt"), "docs/a (restored 2).txt");
        // A dotfile keeps its leading dot in the stem.
        taken.insert(".env".to_string());
        assert_eq!(dedup_path(&taken, ".env"), ".env (restored)");
    }

    #[test]
    fn move_options_offer_root_and_live_folders_minus_self() {
        let e = sample_with_trash();
        // Moving a file: every live folder is a valid target; trash is excluded.
        let opts = move_folder_options(&e, &["docs/a.txt".to_string()]);
        let paths: Vec<&str> = opts.iter().map(|(p, _, _)| p.as_str()).collect();
        assert_eq!(paths, vec!["", "docs"]);
        // Moving the "docs" folder: it (and any subtree) is not offered as a target.
        let opts = move_folder_options(&e, &["docs".to_string()]);
        let paths: Vec<&str> = opts.iter().map(|(p, _, _)| p.as_str()).collect();
        assert_eq!(paths, vec![""]);
    }

    #[test]
    fn summary_describes_the_view() {
        let rows = visible_rows(&sample(), "", "", SortMode::NameAsc);
        // root holds docs/ + notes.md + photo.png.
        assert!(view_summary(&rows, false).starts_with("1 folder · 2 files · "));
        assert_eq!(view_summary(&rows, true), "3 matches");
    }

    #[test]
    fn prune_nested_keeps_only_top_level() {
        let paths = vec![
            "docs".to_string(),
            "docs/a.txt".to_string(),
            "docs/sub/b.txt".to_string(),
            "photo.png".to_string(),
        ];
        let mut kept = prune_nested(&paths);
        kept.sort();
        // Only "docs" (its descendants are dropped) and the unrelated "photo.png".
        assert_eq!(kept, vec!["docs".to_string(), "photo.png".to_string()]);
    }

    /// The root view rows (folders first), used to exercise click selection.
    fn root_rows() -> Vec<Row> {
        // docs/ (dir), notes.md, photo.png  — see `sample()`.
        visible_rows(&sample(), "", "", SortMode::NameAsc)
    }

    fn sel(set: &HashSet<String>) -> Vec<String> {
        let mut v: Vec<String> = set.iter().cloned().collect();
        v.sort();
        v
    }

    #[test]
    fn plain_click_selects_only_that_row_and_sets_anchor() {
        let rows = root_rows();
        let mut s = HashSet::new();
        let mut anchor = None;
        // Pre-existing selection is replaced by a plain click.
        s.insert("notes.md".to_string());
        resolve_single_click(&mut s, &mut anchor, &rows, 0, false, false);
        assert_eq!(sel(&s), vec!["docs".to_string()]);
        assert_eq!(anchor.as_deref(), Some("docs"));
    }

    #[test]
    fn ctrl_click_toggles_membership() {
        let rows = root_rows();
        let mut s = HashSet::new();
        let mut anchor = None;
        resolve_single_click(&mut s, &mut anchor, &rows, 0, false, true); // +docs
        resolve_single_click(&mut s, &mut anchor, &rows, 1, false, true); // +notes.md
        assert_eq!(sel(&s), vec!["docs".to_string(), "notes.md".to_string()]);
        resolve_single_click(&mut s, &mut anchor, &rows, 0, false, true); // -docs
        assert_eq!(sel(&s), vec!["notes.md".to_string()]);
    }

    #[test]
    fn shift_click_selects_the_range_from_the_anchor() {
        let rows = root_rows(); // [docs, notes.md, photo.png]
        let mut s = HashSet::new();
        let mut anchor = None;
        resolve_single_click(&mut s, &mut anchor, &rows, 0, false, false); // anchor=docs
        resolve_single_click(&mut s, &mut anchor, &rows, 2, true, false); // shift→0..=2
        assert_eq!(
            sel(&s),
            vec![
                "docs".to_string(),
                "notes.md".to_string(),
                "photo.png".to_string()
            ]
        );
        // Shift again to a closer row replaces the range (anchor unchanged).
        resolve_single_click(&mut s, &mut anchor, &rows, 1, true, false);
        assert_eq!(sel(&s), vec!["docs".to_string(), "notes.md".to_string()]);
    }

    #[test]
    fn shift_ctrl_click_adds_a_range_to_the_selection() {
        let rows = root_rows();
        let mut s = HashSet::new();
        let mut anchor = None;
        resolve_single_click(&mut s, &mut anchor, &rows, 2, false, true); // +photo.png, anchor=photo
        resolve_single_click(&mut s, &mut anchor, &rows, 0, true, true); // additive range 0..=2
        assert_eq!(
            sel(&s),
            vec![
                "docs".to_string(),
                "notes.md".to_string(),
                "photo.png".to_string()
            ]
        );
    }
}
