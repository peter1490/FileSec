//! The GPUI application: state machine, screens, and action handling.
//!
//! [`FileSecApp`] is the window's root view (a GPUI entity). Rendering is a
//! pure function of its state: every screen only *describes* elements and
//! wires their handlers to an [`Action`]; [`FileSecApp::dispatch`] applies it.
//!
//! All crypto and I/O (Argon2 unlock, vault encryption/decryption, export and
//! import) run on a **background worker thread** so the UI never blocks — even
//! for very large vaults. While a job is in flight the UI is covered by a
//! spinner; when the worker finishes it sends back a [`JobReport`], wakes the
//! UI through the [`Repaint`] pump, and the report is applied on the UI thread.
//!
//! Native file dialogs are GPUI's asynchronous prompts. A dialog is a two-step
//! action: the first step validates and opens the prompt (the UI stays
//! responsive but inert behind it), and the picked path comes back as a
//! continuation action (e.g. [`Action::ImportContainerFrom`]).

mod dispatch;
mod fields;
mod jobs;
mod model;
#[cfg(test)]
mod tests;
#[cfg(feature = "net")]
mod transfer;
mod views;

use std::cell::Cell;
use std::collections::HashSet;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use gpui_kit::{
    div, prelude::FluentBuilder, px, App, ClipboardItem, Context, ExternalPaths, FocusHandle,
    InteractiveElement, IntoElement, KeyBinding, KeyDownEvent, ParentElement, PathPromptOptions,
    Render, SharedString, Styled, Subscription, Window,
};
use zeroize::Zeroizing;

use filesec_core::contacts::{ContactBook, Trust};
use filesec_core::format_v2::VaultReaderV2;
use filesec_core::identity::{Identity, PublicIdentity};
use filesec_core::keystore::PasskeyInfo;
use filesec_core::util::hex;
use filesec_core::SuiteId;

use crate::autounlock;
use crate::prefs::ThemeChoice;
use crate::repaint::Repaint;
use crate::store::{Registry, Store, ANCHOR_RECOVERY_REQUIRED};
use crate::theme;
use crate::wipe::Wiper;

use fields::{FieldId, Fields};
use model::*;

pub(crate) const MIN_PASSPHRASE_CHARS: usize = 12;
pub(crate) const MIN_PASSPHRASE_SCORE: u32 = 7;
pub(crate) const PASSPHRASE_HINT: &str = "Strong passphrase";
pub(crate) const PASSPHRASE_STRENGTH_MESSAGE: &str =
    "Use a stronger passphrase: combine several words or mix letters, numbers, and symbols.";
/// Accurate description of what enrolling a security key does: it is an
/// **alternative** unlock method (either the passphrase or the key opens the
/// keystore), not a second factor layered on the passphrase. Kept as a constant
/// so the "alternative unlock, not two-factor" wording stays regression-tested
/// (F04). Also states the PIN/UV requirement introduced in F10.
pub(crate) const PASSKEY_ALT_UNLOCK_DESC: &str =
    "Unlock with a hardware security key (FIDO2) as an alternative to your passphrase — either \
     one opens your keystore. This is a second way in, not a second factor. Your passphrase \
     always keeps working, so a lost key is never a lockout. Enrolling and unlocking require \
     user verification (your key's PIN or biometric).";
pub(crate) const MAX_PUBLIC_IDENTITY_FILE_LEN: u64 = 256 * 1024;
pub(crate) const MAX_IDENTITY_BACKUP_FILE_LEN: u64 = 4 * 1024 * 1024;
pub(crate) const COMMON_WEAK_PASSPHRASES: &[&str] = &[
    "password",
    "password1",
    "password12",
    "password123",
    "password1234",
    "123456789012",
    "qwerty123456",
    "letmein12345",
    "admin1234567",
    "filesec12345",
];

/// How long a quit will wait for the shredder before giving up and closing.
/// Anything left behind is swept by `Store::clean_checkout_dir` on the next
/// unlock, so the cap trades a narrow exposure window for never hanging the app.
const EXIT_WIPE_GRACE: Duration = Duration::from_secs(5);

/// How long a success toast stays up. Errors stay until dismissed.
const TOAST_TTL: Duration = Duration::from_secs(6);

/// Keyboard-only commands (GPUI actions). Everything a click can do goes
/// through [`Action`] instead.
mod keys {
    gpui_kit::actions!(
        filesec,
        [
            /// ⌘/Ctrl-A in the file browser: select every item in this view.
            SelectAllFiles,
            /// Delete / ⌘⌫ in the file browser: move the selection to the Trash.
            TrashSelection,
            /// ⌘/Ctrl-F in the file browser: jump to the search field.
            FocusSearch,
            /// ⌘/Ctrl-Q: quit (held while plaintext temps are shredded).
            Quit,
        ]
    );
}
pub(crate) use keys::{FocusSearch, Quit, SelectAllFiles, TrashSelection};

/// The key context of the file browser, so its shortcuts apply only there (and
/// a focused text field, deeper in the context stack, still wins).
const BROWSER_CONTEXT: &str = "FileBrowser";

/// Register the app's key bindings. Called once from [`crate::init`].
pub fn init(cx: &mut App) {
    use crate::secret_input::primary;
    cx.bind_keys([
        KeyBinding::new(primary!("a"), SelectAllFiles, Some(BROWSER_CONTEXT)),
        KeyBinding::new("delete", TrashSelection, Some(BROWSER_CONTEXT)),
        KeyBinding::new(primary!("backspace"), TrashSelection, Some(BROWSER_CONTEXT)),
        KeyBinding::new(primary!("f"), FocusSearch, Some(BROWSER_CONTEXT)),
        KeyBinding::new(primary!("q"), Quit, None),
    ]);
    cx.set_menus([gpui_kit::Menu {
        name: "FileSec".into(),
        items: vec![gpui_kit::MenuItem::action("Quit FileSec", Quit)],
        disabled: false,
    }]);
}

/// The window's root view.
pub struct FileSecApp {
    store: Option<Arc<Store>>,
    state: State,
    toast: Option<Toast>,
    job: Option<Job>,
    /// One-shot flag: a secret is saved in the OS keychain for this data dir, so
    /// try to auto-unlock with it on first launch. Cleared after the attempt is
    /// fired, and never set after a manual lock (locking signals intent to stop).
    auto_unlock_pending: bool,
    /// Background shredder for plaintext temp files. Lives here rather than on
    /// [`Session`] because locking or closing a vault drops the session while its
    /// wipes are still running.
    wiper: Wiper,
    /// Set once the user asks to close the window and there are still temps to
    /// shred; see [`FileSecApp::request_close`].
    exit_wipe: Option<ExitWipe>,
    /// Every text field, as GPUI input entities (see [`fields`]).
    fields: Fields,
    /// Wakes this view from worker threads (job done, wipe done, net event).
    repaint: Repaint,
    /// A native file dialog is open; the UI stays inert until it answers.
    prompt_open: bool,
    /// Focus target for the file browser's keyboard shortcuts.
    browser_focus: FocusHandle,
    /// The "Cancel" of a destructive confirmation dialog, focused on open.
    dialog_focus: FocusHandle,
    /// The root view's own focus: the fallback whenever nothing more specific
    /// is focused, so window-level keys (Escape, ⌘Q) always reach the app.
    root_focus: FocusHandle,
    /// Last folder a file dialog was pointed at, to start the next one there.
    last_dir: Option<PathBuf>,
    /// Monotonic toast id, so an old toast's timer never dismisses a new one.
    toast_seq: u64,
    /// A press on empty titlebar space is waiting for the pointer to move to
    /// start a window drag (macOS unified titlebar; see
    /// `views::shell::window_drag_strip`).
    titlebar_drag: Rc<Cell<bool>>,
    _subscriptions: Vec<Subscription>,
}

/// A close request being held open while the wiper drains.
struct ExitWipe {
    /// After this instant we stop waiting and close anyway.
    deadline: Instant,
}

struct Toast {
    msg: String,
    error: bool,
    id: u64,
}

enum State {
    Fatal(String),
    /// The rollback-anchor backend could not be trusted as found; the only way
    /// forward is the explicit, passphrase-authenticated re-anchoring.
    AnchorRecovery(AnchorRecovery),
    FirstRun(FirstRun),
    Unlock(Unlock),
    Unlocked(Box<Session>),
}

/// The "re-establish rollback protection" screen (see
/// [`Store::recover_rollback_anchors`]). It never runs implicitly: the user must
/// read why, confirm that the data directory is the copy to keep, and
/// authenticate with the passphrase (in `fields.anchor_pass`).
#[derive(Default)]
struct AnchorRecovery {
    reason: String,
    confirmed: bool,
    error: Option<String>,
}

/// First run: create an identity (name + passphrase ×2 in [`Fields`]) or
/// restore one from a backup.
#[derive(Default)]
struct FirstRun {
    error: Option<String>,
    /// When set, the "restore from a backup" sub-flow is active (a backup file
    /// has been picked) and its card is shown instead of "create identity".
    restore: Option<RestoreForm>,
}

/// First-run "restore from a backup" sub-form: the picked `.fsecid` file. The
/// backup passphrase and the new local passphrase (×2) live in [`Fields`].
#[derive(Default)]
struct RestoreForm {
    path: PathBuf,
    error: Option<String>,
}

#[derive(Default)]
struct Unlock {
    /// Whether the on-disk keystore has any passkeys enrolled (decided once at
    /// startup / lock so the unlock screen can offer the security-key button).
    has_passkeys: bool,
    /// Whether a device unlock is saved in the OS keychain for this data dir.
    has_saved: bool,
    /// A valid pre-anchor keystore was found. The UI changes the normal unlock
    /// action into an explicit one-time recovery/upgrade confirmation.
    legacy_recovery: bool,
    error: Option<String>,
}

impl Unlock {
    /// Build the unlock screen state, noting whether the keystore has passkeys
    /// and whether a device unlock is saved in the OS keychain.
    fn for_store(store: &Store) -> Self {
        let recovery_pending = store.data_dir().join(".legacy-recovery-pending").exists();
        let (has_passkeys, legacy_recovery) = match store.load_keystore() {
            Ok(keystore) => (keystore.has_passkeys(), recovery_pending),
            Err(error) if error.contains("legacy state requires explicit recovery") => {
                (false, true)
            }
            Err(_) => (false, false),
        };
        Self {
            has_passkeys,
            has_saved: autounlock::is_saved(&store.data_dir().display().to_string()),
            legacy_recovery,
            error: None,
        }
    }
}

/// The "Add security key" dialog (label, passphrase and PIN live in [`Fields`]).
#[derive(Default)]
struct PasskeyEnrollForm {
    error: Option<String>,
}

/// The "Remember on this device" dialog.
#[derive(Default)]
struct AutoUnlockForm {
    error: Option<String>,
}

/// The "Export identity backup" dialog (backup passphrase ×2 in [`Fields`]).
#[derive(Default)]
struct ExportIdentityForm {
    error: Option<String>,
}

/// The "Upgrade to post-quantum" confirmation dialog.
#[cfg(feature = "pqc")]
#[derive(Default)]
struct MigrateForm {
    error: Option<String>,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum Nav {
    Vaults,
    Contacts,
    Identity,
    #[cfg(feature = "net")]
    Transfer,
    /// Reached from the sidebar's Settings entry rather than a nav row, so it
    /// sits last and keeps the `cfg` attribute attached only to `Transfer`.
    Settings,
}

/// Sort order for the in-vault file browser. Directories always sort before
/// files regardless; this only orders within each group.
#[derive(PartialEq, Eq, Clone, Copy, Default, Debug)]
pub(crate) enum SortMode {
    #[default]
    NameAsc,
    NameDesc,
    SizeDesc,
    SizeAsc,
}

impl SortMode {
    const ALL: [SortMode; 4] = [
        SortMode::NameAsc,
        SortMode::NameDesc,
        SortMode::SizeDesc,
        SortMode::SizeAsc,
    ];

    fn label(self) -> &'static str {
        match self {
            SortMode::NameAsc => "Name (A–Z)",
            SortMode::NameDesc => "Name (Z–A)",
            SortMode::SizeDesc => "Size (large first)",
            SortMode::SizeAsc => "Size (small first)",
        }
    }
}

struct OpenVault {
    id: String,
    reader: VaultReaderV2,
}

/// An in-progress check-out: one file decrypted to a private temp file and
/// (best-effort) opened in the OS editor, awaiting check-in or discard. At most
/// one is active per session.
struct Checkout {
    /// Vault the file belongs to (matches the open vault's id).
    vault_id: String,
    /// The file's normalized path inside the vault.
    entry_path: String,
    /// Display leaf shown in the editing banner.
    leaf: String,
    /// The decrypted plaintext temp file on disk.
    temp_path: PathBuf,
    /// Plaintext BLAKE3 at check-out, to detect "no changes" on check-in.
    orig_blake3: [u8; 32],
    /// Advisory mode bits to preserve on the re-encrypted entry.
    mode: Option<u32>,
}

/// A read-only view in progress: one file decrypted to a disposable temp file
/// and opened in the OS app. A detached watcher thread securely wipes the temp
/// the moment the app that opened it closes, and any survivors are wiped when
/// the vault is left. Multiple views may be active.
struct ActiveView {
    /// Display leaf (for the "viewing" banner).
    leaf: String,
    /// The decrypted read-only temp file on disk.
    temp_path: PathBuf,
}

pub(crate) struct ExportForm {
    vault_id: String,
    selected: HashSet<String>,
    /// Fingerprints (hex) of unverified recipients the user explicitly chose to
    /// encrypt to *for this export only*. A warning alone is not consent, and
    /// this never changes the contact's trust (audit: unverified export).
    confirmed_unverified: HashSet<String>,
    include_self: bool,
    /// Algorithm suite to encrypt under (Classic by default; the post-quantum
    /// suites are offered only in a `pqc` build).
    suite: SuiteId,
}

struct ImportInfo {
    /// The verified sender's public identity (name field is empty — the
    /// trustworthy name comes from the contact book, below).
    sender: PublicIdentity,
    sender_fpr_hex: String,
    /// Display name from the contact book, if the sender is a known contact.
    sender_name: Option<String>,
    verified: bool,
    vault_name: String,
    file_count: usize,
}

/// A public key that has been parsed but not yet added to the contact book,
/// shown for confirmation so the user can eyeball exactly who they're about to
/// trust (and so self/duplicate/rename surprises surface *before* the save).
struct ContactPreview {
    pubid: PublicIdentity,
    status: PreviewStatus,
}

/// How a previewed key relates to what's already in the contact book.
enum PreviewStatus {
    /// Not currently a contact — adding it is a plain insert.
    New,
    /// Already a contact under the same display name.
    Existing { verified: bool },
    /// Already a contact, but the pasted key carries a different display name.
    Renamed { old: String, verified: bool },
    /// This is the user's own public key — adding yourself is pointless.
    SelfKey,
}

/// State backing the per-contact verification dialog: the user compares this
/// safety number with the contact out-of-band, optionally typing what they read
/// back (in `fields.verify_input`) so the app checks the match for them.
struct VerifyForm {
    fpr_hex: String,
    name: String,
    /// Canonical safety number, for display.
    safety_number: String,
    /// "I compared it myself and it matches" — an alternative to typing it in.
    manual_ok: bool,
}

struct DeleteVaultForm {
    vault_id: String,
}

/// The open "move to folder" dialog: the entries being moved and the
/// destination folder currently chosen ("" = the vault root).
struct MoveForm {
    paths: Vec<String>,
    dest: String,
}

/// The in-app quick text editor. The live buffer is the `fields.editor`
/// textarea; `original` is the loaded content, to flag unsaved changes. The
/// plaintext only ever lives in memory (never a temp file on disk).
struct TextEditor {
    /// Vault path being edited.
    path: String,
    /// Display name (with extension).
    leaf: String,
    /// Content as loaded, for the dirty check. Wiped on drop.
    original: Zeroizing<String>,
    /// Whether the buffer differs from `original` (recomputed on each edit).
    dirty: bool,
}

/// A file's decrypted text on its way from the worker into the editor. Wiped
/// as soon as it has been copied into the textarea.
struct LoadedText {
    path: String,
    leaf: String,
    text: Zeroizing<String>,
}

/// Unlocked session state. The identity is reference-counted so it can be
/// shared (read-only) with background worker threads.
struct Session {
    identity: Arc<Identity>,
    contacts: ContactBook,
    registry: Registry,
    nav: Nav,
    open: Option<OpenVault>,
    checkout: Option<Checkout>,
    views: Vec<ActiveView>,
    show_new_vault: bool,
    /// A vault is only deleted after this dialog's explicit confirmation.
    delete_vault: Option<DeleteVaultForm>,
    /// Folder currently being browsed inside the open vault ("" = vault root).
    current_dir: String,
    /// Whether the inline "new folder" composer is shown in the browser.
    show_new_folder: bool,
    /// Files multi-selected in the browser (full vault paths), for batch actions.
    selected: HashSet<String>,
    /// Sort order for the browser's file/folder list.
    sort: SortMode,
    /// Whether the trash view (soft-deleted entries) is shown instead of files.
    show_trash: bool,
    /// Whether the inline "empty the trash?" confirmation is armed (a guard on the
    /// one irreversible bulk action in the browser).
    confirm_empty_trash: bool,
    /// The entry currently being renamed inline (its vault path); `None` when
    /// no rename is in progress. The draft name is `fields.rename`.
    rename_target: Option<String>,
    /// The open "move to folder" dialog, if any.
    move_form: Option<MoveForm>,
    /// Anchor row (vault path) for shift-range selection, à la a file explorer.
    select_anchor: Option<String>,
    /// The inline "new text file" composer state.
    show_new_file: bool,
    /// The open in-app quick text editor, if any.
    text_editor: Option<TextEditor>,
    /// Whether the "Add a contact" card is expanded.
    show_add_contact: bool,
    /// A parsed key staged for confirmation before it joins the contact book.
    contact_preview: Option<ContactPreview>,
    /// The currently-open verification dialog, if any.
    verify: Option<VerifyForm>,
    export: Option<ExportForm>,
    last_import: Option<ImportInfo>,
    /// The open "upgrade to post-quantum" dialog, if any.
    #[cfg(feature = "pqc")]
    migrate: Option<MigrateForm>,
    /// Passkeys enrolled on the keystore (cached; refreshed after add/remove).
    passkeys: Vec<PasskeyInfo>,
    /// The open "add security key" dialog, if any.
    add_passkey: Option<PasskeyEnrollForm>,
    /// Whether this device's unlock is saved in the OS keychain (cached;
    /// refreshed after enable/disable).
    auto_unlock: bool,
    /// The open "remember on this device" dialog, if any.
    auto_unlock_form: Option<AutoUnlockForm>,
    /// The open "export identity backup" dialog, if any.
    export_identity: Option<ExportIdentityForm>,
    /// Whether the identity fingerprint disclosure is expanded.
    show_fingerprint: bool,
    /// Whether the open-source notices disclosure on Settings is expanded.
    show_notices: bool,
    data_dir: String,
    rollback_warning: Option<String>,
    /// Direct network-transfer state (the `net` feature).
    #[cfg(feature = "net")]
    transfer: transfer::TransferState,
    /// Everything the browser derives from the open vault's manifest, built
    /// once per committed revision rather than every frame (O-02).
    browser_model: Option<Arc<BrowserModel>>,
    /// The visible rows for the last (revision, folder, search, sort) shown.
    rows_cache: Option<(RowsKey, Arc<Vec<Row>>)>,
}

impl Session {
    fn new(
        identity: Arc<Identity>,
        contacts: ContactBook,
        registry: Registry,
        passkeys: Vec<PasskeyInfo>,
        auto_unlock: bool,
        data_dir: String,
        rollback_warning: Option<String>,
    ) -> Self {
        let show_add_contact = contacts.contacts.is_empty();
        Self {
            identity,
            contacts,
            registry,
            nav: Nav::Vaults,
            open: None,
            checkout: None,
            views: Vec::new(),
            show_new_vault: false,
            delete_vault: None,
            current_dir: String::new(),
            show_new_folder: false,
            selected: HashSet::new(),
            sort: SortMode::default(),
            show_trash: false,
            confirm_empty_trash: false,
            rename_target: None,
            move_form: None,
            select_anchor: None,
            show_new_file: false,
            text_editor: None,
            show_add_contact,
            contact_preview: None,
            verify: None,
            export: None,
            last_import: None,
            #[cfg(feature = "pqc")]
            migrate: None,
            passkeys,
            add_passkey: None,
            auto_unlock,
            auto_unlock_form: None,
            export_identity: None,
            show_fingerprint: false,
            show_notices: false,
            data_dir,
            rollback_warning,
            #[cfg(feature = "net")]
            transfer: transfer::TransferState::default(),
            browser_model: None,
            rows_cache: None,
        }
    }

    /// The browser model for the open vault, rebuilt only when the vault's
    /// committed state (or the vault itself) changed since the last render.
    fn browser_model(&mut self) -> Option<Arc<BrowserModel>> {
        let open = self.open.as_ref()?;
        let key = BrowserModel::key_of(&open.id, &open.reader);
        match &self.browser_model {
            Some(model) if model.key == key => Some(Arc::clone(model)),
            _ => {
                let model = Arc::new(BrowserModel::build(key, &open.reader));
                self.browser_model = Some(Arc::clone(&model));
                Some(model)
            }
        }
    }

    /// The visible rows for `dir`/`search`/`sort` over `model`, reusing the
    /// previous render's rows when none of those changed.
    fn visible_rows(&mut self, model: &BrowserModel, dir: &str, search: &str) -> Arc<Vec<Row>> {
        let key = RowsKey {
            model: model.key.clone(),
            dir: dir.to_string(),
            search: search.to_string(),
            sort: self.sort,
        };
        if let Some((cached, rows)) = &self.rows_cache {
            if *cached == key {
                return Arc::clone(rows);
            }
        }
        let rows = Arc::new(visible_rows(&model.entries, dir, search, self.sort));
        self.rows_cache = Some((key, Arc::clone(&rows)));
        rows
    }

    /// Reset the browser's transient view state. Called when a vault is opened
    /// or closed so navigation, selection, search, and the composers never leak
    /// from one vault (or browsing session) into the next. The text fields are
    /// emptied by [`FileSecApp::scrub_fields`] once their composers are hidden.
    fn reset_browse(&mut self) {
        self.current_dir.clear();
        self.show_new_folder = false;
        self.selected.clear();
        self.show_trash = false;
        self.confirm_empty_trash = false;
        self.rename_target = None;
        self.move_form = None;
        self.select_anchor = None;
        self.show_new_file = false;
        // Drop any open editor; its `original` is zeroized on drop and the
        // textarea is emptied by `scrub_fields`.
        self.text_editor = None;
    }

    /// Whether any modal dialog is open over the session.
    fn modal_open(&self) -> bool {
        let base = self.export.is_some()
            || self.last_import.is_some()
            || self.contact_preview.is_some()
            || self.verify.is_some()
            || self.add_passkey.is_some()
            || self.auto_unlock_form.is_some()
            || self.export_identity.is_some()
            || self.delete_vault.is_some()
            || self.move_form.is_some()
            || self.text_editor.is_some();
        #[cfg(feature = "pqc")]
        let base = base || self.migrate.is_some();
        #[cfg(feature = "net")]
        let base = base
            || self
                .transfer
                .active
                .as_ref()
                .is_some_and(|a| a.offer.is_some());
        base
    }
}

/// How the user clicked a row's body, plus what it was (resolved on dispatch
/// against the rows actually shown).
#[derive(Clone, Debug)]
pub(crate) struct RowClickAt {
    path: String,
    click: RowClick,
}

/// Deferred mutations, emitted by the UI and applied by
/// [`FileSecApp::dispatch`].
#[derive(Clone, Debug)]
enum Action {
    /// Run the explicit, passphrase-authenticated rollback-anchor recovery.
    RecoverAnchors,
    /// Tick / untick "this data directory is the copy I intend to keep".
    SetAnchorConfirmed(bool),
    CreateIdentity,
    Unlock,
    Lock,
    Nav(Nav),
    /// Switch the appearance and remember it for next launch.
    SetTheme(ThemeChoice),
    /// Copy the data-directory path shown on the Settings page.
    CopyDataDir,
    /// Open the data directory in the OS file manager.
    RevealDataDir,
    /// Copy a one-line build summary for bug reports.
    CopyBuildInfo,
    /// Copy arbitrary display text (an address or transfer code).
    #[cfg_attr(not(feature = "net"), allow(dead_code))]
    CopyText(String),
    ToggleNewVault(bool),
    CreateVault,
    OpenVault(String),
    CloseVault,
    RequestDeleteVault(String),
    CancelDeleteVault,
    ConfirmDeleteVault,
    /// Pick a `.fsec` container, then import it ([`Action::ImportContainerFrom`]).
    ImportContainer,
    ImportContainerFrom(PathBuf),
    AddFiles,
    AddFolder,
    /// Add OS files/folders (dropped onto the window, or picked) into the
    /// current folder.
    DropPaths(Vec<PathBuf>),
    NewFolder,
    /// Toggle the inline "new folder" composer in the browser.
    ToggleNewFolder(bool),
    /// Toggle the inline "new text file" composer in the browser.
    ToggleNewFile(bool),
    /// Create the composed text file and open it in the quick editor.
    NewFile,
    /// Open an existing text file in the in-app quick editor.
    QuickEdit(String),
    /// Save the quick editor's buffer back to the vault.
    SaveTextFile,
    /// Close the quick editor, discarding any unsaved changes.
    CloseTextEditor,
    /// Navigate the browser into a folder ("" = vault root).
    EnterDir(String),
    /// A click on a browser row's body (selection or open).
    RowClicked(RowClickAt),
    /// Soft-delete an entry: move it (and any subtree) into the trash.
    Trash(String),
    /// Pick a destination, then decrypt the entry there.
    SaveEntryAs(String),
    SaveEntryTo(String, PathBuf),
    ViewFile(String),
    CheckOut(String),
    CheckIn,
    Discard,
    ExtractAll,
    ExtractAllTo(PathBuf),
    /// Select every file or folder in the current view.
    SelectAllVisible,
    /// Clear the browser selection.
    ClearSelection,
    /// Soft-delete every selected file into the trash.
    TrashSelected,
    /// Decrypt every selected file to a chosen folder.
    ExtractSelected,
    ExtractSelectedTo(PathBuf),
    /// Change the browser's sort order.
    SetSort(SortMode),
    /// Empty one of the search boxes.
    ClearVaultSearch,
    ClearContactSearch,
    ClearFileSearch,
    /// Begin renaming an entry inline (carries its vault path).
    BeginRename(String),
    /// Commit / cancel the inline rename.
    ConfirmRename,
    CancelRename,
    /// Open the "move to folder" dialog for these entries.
    BeginMove(Vec<String>),
    /// Choose the destination folder in the open move dialog ("" = root).
    SetMoveDest(String),
    /// Commit / cancel the move.
    ConfirmMove,
    CancelMove,
    /// Show or hide the trash view.
    ShowTrash(bool),
    /// Restore a soft-deleted entry to its original location (by trashed path).
    RestoreTrashed(String),
    /// Permanently delete one trashed entry (by trashed path).
    PurgeTrashed(String),
    /// Arm / disarm the inline "empty the trash?" confirmation.
    PromptEmptyTrash(bool),
    /// Permanently delete everything in the trash.
    EmptyTrash,
    BeginExport(String),
    CancelExport,
    /// Validate the export, pick a destination, then export ([`Action::ExportTo`]).
    DoExport,
    ExportTo(PathBuf),
    ToggleRecipient(String),
    /// Explicitly allow (or withdraw) encrypting to one unverified recipient,
    /// by hex fingerprint, for the export dialog that is open.
    ConfirmUnverifiedRecipient(String, bool),
    ToggleIncludeSelf,
    /// Pick the algorithm suite to export under (pqc builds only).
    #[cfg(feature = "pqc")]
    SetExportSuite(SuiteId),
    /// Open / cancel / confirm the "upgrade to post-quantum" dialog (pqc only).
    #[cfg(feature = "pqc")]
    BeginMigrate,
    #[cfg(feature = "pqc")]
    CancelMigrate,
    #[cfg(feature = "pqc")]
    DoMigrate,
    /// Expand / collapse the "Add a contact" card.
    ToggleAddContact(bool),
    /// Parse the paste box / a picked file into a staged [`ContactPreview`].
    PreviewContactPaste,
    PreviewContactFile,
    PreviewContactFileFrom(PathBuf),
    /// Commit the staged preview into the contact book.
    ConfirmAddContact,
    CancelPreview,
    /// Open the verification dialog for a contact (by hex fingerprint).
    BeginVerify(String),
    /// Copy the safety number shown in the verification dialog.
    CopyVerifySafetyNumber,
    /// Tick / untick "I compared it myself".
    SetVerifyManual(bool),
    /// Finish verification — mark the contact verified and close the dialog.
    ConfirmVerify(String),
    CancelVerify,
    SetTrust(String, Trust),
    RemoveContact(String),
    /// Stage the just-imported container's (unknown) sender for adding.
    AddSenderToContacts,
    CopyPubKey,
    SavePubKey,
    SavePubKeyTo(PathBuf),
    /// Expand / collapse disclosures on the identity and settings pages.
    ToggleFingerprint,
    ToggleNotices,
    /// Open / cancel / confirm the "export identity backup" dialog.
    BeginExportIdentity,
    CancelExportIdentity,
    DoExportIdentity,
    ExportIdentityTo(PathBuf),
    /// First-run restore: pick a backup file, then cancel / confirm the restore.
    BeginRestore,
    RestoreFrom(PathBuf),
    CancelRestore,
    DoRestore,
    DismissImportInfo,
    /// Unlock by deriving a key from an enrolled security key (passkey).
    UnlockWithPasskey,
    /// Open / cancel the "add security key" dialog.
    BeginAddPasskey,
    CancelAddPasskey,
    /// Enroll a new security key from the open dialog.
    AddPasskey,
    /// Remove the enrolled passkey at this slot index.
    RemovePasskey(usize),
    /// Unlock using the device token saved in the OS keychain (this device).
    UnlockWithKeyring,
    /// Open / cancel the "remember on this device" dialog.
    BeginEnableAutoUnlock,
    CancelEnableAutoUnlock,
    /// Verify the entered passphrase and save a device token to the keychain.
    ConfirmEnableAutoUnlock,
    /// Forget the device unlock saved in the OS keychain for this device.
    DisableAutoUnlock,
    /// Dismiss the toast.
    DismissToast,
    /// Transfer form choices (the `net` feature).
    #[cfg(feature = "net")]
    SetRecvContact(String),
    #[cfg(feature = "net")]
    SetRecvInternet(bool),
    #[cfg(feature = "net")]
    SetSendContact(String),
    #[cfg(feature = "net")]
    SetSendVault(String),
    #[cfg(feature = "net")]
    SetSendAllowClassical(bool),
    /// Start listening to receive a transfer.
    #[cfg(feature = "net")]
    StartListen,
    /// Stop the active listener.
    #[cfg(feature = "net")]
    StopTransfer,
    /// Start sending the chosen vault to the chosen verified contact.
    #[cfg(feature = "net")]
    StartSend,
    /// Accept the pending incoming offer.
    #[cfg(feature = "net")]
    AcceptIncoming,
    /// Reject the pending incoming offer.
    #[cfg(feature = "net")]
    RejectIncoming,
    /// Cancel an in-progress transfer.
    #[cfg(feature = "net")]
    CancelTransfer,
}

// ---------------------------------------------------------------------------
// Background jobs
// ---------------------------------------------------------------------------

/// A running background job; the UI polls `rx` whenever it is woken.
struct Job {
    rx: mpsc::Receiver<JobReport>,
    label: String,
}

/// What a finished worker asks the UI thread to do.
struct JobReport {
    outcome: Outcome,
    /// Optional `(message, is_error)` toast.
    toast: Option<(String, bool)>,
}

impl JobReport {
    fn ok(outcome: Outcome, msg: impl Into<String>) -> Self {
        let msg = msg.into();
        let toast = if msg.is_empty() {
            None
        } else {
            Some((msg, false))
        };
        Self { outcome, toast }
    }

    fn err(msg: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Noop,
            toast: Some((msg.into(), true)),
        }
    }
}

/// Freshly-unlocked session material produced by a worker.
struct SessionInit {
    identity: Identity,
    contacts: ContactBook,
    registry: Registry,
    passkeys: Vec<PasskeyInfo>,
    /// Whether a device unlock is saved in the OS keychain for this data dir.
    auto_unlock: bool,
    data_dir: String,
    rollback_warning: Option<String>,
}

/// Result of importing a `.fsec` container (sender trust is resolved on the UI
/// thread against the live contact book).
struct ImportData {
    registry: Registry,
    /// The cryptographically-verified sender (name field empty).
    sender: PublicIdentity,
    vault_name: String,
    file_count: usize,
}

/// State mutations applied on the UI thread when a job completes.
enum Outcome {
    Noop,
    /// Stop the session: the store needs a restart to reach a consistent state
    /// (for example, to finish a committed identity migration).
    #[cfg_attr(not(feature = "pqc"), allow(dead_code))]
    Fatal(String),
    /// Rollback anchors were re-established; continue to the unlock screen.
    AnchorsRecovered(Box<Store>),
    AnchorRecoveryFailed(String),
    Unlocked(Box<SessionInit>),
    FirstRunFailed(String),
    UnlockFailed(String),
    Created {
        registry: Registry,
        id: String,
        reader: Box<VaultReaderV2>,
    },
    SetOpen {
        id: String,
        reader: Box<VaultReaderV2>,
    },
    /// Replace the open vault's reader after a successful mutate + re-encrypt.
    ReplaceOpen {
        id: String,
        reader: Box<VaultReaderV2>,
        registry: Registry,
    },
    /// Like [`Outcome::ReplaceOpen`], but also open the just-created file in the
    /// in-app quick editor (with an empty buffer).
    CreatedTextFile {
        id: String,
        reader: Box<VaultReaderV2>,
        registry: Registry,
        path: String,
        leaf: String,
    },
    /// Open an existing file's decrypted text in the quick editor.
    OpenTextEditor(Box<LoadedText>),
    /// A quick-editor save landed: swap the reader and close the editor.
    SavedTextFile {
        id: String,
        reader: Box<VaultReaderV2>,
        registry: Registry,
    },
    Deleted {
        registry: Registry,
        closed_id: String,
    },
    /// Install a fresh check-out into the session after decrypting to temp.
    StartCheckout(Box<Checkout>),
    /// End the active check-out (clearing it). When `replace` is `Some`, also
    /// swap in the re-encrypted vault's reader + registry — i.e. a check-in that
    /// actually changed the file. `None` is a discard or a no-change check-in.
    EndCheckout {
        replace: Option<(String, Box<VaultReaderV2>, Registry)>,
    },
    /// Register a read-only view after decrypting it to a temp file.
    StartView(Box<ActiveView>),
    Imported(Box<ImportData>),
    Contacts(ContactBook),
    /// Replace the cached passkey list after an enroll/remove and close the
    /// "add security key" dialog.
    PasskeysUpdated(Vec<PasskeyInfo>),
    /// Update the cached "remember on this device" state after enable/disable and
    /// close the dialog.
    AutoUnlockChanged(bool),
    /// Close the "export identity backup" dialog after a successful export.
    ExportIdentityDone,
}

impl FileSecApp {
    /// Construct the app, discovering storage and the initial screen.
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let (store, state, auto_unlock_pending) = match Store::discover() {
            Ok(store) => {
                let unlock = store.keystore_exists().then(|| Unlock::for_store(&store));
                // Offer to auto-unlock from the keychain only at first launch (a
                // saved secret exists and this build can read it). A manual lock
                // later never re-arms this.
                let auto_unlock_pending = unlock
                    .as_ref()
                    .is_some_and(|u| u.has_saved && autounlock::SUPPORTED);
                let state = match unlock {
                    Some(u) => State::Unlock(u),
                    None => State::FirstRun(FirstRun::default()),
                };
                (Some(Arc::new(store)), state, auto_unlock_pending)
            }
            Err(e) if e.starts_with(ANCHOR_RECOVERY_REQUIRED) => (
                None,
                State::AnchorRecovery(AnchorRecovery {
                    reason: e,
                    confirmed: false,
                    error: None,
                }),
                false,
            ),
            Err(e) => (None, State::Fatal(e), false),
        };
        let mut app = Self::with_state(store, state, window, cx);
        app.auto_unlock_pending = auto_unlock_pending;
        app.focus_first_field(window, cx);
        // The saved appearance must reach the very first frame: the unlock and
        // first-run screens are painted before any identity exists, and waiting
        // for a session would flash the wrong theme on every launch.
        app.apply_saved_theme(cx);
        if auto_unlock_pending {
            // Fire once, after the first frame, without overriding a user action.
            cx.defer_in(window, |this, window, cx| {
                if this.auto_unlock_pending && !this.is_busy() {
                    this.auto_unlock_pending = false;
                    if matches!(this.state, State::Unlock(_)) {
                        this.dispatch(Action::UnlockWithKeyring, window, cx);
                    }
                }
            });
        }
        app
    }

    /// Wire up a view around an explicit store and starting screen (shared by
    /// [`FileSecApp::new`] and the UI tests).
    fn with_state(
        store: Option<Arc<Store>>,
        state: State,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let fields = Fields::new(window, cx);
        let mut subscriptions = fields.subscribe(window, cx);

        // The repaint pump: worker threads poke a 1-slot channel (so a burst of
        // wake-ups coalesces into one), and this foreground task drains it and
        // polls the job / transfer / shutdown state on the UI thread.
        let (tx, rx) = async_channel::bounded::<()>(1);
        let repaint = Repaint::new(move || {
            let _ = tx.try_send(());
        });
        cx.spawn_in(window, async move |this, cx| {
            while rx.recv().await.is_ok() {
                if this
                    .update_in(cx, |this, window, cx| this.pump(window, cx))
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();

        // Follow the OS appearance live (only visible when the user picked
        // "System").
        theme::set_system_appearance(window.appearance(), cx);
        subscriptions.push(cx.observe_window_appearance(window, |_, window, cx| {
            theme::set_system_appearance(window.appearance(), cx);
        }));

        // Hold a close request open while plaintext temps are being shredded.
        let this = cx.weak_entity();
        window.on_window_should_close(cx, move |window, cx| {
            this.update(cx, |app, cx| app.request_close(window, cx))
                .unwrap_or(true)
        });

        // Last chance to wipe on quit (an OS logout, a quit from elsewhere): queue
        // every temp and give the shredder a bounded moment. A hard crash bypasses
        // even this; the next unlock's `clean_checkout_dir` is the backstop.
        subscriptions.push(cx.on_app_quit(|this, _| {
            this.wipe_all_temps(false);
            this.wiper.finish(Duration::from_secs(2));
            async {}
        }));

        // Keep keyboard focus inside the app: when the focused element goes
        // away (a dialog closed, a composer was hidden), fall back to the root.
        let root_focus = cx.focus_handle();
        window.focus(&root_focus, cx);
        subscriptions.push(cx.on_focus_lost(window, |this, window, cx| {
            window.focus(&this.root_focus, cx);
        }));

        Self {
            store,
            state,
            toast: None,
            job: None,
            auto_unlock_pending: false,
            wiper: Wiper::new(),
            exit_wipe: None,
            fields,
            repaint,
            prompt_open: false,
            browser_focus: cx.focus_handle(),
            dialog_focus: cx.focus_handle(),
            root_focus,
            titlebar_drag: Rc::new(Cell::new(false)),
            last_dir: None,
            toast_seq: 0,
            _subscriptions: subscriptions,
        }
    }

    /// Apply the theme saved in the data directory. Falls back to following
    /// the system when there is no store (the fatal screen) or nothing saved.
    fn apply_saved_theme(&self, cx: &mut App) {
        let choice = self
            .store
            .as_ref()
            .map_or_else(ThemeChoice::default, |s| s.load_prefs().theme);
        theme::apply_choice(choice, cx);
    }

    /// Whether the UI must stay inert: a job is running, a close is being held
    /// for the shredder, or a native file dialog is open.
    fn is_busy(&self) -> bool {
        self.job.is_some() || self.exit_wipe.is_some() || self.prompt_open
    }

    /// Show a toast. Success toasts dismiss themselves after [`TOAST_TTL`];
    /// errors stay until dismissed, so they can be read.
    fn set_toast(&mut self, msg: impl Into<String>, error: bool) {
        self.toast_seq += 1;
        self.toast = Some(Toast {
            msg: msg.into(),
            error,
            id: self.toast_seq,
        });
    }

    /// Arm the auto-dismiss timer for the current (success) toast. Separate from
    /// [`Self::set_toast`] so the many call sites that have no `Context` stay
    /// simple; called after every dispatch / apply.
    fn arm_toast_timer(&mut self, cx: &mut Context<Self>) {
        let Some(toast) = &self.toast else {
            return;
        };
        if toast.error {
            return;
        }
        let id = toast.id;
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(TOAST_TTL).await;
            let _ = this.update(cx, |this, cx| {
                if this.toast.as_ref().is_some_and(|t| t.id == id) {
                    this.toast = None;
                    cx.notify();
                }
            });
        })
        .detach();
    }

    fn store_arc(&self) -> Option<Arc<Store>> {
        self.store.clone()
    }

    fn ident_arc(&self) -> Option<Arc<Identity>> {
        if let State::Unlocked(s) = &self.state {
            Some(s.identity.clone())
        } else {
            None
        }
    }

    /// Snapshot the open vault for a *mutating* worker: id + a cheap clone of the
    /// metadata-only reader + a clone of the registry. The session keeps its
    /// reader; on success a fresh reader is swapped in via `ReplaceOpen`.
    fn open_ctx(&self) -> Option<(String, VaultReaderV2, Registry)> {
        if let State::Unlocked(s) = &self.state {
            if let Some(o) = &s.open {
                return Some((o.id.clone(), o.reader.clone(), s.registry.clone()));
            }
        }
        None
    }

    /// Snapshot the open vault for a *read-only* worker.
    fn open_reader(&self) -> Option<(String, VaultReaderV2)> {
        if let State::Unlocked(s) = &self.state {
            if let Some(o) = &s.open {
                return Some((o.id.clone(), o.reader.clone()));
            }
        }
        None
    }

    /// Spawn `work` on a background thread and show a spinner labelled `label`.
    fn spawn_job(
        &mut self,
        cx: &mut Context<Self>,
        label: impl Into<String>,
        work: impl FnOnce() -> JobReport + Send + 'static,
    ) {
        let (tx, rx) = mpsc::channel();
        let repaint = self.repaint.clone();
        std::thread::spawn(move || {
            let report = work();
            let _ = tx.send(report);
            repaint.request_repaint();
        });
        self.job = Some(Job {
            rx,
            label: label.into(),
        });
        cx.notify();
    }

    /// Woken by a worker thread: apply a finished job, drain transfer events,
    /// and re-render (a shutdown overlay counts down as the wiper drains).
    fn pump(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let report = self.job.as_ref().and_then(|job| job.rx.try_recv().ok());
        if let Some(report) = report {
            self.job = None;
            self.apply(report, window, cx);
        }
        #[cfg(feature = "net")]
        self.poll_transfer(cx);
        cx.notify();
    }

    fn apply(&mut self, report: JobReport, window: &mut Window, cx: &mut Context<Self>) {
        if let Some((msg, error)) = report.toast {
            self.set_toast(msg, error);
        }
        match report.outcome {
            Outcome::Noop => {}
            Outcome::Fatal(msg) => {
                self.state = State::Fatal(msg);
            }
            Outcome::AnchorsRecovered(store) => {
                let unlock = Unlock::for_store(&store);
                self.store = Some(Arc::new(*store));
                self.state = State::Unlock(unlock);
            }
            Outcome::AnchorRecoveryFailed(msg) => {
                if let State::AnchorRecovery(r) = &mut self.state {
                    r.error = Some(msg);
                }
            }
            Outcome::Unlocked(init) => {
                let SessionInit {
                    identity,
                    contacts,
                    registry,
                    passkeys,
                    auto_unlock,
                    data_dir,
                    rollback_warning,
                } = *init;
                self.state = State::Unlocked(Box::new(Session::new(
                    Arc::new(identity),
                    contacts,
                    registry,
                    passkeys,
                    auto_unlock,
                    data_dir,
                    rollback_warning,
                )));
            }
            Outcome::FirstRunFailed(msg) => {
                if let State::FirstRun(f) = &mut self.state {
                    // Surface the error in whichever card is showing: the restore
                    // sub-form when restoring, otherwise the create form.
                    match &mut f.restore {
                        Some(r) => r.error = Some(msg),
                        None => f.error = Some(msg),
                    }
                }
            }
            Outcome::UnlockFailed(msg) => {
                if let State::Unlock(u) = &mut self.state {
                    u.error = Some(msg);
                }
            }
            Outcome::Created {
                registry,
                id,
                reader,
            } => {
                if let State::Unlocked(s) = &mut self.state {
                    s.registry = registry;
                    s.show_new_vault = false;
                    s.reset_browse();
                    s.open = Some(OpenVault {
                        id,
                        reader: *reader,
                    });
                }
                self.focus_browser(window, cx);
            }
            Outcome::SetOpen { id, reader } => {
                if let State::Unlocked(s) = &mut self.state {
                    s.reset_browse();
                    s.open = Some(OpenVault {
                        id,
                        reader: *reader,
                    });
                }
                fields::clear(&self.fields.file_search, window, cx);
                self.focus_browser(window, cx);
            }
            Outcome::ReplaceOpen {
                id,
                reader,
                registry,
            } => {
                if let State::Unlocked(s) = &mut self.state {
                    s.registry = registry;
                    s.open = Some(OpenVault {
                        id,
                        reader: *reader,
                    });
                }
            }
            Outcome::CreatedTextFile {
                id,
                reader,
                registry,
                path,
                leaf,
            } => {
                if let State::Unlocked(s) = &mut self.state {
                    s.registry = registry;
                    s.open = Some(OpenVault {
                        id,
                        reader: *reader,
                    });
                    s.show_new_file = false;
                    // Open the (empty) new file straight into the quick editor.
                    s.text_editor = Some(TextEditor {
                        path,
                        leaf,
                        original: Zeroizing::new(String::new()),
                        dirty: false,
                    });
                }
                self.fields.editor.update(cx, |e, cx| {
                    e.set_value("", window, cx);
                    e.focus(window, cx);
                });
            }
            Outcome::OpenTextEditor(loaded) => {
                let LoadedText { path, leaf, text } = *loaded;
                if let State::Unlocked(s) = &mut self.state {
                    let shown: SharedString = text.as_str().to_string().into();
                    self.fields.editor.update(cx, |e, cx| {
                        e.set_value(shown, window, cx);
                        e.focus(window, cx);
                    });
                    s.text_editor = Some(TextEditor {
                        path,
                        leaf,
                        original: text,
                        dirty: false,
                    });
                }
            }
            Outcome::SavedTextFile {
                id,
                reader,
                registry,
            } => {
                if let State::Unlocked(s) = &mut self.state {
                    s.registry = registry;
                    s.open = Some(OpenVault {
                        id,
                        reader: *reader,
                    });
                    s.text_editor = None;
                }
            }
            Outcome::Deleted {
                registry,
                closed_id,
            } => {
                if let State::Unlocked(s) = &mut self.state {
                    s.registry = registry;
                    if s.open.as_ref().map(|o| o.id == closed_id).unwrap_or(false) {
                        s.open = None;
                    }
                }
            }
            Outcome::StartCheckout(c) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.checkout = Some(*c);
                }
            }
            Outcome::EndCheckout { replace } => {
                if let State::Unlocked(s) = &mut self.state {
                    s.checkout = None;
                    if let Some((id, reader, registry)) = replace {
                        s.registry = registry;
                        s.open = Some(OpenVault {
                            id,
                            reader: *reader,
                        });
                    }
                }
            }
            Outcome::StartView(v) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.views.push(*v);
                }
            }
            Outcome::Imported(data) => {
                if let State::Unlocked(s) = &mut self.state {
                    let fpr = data.sender.fingerprint();
                    let contact = s.contacts.find(&fpr);
                    let sender_name = contact.map(|c| c.identity.name.clone());
                    let verified = matches!(contact.map(|c| c.trust), Some(Trust::Verified));
                    s.registry = data.registry;
                    s.last_import = Some(ImportInfo {
                        sender: data.sender,
                        sender_fpr_hex: hex(&fpr),
                        sender_name,
                        verified,
                        vault_name: data.vault_name,
                        file_count: data.file_count,
                    });
                }
            }
            Outcome::Contacts(book) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.contacts = book;
                }
            }
            Outcome::PasskeysUpdated(passkeys) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.passkeys = passkeys;
                    s.add_passkey = None;
                }
            }
            Outcome::AutoUnlockChanged(enabled) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.auto_unlock = enabled;
                    s.auto_unlock_form = None;
                }
            }
            Outcome::ExportIdentityDone => {
                if let State::Unlocked(s) = &mut self.state {
                    s.export_identity = None;
                }
            }
        }
        self.scrub_fields(window, cx);
        self.arm_toast_timer(cx);
        cx.notify();
    }

    /// Whether a file is currently checked out for editing. Leaving the vault,
    /// locking, or navigating away would orphan the temp file and lose the
    /// in-flight edit, so those actions are blocked while this is true.
    fn checkout_active(&self) -> bool {
        matches!(&self.state, State::Unlocked(s) if s.checkout.is_some())
    }

    /// Hand every read-only view's temp file to the background shredder and clear
    /// the list. Called when leaving the vault (close/nav/lock).
    ///
    /// Returns immediately: `secure_wipe` overwrites the whole file and `fsync`s,
    /// which takes minutes on a large one, and the UI must not wait for it. The
    /// banner clears in this frame; the shredding finishes behind the scenes.
    fn wipe_all_views(&mut self) {
        let paths: Vec<PathBuf> = match &mut self.state {
            State::Unlocked(s) => s.views.drain(..).map(|v| v.temp_path).collect(),
            _ => Vec::new(),
        };
        for p in paths {
            self.wiper.enqueue(&self.repaint, p);
        }
    }

    /// Hand *every* plaintext temp this session still owns — the checked-out file
    /// as well as all read-only views — to the shredder. Shutdown only: it drops
    /// an in-flight check-out without checking it in, which is the long-standing
    /// on-exit behaviour.
    ///
    /// The check-out temp is left alone while a background job is running: a
    /// check-in streams that exact file back into the vault, and shredding it
    /// mid-read would feed the worker random bytes. Leaving plaintext for the
    /// next unlock's `clean_checkout_dir` sweep is the safer of the two failures.
    ///
    /// `wake` is `false` from the quit hook, where the window is already gone.
    fn wipe_all_temps(&mut self, wake: bool) {
        let job_owns_checkout = self.job.is_some();
        let paths: Vec<PathBuf> = match &mut self.state {
            State::Unlocked(s) => s
                .checkout
                .take_if(|_| !job_owns_checkout)
                .map(|c| c.temp_path)
                .into_iter()
                .chain(s.views.drain(..).map(|v| v.temp_path))
                .collect(),
            _ => Vec::new(),
        };
        for p in paths {
            if wake {
                self.wiper.enqueue(&self.repaint, p);
            } else {
                self.wiper.enqueue_quiet(p);
            }
        }
    }

    /// The window's close button (or ⌘Q): keep the window alive while the
    /// shredder finishes this session's plaintext temps, instead of freezing on
    /// the way out. Returns whether the close may proceed now.
    ///
    /// The first request queues every temp; if anything is left to shred the
    /// close is refused and a spinner covers the window while a timer polls the
    /// queue, then closes the window itself once it drains. If the queue outlives
    /// [`EXIT_WIPE_GRACE`] the window closes anyway —
    /// `Store::clean_checkout_dir` shreds whatever is left on the next unlock.
    fn request_close(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        if self.exit_wipe.is_some() {
            // Already draining; the poller closes the window when done.
            return false;
        }
        self.wipe_all_temps(true);
        if self.wiper.pending() == 0 {
            // Nothing left to shred (the common case — most temps are queued
            // the moment their viewer closes). Let the close through.
            return true;
        }
        self.exit_wipe = Some(ExitWipe {
            deadline: Instant::now() + EXIT_WIPE_GRACE,
        });
        cx.spawn_in(window, async move |this, cx| loop {
            cx.background_executor()
                .timer(Duration::from_millis(100))
                .await;
            let done = this.update(cx, |this, cx| {
                cx.notify();
                this.exit_wipe_finished()
            });
            match done {
                Ok(true) => {
                    let _ = cx.update(|window, _| window.remove_window());
                    break;
                }
                Ok(false) => {}
                Err(_) => break,
            }
        })
        .detach();
        cx.notify();
        false
    }

    /// Whether a held close may now go through (queue drained or grace over).
    fn exit_wipe_finished(&self) -> bool {
        match &self.exit_wipe {
            Some(e) => self.wiper.pending() == 0 || Instant::now() > e.deadline,
            None => true,
        }
    }

    fn quit(&mut self, _: &Quit, window: &mut Window, cx: &mut Context<Self>) {
        if self.request_close(window, cx) {
            cx.quit();
        }
    }

    fn focus_browser(&self, window: &mut Window, cx: &mut App) {
        window.focus(&self.browser_focus, cx);
    }

    /// Put the caret in the screen's first field, so typing works straight away
    /// on the auth screens.
    fn focus_first_field(&self, window: &mut Window, cx: &mut App) {
        use gpui_kit::Focusable;
        match &self.state {
            State::Unlock(_) => {
                let handle = self.fields.unlock_pass.read(cx).focus_handle(cx);
                window.focus(&handle, cx);
            }
            State::FirstRun(f) if f.restore.is_none() => {
                self.fields
                    .first_name
                    .update(cx, |input, cx| input.focus(window, cx));
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // Native file dialogs
    // -----------------------------------------------------------------------

    /// The folder a save dialog should start in.
    fn dialog_dir(&self) -> PathBuf {
        self.last_dir
            .clone()
            .or_else(|| {
                directories::UserDirs::new().map(|d| {
                    d.document_dir()
                        .map(std::path::Path::to_path_buf)
                        .unwrap_or_else(|| d.home_dir().to_path_buf())
                })
            })
            .unwrap_or_else(std::env::temp_dir)
    }

    /// Open the native "open" dialog; `then` turns the picked paths into the
    /// continuation action. Cancelling does nothing.
    fn pick_paths(
        &mut self,
        options: PathPromptOptions,
        window: &mut Window,
        cx: &mut Context<Self>,
        then: impl FnOnce(Vec<PathBuf>) -> Option<Action> + 'static,
    ) {
        let rx = cx.prompt_for_paths(options);
        self.prompt_open = true;
        cx.notify();
        cx.spawn_in(window, async move |this, cx| {
            let picked = rx.await;
            let _ = this.update_in(cx, |this, window, cx| {
                this.prompt_open = false;
                match picked {
                    Ok(Ok(Some(paths))) if !paths.is_empty() => {
                        if let Some(parent) = paths[0].parent() {
                            this.last_dir = Some(parent.to_path_buf());
                        }
                        if let Some(action) = then(paths) {
                            this.dispatch(action, window, cx);
                        }
                    }
                    Ok(Err(e)) => {
                        this.set_toast(format!("Could not open the file dialog: {e}"), true);
                    }
                    _ => {}
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// Open the native "save" dialog with a suggested file name. A path without
    /// an extension gets `ext` (the type the file is), like the platform
    /// dialogs' type filters used to add. `on_cancel` runs when the user backs
    /// out.
    #[allow(clippy::too_many_arguments)]
    fn pick_save(
        &mut self,
        suggested: &str,
        ext: Option<&'static str>,
        window: &mut Window,
        cx: &mut Context<Self>,
        then: impl FnOnce(PathBuf) -> Action + 'static,
        on_cancel: Option<Action>,
    ) {
        let dir = self.dialog_dir();
        let rx = cx.prompt_for_new_path(&dir, Some(suggested));
        self.prompt_open = true;
        cx.notify();
        cx.spawn_in(window, async move |this, cx| {
            let picked = rx.await;
            let _ = this.update_in(cx, |this, window, cx| {
                this.prompt_open = false;
                match picked {
                    Ok(Ok(Some(mut path))) => {
                        if let Some(ext) = ext {
                            if path.extension().is_none() {
                                path.set_extension(ext);
                            }
                        }
                        if let Some(parent) = path.parent() {
                            this.last_dir = Some(parent.to_path_buf());
                        }
                        this.dispatch(then(path), window, cx);
                    }
                    Ok(Err(e)) => {
                        this.set_toast(format!("Could not open the file dialog: {e}"), true);
                    }
                    _ => {
                        if let Some(action) = on_cancel {
                            this.dispatch(action, window, cx);
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn copy_to_clipboard(&self, text: String, cx: &mut App) {
        cx.write_to_clipboard(ClipboardItem::new_string(text));
    }

    // -----------------------------------------------------------------------
    // Text field events
    // -----------------------------------------------------------------------

    fn on_field_changed(&mut self, id: FieldId, _: &mut Window, cx: &mut Context<Self>) {
        match (&mut self.state, id) {
            (State::FirstRun(f), FieldId::FirstName | FieldId::FirstPass | FieldId::FirstPass2) => {
                f.error = None;
            }
            (
                State::FirstRun(f),
                FieldId::RestoreBackupPass | FieldId::RestoreNewPass | FieldId::RestoreNewPass2,
            ) => {
                if let Some(r) = &mut f.restore {
                    r.error = None;
                }
            }
            (State::Unlock(u), FieldId::UnlockPass) => u.error = None,
            (State::Unlocked(s), FieldId::FileSearch) => {
                // A new search starts from a clean selection.
                s.selected.clear();
                s.select_anchor = None;
            }
            (State::Unlocked(s), FieldId::Editor) => {
                if let Some(te) = &mut s.text_editor {
                    let now = Zeroizing::new(self.fields.editor.read(cx).value().to_string());
                    te.dirty = *now != *te.original;
                }
            }
            _ => {}
        }
        cx.notify();
    }

    /// Enter in a field: submit its form when it is ready, as the primary
    /// button would.
    fn on_field_submit(&mut self, id: FieldId, window: &mut Window, cx: &mut Context<Self>) {
        let ready = |e: &gpui_kit::Entity<crate::secret_input::SecretInput>, cx: &App| {
            !e.read(cx).is_empty()
        };
        let action = match (&self.state, id) {
            (State::AnchorRecovery(r), FieldId::AnchorPass) => (r.confirmed
                && ready(&self.fields.anchor_pass, cx))
            .then_some(Action::RecoverAnchors),
            (State::FirstRun(_), FieldId::FirstPass2) => {
                self.first_run_ready(cx).then_some(Action::CreateIdentity)
            }
            (State::FirstRun(_), FieldId::RestoreNewPass2) => {
                self.restore_ready(cx).then_some(Action::DoRestore)
            }
            (State::Unlock(_), FieldId::UnlockPass) => {
                ready(&self.fields.unlock_pass, cx).then_some(Action::Unlock)
            }
            (State::Unlocked(_), FieldId::NewVaultName) => {
                (!fields::value(&self.fields.new_vault_name, cx)
                    .trim()
                    .is_empty())
                .then_some(Action::CreateVault)
            }
            (State::Unlocked(_), FieldId::NewFolderName) => Some(Action::NewFolder),
            (State::Unlocked(_), FieldId::NewFileName) => Some(Action::NewFile),
            (State::Unlocked(_), FieldId::Rename) => Some(Action::ConfirmRename),
            (State::Unlocked(_), FieldId::AutoUnlockPass) => Some(Action::ConfirmEnableAutoUnlock),
            _ => None,
        };
        if let Some(action) = action {
            self.dispatch(action, window, cx);
        }
    }

    fn first_run_ready(&self, cx: &App) -> bool {
        let pass = self.fields.first_pass.read(cx).value();
        !fields::value(&self.fields.first_name, cx).trim().is_empty()
            && passphrase_policy_error(pass).is_none()
            && pass == self.fields.first_pass2.read(cx).value()
    }

    fn restore_ready(&self, cx: &App) -> bool {
        let new_pass = self.fields.restore_new_pass.read(cx).value();
        !self.fields.restore_backup_pass.read(cx).is_empty()
            && passphrase_policy_error(new_pass).is_none()
            && new_pass == self.fields.restore_new_pass2.read(cx).value()
    }

    /// Empty every field whose form is no longer on screen. The GPUI
    /// equivalent of the egui forms' zeroize-on-drop: a passphrase typed into a
    /// dialog that was cancelled, or into the unlock screen once unlocked, does
    /// not linger in the field.
    fn scrub_fields(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let f = &self.fields;
        let (anchor, first, restore, unlock) = match &self.state {
            State::AnchorRecovery(_) => (true, false, false, false),
            State::FirstRun(fr) => (false, fr.restore.is_none(), fr.restore.is_some(), false),
            State::Unlock(_) => (false, false, false, true),
            _ => (false, false, false, false),
        };
        if !anchor {
            fields::wipe(&f.anchor_pass, cx);
        }
        if !first {
            fields::wipe(&f.first_pass, cx);
            fields::wipe(&f.first_pass2, cx);
        }
        if !matches!(self.state, State::FirstRun(_)) {
            fields::clear(&f.first_name, window, cx);
        }
        if !restore {
            fields::wipe(&f.restore_backup_pass, cx);
            fields::wipe(&f.restore_new_pass, cx);
            fields::wipe(&f.restore_new_pass2, cx);
        }
        if !unlock {
            fields::wipe(&f.unlock_pass, cx);
            fields::wipe(&f.unlock_pin, cx);
        }
        let s = match &self.state {
            State::Unlocked(s) => Some(s.as_ref()),
            _ => None,
        };
        let open = |pred: fn(&Session) -> bool| s.is_some_and(pred);
        if !open(|s| s.show_new_vault) {
            fields::clear(&f.new_vault_name, window, cx);
        }
        if s.is_none() {
            fields::clear(&f.vault_search, window, cx);
            fields::clear(&f.contact_search, window, cx);
            fields::clear_area(&f.contact_paste, window, cx);
        }
        if !open(|s| s.open.is_some()) {
            fields::clear(&f.file_search, window, cx);
        }
        if !open(|s| s.show_new_folder) {
            fields::clear(&f.new_folder_name, window, cx);
        }
        if !open(|s| s.show_new_file) {
            fields::clear(&f.new_file_name, window, cx);
        }
        if !open(|s| s.rename_target.is_some()) {
            fields::clear(&f.rename, window, cx);
        }
        if !open(|s| s.verify.is_some()) {
            fields::clear(&f.verify_input, window, cx);
        }
        if !open(|s| s.text_editor.is_some()) {
            fields::clear_area(&f.editor, window, cx);
        }
        if !open(|s| s.add_passkey.is_some()) {
            fields::clear(&f.passkey_label, window, cx);
            fields::wipe(&f.passkey_pass, cx);
            fields::wipe(&f.passkey_pin, cx);
        }
        if !open(|s| s.auto_unlock_form.is_some()) {
            fields::wipe(&f.autounlock_pass, cx);
        }
        if !open(|s| s.export_identity.is_some()) {
            fields::wipe(&f.export_id_pass, cx);
            fields::wipe(&f.export_id_pass2, cx);
        }
        #[cfg(feature = "pqc")]
        if !open(|s| s.migrate.is_some()) {
            fields::wipe(&f.migrate_pass, cx);
        }
        #[cfg(feature = "net")]
        if s.is_none() {
            fields::clear(&f.recv_port, window, cx);
            fields::clear(&f.send_host, window, cx);
            fields::clear(&f.send_port, window, cx);
            fields::clear(&f.send_pairing, window, cx);
        }
    }

    // -----------------------------------------------------------------------
    // Keyboard
    // -----------------------------------------------------------------------

    /// Escape closes the topmost dialog (except the text editor, which only its
    /// buttons close), cancels the new-vault composer, or — in the browser with
    /// nothing focused — clears the selection, then the search.
    fn on_key_down(&mut self, event: &KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        if event.keystroke.key != "escape" || self.is_busy() {
            return;
        }
        let action = match &self.state {
            State::Unlocked(s) => {
                if s.delete_vault.is_some() {
                    Some(Action::CancelDeleteVault)
                } else if s.move_form.is_some() {
                    Some(Action::CancelMove)
                } else if s.text_editor.is_some() {
                    None
                } else if s.export.is_some() {
                    Some(Action::CancelExport)
                } else if s.last_import.is_some() {
                    Some(Action::DismissImportInfo)
                } else if s.contact_preview.is_some() {
                    Some(Action::CancelPreview)
                } else if s.verify.is_some() {
                    Some(Action::CancelVerify)
                } else if s.add_passkey.is_some() {
                    Some(Action::CancelAddPasskey)
                } else if s.auto_unlock_form.is_some() {
                    Some(Action::CancelEnableAutoUnlock)
                } else if s.export_identity.is_some() {
                    Some(Action::CancelExportIdentity)
                } else if migrate_open(s) {
                    #[cfg(feature = "pqc")]
                    {
                        Some(Action::CancelMigrate)
                    }
                    #[cfg(not(feature = "pqc"))]
                    {
                        None
                    }
                } else if s.show_new_vault && s.open.is_none() {
                    Some(Action::ToggleNewVault(false))
                } else if s.open.is_some() && !s.show_trash {
                    if !s.selected.is_empty() {
                        Some(Action::ClearSelection)
                    } else if !fields::value(&self.fields.file_search, cx)
                        .trim()
                        .is_empty()
                    {
                        Some(Action::ClearFileSearch)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(action) = action {
            cx.stop_propagation();
            self.dispatch(action, window, cx);
        }
    }

    fn browser_ready_for_shortcut(&self) -> bool {
        matches!(&self.state, State::Unlocked(s)
            if s.open.is_some()
                && !s.show_trash
                && s.checkout.is_none()
                && s.rename_target.is_none()
                && !s.modal_open())
            && !self.is_busy()
    }

    fn select_all_files(
        &mut self,
        _: &SelectAllFiles,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.browser_ready_for_shortcut() {
            self.dispatch(Action::SelectAllVisible, window, cx);
        }
    }

    fn trash_selection(&mut self, _: &TrashSelection, window: &mut Window, cx: &mut Context<Self>) {
        let any = matches!(&self.state, State::Unlocked(s) if !s.selected.is_empty());
        if self.browser_ready_for_shortcut() && any {
            self.dispatch(Action::TrashSelected, window, cx);
        }
    }

    fn focus_search(&mut self, _: &FocusSearch, window: &mut Window, cx: &mut Context<Self>) {
        let browsing = matches!(&self.state, State::Unlocked(s)
            if s.open.is_some() && !s.show_trash && !s.modal_open());
        if browsing && !self.is_busy() {
            self.fields
                .file_search
                .update(cx, |s, cx| s.focus(window, cx));
        }
    }

    fn on_drop_paths(
        &mut self,
        paths: &ExternalPaths,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let droppable = matches!(&self.state, State::Unlocked(s)
            if s.open.is_some() && !s.show_trash && s.checkout.is_none() && !s.modal_open());
        if droppable && !self.is_busy() {
            let paths: Vec<PathBuf> = paths.paths().to_vec();
            self.dispatch(Action::DropPaths(paths), window, cx);
        }
    }
}

/// Whether the post-quantum upgrade dialog is open (always `false` without
/// the `pqc` feature).
fn migrate_open(s: &Session) -> bool {
    #[cfg(feature = "pqc")]
    {
        s.migrate.is_some()
    }
    #[cfg(not(feature = "pqc"))]
    {
        let _ = s;
        false
    }
}

impl Render for FileSecApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let c = theme::colors(cx);
        let viewport = window.viewport_size();
        let unlocked = matches!(self.state, State::Unlocked(_));
        // The content column: what is left beside the sidebar, capped at the
        // page width, minus the page padding on both sides.
        let content_width = (viewport.width - if unlocked { theme::SIDEBAR_W } else { px(0.0) })
            .min(theme::CONTENT_MAX)
            - theme::PAGE_PAD * 2.0;
        let busy_label = self.busy_label();
        let weak = cx.weak_entity();
        let toast = self.toast.as_ref().map(|t| (t.msg.clone(), t.error));
        let prompt_open = self_prompt_open(self);
        // Clear of the browser's status bar, so a toast never covers the
        // selection actions.
        let toast_inset = match &self.state {
            State::Unlocked(s) if s.open.is_some() && !s.show_trash => px(72.0),
            _ => px(20.0),
        };
        let drag_strip = crate::UNIFIED_TITLEBAR
            .then(|| views::shell::window_drag_strip(self.titlebar_drag.clone()));
        let FileSecApp {
            state,
            fields,
            browser_focus,
            dialog_focus,
            ..
        } = self;
        let v = views::View {
            app: weak,
            c,
            cx,
            fields,
            width: content_width,
            window_width: viewport.width,
            height: viewport.height,
            browser_focus: browser_focus.clone(),
            dialog_focus: dialog_focus.clone(),
        };

        let sidebar = match &*state {
            State::Unlocked(s) => Some(views::shell::sidebar(s, &v)),
            _ => None,
        };
        let main = match state {
            State::Fatal(msg) => views::auth::fatal(msg, &v).into_any_element(),
            State::AnchorRecovery(r) => views::auth::anchor_recovery(r, &v).into_any_element(),
            State::FirstRun(f) => views::auth::first_run(f, &v).into_any_element(),
            State::Unlock(u) => views::auth::unlock(u, &v).into_any_element(),
            State::Unlocked(s) => views::shell::session(s, &v).into_any_element(),
        };
        let dialogs = match state {
            State::Unlocked(s) => views::dialogs::session_dialogs(s, &v),
            _ => Vec::new(),
        };
        let toast_el = toast.map(|(msg, error)| views::shell::toast(msg, error, toast_inset, &v));
        let busy_el = busy_label.map(|label| views::shell::busy_overlay(label, &v));
        let prompt_block = prompt_open.then(|| theme::backdrop("prompt-block", 0));

        div()
            .id("filesec-root")
            .key_context("FileSec")
            .track_focus(&self.root_focus)
            .on_key_down(cx.listener(Self::on_key_down))
            .on_action(cx.listener(Self::quit))
            .on_action(cx.listener(Self::select_all_files))
            .on_action(cx.listener(Self::trash_selection))
            .on_action(cx.listener(Self::focus_search))
            .size_full()
            .relative()
            .flex()
            .flex_row()
            .bg(c.bg)
            .font_family(theme::FONT_UI)
            .text_size(theme::TEXT_BODY)
            .text_color(c.text)
            // Beneath everything, so the headers' own controls take their
            // presses first.
            .children(drag_strip)
            .children(sidebar)
            .child(
                div()
                    .id("main")
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .flex()
                    .flex_col()
                    .bg(c.bg)
                    .when(unlocked, |el| el.on_drop(cx.listener(Self::on_drop_paths)))
                    .child(main),
            )
            .children(dialogs)
            .children(toast_el)
            .children(busy_el)
            .children(prompt_block)
    }
}

/// Split out so the destructuring borrow in `render` stays simple.
fn self_prompt_open(app: &FileSecApp) -> bool {
    app.prompt_open && app.job.is_none() && app.exit_wipe.is_none()
}

/// Options for picking one file.
fn open_file(prompt: &'static str) -> PathPromptOptions {
    PathPromptOptions {
        files: true,
        directories: false,
        multiple: false,
        prompt: Some(prompt.into()),
    }
}

/// Options for picking any number of files.
fn open_files(prompt: &'static str) -> PathPromptOptions {
    PathPromptOptions {
        multiple: true,
        ..open_file(prompt)
    }
}

/// Options for picking one folder.
fn open_folder(prompt: &'static str) -> PathPromptOptions {
    PathPromptOptions {
        files: false,
        directories: true,
        multiple: false,
        prompt: Some(prompt.into()),
    }
}

impl FileSecApp {
    /// The busy overlay's label, when one should cover the window. A pending
    /// shutdown takes the label, so the user sees why the window is still up.
    fn busy_label(&self) -> Option<String> {
        if self.exit_wipe.is_some() {
            return Some(match self.wiper.pending() {
                0 | 1 => "Securing temporary files…".to_string(),
                n => format!("Securing temporary files… ({n} remaining)"),
            });
        }
        self.job.as_ref().map(|j| j.label.clone())
    }
}
