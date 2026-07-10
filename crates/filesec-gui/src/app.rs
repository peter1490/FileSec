//! The egui application: state machine, screens, and action handling.
//!
//! Rendering is immediate-mode and side-effect-free: each screen only *collects*
//! an [`Action`]. After the frame is laid out, [`App::dispatch`] applies it.
//!
//! All crypto and I/O (Argon2 unlock, vault encryption/decryption, export and
//! import) run on a **background worker thread** so the UI never blocks — even
//! for very large vaults. While a job is in flight the UI is disabled behind a
//! spinner; when the worker finishes it sends back a [`JobReport`] that is
//! applied on the UI thread.

use std::collections::HashSet;
use std::sync::{mpsc, Arc};
use std::time::UNIX_EPOCH;

use eframe::egui::{self, Color32, RichText};
use zeroize::{Zeroize, Zeroizing};

use filesec_core::contacts::{ContactBook, Trust, UpsertOutcome};
use filesec_core::format::{self, ExportOptions};
use filesec_core::format_v2::{is_trashed, VaultReaderV2, TRASH_DIR};
use filesec_core::identity::{Identity, PublicIdentity};
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::{KeystoreFile, PasskeyInfo, HMAC_SECRET_LEN};
use filesec_core::manifest::EntryKind;
use filesec_core::util::{hex, now_unix};
use filesec_core::vault::Vault;
use filesec_core::SuiteId;

use crate::autounlock;
use crate::passkey;
use crate::store::{new_vault_id, write_private_export, Registry, Store, StoreResult, VaultMeta};

use crate::theme::{self, ACCENT, ERR_RED, MUTED, OK_GREEN, WARN_AMBER};

const MIN_PASSPHRASE_CHARS: usize = 12;
const MIN_PASSPHRASE_SCORE: u32 = 7;
const PASSPHRASE_HINT: &str = "Strong passphrase";
const PASSPHRASE_STRENGTH_MESSAGE: &str =
    "Use a stronger passphrase: combine several words or mix letters, numbers, and symbols.";
/// Accurate description of what enrolling a security key does: it is an
/// **alternative** unlock method (either the passphrase or the key opens the
/// keystore), not a second factor layered on the passphrase. Kept as a constant
/// so the "alternative unlock, not two-factor" wording stays regression-tested
/// (F04). Also states the PIN/UV requirement introduced in F10.
const PASSKEY_ALT_UNLOCK_DESC: &str =
    "Unlock with a hardware security key (FIDO2) as an alternative to your passphrase — either \
     one opens your keystore. This is a second way in, not a second factor. Your passphrase \
     always keeps working, so a lost key is never a lockout. Enrolling and unlocking require \
     user verification (your key's PIN or biometric).";
const MAX_PUBLIC_IDENTITY_FILE_LEN: u64 = 256 * 1024;
const MAX_IDENTITY_BACKUP_FILE_LEN: u64 = 4 * 1024 * 1024;
const COMMON_WEAK_PASSPHRASES: &[&str] = &[
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

/// Top-level application.
pub struct App {
    store: Option<Arc<Store>>,
    state: State,
    toast: Option<Toast>,
    job: Option<Job>,
    /// One-shot flag: a secret is saved in the OS keychain for this data dir, so
    /// try to auto-unlock with it on first launch. Cleared after the attempt is
    /// fired, and never set after a manual lock (locking signals intent to stop).
    auto_unlock_pending: bool,
}

struct Toast {
    msg: String,
    error: bool,
    /// egui-clock time (seconds) the toast was first painted, for auto-dismiss.
    /// Stamped lazily on first render so both constructors can leave it `None`.
    shown_at: Option<f64>,
}

enum State {
    Fatal(String),
    FirstRun(FirstRun),
    Unlock(Unlock),
    Unlocked(Box<Session>),
}

#[derive(Default)]
struct FirstRun {
    name: String,
    pass: String,
    pass2: String,
    error: Option<String>,
    /// When set, the "restore from a backup" sub-flow is active (a backup file
    /// has been picked) and its card is shown instead of "create identity".
    restore: Option<RestoreForm>,
}

/// Wipe the passphrase buffers when the first-run form is discarded (e.g. on a
/// successful unlock). `String::clear`/`mem::take` alone leave the old bytes in
/// freed heap; this zeroizes them.
impl Drop for FirstRun {
    fn drop(&mut self) {
        self.pass.zeroize();
        self.pass2.zeroize();
    }
}

/// First-run "restore from a backup" sub-form: the picked `.fsecid` file, the
/// passphrase that decrypts it, and a new local passphrase (×2) to seal the
/// restored identity into this device's keystore.
#[derive(Default)]
struct RestoreForm {
    path: std::path::PathBuf,
    backup_pass: String,
    new_pass: String,
    new_pass2: String,
    error: Option<String>,
}

impl Drop for RestoreForm {
    fn drop(&mut self) {
        self.backup_pass.zeroize();
        self.new_pass.zeroize();
        self.new_pass2.zeroize();
    }
}

#[derive(Default)]
struct Unlock {
    pass: String,
    /// Optional PIN for unlocking with a security key (blank ⇒ no PIN / on-device
    /// user verification only). Kept here so it survives across frames.
    pin: String,
    /// Whether the on-disk keystore has any passkeys enrolled (decided once at
    /// startup / lock so the unlock screen can offer the security-key button).
    has_passkeys: bool,
    /// Whether a passphrase is saved in the OS keychain for this data dir, so the
    /// unlock screen can offer "unlock with saved passphrase (this device)".
    has_saved: bool,
    /// A valid pre-anchor keystore was found. The UI changes the normal unlock
    /// action into an explicit one-time recovery/upgrade confirmation.
    legacy_recovery: bool,
    error: Option<String>,
}

impl Unlock {
    /// Build the unlock screen state, noting whether the keystore has passkeys
    /// and whether a passphrase is saved in the OS keychain for this device.
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
            pass: String::new(),
            pin: String::new(),
            has_passkeys,
            has_saved: autounlock::is_saved(&store.data_dir().display().to_string()),
            legacy_recovery,
            error: None,
        }
    }
}

/// Wipe the passphrase and PIN buffers when the unlock form is discarded. See
/// [`FirstRun`].
impl Drop for Unlock {
    fn drop(&mut self) {
        self.pass.zeroize();
        self.pin.zeroize();
    }
}

/// The "Add security key" dialog: a label, the passphrase that authorizes the
/// change, and an optional security-key PIN.
#[derive(Default)]
struct PasskeyEnrollForm {
    label: String,
    pass: String,
    pin: String,
    error: Option<String>,
}

impl Drop for PasskeyEnrollForm {
    fn drop(&mut self) {
        self.pass.zeroize();
        self.pin.zeroize();
    }
}

/// The "Remember on this device" dialog: the passphrase to verify and then save
/// into the OS keychain so this device can auto-unlock.
#[derive(Default)]
struct AutoUnlockForm {
    pass: String,
    error: Option<String>,
}

impl Drop for AutoUnlockForm {
    fn drop(&mut self) {
        self.pass.zeroize();
    }
}

/// The "Export identity backup" dialog: a backup passphrase (×2) that seals the
/// exported `.fsecid` file. Independent of the daily passphrase.
#[derive(Default)]
struct ExportIdentityForm {
    pass: String,
    pass2: String,
    error: Option<String>,
}

impl Drop for ExportIdentityForm {
    fn drop(&mut self) {
        self.pass.zeroize();
        self.pass2.zeroize();
    }
}

/// The "Upgrade to post-quantum" confirmation dialog. Re-sealing the keystore
/// needs the passphrase, so it is re-entered here (this also confirms intent).
#[cfg(feature = "pqc")]
#[derive(Default)]
struct MigrateForm {
    pass: String,
    error: Option<String>,
}

#[cfg(feature = "pqc")]
impl Drop for MigrateForm {
    fn drop(&mut self) {
        self.pass.zeroize();
    }
}

#[derive(PartialEq, Clone, Copy)]
enum Nav {
    Vaults,
    Contacts,
    Identity,
    #[cfg(feature = "net")]
    Transfer,
}

/// Sort order for the in-vault file browser. Directories always sort before
/// files regardless; this only orders within each group.
#[derive(PartialEq, Clone, Copy, Default)]
enum SortMode {
    #[default]
    NameAsc,
    NameDesc,
    SizeDesc,
    SizeAsc,
}

impl SortMode {
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
    temp_path: std::path::PathBuf,
    /// Plaintext BLAKE3 at check-out, to detect "no changes" on check-in.
    orig_blake3: [u8; 32],
    /// Advisory mode bits to preserve on the re-encrypted entry.
    mode: Option<u32>,
}

/// A read-only view in progress: one file decrypted to a disposable temp file
/// and opened in the OS app. There is nothing to check in — a detached watcher
/// thread securely wipes the temp the moment the app that opened it closes, and
/// any survivors are wiped when the vault is left. Multiple views may be active.
struct ActiveView {
    /// Display leaf (for the "viewing" banner).
    leaf: String,
    /// The decrypted read-only temp file on disk.
    temp_path: std::path::PathBuf,
}

struct ExportForm {
    vault_id: String,
    selected: HashSet<String>,
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
    /// Renaming a *verified* contact is the notable case (the keys are
    /// unchanged, so verification still holds, but it's worth a second look).
    Renamed { old: String, verified: bool },
    /// This is the user's own public key — adding yourself is pointless.
    SelfKey,
}

/// State backing the per-contact verification dialog: the user compares this
/// safety number with the contact out-of-band, optionally typing what they read
/// back so the app checks the match for them.
struct VerifyForm {
    fpr_hex: String,
    name: String,
    /// Canonical safety number, for display.
    safety_number: String,
    /// What the user types/pastes from the other party (compared leniently).
    input: String,
    /// "I compared it myself and it matches" — an alternative to typing it in.
    manual_ok: bool,
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
    new_vault_name: String,
    show_new_vault: bool,
    new_folder_name: String,
    /// Folder currently being browsed inside the open vault ("" = vault root).
    current_dir: String,
    /// Whether the inline "new folder" composer is shown in the browser.
    show_new_folder: bool,
    /// Live name filter over the open vault; non-empty searches the whole vault.
    file_search: String,
    /// Files multi-selected in the browser (full vault paths), for batch actions.
    selected: HashSet<String>,
    /// Sort order for the browser's file/folder list.
    sort: SortMode,
    /// Whether the trash view (soft-deleted entries) is shown instead of files.
    show_trash: bool,
    /// Whether the inline "empty the trash?" confirmation is armed (a guard on the
    /// one irreversible bulk action in the browser).
    confirm_empty_trash: bool,
    /// The entry currently being renamed inline (its vault path) and the draft
    /// name being typed; `None` when no rename is in progress.
    rename_target: Option<String>,
    rename_input: String,
    /// The open "move to folder" dialog, if any.
    move_form: Option<MoveForm>,
    /// Anchor row (vault path) for shift-range selection, à la a file explorer.
    select_anchor: Option<String>,
    /// The inline "new text file" composer state.
    show_new_file: bool,
    new_file_name: String,
    /// The open in-app quick text editor, if any.
    text_editor: Option<TextEditor>,
    contact_paste: String,
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
    /// Whether this device's passphrase is saved in the OS keychain (cached;
    /// refreshed after enable/disable).
    auto_unlock: bool,
    /// The open "remember on this device" dialog, if any.
    auto_unlock_form: Option<AutoUnlockForm>,
    /// The open "export identity backup" dialog, if any.
    export_identity: Option<ExportIdentityForm>,
    data_dir: String,
    rollback_warning: Option<String>,
    /// Direct network-transfer state (the `net` feature).
    #[cfg(feature = "net")]
    transfer: TransferState,
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
        Self {
            identity,
            contacts,
            registry,
            nav: Nav::Vaults,
            open: None,
            checkout: None,
            views: Vec::new(),
            new_vault_name: String::new(),
            show_new_vault: false,
            new_folder_name: String::new(),
            current_dir: String::new(),
            show_new_folder: false,
            file_search: String::new(),
            selected: HashSet::new(),
            sort: SortMode::default(),
            show_trash: false,
            confirm_empty_trash: false,
            rename_target: None,
            rename_input: String::new(),
            move_form: None,
            select_anchor: None,
            show_new_file: false,
            new_file_name: String::new(),
            text_editor: None,
            contact_paste: String::new(),
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
            data_dir,
            rollback_warning,
            #[cfg(feature = "net")]
            transfer: TransferState::default(),
        }
    }

    /// Reset the browser's transient view state. Called when a vault is opened or
    /// closed so navigation, selection, search, and the new-folder composer never
    /// leak from one vault (or browsing session) into the next.
    fn reset_browse(&mut self) {
        self.current_dir.clear();
        self.show_new_folder = false;
        self.new_folder_name.clear();
        self.file_search.clear();
        self.selected.clear();
        self.show_trash = false;
        self.confirm_empty_trash = false;
        self.rename_target = None;
        self.rename_input.clear();
        self.move_form = None;
        self.select_anchor = None;
        self.show_new_file = false;
        self.new_file_name.clear();
        // Drop any open editor, scrubbing its plaintext buffer.
        if let Some(mut te) = self.text_editor.take() {
            te.zeroize();
        }
    }
}

/// The open "move to folder" dialog: the entries being moved and the destination
/// folder currently chosen ("" = the vault root).
struct MoveForm {
    paths: Vec<String>,
    dest: String,
}

/// The in-app quick text editor: a file's plaintext held in memory (never written
/// to a temp on disk, unlike check-out), edited in place and saved back as a fresh
/// blob. `original` is the loaded content, to flag unsaved changes.
struct TextEditor {
    /// Vault path being edited.
    path: String,
    /// Display name (with extension).
    leaf: String,
    /// The editable buffer.
    content: String,
    /// Content as loaded, for the dirty check.
    original: String,
}

impl TextEditor {
    fn dirty(&self) -> bool {
        self.content != self.original
    }
    /// Scrub the plaintext buffers from memory when the editor closes.
    fn zeroize(&mut self) {
        self.content.zeroize();
        self.original.zeroize();
    }
}

/// All direct-transfer UI state (the `net` feature): the running transfer, if
/// any, plus the receive/send form fields. Lives in the [`Session`] so it
/// survives navigation and is torn down (stopping the worker) when the session
/// drops on lock or exit.
#[cfg(feature = "net")]
#[derive(Default)]
struct TransferState {
    /// The running listener or sender, if any.
    active: Option<ActiveTransfer>,
    // Receive form.
    recv_contact: Option<String>, // hex fingerprint of the designated sender
    recv_internet: bool,
    recv_port: String,
    // Send form.
    send_contact: Option<String>, // hex fingerprint of the chosen verified contact
    send_host: String,
    send_port: String,
    send_pairing: String,
    send_vault: Option<String>, // vault id to send
}

/// A running transfer and the UI view of its progress.
#[cfg(feature = "net")]
struct ActiveTransfer {
    handle: crate::net::NetHandle,
    kind: ActiveKind,
    status: String,
    listen: Option<ListenView>,
    peer: Option<String>,
    offer: Option<OfferView>,
    progress: Option<(u64, u64)>,
}

#[cfg(feature = "net")]
#[derive(PartialEq, Clone, Copy)]
enum ActiveKind {
    Receive,
    Send,
}

/// The listening address(es) + transfer code shown to the user in receive mode.
#[cfg(feature = "net")]
struct ListenView {
    lan_addr: String,
    public_addr: Option<String>,
    nat: String,
    transfer_code: String,
}

/// A pending incoming offer awaiting the user's accept/reject.
#[cfg(feature = "net")]
struct OfferView {
    filename: String,
    size: u64,
    sender: String,
}

/// Deferred mutations collected during rendering.
enum Action {
    CreateIdentity,
    Unlock,
    Lock,
    Nav(Nav),
    ToggleNewVault(bool),
    CreateVault,
    OpenVault(String),
    CloseVault,
    DeleteVault(String),
    ImportContainer,
    AddFiles,
    AddFolder,
    /// Add OS files/folders dropped onto the window into the current folder.
    DropPaths(Vec<std::path::PathBuf>),
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
    /// Soft-delete an entry: move it (and any subtree) into the trash.
    Trash(String),
    SaveEntryAs(String),
    ViewFile(String),
    CheckOut(String),
    CheckIn,
    Discard,
    ExtractAll,
    /// Select every file or folder in the current view.
    SelectAllVisible,
    /// Clear the browser selection.
    ClearSelection,
    /// Soft-delete every selected file into the trash.
    TrashSelected,
    /// Decrypt every selected file to a chosen folder.
    ExtractSelected,
    /// Change the browser's sort order.
    SetSort(SortMode),
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
    DoExport,
    ToggleRecipient(String),
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
    /// Parse the paste box / a picked file into a staged [`ContactPreview`].
    PreviewContactPaste,
    PreviewContactFile,
    /// Commit the staged preview into the contact book.
    ConfirmAddContact,
    CancelPreview,
    /// Open the verification dialog for a contact (by hex fingerprint).
    BeginVerify(String),
    /// Copy the safety number shown in the verification dialog.
    CopyVerifySafetyNumber,
    /// Finish verification — mark the contact verified and close the dialog.
    ConfirmVerify(String),
    CancelVerify,
    SetTrust(String, Trust),
    RemoveContact(String),
    /// Stage the just-imported container's (unknown) sender for adding.
    AddSenderToContacts,
    CopyPubKey,
    SavePubKey,
    /// Open / cancel / confirm the "export identity backup" dialog.
    BeginExportIdentity,
    CancelExportIdentity,
    DoExportIdentity,
    /// First-run restore: pick a backup file, then cancel / confirm the restore.
    BeginRestore,
    CancelRestore,
    DoRestore,
    DismissImportInfo,
    DismissToast,
    /// Unlock by deriving a key from an enrolled security key (passkey).
    UnlockWithPasskey,
    /// Open / cancel the "add security key" dialog.
    BeginAddPasskey,
    CancelAddPasskey,
    /// Enroll a new security key from the open dialog.
    AddPasskey,
    /// Remove the enrolled passkey at this slot index.
    RemovePasskey(usize),
    /// Unlock using the passphrase saved in the OS keychain (this device).
    UnlockWithKeyring,
    /// Open / cancel the "remember on this device" dialog.
    BeginEnableAutoUnlock,
    CancelEnableAutoUnlock,
    /// Verify the entered passphrase and save it to the OS keychain.
    ConfirmEnableAutoUnlock,
    /// Forget the passphrase saved in the OS keychain for this device.
    DisableAutoUnlock,
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

/// A running background job; the UI polls `rx` each frame.
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
    /// Whether a passphrase is saved in the OS keychain for this data dir.
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
    OpenTextEditor(Box<TextEditor>),
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

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// Construct the app, discovering storage and the initial screen.
    pub fn new() -> Self {
        match Store::discover() {
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
                App {
                    store: Some(Arc::new(store)),
                    state,
                    toast: None,
                    job: None,
                    auto_unlock_pending,
                }
            }
            Err(e) => App {
                store: None,
                state: State::Fatal(e),
                toast: None,
                job: None,
                auto_unlock_pending: false,
            },
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Apply a finished background job, if any.
        if let Some(job) = &self.job {
            if let Ok(report) = job.rx.try_recv() {
                self.job = None;
                self.apply(report);
            }
        }
        // Drain any direct-transfer events (independent of the one-shot job slot).
        #[cfg(feature = "net")]
        self.poll_transfer(ctx);
        let busy = self.job.is_some();
        let mut action: Option<Action> = None;

        // Left sidebar — only once unlocked. Auth/fatal screens are full-window.
        if matches!(self.state, State::Unlocked(_)) {
            let sidebar_fill = theme::colors_for(ctx).sidebar;
            egui::SidePanel::left("sidebar")
                .resizable(false)
                .exact_width(theme::SIDEBAR_W)
                .frame(
                    egui::Frame::NONE
                        .fill(sidebar_fill)
                        .inner_margin(egui::Margin::same(12)),
                )
                .show(ctx, |ui| {
                    ui.add_enabled_ui(!busy, |ui| self.sidebar(ui, &mut action));
                });
        }

        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(theme::colors_for(ctx).bg)
                    .inner_margin(egui::Margin::same(20)),
            )
            .show(ctx, |ui| {
                ui.add_enabled_ui(!busy, |ui| match &mut self.state {
                    State::Fatal(msg) => fatal_ui(msg, ui),
                    State::FirstRun(f) => first_run_ui(f, ui, &mut action),
                    State::Unlock(u) => unlock_ui(u, ui, &mut action),
                    State::Unlocked(s) => session_ui(s, ui, &mut action),
                });
            });

        // Floating, auto-dismissing toast (bottom-right).
        if let Some(t) = &mut self.toast {
            let now = ctx.input(|i| i.time);
            let shown = *t.shown_at.get_or_insert(now);
            let msg = t.msg.clone();
            let error = t.error;
            let dismissed = theme::toast(ctx, &msg, error);
            const TTL: f64 = 4.0;
            let age = now - shown;
            if dismissed || age > TTL {
                action = Some(Action::DismissToast);
            } else {
                ctx.request_repaint_after(std::time::Duration::from_secs_f64(
                    (TTL - age).max(0.05),
                ));
            }
        }

        // Busy overlay: dimmed backdrop + centered spinner.
        if busy {
            let label = self
                .job
                .as_ref()
                .map(|j| j.label.clone())
                .unwrap_or_default();
            egui::Modal::new(egui::Id::new("working"))
                .backdrop_color(Color32::from_black_alpha(140))
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new());
                        ui.add_space(8.0);
                        ui.label(label);
                    });
                });
        }

        // One-shot keychain auto-unlock on first launch: fire it once when idle
        // and still on the unlock screen, without overriding a user action.
        if self.auto_unlock_pending && !busy && action.is_none() {
            self.auto_unlock_pending = false;
            if matches!(self.state, State::Unlock(_)) {
                action = Some(Action::UnlockWithKeyring);
            }
        }

        if let Some(a) = action {
            match a {
                // The toast can always be dismissed, even mid-job.
                Action::DismissToast => self.toast = None,
                _ if !busy => self.dispatch(a, ctx),
                _ => {}
            }
        }
    }

    /// Best-effort wipe of an active check-out's temp file and any read-only view
    /// temps on a clean exit. A hard crash (SIGKILL/power loss) bypasses this; the
    /// next-unlock `clean_checkout_dir` is the backstop.
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let State::Unlocked(s) = &mut self.state {
            if let Some(c) = &s.checkout {
                let _ = crate::store::secure_wipe(&c.temp_path);
            }
            wipe_all_views(&mut s.views);
        }
    }
}

impl App {
    fn sidebar(&self, ui: &mut egui::Ui, action: &mut Option<Action>) {
        let c = theme::colors(ui);

        // Brand.
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(theme::icon_text(theme::icon::LOCK_KEY, 22.0).color(c.accent));
            ui.label(RichText::new("FileSec").heading().color(c.accent));
        });
        ui.label(
            RichText::new("secure file exchange")
                .small()
                .color(c.text_muted),
        );
        ui.add_space(16.0);

        if let State::Unlocked(s) = &self.state {
            let mut nav_item = |ui: &mut egui::Ui, glyph: &str, label: &str, nav: Nav| {
                let selected = s.open.is_none() && s.nav == nav;
                if sidebar_nav_item(ui, glyph, label, selected).clicked() {
                    *action = Some(Action::Nav(nav));
                }
            };
            nav_item(ui, theme::icon::VAULT, "Vaults", Nav::Vaults);
            nav_item(ui, theme::icon::CONTACTS, "Contacts", Nav::Contacts);
            nav_item(ui, theme::icon::IDENTITY, "My Identity", Nav::Identity);
            #[cfg(feature = "net")]
            nav_item(ui, theme::icon::SEND, "Transfer", Nav::Transfer);

            // Bottom-pinned: theme controls and Lock.
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                ui.add_space(2.0);
                if theme::secondary_button(ui, "Lock").clicked() {
                    *action = Some(Action::Lock);
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    let dark = ui.visuals().dark_mode;
                    let (glyph, hover, pref) = if dark {
                        (
                            theme::icon::SUN,
                            "Switch to light",
                            egui::ThemePreference::Light,
                        )
                    } else {
                        (
                            theme::icon::MOON,
                            "Switch to dark",
                            egui::ThemePreference::Dark,
                        )
                    };
                    if ui
                        .add(
                            egui::Button::new(theme::icon_text(glyph, 16.0).color(c.text_muted))
                                .frame(false),
                        )
                        .on_hover_text(hover)
                        .clicked()
                    {
                        ui.ctx().set_theme(pref);
                    }
                    if ui
                        .add(
                            egui::Button::new(
                                theme::icon_text(theme::icon::GEAR, 16.0).color(c.text_muted),
                            )
                            .frame(false),
                        )
                        .on_hover_text("Follow system theme")
                        .clicked()
                    {
                        ui.ctx().set_theme(egui::ThemePreference::System);
                    }
                });
            });
        }
    }

    fn set_toast(&mut self, msg: impl Into<String>, error: bool) {
        self.toast = Some(Toast {
            msg: msg.into(),
            error,
            shown_at: None,
        });
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
        ctx: &egui::Context,
        label: impl Into<String>,
        work: impl FnOnce() -> JobReport + Send + 'static,
    ) {
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let report = work();
            let _ = tx.send(report);
            ctx.request_repaint();
        });
        self.job = Some(Job {
            rx,
            label: label.into(),
        });
    }

    fn apply(&mut self, report: JobReport) {
        if let Some((msg, error)) = report.toast {
            self.toast = Some(Toast {
                msg,
                error,
                shown_at: None,
            });
        }
        match report.outcome {
            Outcome::Noop => {}
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
                    s.new_vault_name.clear();
                    s.show_new_vault = false;
                    s.reset_browse();
                    s.open = Some(OpenVault {
                        id,
                        reader: *reader,
                    });
                }
            }
            Outcome::SetOpen { id, reader } => {
                if let State::Unlocked(s) = &mut self.state {
                    s.reset_browse();
                    s.open = Some(OpenVault {
                        id,
                        reader: *reader,
                    });
                }
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
                    s.new_file_name.clear();
                    // Open the (empty) new file straight into the quick editor.
                    s.text_editor = Some(TextEditor {
                        path,
                        leaf,
                        content: String::new(),
                        original: String::new(),
                    });
                }
            }
            Outcome::OpenTextEditor(te) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.text_editor = Some(*te);
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
                    if let Some(mut te) = s.text_editor.take() {
                        te.zeroize();
                    }
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
    }

    /// Whether a file is currently checked out for editing. Leaving the vault,
    /// locking, or navigating away would orphan the temp file and lose the
    /// in-flight edit, so those actions are blocked while this is true.
    fn checkout_active(&self) -> bool {
        matches!(&self.state, State::Unlocked(s) if s.checkout.is_some())
    }

    fn dispatch(&mut self, action: Action, ctx: &egui::Context) {
        match action {
            // --- instant, UI-only actions ---
            Action::Lock => {
                if self.checkout_active() {
                    self.set_toast("Check in or discard your edit first.", true);
                    return;
                }
                if let State::Unlocked(s) = &mut self.state {
                    wipe_all_views(&mut s.views);
                }
                self.state = match &self.store {
                    Some(store) => State::Unlock(Unlock::for_store(store)),
                    None => State::Unlock(Unlock::default()),
                };
                self.toast = None;
            }
            #[cfg(feature = "net")]
            Action::StartListen => self.start_listen(ctx),
            #[cfg(feature = "net")]
            Action::StopTransfer => self.stop_transfer(),
            #[cfg(feature = "net")]
            Action::StartSend => self.start_send(ctx),
            #[cfg(feature = "net")]
            Action::AcceptIncoming => {
                self.transfer_command(crate::net::NetCommand::AcceptOffer, true)
            }
            #[cfg(feature = "net")]
            Action::RejectIncoming => {
                self.transfer_command(crate::net::NetCommand::RejectOffer, true)
            }
            #[cfg(feature = "net")]
            Action::CancelTransfer => self.transfer_command(crate::net::NetCommand::Cancel, false),
            Action::DismissToast => self.toast = None,
            Action::DismissImportInfo => {
                if let State::Unlocked(s) = &mut self.state {
                    s.last_import = None;
                }
            }
            Action::Nav(n) => {
                if self.checkout_active() {
                    self.set_toast("Check in or discard your edit first.", true);
                    return;
                }
                if let State::Unlocked(s) = &mut self.state {
                    wipe_all_views(&mut s.views);
                    s.nav = n;
                    s.open = None;
                }
            }
            Action::ToggleNewVault(b) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.show_new_vault = b;
                    if !b {
                        s.new_vault_name.clear();
                    }
                }
            }
            Action::CloseVault => {
                if self.checkout_active() {
                    self.set_toast("Check in or discard your edit first.", true);
                    return;
                }
                if let State::Unlocked(s) = &mut self.state {
                    wipe_all_views(&mut s.views);
                    s.open = None;
                    s.reset_browse();
                }
            }
            Action::EnterDir(dir) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.current_dir = dir;
                    // Selection, anchor, and search are scoped to a folder view;
                    // leaving the folder (or a breadcrumb jump) starts fresh.
                    s.selected.clear();
                    s.select_anchor = None;
                    s.file_search.clear();
                }
            }
            Action::ToggleNewFolder(b) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.show_new_folder = b;
                    if !b {
                        s.new_folder_name.clear();
                    }
                }
            }
            Action::ToggleNewFile(b) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.show_new_file = b;
                    if !b {
                        s.new_file_name.clear();
                    }
                }
            }
            Action::CloseTextEditor => {
                if let State::Unlocked(s) = &mut self.state {
                    if let Some(mut te) = s.text_editor.take() {
                        te.zeroize();
                    }
                }
            }
            Action::SelectAllVisible => {
                if let State::Unlocked(s) = &mut self.state {
                    if let Some(o) = &s.open {
                        let entries = snapshot_entries(&o.reader);
                        // Select every visible row — files and folders alike.
                        for row in visible_rows(&entries, &s.current_dir, &s.file_search, s.sort) {
                            s.selected.insert(row.path);
                        }
                    }
                }
            }
            Action::ClearSelection => {
                if let State::Unlocked(s) = &mut self.state {
                    s.selected.clear();
                    s.select_anchor = None;
                }
            }
            Action::SetSort(mode) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.sort = mode;
                }
            }
            Action::ShowTrash(b) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.show_trash = b;
                    // Leaving file/trash views resets the transient browser bits
                    // so a half-typed rename, stale selection, or armed "empty
                    // trash" confirmation never lingers.
                    s.selected.clear();
                    s.rename_target = None;
                    s.rename_input.clear();
                    s.confirm_empty_trash = false;
                }
            }
            Action::PromptEmptyTrash(b) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.confirm_empty_trash = b;
                }
            }
            Action::BeginRename(path) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.rename_input = leaf_name(&path).to_string();
                    s.rename_target = Some(path);
                }
            }
            Action::CancelRename => {
                if let State::Unlocked(s) = &mut self.state {
                    s.rename_target = None;
                    s.rename_input.clear();
                }
            }
            Action::BeginMove(paths) => {
                if let State::Unlocked(s) = &mut self.state {
                    if !paths.is_empty() {
                        // Default the destination to the parent of the first item.
                        let dest = parent_dir(&paths[0]).to_string();
                        s.move_form = Some(MoveForm { paths, dest });
                    }
                }
            }
            Action::SetMoveDest(dest) => {
                if let State::Unlocked(s) = &mut self.state {
                    if let Some(f) = &mut s.move_form {
                        f.dest = dest;
                    }
                }
            }
            Action::CancelMove => {
                if let State::Unlocked(s) = &mut self.state {
                    s.move_form = None;
                }
            }
            Action::CancelExport => {
                if let State::Unlocked(s) = &mut self.state {
                    s.export = None;
                }
            }
            Action::BeginExport(id) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.export = Some(ExportForm {
                        vault_id: id,
                        selected: HashSet::new(),
                        include_self: false,
                        suite: SuiteId::default(),
                    });
                }
            }
            Action::ToggleRecipient(fpr) => {
                if let State::Unlocked(s) = &mut self.state {
                    if let Some(e) = &mut s.export {
                        if !e.selected.insert(fpr.clone()) {
                            e.selected.remove(&fpr);
                        }
                    }
                }
            }
            Action::ToggleIncludeSelf => {
                if let State::Unlocked(s) = &mut self.state {
                    if let Some(e) = &mut s.export {
                        e.include_self = !e.include_self;
                    }
                }
            }
            #[cfg(feature = "pqc")]
            Action::SetExportSuite(suite) => {
                if let State::Unlocked(s) = &mut self.state {
                    if let Some(e) = &mut s.export {
                        e.suite = suite;
                    }
                }
            }
            #[cfg(feature = "pqc")]
            Action::BeginMigrate => {
                if let State::Unlocked(s) = &mut self.state {
                    if !s.identity.is_hybrid_capable() {
                        s.migrate = Some(MigrateForm::default());
                    }
                }
            }
            #[cfg(feature = "pqc")]
            Action::CancelMigrate => {
                if let State::Unlocked(s) = &mut self.state {
                    s.migrate = None;
                }
            }
            #[cfg(feature = "pqc")]
            Action::DoMigrate => self.spawn_migrate(ctx),
            Action::CopyPubKey => {
                let armored = if let State::Unlocked(s) = &self.state {
                    Some(s.identity.public().to_armored())
                } else {
                    None
                };
                match armored {
                    Some(Ok(text)) => {
                        ctx.copy_text(text);
                        self.set_toast("Public key copied to clipboard.", false);
                    }
                    Some(Err(e)) => self.set_toast(e.to_string(), true),
                    None => {}
                }
            }
            Action::CancelPreview => {
                if let State::Unlocked(s) = &mut self.state {
                    s.contact_preview = None;
                }
            }
            Action::BeginAddPasskey => {
                if let State::Unlocked(s) = &mut self.state {
                    s.add_passkey = Some(PasskeyEnrollForm::default());
                }
            }
            Action::CancelAddPasskey => {
                if let State::Unlocked(s) = &mut self.state {
                    s.add_passkey = None;
                }
            }
            Action::BeginEnableAutoUnlock => {
                if let State::Unlocked(s) = &mut self.state {
                    s.auto_unlock_form = Some(AutoUnlockForm::default());
                }
            }
            Action::CancelEnableAutoUnlock => {
                if let State::Unlocked(s) = &mut self.state {
                    s.auto_unlock_form = None;
                }
            }
            Action::BeginExportIdentity => {
                if let State::Unlocked(s) = &mut self.state {
                    s.export_identity = Some(ExportIdentityForm::default());
                }
            }
            Action::CancelExportIdentity => {
                if let State::Unlocked(s) = &mut self.state {
                    s.export_identity = None;
                }
            }
            Action::BeginRestore => {
                if let State::FirstRun(f) = &mut self.state {
                    // Pick the backup file up front; only open the restore card
                    // once a file is chosen (cancelling the picker is a no-op).
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("FileSec identity backup", &["fsecid"])
                        .pick_file()
                    {
                        f.error = None;
                        f.restore = Some(RestoreForm {
                            path,
                            backup_pass: String::new(),
                            new_pass: String::new(),
                            new_pass2: String::new(),
                            error: None,
                        });
                    }
                }
            }
            Action::CancelRestore => {
                if let State::FirstRun(f) = &mut self.state {
                    f.restore = None;
                }
            }
            Action::CancelVerify => {
                if let State::Unlocked(s) = &mut self.state {
                    s.verify = None;
                }
            }
            Action::BeginVerify(fpr_hex) => self.begin_verify(fpr_hex),
            Action::CopyVerifySafetyNumber => {
                if let State::Unlocked(s) = &self.state {
                    if let Some(v) = &s.verify {
                        ctx.copy_text(v.safety_number.clone());
                        self.set_toast("Safety number copied to clipboard.", false);
                    }
                }
            }
            Action::AddSenderToContacts => {
                // Stage the just-imported container's sender (an unknown party)
                // for confirmation, then close the import dialog behind it.
                if let State::Unlocked(s) = &mut self.state {
                    if let Some(sender) = s.last_import.as_ref().map(|i| i.sender.clone()) {
                        let preview = build_contact_preview(s, sender);
                        s.contact_preview = Some(preview);
                        s.last_import = None;
                    }
                }
            }
            // --- background jobs ---
            Action::CreateIdentity => self.spawn_create_identity(ctx),
            Action::Unlock => self.spawn_unlock(ctx),
            Action::UnlockWithPasskey => self.spawn_unlock_passkey(ctx),
            Action::AddPasskey => self.spawn_add_passkey(ctx),
            Action::RemovePasskey(i) => self.spawn_remove_passkey(ctx, i),
            Action::UnlockWithKeyring => self.spawn_unlock_keyring(ctx),
            Action::ConfirmEnableAutoUnlock => self.spawn_enable_auto_unlock(ctx),
            Action::DisableAutoUnlock => self.spawn_disable_auto_unlock(ctx),
            Action::CreateVault => self.spawn_create_vault(ctx),
            Action::OpenVault(id) => self.spawn_open_vault(ctx, id),
            Action::DeleteVault(id) => self.spawn_delete_vault(ctx, id),
            Action::AddFiles => self.spawn_add_files(ctx),
            Action::AddFolder => self.spawn_add_folder(ctx),
            Action::DropPaths(paths) => self.spawn_add_paths(ctx, paths),
            Action::NewFolder => self.spawn_new_folder(ctx),
            Action::NewFile => self.spawn_new_file(ctx),
            Action::QuickEdit(p) => self.spawn_quick_edit(ctx, p),
            Action::SaveTextFile => self.spawn_save_text_file(ctx),
            Action::Trash(p) => self.spawn_trash_entry(ctx, p),
            Action::TrashSelected => self.spawn_trash_selected(ctx),
            Action::RestoreTrashed(p) => self.spawn_restore(ctx, p),
            Action::PurgeTrashed(p) => self.spawn_purge(ctx, p),
            Action::EmptyTrash => self.spawn_empty_trash(ctx),
            Action::ConfirmRename => self.spawn_rename(ctx),
            Action::ConfirmMove => self.spawn_move(ctx),
            Action::ExtractSelected => self.spawn_extract_selected(ctx),
            Action::ExtractAll => self.spawn_extract_all(ctx),
            Action::SaveEntryAs(p) => self.spawn_save_entry_as(ctx, p),
            Action::ViewFile(p) => self.spawn_view(ctx, p),
            Action::CheckOut(p) => self.spawn_check_out(ctx, p),
            Action::CheckIn => self.spawn_check_in(ctx),
            Action::Discard => self.spawn_discard(ctx),
            Action::ImportContainer => self.spawn_import(ctx),
            Action::DoExport => self.spawn_export(ctx),
            Action::PreviewContactPaste => self.preview_contact_paste(),
            Action::PreviewContactFile => self.preview_contact_file(),
            Action::ConfirmAddContact => self.spawn_confirm_add_contact(ctx),
            Action::ConfirmVerify(fpr) => self.confirm_verify(ctx, fpr),
            Action::SetTrust(fpr, t) => self.spawn_set_trust(ctx, fpr, t),
            Action::RemoveContact(fpr) => self.spawn_remove_contact(ctx, fpr),
            Action::SavePubKey => self.spawn_save_pubkey(ctx),
            Action::DoExportIdentity => self.spawn_export_identity(ctx),
            Action::DoRestore => self.spawn_restore_identity(ctx),
        }
    }

    fn spawn_create_identity(&mut self, ctx: &egui::Context) {
        let (name, pass) = {
            let f = match &mut self.state {
                State::FirstRun(f) => f,
                _ => return,
            };
            let name = f.name.trim().to_string();
            if name.is_empty() {
                f.error = Some("Please enter a display name.".into());
                return;
            }
            if let Some(error) = passphrase_policy_error(&f.pass) {
                f.error = Some(error);
                return;
            }
            if f.pass != f.pass2 {
                f.error = Some("Passphrases do not match.".into());
                return;
            }
            f.error = None;
            f.pass2.zeroize();
            // Move the passphrase into a zeroizing buffer so it is wiped after the
            // worker hands it to the keystore, not just dropped.
            (name, Zeroizing::new(std::mem::take(&mut f.pass)))
        };
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        self.spawn_job(ctx, "Creating identity…", move || {
            // New identities are always **classical** by default — even in a build
            // that has the post-quantum suites compiled in. Going post-quantum is an
            // explicit, opt-in step via "Upgrade to post-quantum" in My Identity
            // (which keeps the same X25519/Ed25519 keys and adds the lattice keys).
            // This keeps a fresh identity's safety number stable and predictable and
            // avoids pushing the larger hybrid identity on everyone.
            let generated = Identity::generate(&name, now_unix());
            let identity = match generated {
                Ok(i) => i,
                Err(e) => {
                    return JobReport {
                        outcome: Outcome::FirstRunFailed(e.to_string()),
                        toast: None,
                    }
                }
            };
            let ks = match KeystoreFile::create(&identity, pass.as_bytes(), KdfParams::default()) {
                Ok(k) => k,
                Err(e) => {
                    return JobReport {
                        outcome: Outcome::FirstRunFailed(e.to_string()),
                        toast: None,
                    }
                }
            };
            if let Err(e) = store.save_keystore(&ks) {
                return JobReport {
                    outcome: Outcome::FirstRunFailed(e),
                    toast: None,
                };
            }
            let data_dir = store.data_dir().display().to_string();
            JobReport::ok(
                Outcome::Unlocked(Box::new(SessionInit {
                    identity,
                    contacts: ContactBook::default(),
                    registry: Registry::default(),
                    passkeys: Vec::new(),
                    // A brand-new identity has nothing saved in the keychain yet.
                    auto_unlock: false,
                    data_dir,
                    rollback_warning: store.rollback_protection_warning().map(str::to_string),
                })),
                "Identity created. Your keys are protected by your passphrase.",
            )
        });
    }

    fn spawn_unlock(&mut self, ctx: &egui::Context) {
        let (pass, legacy_recovery) = match &mut self.state {
            State::Unlock(u) => {
                u.error = None;
                // Wiped after the worker uses it (see `spawn_create_identity`).
                (
                    Zeroizing::new(std::mem::take(&mut u.pass)),
                    u.legacy_recovery,
                )
            }
            _ => return,
        };
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        let label = if legacy_recovery {
            "Recovering and upgrading local state…"
        } else {
            "Unlocking…"
        };
        self.spawn_job(ctx, label, move || {
            let recovery_marker = store.data_dir().join(".legacy-recovery-pending");
            if legacy_recovery {
                let _ = std::fs::write(&recovery_marker, b"FileSec legacy recovery v1\n");
            }
            let ks = match if legacy_recovery {
                match store.load_keystore() {
                    Ok(keystore) => Ok(keystore),
                    Err(e) if e.contains("legacy state requires explicit recovery") => {
                        store.recover_legacy_keystore(pass.as_bytes())
                    }
                    Err(e) => Err(e),
                }
            } else {
                store.load_keystore()
            } {
                Ok(k) => k,
                Err(e) => {
                    return JobReport {
                        outcome: Outcome::UnlockFailed(e),
                        toast: None,
                    }
                }
            };
            let identity = match ks.unlock(pass.as_bytes()) {
                Ok(i) => i,
                Err(e) => {
                    return JobReport {
                        outcome: Outcome::UnlockFailed(e.to_string()),
                        toast: None,
                    }
                }
            };
            let contacts = match store.load_contacts(&identity) {
                Ok(contacts) => contacts,
                Err(e) if legacy_recovery && e.contains("legacy") => {
                    match store.recover_legacy_contacts(&identity) {
                        Ok(contacts) => contacts,
                        Err(e) => {
                            return JobReport {
                                outcome: Outcome::UnlockFailed(e),
                                toast: None,
                            }
                        }
                    }
                }
                Err(e) => {
                    return JobReport {
                        outcome: Outcome::UnlockFailed(e),
                        toast: None,
                    }
                }
            };
            let registry = match store.load_registry(&identity) {
                Ok(registry) => registry,
                Err(e) if legacy_recovery && e.contains("legacy") => {
                    match store.recover_legacy_registry(&identity) {
                        Ok(registry) => registry,
                        Err(e) => {
                            return JobReport {
                                outcome: Outcome::UnlockFailed(e),
                                toast: None,
                            }
                        }
                    }
                }
                Err(e) => {
                    return JobReport {
                        outcome: Outcome::UnlockFailed(e),
                        toast: None,
                    }
                }
            };
            if legacy_recovery {
                for meta in &registry.vaults {
                    match store.open_vault(&identity, &meta.id) {
                        Ok(_) => {}
                        Err(e) if e.contains("legacy") => {
                            if let Err(e) = store.recover_legacy_vault(&identity, &meta.id) {
                                return JobReport {
                                    outcome: Outcome::UnlockFailed(format!(
                                        "Could not recover vault \"{}\": {e}",
                                        meta.name
                                    )),
                                    toast: None,
                                };
                            }
                        }
                        Err(e) => {
                            return JobReport {
                                outcome: Outcome::UnlockFailed(format!(
                                    "Could not validate vault \"{}\": {e}",
                                    meta.name
                                )),
                                toast: None,
                            }
                        }
                    }
                }
            }
            let passkeys = ks.passkey_slots();
            let data_dir = store.data_dir().display().to_string();
            // Securely wipe any checkout temp files orphaned by a prior crash,
            // plus any vault-migration scratch dirs left behind by a crash.
            store.clean_checkout_dir();
            store.clean_partial_dirs();
            if legacy_recovery {
                let _ = std::fs::remove_file(&recovery_marker);
            }
            JobReport::ok(
                Outcome::Unlocked(Box::new(SessionInit {
                    identity,
                    contacts,
                    registry,
                    passkeys,
                    auto_unlock: autounlock::is_saved(&data_dir),
                    data_dir,
                    rollback_warning: store.rollback_protection_warning().map(str::to_string),
                })),
                if legacy_recovery {
                    "Legacy local state recovered and upgraded with rollback protection."
                } else {
                    "Unlocked."
                },
            )
        });
    }

    /// Unlock by deriving a key from an enrolled security key (passkey). Tries
    /// each enrolled slot against the connected key; the first that the present
    /// authenticator satisfies opens the keystore.
    fn spawn_unlock_passkey(&mut self, ctx: &egui::Context) {
        let pin = match &mut self.state {
            State::Unlock(u) => {
                u.error = None;
                let pin = u.pin.trim().to_string();
                if pin.is_empty() {
                    None
                } else {
                    Some(Zeroizing::new(pin))
                }
            }
            _ => return,
        };
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        self.spawn_job(ctx, "Waiting for your security key…", move || {
            let ks = match store.load_keystore() {
                Ok(k) => k,
                Err(e) => {
                    return JobReport {
                        outcome: Outcome::UnlockFailed(e),
                        toast: None,
                    }
                }
            };
            let slots = ks.passkey_slots();
            if slots.is_empty() {
                return JobReport {
                    outcome: Outcome::UnlockFailed("No security keys are enrolled.".into()),
                    toast: None,
                };
            }
            let pin = pin.as_deref().map(|s| s.as_str());
            // Try each enrolled credential; the connected key only answers for
            // the one it actually holds. `passkey_slots()` is in keystore order,
            // so the enumerate index is the slot index for `unlock_with_passkey`.
            let mut last_err =
                String::from("Your security key did not match any enrolled passkey.");
            for (i, slot) in slots.iter().enumerate() {
                let salt: [u8; HMAC_SECRET_LEN] = match slot.hmac_salt.as_slice().try_into() {
                    Ok(s) => s,
                    Err(_) => continue, // malformed slot; skip
                };
                let secret = match passkey::assert(&slot.credential_id, &salt, pin) {
                    Ok(s) => s,
                    Err(e) => {
                        last_err = e.to_string();
                        continue;
                    }
                };
                match ks.unlock_with_passkey(i, &secret) {
                    Ok(identity) => {
                        let contacts = match store.load_contacts(&identity) {
                            Ok(contacts) => contacts,
                            Err(e) => {
                                return JobReport {
                                    outcome: Outcome::UnlockFailed(e),
                                    toast: None,
                                }
                            }
                        };
                        let registry = match store.load_registry(&identity) {
                            Ok(registry) => registry,
                            Err(e) => {
                                return JobReport {
                                    outcome: Outcome::UnlockFailed(e),
                                    toast: None,
                                }
                            }
                        };
                        let passkeys = ks.passkey_slots();
                        let data_dir = store.data_dir().display().to_string();
                        store.clean_checkout_dir();
                        store.clean_partial_dirs();
                        return JobReport::ok(
                            Outcome::Unlocked(Box::new(SessionInit {
                                identity,
                                contacts,
                                registry,
                                passkeys,
                                auto_unlock: autounlock::is_saved(&data_dir),
                                data_dir,
                                rollback_warning: store
                                    .rollback_protection_warning()
                                    .map(str::to_string),
                            })),
                            "Unlocked with your security key.",
                        );
                    }
                    Err(e) => last_err = e.to_string(),
                }
            }
            JobReport {
                outcome: Outcome::UnlockFailed(last_err),
                toast: None,
            }
        });
    }

    /// Enroll a new security key as an additional unlock method. Reads the open
    /// "add security key" dialog (label + passphrase + optional PIN).
    fn spawn_add_passkey(&mut self, ctx: &egui::Context) {
        let (label, pass, pin) = match &mut self.state {
            State::Unlocked(s) => match &mut s.add_passkey {
                Some(f) => {
                    let label = f.label.trim().to_string();
                    if label.is_empty() {
                        f.error = Some("Give this key a name so you can recognize it.".into());
                        return;
                    }
                    if f.pass.is_empty() {
                        f.error = Some("Enter your passphrase to authorize this change.".into());
                        return;
                    }
                    f.error = None;
                    let pin = f.pin.trim().to_string();
                    let pin = if pin.is_empty() {
                        None
                    } else {
                        Some(Zeroizing::new(pin))
                    };
                    (label, Zeroizing::new(std::mem::take(&mut f.pass)), pin)
                }
                None => return,
            },
            _ => return,
        };
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        self.spawn_job(
            ctx,
            "Touch your security key twice to enroll it…",
            move || {
                // 1. Talk to the hardware (blocks on a touch).
                let enrollment =
                    match passkey::enroll(&label, pin.as_deref().map(|s| s.as_str()), now_unix()) {
                        Ok(e) => e,
                        Err(e) => {
                            return JobReport::err(format!(
                                "Could not enroll the security key: {e}"
                            ))
                        }
                    };
                // 2. Wrap the keystore's data key under the new passkey (authorized by
                //    the passphrase) and persist atomically.
                let mut ks = match store.load_keystore() {
                    Ok(k) => k,
                    Err(e) => return JobReport::err(e),
                };
                if let Err(e) = ks.add_passkey(pass.as_bytes(), enrollment) {
                    return JobReport::err(e.to_string());
                }
                if let Err(e) = store.save_keystore(&ks) {
                    return JobReport::err(e);
                }
                JobReport::ok(
                    Outcome::PasskeysUpdated(ks.passkey_slots()),
                    "Security key enrolled. You can now unlock with it.",
                )
            },
        );
    }

    /// Remove the enrolled passkey at `index`. The passphrase always remains, so
    /// this never risks a lockout.
    fn spawn_remove_passkey(&mut self, ctx: &egui::Context, index: usize) {
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        let identity = match self.ident_arc() {
            Some(identity) => identity,
            None => return,
        };
        self.spawn_job(ctx, "Removing security key…", move || {
            let mut ks = match store.load_keystore() {
                Ok(k) => k,
                Err(e) => return JobReport::err(e),
            };
            if let Err(e) = ks.remove_passkey(index, &identity) {
                return JobReport::err(e.to_string());
            }
            if let Err(e) = store.save_keystore(&ks) {
                return JobReport::err(e);
            }
            JobReport::ok(
                Outcome::PasskeysUpdated(ks.passkey_slots()),
                "Security key removed.",
            )
        });
    }

    /// Unlock using the random device token saved in the OS keychain for this
    /// data dir. The token wraps the keystore's data key in a device keyslot —
    /// the passphrase is never stored. If the token is gone or stale it falls
    /// back to the passphrase prompt with a clear message (and drops the entry).
    fn spawn_unlock_keyring(&mut self, ctx: &egui::Context) {
        if let State::Unlock(u) = &mut self.state {
            u.error = None;
        }
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        self.spawn_job(ctx, "Unlocking from this device…", move || {
            let data_dir = store.data_dir().display().to_string();
            let token = match autounlock::load_device_token(&data_dir) {
                Ok(Some(s)) => s,
                Ok(None) => {
                    return JobReport {
                        outcome: Outcome::UnlockFailed(
                            "This device has no saved unlock. Enter your passphrase.".into(),
                        ),
                        toast: None,
                    }
                }
                Err(e) => {
                    return JobReport {
                        outcome: Outcome::UnlockFailed(e.to_string()),
                        toast: None,
                    }
                }
            };
            let ks = match store.load_keystore() {
                Ok(k) => k,
                Err(e) => {
                    return JobReport {
                        outcome: Outcome::UnlockFailed(e),
                        toast: None,
                    }
                }
            };
            let identity = match ks.unlock_with_device_token(token.as_slice()) {
                Ok(i) => i,
                Err(_) => {
                    // The token no longer opens the keystore (e.g. auto-unlock
                    // was reset elsewhere, or the device slot was removed).
                    // Drop the stale token so the UI falls back cleanly.
                    let _ = autounlock::clear_device_token(&data_dir);
                    return JobReport {
                        outcome: Outcome::UnlockFailed(
                            "This device's saved unlock no longer works and was removed. \
                             Enter your passphrase."
                                .into(),
                        ),
                        toast: None,
                    };
                }
            };
            let contacts = match store.load_contacts(&identity) {
                Ok(contacts) => contacts,
                Err(e) => {
                    return JobReport {
                        outcome: Outcome::UnlockFailed(e),
                        toast: None,
                    }
                }
            };
            let registry = match store.load_registry(&identity) {
                Ok(registry) => registry,
                Err(e) => {
                    return JobReport {
                        outcome: Outcome::UnlockFailed(e),
                        toast: None,
                    }
                }
            };
            let passkeys = ks.passkey_slots();
            store.clean_checkout_dir();
            store.clean_partial_dirs();
            JobReport::ok(
                Outcome::Unlocked(Box::new(SessionInit {
                    identity,
                    contacts,
                    registry,
                    passkeys,
                    auto_unlock: true,
                    data_dir,
                    rollback_warning: store.rollback_protection_warning().map(str::to_string),
                })),
                "Unlocked from this device.",
            )
        });
    }

    /// Verify the entered passphrase, then enroll a random device token: it wraps
    /// the keystore's data key in a device keyslot and is saved to the OS
    /// keychain. The passphrase itself is never stored (F09).
    fn spawn_enable_auto_unlock(&mut self, ctx: &egui::Context) {
        let pass = match &mut self.state {
            State::Unlocked(s) => match &mut s.auto_unlock_form {
                Some(f) => {
                    if f.pass.is_empty() {
                        f.error = Some("Enter your passphrase to confirm.".into());
                        return;
                    }
                    f.error = None;
                    // Wiped after the worker uses it (see `spawn_create_identity`).
                    Zeroizing::new(std::mem::take(&mut f.pass))
                }
                None => return,
            },
            _ => return,
        };
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        self.spawn_job(ctx, "Saving to this device…", move || {
            let mut ks = match store.load_keystore() {
                Ok(k) => k,
                Err(e) => return JobReport::err(e),
            };
            // Confirm the passphrase opens the keystore, and keep the identity so
            // a keychain failure can undo the on-disk device slot cleanly.
            let identity = match ks.unlock(pass.as_bytes()) {
                Ok(i) => i,
                Err(_) => return JobReport::err("That passphrase is incorrect."),
            };
            // A full-entropy device token — never the passphrase — is what lands
            // in the keychain.
            let token =
                match filesec_core::secret::random_secret(filesec_core::keystore::DEVICE_TOKEN_LEN)
                {
                    Ok(t) => t,
                    Err(_) => return JobReport::err("Secure random generation failed."),
                };
            if let Err(e) = ks.set_device_token(pass.as_bytes(), &token) {
                return JobReport::err(e.to_string());
            }
            if let Err(e) = store.save_keystore(&ks) {
                return JobReport::err(e);
            }
            let data_dir = store.data_dir().display().to_string();
            if let Err(e) = autounlock::save_device_token(&data_dir, &token) {
                // Best-effort: undo the on-disk device slot so it doesn't dangle
                // without a matching token. The passphrase always still works.
                if ks.remove_device_token(&identity).is_ok() {
                    let _ = store.save_keystore(&ks);
                }
                return JobReport::err(e.to_string());
            }
            JobReport::ok(
                Outcome::AutoUnlockChanged(true),
                "This device will now unlock automatically. Your passphrase still works.",
            )
        });
    }

    /// Forget this device's auto-unlock: clear the keychain token and remove the
    /// device keyslot from the keystore (advancing its rollback-protected epoch,
    /// so a restored older keystore cannot silently re-enable it).
    fn spawn_disable_auto_unlock(&mut self, ctx: &egui::Context) {
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        let identity = match self.ident_arc() {
            Some(i) => i,
            None => return,
        };
        self.spawn_job(ctx, "Updating this device…", move || {
            let data_dir = store.data_dir().display().to_string();
            // Remove the device keyslot first (if any), then clear the token.
            match store.load_keystore() {
                Ok(mut ks) if ks.has_device_token() => {
                    if let Err(e) = ks.remove_device_token(&identity) {
                        return JobReport::err(e.to_string());
                    }
                    if let Err(e) = store.save_keystore(&ks) {
                        return JobReport::err(e);
                    }
                }
                Ok(_) => {}
                Err(e) => return JobReport::err(e),
            }
            if let Err(e) = autounlock::clear_device_token(&data_dir) {
                return JobReport::err(e.to_string());
            }
            JobReport::ok(
                Outcome::AutoUnlockChanged(false),
                "This device will no longer unlock automatically.",
            )
        });
    }

    fn spawn_create_vault(&mut self, ctx: &egui::Context) {
        let (name, registry) = match &self.state {
            State::Unlocked(s) => (s.new_vault_name.trim().to_string(), s.registry.clone()),
            _ => return,
        };
        if name.is_empty() {
            self.set_toast("Enter a vault name.", true);
            return;
        }
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        self.spawn_job(ctx, "Creating vault…", move || {
            let id = match new_vault_id() {
                Ok(id) => id,
                Err(e) => return JobReport::err(e),
            };
            let vault = Vault::new(&name, now_unix());
            if let Err(e) = store.save_vault(&identity, &id, &vault) {
                return JobReport::err(e);
            }
            let reader = match store.open_vault(&identity, &id) {
                Ok(r) => r,
                Err(e) => return JobReport::err(e),
            };
            let mut registry = registry;
            registry.upsert(VaultMeta {
                id: id.clone(),
                name: name.clone(),
                created_at: reader.created_at(),
                modified_at: now_unix(),
                file_count: 0,
                total_size: 0,
            });
            if let Err(e) = store.save_registry(&identity, &registry) {
                return JobReport::err(e);
            }
            JobReport::ok(
                Outcome::Created {
                    registry,
                    id,
                    reader: Box::new(reader),
                },
                format!("Created vault \"{name}\"."),
            )
        });
    }

    fn spawn_open_vault(&mut self, ctx: &egui::Context, id: String) {
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        self.spawn_job(ctx, "Opening vault…", move || {
            match store.open_vault(&identity, &id) {
                Ok(reader) => {
                    let name = reader.name().to_string();
                    JobReport::ok(
                        Outcome::SetOpen {
                            id,
                            reader: Box::new(reader),
                        },
                        format!("Opened \"{name}\"."),
                    )
                }
                Err(e) => JobReport::err(e),
            }
        });
    }

    fn spawn_delete_vault(&mut self, ctx: &egui::Context, id: String) {
        let registry = match &self.state {
            State::Unlocked(s) => s.registry.clone(),
            _ => return,
        };
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        self.spawn_job(ctx, "Deleting vault…", move || {
            if let Err(e) = store.delete_vault_file(&id) {
                return JobReport::err(e);
            }
            let mut registry = registry;
            registry.remove(&id);
            if let Err(e) = store.save_registry(&identity, &registry) {
                return JobReport::err(e);
            }
            JobReport::ok(
                Outcome::Deleted {
                    registry,
                    closed_id: id,
                },
                "Vault deleted.",
            )
        });
    }

    /// The folder currently being browsed in the open vault ("" = root).
    fn current_dir(&self) -> String {
        if let State::Unlocked(s) = &self.state {
            s.current_dir.clone()
        } else {
            String::new()
        }
    }

    fn spawn_add_files(&mut self, ctx: &egui::Context) {
        let files = match rfd::FileDialog::new().pick_files() {
            Some(f) => f,
            None => return,
        };
        self.add_sources(ctx, files);
    }

    fn spawn_add_folder(&mut self, ctx: &egui::Context) {
        let base = match rfd::FileDialog::new().pick_folder() {
            Some(p) => p,
            None => return,
        };
        self.add_sources(ctx, vec![base]);
    }

    /// Add OS files/folders dropped onto the window. Same path as the pickers.
    fn spawn_add_paths(&mut self, ctx: &egui::Context, paths: Vec<std::path::PathBuf>) {
        self.add_sources(ctx, paths);
    }

    /// Shared core for adding OS files/folders into the open vault at the current
    /// folder — used by "Add files…", "Add folder…", and drag-and-drop. Each
    /// source streams straight from disk; nothing is held in memory at once.
    fn add_sources(&mut self, ctx: &egui::Context, sources: Vec<std::path::PathBuf>) {
        if sources.is_empty() {
            return;
        }
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let into = self.current_dir();
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        self.spawn_job(ctx, "Encrypting…", move || {
            let (added, dirs, failed) = plan_additions(&reader, &into, &sources);
            if added.is_empty() && dirs.is_empty() {
                return JobReport::err(if failed > 0 {
                    format!("{failed} item(s) could not be read.")
                } else {
                    "Nothing new to add.".into()
                });
            }
            let n = added.len();
            if let Err(e) = store.append_files_to_vault(&identity, &id, &reader, &added, &dirs) {
                return JobReport::err(e);
            }
            let dest = if into.is_empty() {
                String::new()
            } else {
                format!(" to {}", leaf_name(&into))
            };
            let msg = if failed > 0 {
                format!("Added {n} file(s){dest}; {failed} could not be read.")
            } else {
                format!("Added {n} file(s){dest}.")
            };
            finalize_after_save(&store, &identity, id, registry, msg)
        });
    }

    fn spawn_new_folder(&mut self, ctx: &egui::Context) {
        let (leaf, into) = match &self.state {
            State::Unlocked(s) => (s.new_folder_name.trim().to_string(), s.current_dir.clone()),
            _ => return,
        };
        if leaf.is_empty() {
            self.set_toast("Enter a folder name.", true);
            return;
        }
        // A folder name is a single path segment; a slash would silently create a
        // nested tree and desync the breadcrumb, so reject it.
        if leaf.contains('/') {
            self.set_toast("Folder names can't contain “/”.", true);
            return;
        }
        if let State::Unlocked(s) = &mut self.state {
            s.new_folder_name.clear();
            s.show_new_folder = false;
        }
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        let vault_path = if into.is_empty() {
            leaf.clone()
        } else {
            format!("{into}/{leaf}")
        };
        self.spawn_job(ctx, "Saving…", move || {
            // Stream the existing data through unchanged and just add the dir entry
            // — no need to decrypt the whole vault into memory.
            if reader.entries().iter().any(|e| e.path == vault_path) {
                return JobReport::err(format!("\"{leaf}\" already exists here."));
            }
            if let Err(e) = store.append_files_to_vault(
                &identity,
                &id,
                &reader,
                &[],
                std::slice::from_ref(&vault_path),
            ) {
                return JobReport::err(e);
            }
            finalize_after_save(
                &store,
                &identity,
                id,
                registry,
                format!("Created folder \"{leaf}\"."),
            )
        });
    }

    /// Create an empty text file (any name/extension) in the current folder and
    /// open it straight in the in-app quick editor.
    fn spawn_new_file(&mut self, ctx: &egui::Context) {
        let (leaf, into) = match &self.state {
            State::Unlocked(s) => (s.new_file_name.trim().to_string(), s.current_dir.clone()),
            _ => return,
        };
        if leaf.is_empty() {
            self.set_toast("Enter a file name.", true);
            return;
        }
        if leaf.contains('/') {
            self.set_toast("File names can't contain “/”.", true);
            return;
        }
        if let State::Unlocked(s) = &mut self.state {
            s.new_file_name.clear();
            s.show_new_file = false;
        }
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        let vault_path = if into.is_empty() {
            leaf.clone()
        } else {
            format!("{into}/{leaf}")
        };
        self.spawn_job(ctx, "Creating…", move || {
            if reader.entries().iter().any(|e| e.path == vault_path) {
                return JobReport::err(format!("\"{leaf}\" already exists here."));
            }
            if let Err(e) = store.put_bytes_in_vault(
                &identity,
                &id,
                &reader,
                &vault_path,
                b"",
                Some(now_unix()),
            ) {
                return JobReport::err(e);
            }
            match reopen_after_save(&store, &identity, id, registry) {
                Ok((id, reader, registry)) => JobReport::ok(
                    Outcome::CreatedTextFile {
                        id,
                        reader: Box::new(reader),
                        registry,
                        path: vault_path,
                        leaf,
                    },
                    // The editor opening is the feedback — no toast.
                    String::new(),
                ),
                Err(e) => JobReport::err(e),
            }
        });
    }

    /// Decrypt a file and, if it is valid UTF-8 text within the size cap, open it
    /// in the in-app quick editor (the plaintext only ever lives in memory).
    fn spawn_quick_edit(&mut self, ctx: &egui::Context, path: String) {
        let (_, reader) = match self.open_reader() {
            Some(x) => x,
            None => return,
        };
        let leaf = leaf_name(&path).to_string();
        // Guard the in-memory editor against huge files (and non-files).
        const MAX_EDIT: u64 = 4 * 1024 * 1024;
        match reader.entries().iter().find(|e| e.path == path) {
            Some(e) if e.kind == EntryKind::File => {
                if e.size > MAX_EDIT {
                    self.set_toast(
                        "That file is too large for the quick editor — use Save as… instead.",
                        true,
                    );
                    return;
                }
            }
            _ => {
                self.set_toast("Only files can be edited.", true);
                return;
            }
        }
        self.spawn_job(ctx, "Opening…", move || {
            let bytes = match reader.read_entry(&path) {
                Ok(b) => b,
                Err(e) => return JobReport::err(e.to_string()),
            };
            match std::str::from_utf8(&bytes) {
                Ok(text) => JobReport::ok(
                    Outcome::OpenTextEditor(Box::new(TextEditor {
                        path,
                        leaf,
                        content: text.to_string(),
                        original: text.to_string(),
                    })),
                    String::new(),
                ),
                Err(_) => JobReport::err(
                    "This file isn't text — use “Check out & edit” to open it in an app.",
                ),
            }
        });
    }

    /// Save the quick editor's buffer back to the vault as a fresh blob.
    fn spawn_save_text_file(&mut self, ctx: &egui::Context) {
        let (path, content) = match &self.state {
            State::Unlocked(s) => match &s.text_editor {
                Some(te) => (te.path.clone(), te.content.clone()),
                None => return,
            },
            _ => return,
        };
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        let leaf = leaf_name(&path).to_string();
        self.spawn_job(ctx, "Saving…", move || {
            if let Err(e) = store.put_bytes_in_vault(
                &identity,
                &id,
                &reader,
                &path,
                content.as_bytes(),
                Some(now_unix()),
            ) {
                return JobReport::err(e);
            }
            match reopen_after_save(&store, &identity, id, registry) {
                Ok((id, reader, registry)) => JobReport::ok(
                    Outcome::SavedTextFile {
                        id,
                        reader: Box::new(reader),
                        registry,
                    },
                    format!("Saved “{leaf}”."),
                ),
                Err(e) => JobReport::err(e),
            }
        });
    }

    /// Soft-delete the browser selection (files and/or folders): each top-level
    /// entry is moved into the trash in one manifest-only pass (no blob is
    /// decrypted or rewritten), so it can be restored later. Each gets its own
    /// trash token, so two items with the same name never collide.
    fn spawn_trash_selected(&mut self, ctx: &egui::Context) {
        let paths: Vec<String> = match &self.state {
            State::Unlocked(s) => prune_nested(&s.selected.iter().cloned().collect::<Vec<_>>()),
            _ => return,
        };
        if paths.is_empty() {
            self.set_toast("Select something first.", true);
            return;
        }
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        let now = now_unix();
        let pairs: Vec<(String, String)> = match paths
            .iter()
            .map(|p| trash_tag().map(|tag| (p.clone(), trash_dest(now, &tag, p))))
            .collect::<StoreResult<_>>()
        {
            Ok(pairs) => pairs,
            Err(e) => {
                self.set_toast(e, true);
                return;
            }
        };
        let n = pairs.len();
        self.spawn_job(ctx, "Moving to Trash…", move || {
            if let Err(e) = store.rename_in_vault(&identity, &id, &reader, &pairs) {
                return JobReport::err(e);
            }
            finalize_after_save(
                &store,
                &identity,
                id,
                registry,
                format!("Moved {n} item(s) to Trash."),
            )
        });
    }

    /// Decrypt the browser selection to a chosen folder, recreating each file's
    /// vault-relative path underneath it. A selected folder expands to all of its
    /// files (its subtree is recreated).
    fn spawn_extract_selected(&mut self, ctx: &egui::Context) {
        let selected: Vec<String> = match &self.state {
            State::Unlocked(s) => s.selected.iter().cloned().collect(),
            _ => return,
        };
        if selected.is_empty() {
            self.set_toast("Select something to extract first.", true);
            return;
        }
        let (_, reader) = match self.open_reader() {
            Some(x) => x,
            None => return,
        };
        // Expand any selected folder into the files it contains.
        let entries = snapshot_entries(&reader);
        let mut paths: Vec<String> = Vec::new();
        for sel in &selected {
            let is_dir = entries
                .iter()
                .any(|(p, k, _)| p == sel && *k == EntryKind::Dir);
            if is_dir {
                let prefix = format!("{sel}/");
                for (p, k, _) in &entries {
                    if *k == EntryKind::File && p.starts_with(&prefix) {
                        paths.push(p.clone());
                    }
                }
            } else {
                paths.push(sel.clone());
            }
        }
        paths.sort();
        paths.dedup();
        if paths.is_empty() {
            self.set_toast("Nothing to extract (the selected folders are empty).", true);
            return;
        }
        let dest = match rfd::FileDialog::new().pick_folder() {
            Some(p) => p,
            None => return,
        };
        let n = paths.len();
        self.spawn_job(ctx, "Decrypting…", move || {
            let mut failed = 0usize;
            for path in &paths {
                // Each file streams through the hardened writer: parents are made
                // without following planted symlinks, the plaintext is verified as
                // it decrypts, and only a complete verified file is renamed into
                // place — a failure leaves no partial plaintext under `dest`.
                if crate::store::extract_file_hardened(&dest, path, |w| {
                    reader.read_entry_to_writer(path, w)
                })
                .is_err()
                {
                    failed += 1;
                }
            }
            let saved = n - failed;
            if saved == 0 {
                return JobReport::err("Could not extract the selected files.");
            }
            let msg = if failed > 0 {
                format!(
                    "Extracted {saved} file(s) to {}; {failed} failed.",
                    dest.display()
                )
            } else {
                format!("Extracted {saved} file(s) to {}.", dest.display())
            };
            JobReport::ok(Outcome::Noop, msg)
        });
    }

    /// Soft-delete a single entry (a file, or a folder and its whole subtree) by
    /// moving it into the trash. Restorable until the trash is emptied.
    fn spawn_trash_entry(&mut self, ctx: &egui::Context, path: String) {
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        let tag = match trash_tag() {
            Ok(tag) => tag,
            Err(e) => {
                self.set_toast(e, true);
                return;
            }
        };
        let dest = trash_dest(now_unix(), &tag, &path);
        let leaf = leaf_name(&path).to_string();
        self.spawn_job(ctx, "Moving to Trash…", move || {
            // A manifest-only rename: the blobs stay put, nothing is decrypted.
            if let Err(e) = store.rename_in_vault(&identity, &id, &reader, &[(path, dest)]) {
                return JobReport::err(e);
            }
            finalize_after_save(
                &store,
                &identity,
                id,
                registry,
                format!("Moved “{leaf}” to Trash."),
            )
        });
    }

    /// Restore a trashed entry to its original location — recreating any parent
    /// folders that were removed meanwhile, and de-duplicating the name if
    /// something already lives there (so a restore never clobbers a live file).
    fn spawn_restore(&mut self, ctx: &egui::Context, trashed_path: String) {
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        let orig = match parse_trash_token(&trashed_path) {
            Some((_, orig)) => orig,
            None => {
                self.set_toast("That item's original name couldn't be read.", true);
                return;
            }
        };
        let taken: HashSet<String> = snapshot_entries(&reader)
            .into_iter()
            .map(|(p, _, _)| p)
            .collect();
        let dest = dedup_path(&taken, &orig);
        let leaf = leaf_name(&dest).to_string();
        self.spawn_job(ctx, "Restoring…", move || {
            if let Err(e) = store.rename_in_vault(&identity, &id, &reader, &[(trashed_path, dest)])
            {
                return JobReport::err(e);
            }
            finalize_after_save(
                &store,
                &identity,
                id,
                registry,
                format!("Restored “{leaf}”."),
            )
        });
    }

    /// Permanently delete one trashed entry (unlinks its blobs — unrecoverable).
    fn spawn_purge(&mut self, ctx: &egui::Context, trashed_path: String) {
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        self.spawn_job(ctx, "Deleting…", move || {
            if let Err(e) = store.remove_paths_from_vault(
                &identity,
                &id,
                &reader,
                std::slice::from_ref(&trashed_path),
            ) {
                return JobReport::err(e);
            }
            finalize_after_save(
                &store,
                &identity,
                id,
                registry,
                "Deleted permanently.".into(),
            )
        });
    }

    /// Permanently delete everything in the trash in one pass.
    fn spawn_empty_trash(&mut self, ctx: &egui::Context) {
        if let State::Unlocked(s) = &mut self.state {
            s.confirm_empty_trash = false;
        }
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        self.spawn_job(ctx, "Emptying Trash…", move || {
            if let Err(e) =
                store.remove_paths_from_vault(&identity, &id, &reader, &[TRASH_DIR.to_string()])
            {
                return JobReport::err(e);
            }
            finalize_after_save(&store, &identity, id, registry, "Trash emptied.".into())
        });
    }

    /// Apply the inline rename: move the target entry to a sibling with the typed
    /// name (manifest-only; a folder keeps its whole subtree).
    fn spawn_rename(&mut self, ctx: &egui::Context) {
        let (from, leaf) = match &self.state {
            State::Unlocked(s) => match &s.rename_target {
                Some(p) => (p.clone(), s.rename_input.trim().to_string()),
                None => return,
            },
            _ => return,
        };
        // Close the composer up front; validation errors surface as a toast.
        if let State::Unlocked(s) = &mut self.state {
            s.rename_target = None;
            s.rename_input.clear();
        }
        if leaf.is_empty() {
            self.set_toast("Enter a name.", true);
            return;
        }
        if leaf.contains('/') {
            self.set_toast("Names can't contain “/”.", true);
            return;
        }
        let parent = parent_dir(&from);
        let to = if parent.is_empty() {
            leaf.clone()
        } else {
            format!("{parent}/{leaf}")
        };
        if to == from {
            return; // No change.
        }
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        self.spawn_job(ctx, "Renaming…", move || {
            if reader.entries().iter().any(|e| e.path == to) {
                return JobReport::err(format!("“{leaf}” already exists here."));
            }
            if let Err(e) = store.rename_in_vault(&identity, &id, &reader, &[(from, to)]) {
                return JobReport::err(e);
            }
            finalize_after_save(
                &store,
                &identity,
                id,
                registry,
                format!("Renamed to “{leaf}”."),
            )
        });
    }

    /// Apply the move: relocate each chosen entry into the destination folder
    /// (manifest-only). A name clash in the destination aborts with a clear
    /// message rather than silently overwriting or merging.
    fn spawn_move(&mut self, ctx: &egui::Context) {
        let (paths, dest) = match &self.state {
            State::Unlocked(s) => match &s.move_form {
                Some(f) => (prune_nested(&f.paths), f.dest.clone()),
                None => return,
            },
            _ => return,
        };
        if let State::Unlocked(s) = &mut self.state {
            s.move_form = None;
        }
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        self.spawn_job(ctx, "Moving…", move || {
            let existing: HashSet<String> =
                reader.entries().iter().map(|e| e.path.clone()).collect();
            let mut pairs = Vec::new();
            for from in &paths {
                if parent_dir(from) == dest {
                    continue; // Already in the destination.
                }
                let to = if dest.is_empty() {
                    leaf_name(from).to_string()
                } else {
                    format!("{dest}/{}", leaf_name(from))
                };
                if existing.contains(&to) {
                    return JobReport::err(format!(
                        "“{}” already exists in that folder.",
                        leaf_name(from)
                    ));
                }
                pairs.push((from.clone(), to));
            }
            if pairs.is_empty() {
                return JobReport::err("Those items are already there.");
            }
            let n = pairs.len();
            if let Err(e) = store.rename_in_vault(&identity, &id, &reader, &pairs) {
                return JobReport::err(e);
            }
            let where_to = if dest.is_empty() {
                "the top level".to_string()
            } else {
                format!("“{}”", leaf_name(&dest))
            };
            finalize_after_save(
                &store,
                &identity,
                id,
                registry,
                format!("Moved {n} item(s) to {where_to}."),
            )
        });
    }

    fn spawn_extract_all(&mut self, ctx: &egui::Context) {
        let (_, reader) = match self.open_reader() {
            Some(x) => x,
            None => return,
        };
        let dest = match rfd::FileDialog::new().pick_folder() {
            Some(p) => p,
            None => return,
        };
        self.spawn_job(ctx, "Decrypting…", move || {
            // Extract the live tree only — soft-deleted files stay in the trash
            // and are never written to disk (matching what "Send…" exports).
            let mut failed = 0usize;
            let mut files = 0usize;
            for (path, kind, _) in snapshot_entries(&reader) {
                if is_trashed(&path) {
                    continue;
                }
                // Hardened writes: symlink-rejecting parent creation, and per-file
                // authenticate-then-atomically-rename so no partial plaintext lands
                // under `dest`.
                match kind {
                    EntryKind::Dir => {
                        if crate::store::extract_dir_hardened(&dest, &path).is_err() {
                            failed += 1;
                        }
                    }
                    EntryKind::File => {
                        files += 1;
                        if crate::store::extract_file_hardened(&dest, &path, |w| {
                            reader.read_entry_to_writer(&path, w)
                        })
                        .is_err()
                        {
                            failed += 1;
                        }
                    }
                }
            }
            if files == 0 && failed == 0 {
                return JobReport::err("There are no files to extract.");
            }
            let msg = if failed > 0 {
                format!("Extracted to {} ({failed} item(s) failed).", dest.display())
            } else {
                format!("Extracted to {}.", dest.display())
            };
            JobReport::ok(Outcome::Noop, msg)
        });
    }

    fn spawn_save_entry_as(&mut self, ctx: &egui::Context, path: String) {
        // Validate the entry kind from metadata (no decryption) on the UI thread.
        let kind = match &self.state {
            State::Unlocked(s) => match &s.open {
                Some(o) => o
                    .reader
                    .entries()
                    .iter()
                    .find(|e| e.path == path)
                    .map(|e| e.kind),
                None => return,
            },
            _ => return,
        };
        match kind {
            Some(EntryKind::File) => {}
            Some(EntryKind::Dir) => {
                self.set_toast("Only files can be saved.", true);
                return;
            }
            None => {
                self.set_toast("Entry not found.", true);
                return;
            }
        }
        let (_, reader) = match self.open_reader() {
            Some(x) => x,
            None => return,
        };
        let suggested = path.rsplit('/').next().unwrap_or("file").to_string();
        let target = match rfd::FileDialog::new().set_file_name(&suggested).save_file() {
            Some(p) => p,
            None => return,
        };
        self.spawn_job(ctx, "Decrypting file…", move || {
            // Stream this file's chunks into a private temp beside the chosen
            // destination (peak memory is one chunk), verifying as it decrypts,
            // then atomically rename into place. A decryption/authentication
            // failure leaves no partial plaintext, and an existing symlink at the
            // chosen path is refused rather than written through.
            let mut out = match filesec_core::safe_io::SafeFileWriter::create(&target) {
                Ok(w) => w,
                Err(e) => return JobReport::err(e.to_string()),
            };
            if let Err(e) = reader.read_entry_to_writer(&path, &mut out) {
                return JobReport::err(e.to_string());
            }
            match out.commit() {
                Ok(()) => JobReport::ok(Outcome::Noop, format!("Saved to {}", target.display())),
                Err(e) => JobReport::err(e.to_string()),
            }
        });
    }

    /// View a file read-only: decrypt it to a disposable, read-only temp file and
    /// open it in the OS default app. There is no check-in — a detached watcher
    /// securely wipes the temp the moment the app that opened it closes (where the
    /// platform can report that), and any survivors are wiped when you leave the
    /// vault. Multiple views may be open at once.
    fn spawn_view(&mut self, ctx: &egui::Context, path: String) {
        // Validate kind on the UI thread (metadata only, no decryption). Viewing
        // is disabled while an edit is checked out (the row buttons enforce this
        // too); guard here as well.
        let leaf = {
            let s = match &self.state {
                State::Unlocked(s) => s,
                _ => return,
            };
            if s.checkout.is_some() {
                self.set_toast("Finish your current edit first.", true);
                return;
            }
            let open = match &s.open {
                Some(o) => o,
                None => return,
            };
            match open.reader.entries().iter().find(|e| e.path == path) {
                Some(e) if e.kind == EntryKind::File => {
                    path.rsplit('/').next().unwrap_or("file").to_string()
                }
                Some(_) => {
                    self.set_toast("Only files can be viewed.", true);
                    return;
                }
                None => {
                    self.set_toast("Entry not found.", true);
                    return;
                }
            }
        };
        let (_, reader) = match self.open_reader() {
            Some(x) => x,
            None => return,
        };
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        let leaf_clean = sanitize_leaf(&leaf);
        self.spawn_job(ctx, "Opening…", move || {
            // Decrypt the one file into a private temp, then drop it to read-only.
            let temp_path = match store.create_private_checkout_file(&leaf_clean) {
                Ok(p) => p,
                Err(e) => return JobReport::err(e),
            };
            let out = match std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&temp_path)
            {
                Ok(f) => f,
                Err(e) => {
                    let _ = crate::store::secure_wipe(&temp_path);
                    return JobReport::err(e.to_string());
                }
            };
            let mut out = std::io::BufWriter::new(out);
            if let Err(e) = reader.read_entry_to_writer(&path, &mut out) {
                let _ = std::io::Write::flush(&mut out);
                drop(out);
                let _ = crate::store::secure_wipe(&temp_path);
                return JobReport::err(e.to_string());
            }
            if let Err(e) = std::io::Write::flush(&mut out) {
                drop(out);
                let _ = crate::store::secure_wipe(&temp_path);
                return JobReport::err(e.to_string());
            }
            drop(out);
            // Signal "look, don't edit" — and make secure_wipe restore writability
            // before it overwrites (see store::secure_wipe).
            let _ = crate::store::make_readonly(&temp_path);
            // Launch the app and, where the platform can report it, watch for the
            // app to close and wipe the temp then. Otherwise it's wiped on leaving
            // the vault.
            let msg = match start_view(&temp_path) {
                ViewLaunch::WatchingForClose => {
                    format!("Viewing {leaf} (read-only) — wiped when you close it.")
                }
                ViewLaunch::LaunchedNoWatch => {
                    format!("Viewing {leaf} (read-only) — wiped when you leave the vault.")
                }
                ViewLaunch::Failed => format!(
                    "Decrypted a read-only copy to {} (couldn't launch an app).",
                    temp_path.display()
                ),
            };
            JobReport::ok(
                Outcome::StartView(Box::new(ActiveView { leaf, temp_path })),
                msg,
            )
        });
    }

    /// Check out a file: decrypt it to a private temp file and (best-effort) open
    /// it in the OS default editor. The user then edits in their own app and
    /// comes back to check in or discard.
    fn spawn_check_out(&mut self, ctx: &egui::Context, path: String) {
        // Validate kind + snapshot the entry's hash/mode from the manifest (no
        // decryption) on the UI thread.
        let (orig_blake3, mode, leaf) = {
            let s = match &self.state {
                State::Unlocked(s) => s,
                _ => return,
            };
            if s.checkout.is_some() {
                self.set_toast("Finish your current edit first.", true);
                return;
            }
            let open = match &s.open {
                Some(o) => o,
                None => return,
            };
            match open.reader.entries().iter().find(|e| e.path == path) {
                Some(e) if e.kind == EntryKind::File => (
                    e.blake3,
                    e.mode,
                    path.rsplit('/').next().unwrap_or("file").to_string(),
                ),
                Some(_) => {
                    self.set_toast("Only files can be edited.", true);
                    return;
                }
                None => {
                    self.set_toast("Entry not found.", true);
                    return;
                }
            }
        };
        let (id, reader) = match self.open_reader() {
            Some(x) => x,
            None => return,
        };
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        let leaf_clean = sanitize_leaf(&leaf);
        self.spawn_job(ctx, "Checking out…", move || {
            // Create the private (0600-from-creation) temp file, then stream the
            // one file's plaintext into it. Wipe on any failure so no partial
            // plaintext is left behind.
            let temp_path = match store.create_private_checkout_file(&leaf_clean) {
                Ok(p) => p,
                Err(e) => return JobReport::err(e),
            };
            let out = match std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&temp_path)
            {
                Ok(f) => f,
                Err(e) => {
                    let _ = crate::store::secure_wipe(&temp_path);
                    return JobReport::err(e.to_string());
                }
            };
            let mut out = std::io::BufWriter::new(out);
            if let Err(e) = reader.read_entry_to_writer(&path, &mut out) {
                let _ = std::io::Write::flush(&mut out);
                drop(out);
                let _ = crate::store::secure_wipe(&temp_path);
                return JobReport::err(e.to_string());
            }
            if let Err(e) = std::io::Write::flush(&mut out) {
                drop(out);
                let _ = crate::store::secure_wipe(&temp_path);
                return JobReport::err(e.to_string());
            }
            drop(out);
            // Best-effort: launch the OS editor. Failure is non-fatal — the temp
            // exists and we tell the user where it is.
            let launched = open_in_default_app(&temp_path).is_ok();
            let msg = if launched {
                format!("Editing {leaf} — check in or discard when done.")
            } else {
                format!(
                    "Decrypted to {} (couldn't launch an editor — open it manually).",
                    temp_path.display()
                )
            };
            JobReport::ok(
                Outcome::StartCheckout(Box::new(Checkout {
                    vault_id: id,
                    entry_path: path,
                    leaf,
                    temp_path,
                    orig_blake3,
                    mode,
                })),
                msg,
            )
        });
    }

    /// Check in the active edit: if the temp file actually changed, re-encrypt it
    /// back into the vault; either way securely wipe the temp file.
    fn spawn_check_in(&mut self, ctx: &egui::Context) {
        let (vault_id, entry_path, temp_path, orig_blake3, mode) = match &self.state {
            State::Unlocked(s) => match &s.checkout {
                Some(c) => (
                    c.vault_id.clone(),
                    c.entry_path.clone(),
                    c.temp_path.clone(),
                    c.orig_blake3,
                    c.mode,
                ),
                None => return,
            },
            _ => return,
        };
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        // The open vault must still be the one we checked out from (the Nav/Close
        // guards should guarantee this, but verify before re-encrypting).
        if id != vault_id {
            self.set_toast("The checked-out vault is no longer open.", true);
            return;
        }
        self.spawn_job(ctx, "Checking in…", move || {
            // Hash the edited temp; if unchanged, skip the re-encrypt entirely.
            let new_hash = match format::hash_path(&temp_path) {
                Ok((h, _)) => h,
                Err(e) => return JobReport::err(e.to_string()),
            };
            if new_hash == orig_blake3 {
                let _ = crate::store::secure_wipe(&temp_path);
                return JobReport::ok(
                    Outcome::EndCheckout { replace: None },
                    "No changes — edit discarded.",
                );
            }
            let mtime = file_mtime(&temp_path);
            if let Err(e) = store.replace_file_in_vault(
                &identity,
                &id,
                &reader,
                &entry_path,
                &temp_path,
                mtime,
                mode,
            ) {
                // Keep the temp so the user can retry or discard.
                return JobReport::err(e);
            }
            let _ = crate::store::secure_wipe(&temp_path);
            match reopen_after_save(&store, &identity, id, registry) {
                Ok((id, reader, registry)) => JobReport::ok(
                    Outcome::EndCheckout {
                        replace: Some((id, Box::new(reader), registry)),
                    },
                    "Checked in.",
                ),
                Err(e) => JobReport::err(e),
            }
        });
    }

    /// Discard the active edit: securely wipe the temp file, vault untouched.
    fn spawn_discard(&mut self, ctx: &egui::Context) {
        let temp_path = match &self.state {
            State::Unlocked(s) => match &s.checkout {
                Some(c) => c.temp_path.clone(),
                None => return,
            },
            _ => return,
        };
        self.spawn_job(ctx, "Discarding…", move || {
            let _ = crate::store::secure_wipe(&temp_path);
            JobReport::ok(Outcome::EndCheckout { replace: None }, "Edit discarded.")
        });
    }

    fn spawn_import(&mut self, ctx: &egui::Context) {
        let path = match rfd::FileDialog::new()
            .add_filter("FileSec container", &["fsec"])
            .pick_file()
        {
            Some(p) => p,
            None => return,
        };
        let registry = match &self.state {
            State::Unlocked(s) => s.registry.clone(),
            _ => return,
        };
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        self.spawn_job(ctx, "Verifying & decrypting…", move || {
            // Verify the signature by streaming the body (no full load), then
            // transcode straight into the local store — also streaming. A huge
            // imported file never lands in memory.
            let (reader, sender) = match format::verify_and_open(&path, &identity) {
                Ok(x) => x,
                Err(e) => return JobReport::err(e.to_string()),
            };
            let id = match new_vault_id() {
                Ok(id) => id,
                Err(e) => return JobReport::err(e),
            };
            if let Err(e) = store.import_reader_to_vault(&identity, &id, &reader) {
                return JobReport::err(e);
            }
            let mut registry = registry;
            registry.upsert(VaultMeta {
                id,
                name: reader.name().to_string(),
                created_at: reader.created_at(),
                modified_at: now_unix(),
                file_count: reader.file_count() as u64,
                total_size: reader.total_size(),
            });
            if let Err(e) = store.save_registry(&identity, &registry) {
                return JobReport::err(e);
            }
            JobReport {
                outcome: Outcome::Imported(Box::new(ImportData {
                    registry,
                    sender: sender.public(),
                    vault_name: reader.name().to_string(),
                    file_count: reader.file_count(),
                })),
                toast: None,
            }
        });
    }

    fn spawn_export(&mut self, ctx: &egui::Context) {
        let gathered = if let State::Unlocked(s) = &self.state {
            s.export.as_ref().map(|form| {
                let mut recipients = Vec::new();
                for c in &s.contacts.contacts {
                    if form.selected.contains(&hex(&c.fingerprint())) {
                        recipients.push(c.identity.clone());
                    }
                }
                if form.include_self {
                    recipients.push(s.identity.public());
                }
                let name = s
                    .registry
                    .vaults
                    .iter()
                    .find(|v| v.id == form.vault_id)
                    .map(|v| v.name.clone())
                    .unwrap_or_else(|| "vault".into());
                (form.vault_id.clone(), recipients, name, form.suite)
            })
        } else {
            None
        };
        let (vault_id, recipients, name, suite) = match gathered {
            Some(x) => x,
            None => return,
        };
        if recipients.is_empty() {
            self.set_toast("Select at least one recipient.", true);
            return;
        }
        // Hybrid PQC needs every recipient (and the sender) to carry post-quantum
        // keys. Catch it here with a clear message rather than failing mid-export.
        if suite.is_hybrid() && recipients.iter().any(|r| !r.is_hybrid_capable()) {
            self.set_toast(
                "Hybrid PQC requires every recipient to have post-quantum keys. \
                 Ask them to re-share an updated public key, or pick another suite.",
                true,
            );
            return;
        }
        let suggested = format!("{}.fsec", sanitize_filename(&name));
        let target = match rfd::FileDialog::new()
            .add_filter("FileSec container", &["fsec"])
            .set_file_name(&suggested)
            .save_file()
        {
            Some(p) => p,
            None => return,
        };
        if let State::Unlocked(s) = &mut self.state {
            s.export = None;
        }
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let count = recipients.len();
        self.spawn_job(ctx, "Encrypting & exporting…", move || {
            // Stream straight from the encrypted source to the new container so
            // the whole vault is never held in memory at once.
            let reader = match store.open_vault(&identity, &vault_id) {
                Ok(r) => r,
                Err(e) => return JobReport::err(e),
            };
            let options = ExportOptions {
                suite,
                ..ExportOptions::default()
            };
            match filesec_core::format_v2::export_v2_to_path(
                &reader,
                &identity,
                &recipients,
                &options,
                &target,
            ) {
                Ok(()) => JobReport::ok(
                    Outcome::Noop,
                    format!(
                        "Exported to {} for {count} recipient(s) using {}.",
                        target.display(),
                        suite.label()
                    ),
                ),
                Err(e) => JobReport::err(e.to_string()),
            }
        });
    }

    /// Run the "upgrade to post-quantum" migration on the worker: re-key the
    /// whole local store to a new hybrid identity, then swap the session over to
    /// it. The keystore re-seal needs the passphrase, taken from the dialog.
    #[cfg(feature = "pqc")]
    fn spawn_migrate(&mut self, ctx: &egui::Context) {
        let (pass, data_dir) = if let State::Unlocked(s) = &mut self.state {
            match &mut s.migrate {
                Some(f) if f.pass.is_empty() => {
                    f.error = Some("Enter your passphrase to confirm.".into());
                    return;
                }
                Some(f) => (Zeroizing::new(f.pass.clone()), s.data_dir.clone()),
                None => return,
            }
        } else {
            return;
        };
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        if let State::Unlocked(s) = &mut self.state {
            s.migrate = None;
        }
        self.spawn_job(ctx, "Upgrading to post-quantum…", move || {
            let new =
                match store.migrate_to_hybrid(&identity, pass.as_bytes(), KdfParams::default()) {
                    Ok(n) => n,
                    Err(e) => return JobReport::err(e),
                };
            // Migration is committed (the keystore now holds the hybrid identity).
            // Reload the store under the new identity to rebuild the session; on
            // the off chance a reload fails, ask for a restart rather than risk an
            // inconsistent session — the keystore is already the new identity.
            let contacts = match store.load_contacts(&new) {
                Ok(c) => c,
                Err(e) => {
                    return JobReport::err(format!(
                        "Upgraded — please restart the app. (reloading contacts failed: {e})"
                    ))
                }
            };
            let registry = match store.load_registry(&new) {
                Ok(r) => r,
                Err(e) => {
                    return JobReport::err(format!(
                        "Upgraded — please restart the app. (reloading vaults failed: {e})"
                    ))
                }
            };
            JobReport::ok(
                Outcome::Unlocked(Box::new(SessionInit {
                    identity: new,
                    contacts,
                    registry,
                    // Migration re-seals a fresh passphrase-only keystore; any
                    // security keys must be re-enrolled afterwards. The passphrase
                    // is unchanged, so a saved keychain secret stays valid.
                    passkeys: Vec::new(),
                    auto_unlock: autounlock::is_saved(&data_dir),
                    data_dir,
                    rollback_warning: store.rollback_protection_warning().map(str::to_string),
                })),
                "Upgraded to post-quantum. Your safety number changed — re-share your \
                 public key so contacts can re-verify it. Re-enroll any security keys.",
            )
        });
    }

    /// Parse the paste box into a staged [`ContactPreview`] (no disk I/O, so it
    /// runs inline rather than on the worker). The user confirms from the
    /// preview window before anything is saved.
    fn preview_contact_paste(&mut self) {
        let text = match &self.state {
            State::Unlocked(s) => s.contact_paste.trim().to_string(),
            _ => return,
        };
        if text.is_empty() {
            self.set_toast("Paste a public key first.", true);
            return;
        }
        match PublicIdentity::from_pasted(&text) {
            Ok(pubid) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.contact_preview = Some(build_contact_preview(s, pubid));
                }
            }
            Err(e) => self.set_toast(format!("Couldn't read that key: {e}"), true),
        }
    }

    /// Pick a `.fsecpub` file and stage it as a [`ContactPreview`]. Reading a
    /// small key file inline keeps the confirm-before-save flow simple.
    fn preview_contact_file(&mut self) {
        let path = match rfd::FileDialog::new()
            .add_filter("FileSec public key", &["fsecpub"])
            .pick_file()
        {
            Some(p) => p,
            None => return,
        };
        let bytes = match read_bounded_file(
            &path,
            MAX_PUBLIC_IDENTITY_FILE_LEN,
            "FileSec public key file",
        ) {
            Ok(b) => b,
            Err(e) => {
                self.set_toast(e, true);
                return;
            }
        };
        // Accept the compact CBOR body or an armored/base64 text export.
        let parsed = PublicIdentity::from_bytes(&bytes).or_else(|_| {
            String::from_utf8(bytes)
                .map_err(|_| filesec_core::Error::Format("not a public key"))
                .and_then(|t| PublicIdentity::from_pasted(&t))
        });
        match parsed {
            Ok(pubid) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.contact_preview = Some(build_contact_preview(s, pubid));
                }
            }
            Err(e) => self.set_toast(format!("Couldn't read that key: {e}"), true),
        }
    }

    /// Commit the staged preview into the contact book (worker side persists the
    /// re-encrypted book). Refuses to add the user's own key.
    fn spawn_confirm_add_contact(&mut self, ctx: &egui::Context) {
        let pubid = match &self.state {
            State::Unlocked(s) => match &s.contact_preview {
                Some(p) if matches!(p.status, PreviewStatus::SelfKey) => {
                    self.set_toast("That's your own key — no need to add yourself.", true);
                    return;
                }
                Some(p) => p.pubid.clone(),
                None => return,
            },
            _ => return,
        };
        let contacts = match &self.state {
            State::Unlocked(s) => s.contacts.clone(),
            _ => return,
        };
        if let State::Unlocked(s) = &mut self.state {
            s.contact_preview = None;
            s.contact_paste.clear();
        }
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        self.spawn_job(ctx, "Saving contact…", move || {
            import_contact_job(&store, &identity, contacts, pubid)
        });
    }

    /// Open the verification dialog for a contact identified by hex fingerprint.
    fn begin_verify(&mut self, fpr_hex: String) {
        let fpr = match decode_fpr(&fpr_hex) {
            Some(f) => f,
            None => {
                self.set_toast("Bad fingerprint.", true);
                return;
            }
        };
        if let State::Unlocked(s) = &mut self.state {
            if let Some(c) = s.contacts.find(&fpr) {
                let name = c.identity.display_name();
                s.verify = Some(VerifyForm {
                    fpr_hex,
                    name,
                    safety_number: c.identity.safety_number(),
                    input: String::new(),
                    manual_ok: false,
                });
                // If verification was launched from the import dialog, close it.
                s.last_import = None;
            }
        }
    }

    /// Finish verification: close the dialog and mark the contact verified.
    fn confirm_verify(&mut self, ctx: &egui::Context, fpr_hex: String) {
        if let State::Unlocked(s) = &mut self.state {
            s.verify = None;
        }
        self.spawn_set_trust(ctx, fpr_hex, Trust::Verified);
    }

    fn spawn_set_trust(&mut self, ctx: &egui::Context, fpr_hex: String, trust: Trust) {
        let fpr = match decode_fpr(&fpr_hex) {
            Some(f) => f,
            None => {
                self.set_toast("Bad fingerprint.", true);
                return;
            }
        };
        let contacts = match &self.state {
            State::Unlocked(s) => s.contacts.clone(),
            _ => return,
        };
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        self.spawn_job(ctx, "Saving…", move || {
            let mut contacts = contacts;
            contacts.set_trust(&fpr, trust, now_unix());
            match store.save_contacts(&identity, &contacts) {
                Ok(()) => JobReport::ok(
                    Outcome::Contacts(contacts),
                    match trust {
                        Trust::Verified => "Marked as verified.",
                        Trust::Unverified => "Marked as unverified.",
                    },
                ),
                Err(e) => JobReport::err(e),
            }
        });
    }

    fn spawn_remove_contact(&mut self, ctx: &egui::Context, fpr_hex: String) {
        let fpr = match decode_fpr(&fpr_hex) {
            Some(f) => f,
            None => {
                self.set_toast("Bad fingerprint.", true);
                return;
            }
        };
        let contacts = match &self.state {
            State::Unlocked(s) => s.contacts.clone(),
            _ => return,
        };
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        self.spawn_job(ctx, "Saving…", move || {
            let mut contacts = contacts;
            contacts.remove(&fpr);
            match store.save_contacts(&identity, &contacts) {
                Ok(()) => JobReport::ok(Outcome::Contacts(contacts), "Contact removed."),
                Err(e) => JobReport::err(e),
            }
        });
    }

    fn spawn_save_pubkey(&mut self, ctx: &egui::Context) {
        let prepared = if let State::Unlocked(s) = &self.state {
            Some((s.identity.public().to_bytes(), s.identity.name.clone()))
        } else {
            None
        };
        let (bytes_res, name) = match prepared {
            Some(x) => x,
            None => return,
        };
        let bytes = match bytes_res {
            Ok(b) => b,
            Err(e) => {
                self.set_toast(e.to_string(), true);
                return;
            }
        };
        let suggested = format!("{}.fsecpub", sanitize_filename(&name));
        let target = match rfd::FileDialog::new()
            .add_filter("FileSec public key", &["fsecpub"])
            .set_file_name(&suggested)
            .save_file()
        {
            Some(p) => p,
            None => return,
        };
        self.spawn_job(ctx, "Saving…", move || {
            match std::fs::write(&target, &bytes) {
                Ok(()) => JobReport::ok(
                    Outcome::Noop,
                    format!("Public key saved to {}", target.display()),
                ),
                Err(e) => JobReport::err(e.to_string()),
            }
        });
    }

    /// Export the current identity as a portable, passphrase-encrypted `.fsecid`
    /// backup. Validates the backup passphrase from the open dialog, picks a save
    /// location, then seals + writes the armored backup in the background.
    fn spawn_export_identity(&mut self, ctx: &egui::Context) {
        // Validate the backup passphrase from the dialog before doing anything.
        let pass = match &mut self.state {
            State::Unlocked(s) => match &mut s.export_identity {
                Some(f) => {
                    if let Some(error) = passphrase_policy_error(&f.pass) {
                        f.error = Some(error);
                        return;
                    }
                    if f.pass != f.pass2 {
                        f.error = Some("Passphrases do not match.".into());
                        return;
                    }
                    f.error = None;
                    f.pass2.zeroize();
                    // Wiped after the worker uses it (see `spawn_create_identity`).
                    Zeroizing::new(std::mem::take(&mut f.pass))
                }
                None => return,
            },
            _ => return,
        };
        let (identity, name) = match self.ident_arc() {
            Some(i) => {
                let name = i.name.clone();
                (i, name)
            }
            None => return,
        };
        let suggested = format!("{}.fsecid", sanitize_filename(&name));
        let target = match rfd::FileDialog::new()
            .add_filter("FileSec identity backup", &["fsecid"])
            .set_file_name(&suggested)
            .save_file()
        {
            Some(p) => p,
            None => {
                // User backed out of the save dialog; close the dialog cleanly.
                if let State::Unlocked(s) = &mut self.state {
                    s.export_identity = None;
                }
                return;
            }
        };
        self.spawn_job(ctx, "Exporting identity…", move || {
            let armored = match filesec_core::keystore::export_identity_armored(
                &identity,
                pass.as_bytes(),
                KdfParams::default(),
            ) {
                Ok(a) => a,
                Err(e) => return JobReport::err(e.to_string()),
            };
            match write_private_export(&target, armored.as_bytes()) {
                Ok(()) => JobReport::ok(
                    Outcome::ExportIdentityDone,
                    format!("Identity backup saved to {}", target.display()),
                ),
                Err(e) => JobReport::err(e),
            }
        });
    }

    /// Restore an identity from a `.fsecid` backup on first run: decrypt the
    /// backup with its passphrase, then seal it into this device's keystore under
    /// a new local passphrase and drop straight into the unlocked session.
    fn spawn_restore_identity(&mut self, ctx: &egui::Context) {
        let (path, backup_pass, new_pass) = match &mut self.state {
            State::FirstRun(f) => match &mut f.restore {
                Some(r) => {
                    if r.backup_pass.is_empty() {
                        r.error = Some("Enter the backup's passphrase.".into());
                        return;
                    }
                    if let Some(error) = passphrase_policy_error(&r.new_pass) {
                        r.error = Some(error);
                        return;
                    }
                    if r.new_pass != r.new_pass2 {
                        r.error = Some("New passphrases do not match.".into());
                        return;
                    }
                    r.error = None;
                    r.new_pass2.zeroize();
                    (
                        r.path.clone(),
                        Zeroizing::new(std::mem::take(&mut r.backup_pass)),
                        Zeroizing::new(std::mem::take(&mut r.new_pass)),
                    )
                }
                None => return,
            },
            _ => return,
        };
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        self.spawn_job(ctx, "Restoring identity…", move || {
            let text = match read_bounded_text_file(
                &path,
                MAX_IDENTITY_BACKUP_FILE_LEN,
                "FileSec identity backup",
            ) {
                Ok(t) => t,
                Err(e) => {
                    return JobReport {
                        outcome: Outcome::FirstRunFailed(format!("Could not read backup: {e}")),
                        toast: None,
                    }
                }
            };
            let identity = match filesec_core::keystore::import_identity_armored(
                &text,
                backup_pass.as_bytes(),
            ) {
                Ok(i) => i,
                Err(filesec_core::error::Error::BadPassphrase) => {
                    return JobReport {
                        outcome: Outcome::FirstRunFailed(
                            "The backup passphrase is incorrect.".into(),
                        ),
                        toast: None,
                    }
                }
                Err(e) => {
                    return JobReport {
                        outcome: Outcome::FirstRunFailed(format!(
                            "This file isn't a valid FileSec identity backup ({e})."
                        )),
                        toast: None,
                    }
                }
            };
            let ks =
                match KeystoreFile::create(&identity, new_pass.as_bytes(), KdfParams::default()) {
                    Ok(k) => k,
                    Err(e) => {
                        return JobReport {
                            outcome: Outcome::FirstRunFailed(e.to_string()),
                            toast: None,
                        }
                    }
                };
            if let Err(e) = store.save_keystore(&ks) {
                return JobReport {
                    outcome: Outcome::FirstRunFailed(e),
                    toast: None,
                };
            }
            let data_dir = store.data_dir().display().to_string();
            JobReport::ok(
                Outcome::Unlocked(Box::new(SessionInit {
                    identity,
                    contacts: ContactBook::default(),
                    registry: Registry::default(),
                    passkeys: Vec::new(),
                    auto_unlock: false,
                    data_dir,
                    rollback_warning: store.rollback_protection_warning().map(str::to_string),
                })),
                "Identity restored. It's now protected by your new passphrase on this device.",
            )
        });
    }
}

/// Re-open a freshly-saved vault (metadata only), refresh its registry entry,
/// and persist the registry, returning the new reader + registry. Shared by the
/// streaming mutate paths and the check-in path (which wrap the result in
/// different outcomes).
fn reopen_after_save(
    store: &Store,
    identity: &Identity,
    id: String,
    mut registry: Registry,
) -> Result<(String, VaultReaderV2, Registry), String> {
    let new_reader = store.open_vault(identity, &id)?;
    // Count only live entries: a trashed file is still stored, but the vault card
    // should reflect what the user actually sees in the browser.
    let (files, size) = live_counts(&snapshot_entries(&new_reader));
    registry.upsert(VaultMeta {
        id: id.clone(),
        name: new_reader.name().to_string(),
        created_at: new_reader.created_at(),
        modified_at: now_unix(),
        file_count: files,
        total_size: size,
    });
    store.save_registry(identity, &registry)?;
    Ok((id, new_reader, registry))
}

/// Re-open a freshly-saved vault and produce the `ReplaceOpen` outcome. Shared
/// by the streaming add/remove paths.
fn finalize_after_save(
    store: &Store,
    identity: &Identity,
    id: String,
    registry: Registry,
    msg: String,
) -> JobReport {
    match reopen_after_save(store, identity, id, registry) {
        Ok((id, reader, registry)) => JobReport::ok(
            Outcome::ReplaceOpen {
                id,
                reader: Box::new(reader),
                registry,
            },
            msg,
        ),
        Err(e) => JobReport::err(e),
    }
}

/// Upsert a contact and persist the book (worker side). The toast reflects what
/// actually happened (a fresh add vs. a re-import vs. a rename) so re-importing
/// a key never looks like it silently re-trusted it.
fn import_contact_job(
    store: &Store,
    identity: &Identity,
    mut contacts: ContactBook,
    pubid: PublicIdentity,
) -> JobReport {
    // Sanitized rendering of the imported (attacker-controlled) name for the
    // status message; the same sanitization is what `upsert` persists.
    let name = pubid.display_name();
    let outcome = contacts.upsert(pubid, now_unix());
    let msg = match outcome {
        UpsertOutcome::Added => {
            format!("Added \"{name}\". Verify their safety number before trusting.")
        }
        UpsertOutcome::Unchanged => format!("\"{name}\" is already a contact — nothing changed."),
        UpsertOutcome::Renamed {
            old, was_verified, ..
        } => {
            if was_verified {
                format!(
                    "Renamed verified contact \"{old}\" → \"{name}\" (keys unchanged; still verified)."
                )
            } else {
                format!("Updated contact name \"{old}\" → \"{name}\".")
            }
        }
    };
    match store.save_contacts(identity, &contacts) {
        Ok(()) => JobReport::ok(Outcome::Contacts(contacts), msg),
        Err(e) => JobReport::err(e),
    }
}

/// Classify a parsed key against the current session: is it the user's own key,
/// already a contact (possibly under a different name), or brand new?
fn build_contact_preview(s: &Session, pubid: PublicIdentity) -> ContactPreview {
    let status = if pubid.fingerprint() == s.identity.public().fingerprint() {
        PreviewStatus::SelfKey
    } else {
        match s.contacts.find(&pubid.fingerprint()) {
            None => PreviewStatus::New,
            Some(c) => {
                let verified = c.trust == Trust::Verified;
                // A name change only matters when both names are present; filling
                // in a blank name (e.g. a key first learned from a container) is
                // not a "rename" worth warning about.
                if c.identity.name == pubid.name
                    || pubid.name.is_empty()
                    || c.identity.name.is_empty()
                {
                    PreviewStatus::Existing { verified }
                } else {
                    PreviewStatus::Renamed {
                        old: c.identity.name.clone(),
                        verified,
                    }
                }
            }
        }
    };
    ContactPreview { pubid, status }
}

// ---------------------------------------------------------------------------
// Screen rendering (collects actions only).
// ---------------------------------------------------------------------------

/// A full-width sidebar navigation row: icon + label, with selected/hover states.
fn sidebar_nav_item(ui: &mut egui::Ui, glyph: &str, label: &str, selected: bool) -> egui::Response {
    let c = theme::colors(ui);
    let (rect, resp) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 38.0), egui::Sense::click());
    let bg = if selected {
        theme::accent_soft(c)
    } else if resp.hovered() {
        c.surface_hi
    } else {
        Color32::TRANSPARENT
    };
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(theme::RADIUS_SM), bg);
    let fg = if selected { c.accent } else { c.text };
    ui.painter().text(
        egui::pos2(rect.left() + 12.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        glyph,
        egui::FontId::new(18.0, egui::FontFamily::Name("phosphor".into())),
        fg,
    );
    ui.painter().text(
        egui::pos2(rect.left() + 40.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::new(14.5, egui::FontFamily::Proportional),
        fg,
    );
    resp
}

// ---------------------------------------------------------------------------
// Direct network transfer (the `net` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "net")]
impl App {
    /// Drain transfer events from the worker and apply them; keep the UI repainting
    /// while a transfer is live so progress stays current.
    fn poll_transfer(&mut self, ctx: &egui::Context) {
        let active = matches!(&self.state, State::Unlocked(s) if s.transfer.active.is_some());
        if !active {
            return;
        }
        let mut events = Vec::new();
        if let State::Unlocked(s) = &self.state {
            if let Some(t) = &s.transfer.active {
                while let Some(event) = t.handle.try_recv() {
                    events.push(event);
                }
            }
        }
        for event in events {
            self.apply_net_event(event);
        }
        if matches!(&self.state, State::Unlocked(s) if s.transfer.active.is_some()) {
            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        }
    }

    /// Apply one transfer event to the session state (and toasts / registry).
    fn apply_net_event(&mut self, event: crate::net::NetEvent) {
        use crate::net::{NatStatus, NetEvent};

        // A completed receive updates the registry (needs store + identity) + toasts.
        if let NetEvent::Received {
            meta,
            file_count,
            sender_name,
        } = &event
        {
            if let (Some(store), Some(identity)) = (self.store_arc(), self.ident_arc()) {
                if let State::Unlocked(s) = &mut self.state {
                    s.registry.upsert(meta.clone());
                    let _ = store.save_registry(&identity, &s.registry);
                    if let Some(t) = &mut s.transfer.active {
                        t.progress = None;
                        t.offer = None;
                        t.status = "Listening for the next transfer…".into();
                    }
                }
            }
            let who = sender_name
                .clone()
                .unwrap_or_else(|| "a verified contact".into());
            self.set_toast(
                format!(
                    "Received \u{201c}{}\u{201d} from {who} ({file_count} file(s)).",
                    meta.name
                ),
                false,
            );
            return;
        }

        let mut toast: Option<(String, bool)> = None;
        if let State::Unlocked(s) = &mut self.state {
            match event {
                NetEvent::Listening {
                    lan_addr,
                    public_addr,
                    nat,
                    transfer_code,
                } => {
                    let nat = match nat {
                        NatStatus::Disabled => "Local network only.".to_string(),
                        NatStatus::Mapped => "Router port opened.".to_string(),
                        NatStatus::Unavailable(m) => format!(
                            "Couldn't open a router port ({m}). You're still reachable on your local network."
                        ),
                    };
                    if let Some(t) = &mut s.transfer.active {
                        t.status = "Listening for a sender…".into();
                        t.listen = Some(ListenView {
                            lan_addr,
                            public_addr,
                            nat,
                            transfer_code,
                        });
                    }
                }
                NetEvent::Connecting => {
                    if let Some(t) = &mut s.transfer.active {
                        t.status = "Connecting…".into();
                    }
                }
                NetEvent::Status(msg) => {
                    if let Some(t) = &mut s.transfer.active {
                        t.status = msg;
                    }
                }
                NetEvent::PeerConnected {
                    fpr_hex,
                    name,
                    verified,
                } => {
                    if let Some(t) = &mut s.transfer.active {
                        let who = name
                            .unwrap_or_else(|| format!("{}…", &fpr_hex[..fpr_hex.len().min(16)]));
                        t.peer = Some(if verified {
                            format!("{who} (verified)")
                        } else {
                            format!("{who} (unverified)")
                        });
                        t.status = "Connected".into();
                    }
                }
                NetEvent::Offer {
                    filename,
                    size,
                    sender_name,
                    verified: _,
                } => {
                    if let Some(t) = &mut s.transfer.active {
                        t.offer = Some(OfferView {
                            filename,
                            size,
                            sender: sender_name.unwrap_or_else(|| "a verified contact".into()),
                        });
                    }
                }
                NetEvent::Progress { done, total } => {
                    if let Some(t) = &mut s.transfer.active {
                        t.progress = Some((done, total));
                    }
                }
                NetEvent::Sent { vault_name } => {
                    toast = Some((format!("Sent \u{201c}{vault_name}\u{201d}."), false));
                    s.transfer.active = None;
                }
                NetEvent::Declined => {
                    toast = Some(("The receiver declined the transfer.".into(), true));
                    s.transfer.active = None;
                }
                NetEvent::Error(msg) => {
                    let is_send = s
                        .transfer
                        .active
                        .as_ref()
                        .is_some_and(|a| a.kind == ActiveKind::Send);
                    toast = Some((msg, true));
                    if is_send {
                        s.transfer.active = None;
                    } else if let Some(t) = &mut s.transfer.active {
                        t.offer = None;
                        t.progress = None;
                        t.status = "Listening for the next transfer…".into();
                    }
                }
                NetEvent::Stopped => s.transfer.active = None,
                NetEvent::Received { .. } => {} // handled above
            }
        }
        if let Some((msg, error)) = toast {
            self.set_toast(msg, error);
        }
    }

    /// Begin listening (receive mode).
    fn start_listen(&mut self, ctx: &egui::Context) {
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let built = match &self.state {
            State::Unlocked(s) if s.transfer.active.is_none() => {
                build_listen_config(&s.transfer, &s.contacts).map(|c| (c, s.contacts.clone()))
            }
            _ => return,
        };
        let (config, contacts) = match built {
            Ok(x) => x,
            Err(msg) => {
                self.set_toast(msg, true);
                return;
            }
        };
        let handle = crate::net::start_listener(config, identity, store, contacts, ctx.clone());
        if let State::Unlocked(s) = &mut self.state {
            s.transfer.active = Some(ActiveTransfer {
                handle,
                kind: ActiveKind::Receive,
                status: "Starting…".into(),
                listen: None,
                peer: None,
                offer: None,
                progress: None,
            });
        }
    }

    /// Begin sending (send mode).
    fn start_send(&mut self, ctx: &egui::Context) {
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let built = match &self.state {
            State::Unlocked(s) if s.transfer.active.is_none() => {
                build_send_config(&s.transfer, &s.contacts)
            }
            _ => return,
        };
        let config = match built {
            Ok(c) => c,
            Err(msg) => {
                self.set_toast(msg, true);
                return;
            }
        };
        let handle = crate::net::start_sender(config, identity, store, ctx.clone());
        if let State::Unlocked(s) = &mut self.state {
            s.transfer.active = Some(ActiveTransfer {
                handle,
                kind: ActiveKind::Send,
                status: "Connecting…".into(),
                listen: None,
                peer: None,
                offer: None,
                progress: None,
            });
        }
    }

    /// Stop the active listener/sender and clear it (the worker unmaps any NAT port).
    fn stop_transfer(&mut self) {
        if let State::Unlocked(s) = &mut self.state {
            if let Some(t) = &mut s.transfer.active {
                t.handle.stop();
            }
            s.transfer.active = None;
        }
    }

    /// Forward a command (accept/reject/cancel) to the active transfer.
    fn transfer_command(&mut self, command: crate::net::NetCommand, clear_offer: bool) {
        if let State::Unlocked(s) = &mut self.state {
            if let Some(t) = &mut s.transfer.active {
                t.handle.send(command);
                if clear_offer {
                    t.offer = None;
                    t.status = "Receiving…".into();
                }
            }
        }
    }
}

/// Validate the send form into a [`crate::net::SendConfig`], or a user-facing error.
/// A comfortable max width for the transfer forms so they neither stretch across a
/// wide window nor collapse to their content on the left.
#[cfg(feature = "net")]
const TRANSFER_COL_W: f32 = 540.0;

/// The user's verified contacts as `(fingerprint_hex, display_name)`.
#[cfg(feature = "net")]
fn verified_contacts(s: &Session) -> Vec<(String, String)> {
    s.contacts
        .contacts
        .iter()
        .filter(|c| c.trust == Trust::Verified)
        .map(|c| {
            let name = if c.identity.name.is_empty() {
                "(unnamed)".to_string()
            } else {
                c.identity.name.clone()
            };
            (hex(&c.fingerprint()), name)
        })
        .collect()
}

/// The display name for the selected `(id, name)` option, or a placeholder.
#[cfg(feature = "net")]
fn combo_label(
    selected: &Option<String>,
    options: &[(String, String)],
    placeholder: &str,
) -> String {
    selected
        .as_ref()
        .and_then(|sel| options.iter().find(|(id, _)| id == sel))
        .map(|(_, name)| name.clone())
        .unwrap_or_else(|| placeholder.to_string())
}

/// A single-line text field with the inset, padded look used across the app.
#[cfg(feature = "net")]
fn net_input(ui: &mut egui::Ui, text: &mut String, hint: &str, width: f32) -> egui::Response {
    ui.add(
        egui::TextEdit::singleline(text)
            .hint_text(hint)
            .desired_width(width)
            .margin(egui::Margin::symmetric(10, 7))
            .font(egui::TextStyle::Body),
    )
}

/// Validate the receive form into a [`crate::net::ListenConfig`], or a user-facing error.
#[cfg(feature = "net")]
fn build_listen_config(
    forms: &TransferState,
    contacts: &ContactBook,
) -> Result<crate::net::ListenConfig, String> {
    let fpr_hex = forms
        .recv_contact
        .clone()
        .ok_or_else(|| "Pick the verified contact you expect to receive from.".to_string())?;
    let contact = contacts
        .contacts
        .iter()
        .find(|c| c.trust == Trust::Verified && hex(&c.fingerprint()) == fpr_hex)
        .ok_or_else(|| "Pick the verified contact you expect to receive from.".to_string())?;
    let port = if forms.recv_port.trim().is_empty() {
        0
    } else {
        forms
            .recv_port
            .trim()
            .parse::<u16>()
            .map_err(|_| "Enter a valid port number, or leave it blank for auto.".to_string())?
    };
    Ok(crate::net::ListenConfig {
        port,
        internet: forms.recv_internet,
        expected_sender_fpr: Some(contact.fingerprint()),
    })
}

#[cfg(feature = "net")]
fn build_send_config(
    forms: &TransferState,
    contacts: &ContactBook,
) -> Result<crate::net::SendConfig, String> {
    let fpr_hex = forms
        .send_contact
        .clone()
        .ok_or_else(|| "Pick a verified contact to send to.".to_string())?;
    let contact = contacts
        .contacts
        .iter()
        .find(|c| c.trust == Trust::Verified && hex(&c.fingerprint()) == fpr_hex)
        .ok_or_else(|| "Pick a verified contact to send to.".to_string())?;
    let host = forms.send_host.trim().to_string();
    if host.is_empty() {
        return Err("Enter the receiver's address.".into());
    }
    let port = forms
        .send_port
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| "Enter a valid port number.".to_string())?;
    let vault_id = forms
        .send_vault
        .clone()
        .ok_or_else(|| "Pick a vault to send.".to_string())?;
    let transfer_code = {
        let p = forms.send_pairing.trim();
        if p.is_empty() {
            return Err("Enter the transfer code the receiver is showing.".into());
        }
        Some(p.to_string())
    };
    Ok(crate::net::SendConfig {
        host,
        port,
        recipient: contact.identity.clone(),
        recipient_fpr: contact.fingerprint(),
        transfer_code,
        vault_id,
    })
}

#[cfg(feature = "net")]
fn transfer_ui(s: &mut Session, ui: &mut egui::Ui, action: &mut Option<Action>) {
    let cc = theme::colors(ui);
    theme::section_header(ui, "Transfer", |_ui| {});
    egui::ScrollArea::vertical()
        .auto_shrink([false, true])
        .show(ui, |ui| {
            // Constrain the forms to a comfortable column (left-aligned) instead of
            // letting cards collapse to their content or stretch the whole window.
            ui.set_max_width(TRANSFER_COL_W);
            ui.label(
                RichText::new(
                    "Send a vault straight to a verified contact over the network — no server in between. Keep both apps open during the transfer.",
                )
                .color(cc.text_muted),
            );
            ui.add_space(12.0);
            if let Some(active) = &s.transfer.active {
                active_transfer_card(active, ui, action);
            } else {
                receive_card(s, ui, action);
                ui.add_space(8.0);
                send_card(s, ui, action);
            }
        });
}

#[cfg(feature = "net")]
fn receive_card(s: &mut Session, ui: &mut egui::Ui, action: &mut Option<Action>) {
    let cc = theme::colors(ui);
    theme::card(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(theme::icon_text(theme::icon::DOWNLOAD, 18.0).color(cc.accent));
            ui.label(RichText::new("Receive").strong().size(15.0));
        });
        ui.add_space(4.0);
        ui.label(
            RichText::new("Wait for a contact you choose to send you a vault.")
                .color(cc.text_muted)
                .small(),
        );
        ui.add_space(10.0);

        let verified = verified_contacts(s);
        if verified.is_empty() {
            ui.label(
                RichText::new("Add and verify the contact you expect to receive from first.")
                    .color(cc.text_muted)
                    .small(),
            );
            return;
        }

        ui.label(RichText::new("Receive from").small().color(cc.text_muted));
        let field_w = ui.available_width();
        let label = combo_label(&s.transfer.recv_contact, &verified, "Choose a contact…");
        egui::ComboBox::from_id_salt("recv_contact")
            .width(field_w)
            .selected_text(label)
            .show_ui(ui, |ui| {
                for (fp, name) in &verified {
                    let selected = s.transfer.recv_contact.as_deref() == Some(fp.as_str());
                    if ui.selectable_label(selected, name).clicked() {
                        s.transfer.recv_contact = Some(fp.clone());
                    }
                }
            });
        ui.label(
            RichText::new("Only this contact will be able to send to you.")
                .color(cc.text_muted)
                .small(),
        );

        ui.add_space(10.0);
        ui.checkbox(
            &mut s.transfer.recv_internet,
            "Reachable over the internet (open a port on my router)",
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Port");
            net_input(ui, &mut s.transfer.recv_port, "auto", 90.0);
            ui.label(RichText::new("(optional)").color(cc.text_muted).small());
        });
        if s.transfer.recv_internet {
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "If your router can't open the port (NAT-PMP), you'll still be reachable on your local network.",
                )
                .color(cc.text_muted)
                .small(),
            );
        }
        ui.add_space(12.0);
        if theme::primary_button(ui, "Start listening").clicked() {
            *action = Some(Action::StartListen);
        }
    });
}

#[cfg(feature = "net")]
fn send_card(s: &mut Session, ui: &mut egui::Ui, action: &mut Option<Action>) {
    let cc = theme::colors(ui);
    theme::card(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(theme::icon_text(theme::icon::SEND, 18.0).color(cc.accent));
            ui.label(RichText::new("Send").strong().size(15.0));
        });
        ui.add_space(8.0);

        let verified = verified_contacts(s);
        if verified.is_empty() {
            ui.label(
                RichText::new(
                    "Add and verify a contact first — you can only send to verified contacts.",
                )
                .color(cc.text_muted)
                .small(),
            );
            return;
        }
        let vaults: Vec<(String, String)> = s
            .registry
            .vaults
            .iter()
            .map(|v| (v.id.clone(), v.name.clone()))
            .collect();
        if vaults.is_empty() {
            ui.label(
                RichText::new("Create a vault to send first.")
                    .color(cc.text_muted)
                    .small(),
            );
            return;
        }

        let field_w = ui.available_width();
        ui.label(RichText::new("Send to").small().color(cc.text_muted));
        let contact_label = combo_label(&s.transfer.send_contact, &verified, "Choose a contact…");
        egui::ComboBox::from_id_salt("send_contact")
            .width(field_w)
            .selected_text(contact_label)
            .show_ui(ui, |ui| {
                for (fp, name) in &verified {
                    let selected = s.transfer.send_contact.as_deref() == Some(fp.as_str());
                    if ui.selectable_label(selected, name).clicked() {
                        s.transfer.send_contact = Some(fp.clone());
                    }
                }
            });

        ui.add_space(8.0);
        ui.label(RichText::new("Vault").small().color(cc.text_muted));
        let vault_label = combo_label(&s.transfer.send_vault, &vaults, "Choose a vault…");
        egui::ComboBox::from_id_salt("send_vault")
            .width(field_w)
            .selected_text(vault_label)
            .show_ui(ui, |ui| {
                for (vid, name) in &vaults {
                    let selected = s.transfer.send_vault.as_deref() == Some(vid.as_str());
                    if ui.selectable_label(selected, name).clicked() {
                        s.transfer.send_vault = Some(vid.clone());
                    }
                }
            });

        ui.add_space(8.0);
        ui.label(RichText::new("Address").small().color(cc.text_muted));
        ui.horizontal(|ui| {
            let avail = ui.available_width();
            net_input(
                ui,
                &mut s.transfer.send_host,
                "IP or hostname",
                (avail - 84.0).max(120.0),
            );
            ui.label(":");
            net_input(ui, &mut s.transfer.send_port, "port", 56.0);
        });

        ui.add_space(8.0);
        ui.label(
            RichText::new("Transfer code (from the receiver)")
                .small()
                .color(cc.text_muted),
        );
        net_input(
            ui,
            &mut s.transfer.send_pairing,
            "e.g. ABCD-EFGH-JKMN-…",
            field_w.min(260.0),
        );

        ui.add_space(12.0);
        if theme::primary_button(ui, "Send").clicked() {
            *action = Some(Action::StartSend);
        }
    });
}

#[cfg(feature = "net")]
fn active_transfer_card(active: &ActiveTransfer, ui: &mut egui::Ui, action: &mut Option<Action>) {
    let cc = theme::colors(ui);
    theme::card(ui, |ui| {
        ui.set_min_width(ui.available_width());
        // The header IS the live phase, so it always matches what's actually
        // happening — e.g. "Listening for a sender…" while waiting, not a
        // misleading "Receiving". The direction (send vs receive) is clear from
        // the rows below (the listen address/code, the peer, the progress).
        ui.horizontal(|ui| {
            ui.add(egui::Spinner::new());
            ui.add_space(6.0);
            ui.label(RichText::new(&active.status).strong().size(15.0));
        });
        if let Some(peer) = &active.peer {
            ui.add_space(6.0);
            ui.label(RichText::new(format!("Peer: {peer}")).color(cc.text_muted));
        }

        if let Some(lv) = &active.listen {
            ui.add_space(8.0);
            ui.separator();
            ui.add_space(4.0);
            addr_row(ui, "On this network", &lv.lan_addr);
            if let Some(pa) = &lv.public_addr {
                addr_row(ui, "Over the internet", pa);
            }
            ui.label(RichText::new(&lv.nat).color(cc.text_muted).small());
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Transfer code:");
                ui.label(
                    RichText::new(&lv.transfer_code)
                        .monospace()
                        .strong()
                        .size(16.0)
                        .color(cc.accent),
                );
                if ui.small_button("Copy").clicked() {
                    ui.ctx().copy_text(lv.transfer_code.clone());
                }
            });
            ui.label(
                RichText::new(
                    "Give the address and this one-time code to the sender. The transfer \
                     can't start until they enter it — it also keeps your identity private \
                     from anyone who doesn't have it.",
                )
                .color(cc.text_muted)
                .small(),
            );
        }

        if let Some((done, total)) = active.progress {
            ui.add_space(8.0);
            let frac = if total > 0 {
                (done as f32 / total as f32).clamp(0.0, 1.0)
            } else {
                0.0
            };
            ui.add(egui::ProgressBar::new(frac).show_percentage());
            ui.label(
                RichText::new(format!("{} / {}", human_size(done), human_size(total)))
                    .color(cc.text_muted)
                    .small(),
            );
        }

        ui.add_space(10.0);
        let (label, act) = match active.kind {
            ActiveKind::Receive => ("Stop listening", Action::StopTransfer),
            ActiveKind::Send => ("Cancel", Action::CancelTransfer),
        };
        if theme::danger_button(ui, label).clicked() {
            *action = Some(act);
        }
    });
}

#[cfg(feature = "net")]
fn addr_row(ui: &mut egui::Ui, label: &str, addr: &str) {
    let cc = theme::colors(ui);
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).color(cc.text_muted).small());
        ui.label(RichText::new(addr).monospace());
        if ui.small_button("Copy").clicked() {
            ui.ctx().copy_text(addr.to_string());
        }
    });
}

#[cfg(feature = "net")]
fn transfer_offer_window(s: &mut Session, ctx: &egui::Context, action: &mut Option<Action>) {
    let (filename, size, sender) = match s.transfer.active.as_ref().and_then(|a| a.offer.as_ref()) {
        Some(o) => (o.filename.clone(), o.size, o.sender.clone()),
        None => return,
    };
    let (_close, ()) = theme::modal(ctx, "Incoming transfer", |ui| {
        let cc = theme::colors(ui);
        ui.label(format!("{sender} wants to send you:"));
        ui.add_space(6.0);
        ui.label(RichText::new(&filename).strong());
        ui.label(RichText::new(human_size(size)).color(cc.text_muted).small());
        ui.add_space(6.0);
        ui.label(
            RichText::new("Only accept files you're expecting from this contact.")
                .color(cc.text_muted)
                .small(),
        );
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if theme::primary_button(ui, "Accept").clicked() {
                *action = Some(Action::AcceptIncoming);
            }
            if theme::secondary_button(ui, "Reject").clicked() {
                *action = Some(Action::RejectIncoming);
            }
        });
    });
}

fn fatal_ui(msg: &str, ui: &mut egui::Ui) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        ui.heading("FileSec could not start");
        ui.add_space(8.0);
        ui.colored_label(ERR_RED, msg);
    });
}

fn first_run_ui(f: &mut FirstRun, ui: &mut egui::Ui, action: &mut Option<Action>) {
    let c = theme::colors(ui);
    ui.add_space(36.0);
    ui.vertical_centered(|ui| {
        ui.set_max_width(440.0);
        ui.label(theme::icon_text(theme::icon::LOCK_KEY, 40.0).color(c.accent));
        ui.add_space(6.0);
        ui.heading("Welcome to FileSec");
        ui.label(
            RichText::new(
                "Create your identity. Your private keys never leave this device \
                 and are encrypted with your passphrase.",
            )
            .color(c.text_muted),
        );
        ui.add_space(18.0);

        match &mut f.restore {
            // Restore-from-backup flow: a `.fsecid` file has been picked.
            Some(r) => {
                theme::card(ui, |ui| {
                    ui.label(RichText::new("Restore from a backup").size(16.0).strong());
                    ui.label(
                        RichText::new(format!(
                            "Restoring from {}",
                            r.path
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_else(|| r.path.display().to_string())
                        ))
                        .color(c.text_muted)
                        .small(),
                    );
                    ui.add_space(12.0);
                    field_label(ui, "Backup passphrase");
                    theme::text_input(
                        ui,
                        &mut r.backup_pass,
                        "Passphrase that protects the backup",
                        true,
                    );
                    ui.add_space(10.0);
                    field_label(ui, "New passphrase for this device");
                    theme::text_input(ui, &mut r.new_pass, PASSPHRASE_HINT, true);
                    ui.add_space(10.0);
                    field_label(ui, "Confirm new passphrase");
                    theme::text_input(ui, &mut r.new_pass2, "Repeat new passphrase", true);
                    ui.add_space(14.0);
                    if let Some(e) = &r.error {
                        ui.colored_label(c.err, e);
                        ui.add_space(10.0);
                    }
                    if theme::primary_button_full(ui, "Restore identity").clicked() {
                        *action = Some(Action::DoRestore);
                    }
                    ui.add_space(6.0);
                    if theme::secondary_button_full(ui, "Cancel").clicked() {
                        *action = Some(Action::CancelRestore);
                    }
                });
            }
            // Default: create a brand-new identity.
            None => {
                theme::card(ui, |ui| {
                    field_label(ui, "Display name");
                    theme::text_input(ui, &mut f.name, "e.g. Alice", false);
                    ui.add_space(10.0);
                    field_label(ui, "Passphrase");
                    theme::text_input(ui, &mut f.pass, PASSPHRASE_HINT, true);
                    ui.add_space(10.0);
                    field_label(ui, "Confirm passphrase");
                    theme::text_input(ui, &mut f.pass2, "Repeat passphrase", true);
                    ui.add_space(14.0);
                    if let Some(e) = &f.error {
                        ui.colored_label(c.err, e);
                        ui.add_space(10.0);
                    }
                    if theme::primary_button_full(ui, "Create identity").clicked() {
                        *action = Some(Action::CreateIdentity);
                    }
                    ui.add_space(6.0);
                    if theme::secondary_button_full(ui, "Restore from a backup…").clicked() {
                        *action = Some(Action::BeginRestore);
                    }
                });

                ui.add_space(12.0);
                ui.label(
                    RichText::new(
                        "⚠ There is no password recovery. If you forget your passphrase, \
                         your vaults cannot be opened.",
                    )
                    .color(c.warn)
                    .small(),
                );
            }
        }
    });
}

/// A small muted field caption above a form input.
fn field_label(ui: &mut egui::Ui, text: &str) {
    let c = theme::colors(ui);
    ui.label(RichText::new(text).small().color(c.text_muted));
    ui.add_space(2.0);
}

fn unlock_ui(u: &mut Unlock, ui: &mut egui::Ui, action: &mut Option<Action>) {
    let c = theme::colors(ui);
    ui.add_space(60.0);
    ui.vertical_centered(|ui| {
        ui.set_max_width(420.0);
        ui.label(theme::icon_text(theme::icon::LOCK, 40.0).color(c.accent));
        ui.add_space(6.0);
        ui.heading("Unlock FileSec");
        ui.add_space(16.0);

        theme::card(ui, |ui| {
            if u.legacy_recovery {
                ui.label(
                    RichText::new(
                        "One-time security upgrade required. FileSec found authenticated local state from before rollback protection was introduced. Enter your passphrase and confirm recovery; the keystore, contacts, registry, and registered vaults will be re-anchored immediately.",
                    )
                    .color(c.warn),
                );
                ui.add_space(10.0);
            }
            let resp = theme::text_input(ui, &mut u.pass, "Passphrase", true);
            let submit = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            ui.add_space(8.0);
            let button = if u.legacy_recovery {
                "Recover and upgrade local state"
            } else {
                "Unlock"
            };
            if theme::primary_button_full(ui, button).clicked() || submit {
                *action = Some(Action::Unlock);
            }

            // Security-key (passkey) unlock, when one is enrolled and this build
            // supports the hardware.
            if !u.legacy_recovery && u.has_passkeys && passkey::SUPPORTED {
                theme::divider_or(ui);
                theme::text_input(ui, &mut u.pin, "Security-key PIN (if set)", true);
                ui.add_space(6.0);
                if theme::secondary_button_full(ui, "🔑  Unlock with security key").clicked() {
                    *action = Some(Action::UnlockWithPasskey);
                }
            } else if !u.legacy_recovery && u.has_passkeys {
                ui.add_space(10.0);
                ui.label(
                    RichText::new(
                        "This identity has a security key enrolled, but this build can't use it \
                         (rebuild with --features passkey). Use your passphrase.",
                    )
                    .color(c.text_muted)
                    .small(),
                );
            }

            // This-device (OS keychain) unlock, when a device token is stored for
            // this device and this build can read it.
            if !u.legacy_recovery && u.has_saved && autounlock::SUPPORTED {
                theme::divider_or(ui);
                if theme::secondary_button_full(ui, "🔓  Unlock on this device").clicked() {
                    *action = Some(Action::UnlockWithKeyring);
                }
            } else if !u.legacy_recovery && u.has_saved {
                ui.add_space(10.0);
                ui.label(
                    RichText::new(
                        "This device has a saved unlock, but this build can't use it \
                         (rebuild with --features keyring). Use your passphrase.",
                    )
                    .color(c.text_muted)
                    .small(),
                );
            }

            if let Some(e) = &u.error {
                ui.add_space(10.0);
                ui.colored_label(c.err, e);
            }
        });
    });
}

fn session_ui(s: &mut Session, ui: &mut egui::Ui, action: &mut Option<Action>) {
    if s.open.is_some() {
        browser_ui(s, ui, action);
    } else {
        match s.nav {
            Nav::Vaults => vaults_ui(s, ui, action),
            Nav::Contacts => contacts_ui(s, ui, action),
            Nav::Identity => identity_ui(s, ui, action),
            #[cfg(feature = "net")]
            Nav::Transfer => transfer_ui(s, ui, action),
        }
    }

    if s.move_form.is_some() {
        move_window(s, ui.ctx(), action);
    }
    if s.text_editor.is_some() {
        text_editor_window(s, ui.ctx(), action);
    }
    if s.export.is_some() {
        export_window(s, ui.ctx(), action);
    }
    if s.last_import.is_some() {
        import_info_window(s, ui.ctx(), action);
    }
    if s.contact_preview.is_some() {
        contact_preview_window(s, ui.ctx(), action);
    }
    if s.verify.is_some() {
        verify_window(s, ui.ctx(), action);
    }
    #[cfg(feature = "pqc")]
    if s.migrate.is_some() {
        migrate_window(s, ui.ctx(), action);
    }
    if s.add_passkey.is_some() {
        add_passkey_window(s, ui.ctx(), action);
    }
    if s.auto_unlock_form.is_some() {
        autounlock_window(s, ui.ctx(), action);
    }
    if s.export_identity.is_some() {
        export_identity_window(s, ui.ctx(), action);
    }
    #[cfg(feature = "net")]
    if s.transfer
        .active
        .as_ref()
        .is_some_and(|a| a.offer.is_some())
    {
        transfer_offer_window(s, ui.ctx(), action);
    }
}

fn vaults_ui(s: &mut Session, ui: &mut egui::Ui, action: &mut Option<Action>) {
    let c = theme::colors(ui);
    theme::section_header(ui, "Vaults", |ui| {
        if theme::primary_button(ui, "+  New vault").clicked() {
            *action = Some(Action::ToggleNewVault(!s.show_new_vault));
        }
        if theme::secondary_button(ui, "Import .fsec…").clicked() {
            *action = Some(Action::ImportContainer);
        }
    });

    if s.show_new_vault {
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut s.new_vault_name)
                        .hint_text("Vault name")
                        .desired_width(240.0),
                );
                if theme::primary_button(ui, "Create").clicked() {
                    *action = Some(Action::CreateVault);
                }
                if theme::secondary_button(ui, "Cancel").clicked() {
                    *action = Some(Action::ToggleNewVault(false));
                }
            });
        });
    }

    if s.registry.vaults.is_empty() {
        theme::empty_state(
            ui,
            theme::icon::VAULT,
            "No vaults yet",
            "Create one, or import a .fsec someone sent you.",
            |ui| {
                if theme::primary_button(ui, "+  New vault").clicked() {
                    *action = Some(Action::ToggleNewVault(true));
                }
            },
        );
        return;
    }

    egui::ScrollArea::vertical().show(ui, |ui| {
        let mut vaults = s.registry.vaults.clone();
        vaults.sort_by_key(|b| std::cmp::Reverse(b.modified_at));
        for v in vaults {
            theme::card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(theme::icon_text(theme::icon::VAULT, 22.0).color(c.accent));
                    ui.add_space(6.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new(&v.name).strong().size(15.0));
                        ui.label(
                            RichText::new(format!(
                                "{} file(s) · {}",
                                v.file_count,
                                human_size(v.total_size)
                            ))
                            .color(c.text_muted)
                            .small(),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::icon_button(ui, theme::icon::TRASH, "Delete vault").clicked() {
                            *action = Some(Action::DeleteVault(v.id.clone()));
                        }
                        if theme::secondary_button(ui, "Send…").clicked() {
                            *action = Some(Action::BeginExport(v.id.clone()));
                        }
                        if theme::primary_button(ui, "Open").clicked() {
                            *action = Some(Action::OpenVault(v.id.clone()));
                        }
                    });
                });
            });
        }
    });
}

fn browser_ui(s: &mut Session, ui: &mut egui::Ui, action: &mut Option<Action>) {
    let panel_rect = ui.max_rect();
    let (name, id, entries) = match &s.open {
        Some(o) => (
            o.reader.name().to_string(),
            o.id.clone(),
            snapshot_entries(&o.reader),
        ),
        None => return,
    };
    // Drop any view whose temp a watcher already wiped (the app was closed), so
    // the banner reflects what is actually still open.
    s.views.retain(|v| v.temp_path.exists());
    // Keep the browse state coherent with the (possibly just-mutated) vault: clamp
    // the current folder to one that still exists, and drop any selection (or
    // anchor) whose entries were removed / renamed / trashed out from under us.
    s.current_dir = clamp_dir(&entries, &s.current_dir);
    {
        let live: HashSet<&str> = entries
            .iter()
            .filter(|(p, _, _)| !is_trashed(p))
            .map(|(p, _, _)| p.as_str())
            .collect();
        s.selected.retain(|p| live.contains(p.as_str()));
        if let Some(a) = &s.select_anchor {
            if !live.contains(a.as_str()) {
                s.select_anchor = None;
            }
        }
    }

    // Leaf of the file currently checked out for editing (if any). While set, all
    // other vault mutations are disabled and the user must check in / discard.
    let editing = s.checkout.as_ref().map(|c| c.leaf.clone());
    let viewing: Vec<String> = s.views.iter().map(|v| v.leaf.clone()).collect();
    let idle = editing.is_none();
    let c = theme::colors(ui);
    let cur = s.current_dir.clone();
    let trash = trashed_items(&entries);
    let in_trash = s.show_trash;

    // ---- Header: back, title, and whole-vault actions ----
    ui.horizontal(|ui| {
        if theme::secondary_button(ui, "←  Vaults").clicked() {
            *action = Some(Action::CloseVault);
        }
        ui.add_space(4.0);
        ui.heading(&name);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // The trash entry point lives in the header in both modes: it opens the
            // trash view, or (when already there) returns to the files. Plain text,
            // like the other header buttons — the Phosphor glyph family renders only
            // via `icon_text`, never inside a button label.
            let trash_label = if in_trash {
                "←  Back to files".to_string()
            } else if trash.is_empty() {
                "Trash".to_string()
            } else {
                format!("Trash ({})", trash.len())
            };
            if theme::secondary_button(ui, trash_label).clicked() {
                *action = Some(Action::ShowTrash(!in_trash));
            }
            if !in_trash {
                if theme::primary_button(ui, "Send…").clicked() {
                    *action = Some(Action::BeginExport(id.clone()));
                }
                if theme::secondary_button(ui, "Extract all…").clicked() {
                    *action = Some(Action::ExtractAll);
                }
            }
        });
    });
    ui.add_space(8.0);

    if let Some(leaf) = &editing {
        theme::banner(ui, c.accent, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::icon_text(theme::icon::EDIT, 16.0).color(c.accent));
                ui.label(
                    RichText::new(format!("Editing {leaf}"))
                        .color(c.accent)
                        .strong(),
                );
                ui.label(
                    RichText::new("— edit in your app, then:")
                        .color(c.text_muted)
                        .small(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::danger_button(ui, "Discard").clicked() {
                        *action = Some(Action::Discard);
                    }
                    if theme::primary_button(ui, "Check in").clicked() {
                        *action = Some(Action::CheckIn);
                    }
                });
            });
        });
    }

    if !viewing.is_empty() {
        let plural = if viewing.len() == 1 { "y" } else { "ies" };
        theme::banner(ui, c.accent, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(theme::icon_text(theme::icon::EYE, 16.0).color(c.accent));
                ui.label(
                    RichText::new(format!("Viewing {} read-only cop{plural}", viewing.len()))
                        .color(c.accent)
                        .strong(),
                );
                ui.label(
                    RichText::new(format!("({})", viewing.join(", ")))
                        .color(c.text_muted)
                        .small(),
                );
                ui.label(
                    RichText::new("— wiped automatically on close, or when you leave the vault.")
                        .color(c.text_muted)
                        .small(),
                );
            });
        });
    }

    // ---- Trash view: a separate mode that replaces the file list ----
    if in_trash {
        trash_panel(ui, c, &trash, idle, s.confirm_empty_trash, action);
        return;
    }

    // ---- Drag-and-drop from the OS (into the current folder) ----
    let modal_open = s.export.is_some()
        || s.last_import.is_some()
        || s.contact_preview.is_some()
        || s.verify.is_some()
        || s.add_passkey.is_some()
        || s.auto_unlock_form.is_some()
        || s.move_form.is_some()
        || s.text_editor.is_some();
    let dnd_enabled = idle && !modal_open;
    let hovering_files = dnd_enabled && ui.input(|i| !i.raw.hovered_files.is_empty());
    if dnd_enabled {
        let dropped: Vec<std::path::PathBuf> = ui.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        if !dropped.is_empty() {
            *action = Some(Action::DropPaths(dropped));
        }
    }

    // ---- Breadcrumb + sort + search ----
    ui.horizontal(|ui| {
        breadcrumb(ui, &cur, action);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if !s.file_search.is_empty()
                && theme::icon_button(ui, theme::icon::CLOSE, "Clear search").clicked()
            {
                s.file_search.clear();
            }
            ui.add(
                egui::TextEdit::singleline(&mut s.file_search)
                    .hint_text("Search this vault…")
                    .desired_width(180.0),
            );
            egui::ComboBox::from_id_salt("file_sort")
                .selected_text(s.sort.label())
                .show_ui(ui, |ui| {
                    for m in [
                        SortMode::NameAsc,
                        SortMode::NameDesc,
                        SortMode::SizeDesc,
                        SortMode::SizeAsc,
                    ] {
                        if ui.selectable_label(s.sort == m, m.label()).clicked() {
                            *action = Some(Action::SetSort(m));
                        }
                    }
                });
        });
    });
    ui.add_space(4.0);

    // ---- Keyboard shortcuts (only when not typing in a field or a dialog) ----
    //   Esc       clear the selection, then the search
    //   Del / ⌘⌫  move the selection to the trash
    //   ⌘/Ctrl-A  select every item in this view
    if idle && !modal_open && s.rename_target.is_none() && !ui.memory(|m| m.focused().is_some()) {
        let (clear, trash_sel, select_all) = ui.input(|i| {
            (
                i.key_pressed(egui::Key::Escape),
                i.key_pressed(egui::Key::Delete)
                    || (i.modifiers.command && i.key_pressed(egui::Key::Backspace)),
                i.modifiers.command && i.key_pressed(egui::Key::A),
            )
        });
        if clear {
            if !s.selected.is_empty() {
                *action = Some(Action::ClearSelection);
            } else if !s.file_search.trim().is_empty() {
                s.file_search.clear();
            }
        } else if select_all {
            *action = Some(Action::SelectAllVisible);
        } else if trash_sel && !s.selected.is_empty() {
            *action = Some(Action::TrashSelected);
        }
    }

    // ---- Add content (targets the current folder) ----
    ui.add_enabled_ui(idle, |ui| {
        ui.horizontal_wrapped(|ui| {
            if theme::secondary_button(ui, "+  Add files…").clicked() {
                *action = Some(Action::AddFiles);
            }
            if theme::secondary_button(ui, "+  Add folder…").clicked() {
                *action = Some(Action::AddFolder);
            }
            if theme::secondary_button(ui, "+  New folder").clicked() {
                *action = Some(Action::ToggleNewFolder(!s.show_new_folder));
            }
            if theme::secondary_button(ui, "+  New file").clicked() {
                *action = Some(Action::ToggleNewFile(!s.show_new_file));
            }
        });
    });

    if s.show_new_folder && idle {
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut s.new_folder_name)
                        .hint_text("Folder name")
                        .desired_width(220.0),
                );
                let submit = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if theme::primary_button(ui, "Create").clicked() || submit {
                    *action = Some(Action::NewFolder);
                }
                if theme::secondary_button(ui, "Cancel").clicked() {
                    *action = Some(Action::ToggleNewFolder(false));
                }
            });
        });
    }

    if s.show_new_file && idle {
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut s.new_file_name)
                        .hint_text("Name with extension, e.g. notes.txt")
                        .desired_width(260.0),
                );
                let submit = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if theme::primary_button(ui, "Create & edit").clicked() || submit {
                    *action = Some(Action::NewFile);
                }
                if theme::secondary_button(ui, "Cancel").clicked() {
                    *action = Some(Action::ToggleNewFile(false));
                }
            });
        });
    }

    // ---- Inline rename composer ----
    if idle {
        if let Some(target) = s.rename_target.clone() {
            theme::card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("Rename “{}”", leaf_name(&target))).color(c.text),
                    );
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut s.rename_input)
                            .hint_text("New name")
                            .desired_width(220.0),
                    );
                    let submit = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if theme::primary_button(ui, "Save").clicked() || submit {
                        *action = Some(Action::ConfirmRename);
                    }
                    if theme::secondary_button(ui, "Cancel").clicked() {
                        *action = Some(Action::CancelRename);
                    }
                });
            });
        }
    }
    ui.add_space(6.0);

    // ---- Selection action bar ----
    if idle && !s.selected.is_empty() {
        let n = s.selected.len();
        let selected: Vec<String> = s.selected.iter().cloned().collect();
        theme::banner(ui, c.accent, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{n} selected"))
                        .color(c.accent)
                        .strong(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::secondary_button(ui, "Clear").clicked() {
                        *action = Some(Action::ClearSelection);
                    }
                    if theme::danger_button(ui, "Delete").clicked() {
                        *action = Some(Action::TrashSelected);
                    }
                    if theme::secondary_button(ui, "Move…").clicked() {
                        *action = Some(Action::BeginMove(selected.clone()));
                    }
                    if theme::primary_button(ui, "Extract…").clicked() {
                        *action = Some(Action::ExtractSelected);
                    }
                });
            });
        });
    }

    // ---- The file/folder list ----
    let search = s.file_search.clone();
    let searching = !search.trim().is_empty();
    let rows = visible_rows(&entries, &cur, &search, s.sort);

    // A vault holding only trashed files still reads as empty here (the live tree
    // is what the browser shows; the trash has its own view).
    if !has_live_entries(&entries) {
        theme::empty_state(
            ui,
            theme::icon::FOLDER,
            "This vault is empty",
            "Add files or folders — or just drag them in from your computer.",
            |ui| {
                if idle && theme::primary_button(ui, "+  Add files…").clicked() {
                    *action = Some(Action::AddFiles);
                }
            },
        );
    } else if rows.is_empty() {
        if searching {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.label(theme::icon_text(theme::icon::FILE, 40.0).color(c.text_muted));
                ui.add_space(8.0);
                ui.label(RichText::new(format!("No files match “{}”", search.trim())).strong());
            });
        } else {
            theme::empty_state(
                ui,
                theme::icon::FOLDER,
                "This folder is empty",
                "Add files here, or drag them in from your computer.",
                |ui| {
                    if idle && theme::primary_button(ui, "+  Add files…").clicked() {
                        *action = Some(Action::AddFiles);
                    }
                },
            );
        }
    } else {
        // An at-a-glance summary of the current view, plus a "select all"
        // affordance on the right when there's more than one item to select.
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(view_summary(&rows, searching))
                    .color(c.text_muted)
                    .small(),
            );
            if !searching && idle && rows.len() > 1 {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add(
                            egui::Button::new(RichText::new("Select all").color(c.accent).small())
                                .frame(false),
                        )
                        .clicked()
                    {
                        *action = Some(Action::SelectAllVisible);
                    }
                });
            }
        });
        ui.add_space(2.0);
        let mut clicked: Option<(usize, RowClick)> = None;
        let mut bg_clicked = false;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                for (i, row) in rows.iter().enumerate() {
                    let is_sel = s.selected.contains(&row.path);
                    match entry_row(ui, c, row, is_sel, idle, searching, action) {
                        RowClick::None => {}
                        rc => clicked = Some((i, rc)),
                    }
                }
                // A click on the empty space below the rows clears the selection.
                let avail = ui.available_size();
                if avail.y > 4.0 && ui.allocate_response(avail, egui::Sense::click()).clicked() {
                    bg_clicked = true;
                }
            });
        // Resolve selection after the scroll area releases its borrow of `s`.
        if let Some((i, rc)) = clicked {
            apply_row_click(s, &rows, i, rc, action);
        } else if bg_clicked && !s.selected.is_empty() {
            *action = Some(Action::ClearSelection);
        }
    }

    // ---- Drag-and-drop overlay ----
    if hovering_files {
        let painter = ui.ctx().layer_painter(egui::LayerId::new(
            egui::Order::Foreground,
            egui::Id::new("filesec_dropzone"),
        ));
        painter.rect_filled(
            panel_rect,
            egui::CornerRadius::same(theme::RADIUS),
            theme::accent_soft(c),
        );
        painter.rect_stroke(
            panel_rect.shrink(2.0),
            egui::CornerRadius::same(theme::RADIUS),
            egui::Stroke::new(2.0, c.accent),
            egui::StrokeKind::Inside,
        );
        let target = if cur.is_empty() {
            name.clone()
        } else {
            leaf_name(&cur).to_string()
        };
        painter.text(
            panel_rect.center(),
            egui::Align2::CENTER_CENTER,
            format!("Drop to add to {target}"),
            egui::FontId::proportional(18.0),
            c.accent,
        );
    }
}

/// Render the folder breadcrumb ("Home / a / b"); each ancestor crumb navigates.
fn breadcrumb(ui: &mut egui::Ui, current: &str, action: &mut Option<Action>) {
    let c = theme::colors(ui);
    let segs = breadcrumb_segments(current);
    let last = segs.len().saturating_sub(1);
    // Scope the tighter crumb spacing so it doesn't leak to the rest of the row.
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        for (i, (label, target)) in segs.iter().enumerate() {
            if i > 0 {
                ui.label(RichText::new("/").color(c.text_muted));
            }
            if i == last {
                ui.label(RichText::new(label).strong().color(c.text));
            } else if ui
                .add(egui::Button::new(RichText::new(label).color(c.accent)).frame(false))
                .clicked()
            {
                *action = Some(Action::EnterDir(target.clone()));
            }
        }
    });
}

/// The trash view: soft-deleted entries, each with Restore / Delete forever, plus
/// an "Empty Trash" action. Items stay encrypted at rest until purged, and are
/// never included when a vault is sent or extracted.
fn trash_panel(
    ui: &mut egui::Ui,
    c: theme::Colors,
    items: &[TrashItem],
    idle: bool,
    confirm_empty: bool,
    action: &mut Option<Action>,
) {
    ui.horizontal(|ui| {
        ui.label(theme::icon_text(theme::icon::TRASH, 18.0).color(c.text_muted));
        ui.heading("Trash");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // Emptying the trash is the one irreversible bulk action here, so it
            // takes a second click to confirm.
            if !items.is_empty() && idle {
                if confirm_empty {
                    if theme::danger_button(ui, "Delete all permanently").clicked() {
                        *action = Some(Action::EmptyTrash);
                    }
                    if theme::secondary_button(ui, "Cancel").clicked() {
                        *action = Some(Action::PromptEmptyTrash(false));
                    }
                    ui.label(
                        RichText::new(format!("Delete {} item(s) forever?", items.len()))
                            .color(c.text_muted)
                            .small(),
                    );
                } else if theme::danger_button(ui, "Empty Trash").clicked() {
                    *action = Some(Action::PromptEmptyTrash(true));
                }
            }
        });
    });
    ui.label(
        RichText::new(
            "Deleted items stay encrypted here until you empty the Trash. They're never \
             included when you Send or Extract a vault.",
        )
        .color(c.text_muted)
        .small(),
    );
    ui.add_space(8.0);

    if items.is_empty() {
        theme::empty_state(
            ui,
            theme::icon::TRASH,
            "Trash is empty",
            "Files you delete land here, so you can put them back.",
            |_ui| {},
        );
        return;
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for item in items {
                theme::card(ui, |ui| {
                    ui.horizontal(|ui| {
                        let (glyph, col) = if item.kind == EntryKind::Dir {
                            (theme::icon::FOLDER, c.accent)
                        } else {
                            (theme::icon::FILE, file_tint(leaf_name(&item.orig_path), c))
                        };
                        ui.label(theme::icon_text(glyph, 18.0).color(col));
                        ui.add_space(4.0);
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(leaf_name(&item.orig_path))
                                    .color(c.text)
                                    .size(14.5),
                            );
                            ui.label(
                                RichText::new(trash_item_detail(item))
                                    .color(c.text_muted)
                                    .small(),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if idle && theme::danger_button(ui, "Delete forever").clicked() {
                                *action = Some(Action::PurgeTrashed(item.trashed_path.clone()));
                            }
                            if idle && theme::primary_button(ui, "Restore").clicked() {
                                *action = Some(Action::RestoreTrashed(item.trashed_path.clone()));
                            }
                        });
                    });
                });
            }
        });
}

/// The secondary line of a trash card: what it is, where it came from, and when
/// it was deleted.
fn trash_item_detail(item: &TrashItem) -> String {
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

/// The "move to folder" dialog: pick a destination folder for the chosen entries.
fn move_window(s: &mut Session, ctx: &egui::Context, action: &mut Option<Action>) {
    let entries = match &s.open {
        Some(o) => snapshot_entries(&o.reader),
        None => return,
    };
    let (paths, dest) = match &s.move_form {
        Some(f) => (f.paths.clone(), f.dest.clone()),
        None => return,
    };
    let options = move_folder_options(&entries, &paths);
    let (close, _) = theme::modal(ctx, "Move to…", |ui| {
        let cc = theme::colors(ui);
        ui.label(
            RichText::new(format!(
                "Moving {} item{}. Choose a destination folder:",
                paths.len(),
                if paths.len() == 1 { "" } else { "s" }
            ))
            .color(cc.text_muted),
        );
        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .max_height(280.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (path, label, depth) in &options {
                    ui.horizontal(|ui| {
                        ui.add_space(*depth as f32 * 16.0);
                        if ui.selectable_label(&dest == path, label).clicked() {
                            *action = Some(Action::SetMoveDest(path.clone()));
                        }
                    });
                }
            });
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if theme::primary_button(ui, "Move here").clicked() {
                *action = Some(Action::ConfirmMove);
            }
            if theme::secondary_button(ui, "Cancel").clicked() {
                *action = Some(Action::CancelMove);
            }
        });
    });
    if close {
        *action = Some(Action::CancelMove);
    }
}

/// The in-app quick text editor: a wide modal holding the file's plaintext in an
/// editable area, with Save / Close. The backdrop and Esc deliberately do *not*
/// dismiss it (a stray click must never discard an in-progress edit) — only the
/// buttons close it, so there is no `should_close` to honour.
fn text_editor_window(s: &mut Session, ctx: &egui::Context, action: &mut Option<Action>) {
    let cc = theme::colors_for(ctx);
    let (leaf, dirty) = match &s.text_editor {
        Some(te) => (te.leaf.clone(), te.dirty()),
        None => return,
    };
    let screen = ctx.screen_rect();
    egui::Modal::new(egui::Id::new("filesec_text_editor"))
        .backdrop_color(Color32::from_black_alpha(130))
        .frame(
            egui::Frame::NONE
                .fill(cc.surface)
                .stroke(egui::Stroke::new(1.0, cc.border))
                .corner_radius(egui::CornerRadius::same(theme::RADIUS))
                .inner_margin(egui::Margin::same(16)),
        )
        .show(ctx, |ui| {
            ui.set_width((screen.width() - 160.0).clamp(360.0, 900.0));
            ui.horizontal(|ui| {
                ui.label(theme::icon_text(theme::icon::EDIT, 16.0).color(cc.accent));
                ui.label(RichText::new(format!("Edit {leaf}")).size(16.0).strong());
                if dirty {
                    ui.label(RichText::new("• unsaved").color(cc.warn).small());
                }
            });
            ui.add_space(8.0);
            let rows = (((screen.height() - 230.0) / 16.0) as usize).clamp(8, 40);
            if let Some(te) = &mut s.text_editor {
                egui::ScrollArea::vertical()
                    .max_height((screen.height() - 200.0).max(160.0))
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut te.content)
                                .code_editor()
                                .desired_rows(rows)
                                .desired_width(f32::INFINITY),
                        );
                    });
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if theme::primary_button(ui, "Save").clicked() {
                    *action = Some(Action::SaveTextFile);
                }
                let close_label = if dirty { "Discard & close" } else { "Close" };
                if theme::secondary_button(ui, close_label).clicked() {
                    *action = Some(Action::CloseTextEditor);
                }
            });
        });
}

/// How the user clicked a row's *body* (its trailing buttons / context menu emit
/// actions directly). The browser resolves this against the full row order + the
/// selection anchor, so shift / ⌘ / Ctrl behave like a real file explorer.
#[derive(Clone, Copy)]
enum RowClick {
    None,
    /// A single primary click, with shift / command (Ctrl on Win/Linux, ⌘ on mac).
    Single {
        shift: bool,
        toggle: bool,
    },
    /// A double primary click: open — enter a folder, view a file.
    Double,
}

/// The pure core of a single (non-double) click: update `selected` + `anchor` per
/// the explorer modifier rules — plain = select only; ⌘/Ctrl = toggle; Shift =
/// range from the anchor; Shift+⌘/Ctrl = add the range. Unit-tested below.
fn resolve_single_click(
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

/// Resolve a row body click into the new selection (and any open action).
/// Double-click opens — enter a folder, view a file.
fn apply_row_click(
    s: &mut Session,
    rows: &[Row],
    idx: usize,
    click: RowClick,
    action: &mut Option<Action>,
) {
    match click {
        RowClick::None => {}
        RowClick::Double => {
            let path = rows[idx].path.clone();
            if rows[idx].kind == EntryKind::Dir {
                *action = Some(Action::EnterDir(path));
            } else {
                s.selected.clear();
                s.selected.insert(path.clone());
                s.select_anchor = Some(path.clone());
                *action = Some(Action::ViewFile(path));
            }
        }
        RowClick::Single { shift, toggle } => {
            resolve_single_click(
                &mut s.selected,
                &mut s.select_anchor,
                rows,
                idx,
                shift,
                toggle,
            );
        }
    }
}

/// One row in the file browser: a full-width, hover/selected-highlighted surface
/// with a type-tinted icon, a name + secondary line, and trailing quick actions
/// revealed on hover. The body click is *returned* (a [`RowClick`]); trailing
/// buttons and the right-click menu emit their actions directly.
fn entry_row(
    ui: &mut egui::Ui,
    c: theme::Colors,
    row: &Row,
    selected: bool,
    idle: bool,
    searching: bool,
    action: &mut Option<Action>,
) -> RowClick {
    let is_dir = row.kind == EntryKind::Dir;
    let (rect, resp) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 44.0), egui::Sense::click());
    // `contains_pointer` (geometric) rather than `hovered` (which a child button
    // on top would steal) so the trailing actions stay visible while you reach for
    // them, and the whole-row highlight doesn't flicker.
    let hovered = resp.contains_pointer();
    let bg = if selected {
        theme::accent_soft(c)
    } else if hovered {
        c.surface_hi
    } else {
        Color32::TRANSPARENT
    };
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(theme::RADIUS_SM), bg);
    if selected {
        ui.painter().rect_stroke(
            rect,
            egui::CornerRadius::same(theme::RADIUS_SM),
            egui::Stroke::new(1.0, c.accent),
            egui::StrokeKind::Inside,
        );
    }

    let inner = egui::Rect::from_min_max(
        egui::pos2(rect.left() + 10.0, rect.top()),
        egui::pos2(rect.right() - 8.0, rect.bottom()),
    );
    let mut cui = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(inner)
            .layout(egui::Layout::left_to_right(egui::Align::Center)),
    );
    let (glyph, col) = if is_dir {
        (theme::icon::FOLDER, c.accent)
    } else {
        (theme::icon::FILE, file_tint(leaf_name(&row.path), c))
    };
    cui.label(theme::icon_text(glyph, 18.0).color(col));
    cui.add_space(8.0);
    cui.vertical(|ui| {
        ui.add_space(4.0);
        ui.label(RichText::new(leaf_name(&row.path)).color(c.text).size(14.5));
        let secondary = if is_dir {
            format!(
                "{} item{}",
                row.children,
                if row.children == 1 { "" } else { "s" }
            )
        } else if searching {
            let parent = parent_dir(&row.path);
            if parent.is_empty() {
                human_size(row.size)
            } else {
                format!("{} · {}", human_size(row.size), parent)
            }
        } else {
            human_size(row.size)
        };
        ui.label(RichText::new(secondary).color(c.text_muted).small());
    });
    // Trailing actions, added right-to-left. Shown on hover or when selected. The
    // full set (incl. Rename / Move) also lives in the right-click menu below.
    cui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        let show = hovered || selected;
        if is_dir {
            if show
                && idle
                && theme::icon_button(ui, theme::icon::TRASH, "Move folder to Trash").clicked()
            {
                *action = Some(Action::Trash(row.path.clone()));
            }
        } else {
            if show && idle && theme::icon_button(ui, theme::icon::TRASH, "Move to Trash").clicked()
            {
                *action = Some(Action::Trash(row.path.clone()));
            }
            if show && theme::icon_button(ui, theme::icon::SAVE, "Save as…").clicked() {
                *action = Some(Action::SaveEntryAs(row.path.clone()));
            }
            if show
                && idle
                && theme::icon_button(ui, theme::icon::EDIT, "Check out & edit").clicked()
            {
                *action = Some(Action::CheckOut(row.path.clone()));
            }
            if show
                && idle
                && theme::icon_button(ui, theme::icon::EYE, "View read-only (auto-wiped on close)")
                    .clicked()
            {
                *action = Some(Action::ViewFile(row.path.clone()));
            }
        }
    });

    // Right-click menu: the same actions, plus Rename / Move which have no hover
    // button. egui closes the menu automatically when an item is clicked.
    resp.context_menu(|ui| {
        if is_dir {
            if ui.button("Open").clicked() {
                *action = Some(Action::EnterDir(row.path.clone()));
            }
        } else {
            if ui.button("View").clicked() {
                *action = Some(Action::ViewFile(row.path.clone()));
            }
            if idle && ui.button("Quick edit (in app)").clicked() {
                *action = Some(Action::QuickEdit(row.path.clone()));
            }
            if idle && ui.button("Check out & edit").clicked() {
                *action = Some(Action::CheckOut(row.path.clone()));
            }
            if ui.button("Save as…").clicked() {
                *action = Some(Action::SaveEntryAs(row.path.clone()));
            }
        }
        if idle {
            ui.separator();
            if ui.button("Rename…").clicked() {
                *action = Some(Action::BeginRename(row.path.clone()));
            }
            if ui.button("Move to…").clicked() {
                *action = Some(Action::BeginMove(vec![row.path.clone()]));
            }
            ui.separator();
            if ui.button("Delete").clicked() {
                *action = Some(Action::Trash(row.path.clone()));
            }
        }
    });

    // Report the body click; the browser resolves selection / open. Modifiers are
    // read at click time so shift / ⌘ / Ctrl emulate a real file explorer.
    if resp.double_clicked() {
        RowClick::Double
    } else if resp.clicked() {
        let (shift, toggle) = ui.input(|i| (i.modifiers.shift, i.modifiers.command));
        RowClick::Single { shift, toggle }
    } else {
        RowClick::None
    }
}

fn contacts_ui(s: &mut Session, ui: &mut egui::Ui, action: &mut Option<Action>) {
    let cc = theme::colors(ui);
    theme::section_header(ui, "Contacts", |_ui| {});
    ui.label(
        RichText::new("Import someone's public key, then verify their safety number out-of-band (in person or over a trusted channel) before sending them anything.")
            .color(cc.text_muted),
    );
    ui.add_space(10.0);

    theme::card(ui, |ui| {
        egui::CollapsingHeader::new("Add a contact")
            .default_open(s.contacts.contacts.is_empty())
            .show(ui, |ui| {
                ui.add_space(4.0);
                if theme::secondary_button(ui, "Load from .fsecpub file…").clicked() {
                    *action = Some(Action::PreviewContactFile);
                }
                ui.add_space(6.0);
                ui.label(
                    RichText::new("…or paste a public key:")
                        .color(cc.text_muted)
                        .small(),
                );
                theme::text_area(
                    ui,
                    &mut s.contact_paste,
                    "-----BEGIN FILESEC PUBLIC KEY-----",
                    4,
                );
                ui.add_space(6.0);
                if theme::primary_button(ui, "Preview key…").clicked() {
                    *action = Some(Action::PreviewContactPaste);
                }
                ui.label(
                    RichText::new(
                        "You'll see who the key belongs to and can confirm before it's added.",
                    )
                    .color(cc.text_muted)
                    .small(),
                );
            });
    });

    if s.contacts.contacts.is_empty() {
        theme::empty_state(
            ui,
            theme::icon::CONTACTS,
            "No contacts yet",
            "Add someone's public key above so you can send them vaults.",
            |_ui| {},
        );
        return;
    }

    egui::ScrollArea::vertical().show(ui, |ui| {
        let contacts = s.contacts.contacts.clone();
        for c in contacts {
            let fpr_hex = hex(&c.fingerprint());
            let display_name = if c.identity.name.is_empty() {
                "(unnamed)"
            } else {
                &c.identity.name
            };
            theme::card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(display_name).strong().size(15.0));
                            match c.trust {
                                Trust::Verified => {
                                    theme::badge(ui, "Verified", theme::BadgeKind::Ok)
                                }
                                Trust::Unverified => {
                                    theme::badge(ui, "Unverified", theme::BadgeKind::Warn)
                                }
                            };
                        });
                        ui.label(
                            RichText::new(c.identity.safety_number())
                                .monospace()
                                .color(cc.text_muted)
                                .small(),
                        );
                        if let (Trust::Verified, Some(t)) = (c.trust, c.verified_at) {
                            ui.label(
                                RichText::new(format!("verified {}", fmt_date(t)))
                                    .color(cc.text_muted)
                                    .small(),
                            );
                        }
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::icon_button(ui, theme::icon::TRASH, "Remove").clicked() {
                            *action = Some(Action::RemoveContact(fpr_hex.clone()));
                        }
                        match c.trust {
                            Trust::Verified => {
                                if theme::secondary_button(ui, "Unverify").clicked() {
                                    *action =
                                        Some(Action::SetTrust(fpr_hex.clone(), Trust::Unverified));
                                }
                            }
                            Trust::Unverified => {
                                if theme::primary_button(ui, "Verify…").clicked() {
                                    *action = Some(Action::BeginVerify(fpr_hex.clone()));
                                }
                            }
                        }
                    });
                });
            });
        }
    });
}

fn identity_ui(s: &mut Session, ui: &mut egui::Ui, action: &mut Option<Action>) {
    let cc = theme::colors(ui);
    let pubid = s.identity.public();
    theme::section_header(ui, "My Identity", |_ui| {});

    egui::ScrollArea::vertical().show(ui, |ui| {
        theme::card(ui, |ui| {
            egui::Grid::new("ident")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Name").color(cc.text_muted));
                    ui.label(RichText::new(&s.identity.name).strong());
                    ui.end_row();
                    ui.label(RichText::new("Fingerprint").color(cc.text_muted));
                    ui.label(RichText::new(pubid.fingerprint_hex()).monospace().small());
                    ui.end_row();
                });
            ui.add_space(8.0);
            ui.label(
                RichText::new("Safety number (read this aloud to verify with others):")
                    .color(cc.text_muted)
                    .small(),
            );
            ui.label(RichText::new(pubid.safety_number()).monospace().color(cc.accent));

            // Post-quantum status + one-click upgrade (pqc builds only).
            #[cfg(feature = "pqc")]
            {
                ui.add_space(10.0);
                if s.identity.is_hybrid_capable() {
                    ui.horizontal(|ui| {
                        ui.label(theme::icon_text(theme::icon::SHIELD, 16.0).color(cc.accent));
                        ui.label(
                            RichText::new(
                                "Post-quantum: hybrid X25519+ML-KEM-768 / Ed25519+ML-DSA-65",
                            )
                            .color(cc.accent),
                        );
                    });
                } else {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Post-quantum: not enabled (classical identity)")
                                .color(cc.text_muted),
                        );
                        if theme::secondary_button(ui, "Upgrade…").clicked() {
                            *action = Some(Action::BeginMigrate);
                        }
                    });
                }
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if theme::secondary_button(ui, "Copy public key").clicked() {
                    *action = Some(Action::CopyPubKey);
                }
                if theme::secondary_button(ui, "Save public key…").clicked() {
                    *action = Some(Action::SavePubKey);
                }
            });
            ui.add_space(6.0);
            ui.label(
                RichText::new("Share your public key with others so they can send you vaults. It contains no secrets.")
                    .color(cc.text_muted)
                    .small(),
            );
        });

        if let Some(warning) = &s.rollback_warning {
            theme::banner(ui, cc.warn, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(theme::icon_text(theme::icon::WARNING, 16.0).color(cc.warn));
                    ui.label(RichText::new(warning).color(cc.warn));
                });
            });
            ui.add_space(8.0);
        }

        // Identity backup: a portable, passphrase-encrypted copy of the private
        // keys, for restoring on another device or after a reinstall.
        theme::card(ui, |ui| {
            ui.label(RichText::new("Identity backup").size(16.0).strong());
            ui.label(
                RichText::new(
                    "Save an encrypted backup of your identity so you can restore it on \
                     another device or after a reinstall. Without a backup, a lost device \
                     means a lost identity — and everything encrypted to it.",
                )
                .color(cc.text_muted)
                .small(),
            );
            ui.add_space(8.0);
            if theme::primary_button(ui, "Export identity backup…").clicked() {
                *action = Some(Action::BeginExportIdentity);
            }
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "⚠ The backup file contains your private keys. Protect it with a strong \
                     passphrase and store it somewhere safe — anyone with the file and its \
                     passphrase becomes you.",
                )
                .color(cc.warn)
                .small(),
            );
        });

        // Security keys (passkeys). Shown when this build supports them, or
        // whenever any are already enrolled.
        if passkey::SUPPORTED || !s.passkeys.is_empty() {
            theme::card(ui, |ui| {
                ui.label(RichText::new("Security keys").size(16.0).strong());
                ui.label(
                    RichText::new(PASSKEY_ALT_UNLOCK_DESC)
                        .color(cc.text_muted)
                        .small(),
                );
                ui.add_space(8.0);
                if s.passkeys.is_empty() {
                    ui.label(RichText::new("No security keys enrolled.").color(cc.text_muted));
                } else {
                    for (i, pk) in s.passkeys.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(theme::icon_text(theme::icon::KEY, 16.0).color(cc.text_muted));
                            ui.label(RichText::new(pk.label.as_str()).strong());
                            ui.label(
                                RichText::new(format!("added {}", fmt_date(pk.added_at)))
                                    .color(cc.text_muted)
                                    .small(),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if theme::secondary_button(ui, "Remove").clicked() {
                                        *action = Some(Action::RemovePasskey(i));
                                    }
                                },
                            );
                        });
                    }
                }
                if passkey::SUPPORTED {
                    ui.add_space(8.0);
                    if theme::primary_button(ui, "+  Add security key…").clicked() {
                        *action = Some(Action::BeginAddPasskey);
                    }
                }
            });
        }

        // This-device convenience: remember the passphrase in the OS keychain so
        // this machine can auto-unlock. Shown when this build supports it, or
        // whenever a secret is already saved (so it can always be turned off).
        if autounlock::SUPPORTED || s.auto_unlock {
            theme::card(ui, |ui| {
                ui.label(RichText::new("This device").size(16.0).strong());
                ui.label(
                    RichText::new(
                        "Save a device unlock key in this computer's keychain so FileSec unlocks \
                         automatically here. Your passphrase is not stored — it still works and \
                         stays your recovery secret. Anyone with access to your logged-in \
                         account could then open FileSec, so only enable this on a trusted \
                         personal device.",
                    )
                    .color(cc.text_muted)
                    .small(),
                );
                if let Some(warning) = autounlock::device_binding_warning() {
                    ui.add_space(4.0);
                    ui.label(RichText::new(warning).color(cc.warn).small());
                }
                ui.add_space(8.0);
                if s.auto_unlock {
                    ui.horizontal(|ui| {
                        ui.label(theme::icon_text(theme::icon::LOCK_KEY, 15.0).color(cc.ok));
                        ui.colored_label(cc.ok, "Auto-unlock is on for this device.");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if theme::secondary_button(ui, "Forget on this device").clicked() {
                                *action = Some(Action::DisableAutoUnlock);
                            }
                        });
                    });
                } else if autounlock::SUPPORTED
                    && theme::secondary_button(ui, "Remember on this device…").clicked()
                {
                    *action = Some(Action::BeginEnableAutoUnlock);
                }
            });
        }

        ui.add_space(4.0);
        ui.label(
            RichText::new(format!("Encrypted data is stored at: {}", s.data_dir))
                .color(cc.text_muted)
                .small(),
        );
    });
}

/// The "Upgrade to post-quantum" confirmation dialog.
#[cfg(feature = "pqc")]
fn migrate_window(s: &mut Session, ctx: &egui::Context, action: &mut Option<Action>) {
    let form = match &mut s.migrate {
        Some(f) => f,
        None => return,
    };
    let (close, ()) = theme::modal(ctx, "Upgrade to post-quantum", |ui| {
        let c = theme::colors(ui);
        ui.label(
            "This adds ML-KEM-768 and ML-DSA-65 keys to your identity and re-encrypts your \
             whole local vault store under the hybrid post-quantum suite. Your existing \
             X25519/Ed25519 keys are kept.",
        );
        ui.add_space(8.0);
        ui.colored_label(c.err, "⚠ Your safety number will change.");
        ui.label(
            RichText::new(
                "Your identity now commits to its post-quantum keys, so your fingerprint and \
                 safety number change. After upgrading, re-share your public key and have your \
                 contacts re-verify it.",
            )
            .color(c.text_muted)
            .small(),
        );
        ui.add_space(6.0);
        ui.label(
            RichText::new(
                "Import any pending .fsec files first — containers others already sent to your \
                 old identity won't be openable afterwards.",
            )
            .color(c.text_muted)
            .small(),
        );
        ui.add_space(10.0);
        ui.label("Confirm your passphrase to re-seal the keystore:");
        ui.add(
            egui::TextEdit::singleline(&mut form.pass)
                .password(true)
                .desired_width(f32::INFINITY),
        );
        if let Some(e) = &form.error {
            ui.colored_label(c.err, e);
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if theme::primary_button(ui, "Upgrade now").clicked() {
                *action = Some(Action::DoMigrate);
            }
            if theme::secondary_button(ui, "Cancel").clicked() {
                *action = Some(Action::CancelMigrate);
            }
        });
    });
    if close {
        *action = Some(Action::CancelMigrate);
    }
}

/// The "Add security key" dialog.
fn add_passkey_window(s: &mut Session, ctx: &egui::Context, action: &mut Option<Action>) {
    let form = match &mut s.add_passkey {
        Some(f) => f,
        None => return,
    };
    let (close, ()) = theme::modal(ctx, "Add security key", |ui| {
        let c = theme::colors(ui);
        ui.label(
            "Enroll a FIDO2 hardware key (YubiKey, SoloKey, …) as an alternative way to unlock. \
             You'll be asked to verify (PIN or biometric) and touch it — once to create the key, \
             once to set up unlock. Your passphrase keeps working too.",
        );
        ui.add_space(10.0);
        egui::Grid::new("add_passkey_grid")
            .num_columns(2)
            .spacing([10.0, 8.0])
            .show(ui, |ui| {
                ui.label("Name");
                ui.add(
                    egui::TextEdit::singleline(&mut form.label)
                        .hint_text("e.g. YubiKey 5C")
                        .desired_width(240.0),
                );
                ui.end_row();
                ui.label("Passphrase");
                ui.add(
                    egui::TextEdit::singleline(&mut form.pass)
                        .password(true)
                        .hint_text("authorizes the change")
                        .desired_width(240.0),
                );
                ui.end_row();
                ui.label("Key PIN");
                ui.add(
                    egui::TextEdit::singleline(&mut form.pin)
                        .password(true)
                        .hint_text("your key's PIN, if it uses one for verification")
                        .desired_width(240.0),
                );
                ui.end_row();
            });
        if let Some(e) = &form.error {
            ui.add_space(4.0);
            ui.colored_label(c.err, e);
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if theme::primary_button(ui, "Touch key to enroll").clicked() {
                *action = Some(Action::AddPasskey);
            }
            if theme::secondary_button(ui, "Cancel").clicked() {
                *action = Some(Action::CancelAddPasskey);
            }
        });
    });
    if close {
        *action = Some(Action::CancelAddPasskey);
    }
}

/// The "Remember on this device" dialog: confirm the passphrase before saving it
/// to the OS keychain.
fn autounlock_window(s: &mut Session, ctx: &egui::Context, action: &mut Option<Action>) {
    let form = match &mut s.auto_unlock_form {
        Some(f) => f,
        None => return,
    };
    let (close, ()) = theme::modal(ctx, "Remember on this device", |ui| {
        let c = theme::colors(ui);
        ui.label(
            "Save a device unlock key in this computer's keychain so FileSec unlocks \
             automatically on this device. Your passphrase is not stored — it still works \
             everywhere and remains your recovery secret.",
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new(
                "Only do this on a trusted personal device: anyone who can use your \
                 logged-in account could then open FileSec here.",
            )
            .color(c.warn)
            .small(),
        );
        ui.add_space(10.0);
        ui.label("Confirm your passphrase:");
        let resp = ui.add(
            egui::TextEdit::singleline(&mut form.pass)
                .password(true)
                .desired_width(f32::INFINITY),
        );
        let submit = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if let Some(e) = &form.error {
            ui.colored_label(c.err, e);
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if theme::primary_button(ui, "Save on this device").clicked() || submit {
                *action = Some(Action::ConfirmEnableAutoUnlock);
            }
            if theme::secondary_button(ui, "Cancel").clicked() {
                *action = Some(Action::CancelEnableAutoUnlock);
            }
        });
    });
    if close {
        *action = Some(Action::CancelEnableAutoUnlock);
    }
}

/// The "Export identity backup" dialog: choose a backup passphrase to seal the
/// `.fsecid` file (independent of the daily passphrase).
fn export_identity_window(s: &mut Session, ctx: &egui::Context, action: &mut Option<Action>) {
    let form = match &mut s.export_identity {
        Some(f) => f,
        None => return,
    };
    let (close, ()) = theme::modal(ctx, "Export identity backup", |ui| {
        let c = theme::colors(ui);
        ui.label(
            "Choose a passphrase to protect this backup. You'll need it (not your \
             everyday passphrase) to restore the identity later, so it can differ from \
             the one you use day to day.",
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new(
                "The backup file holds your private keys. Anyone with the file and this \
                 passphrase becomes you — keep both safe.",
            )
            .color(c.warn)
            .small(),
        );
        ui.add_space(10.0);
        egui::Grid::new("export_identity_grid")
            .num_columns(2)
            .spacing([10.0, 8.0])
            .show(ui, |ui| {
                ui.label("Backup passphrase");
                ui.add(
                    egui::TextEdit::singleline(&mut form.pass)
                        .password(true)
                        .hint_text(PASSPHRASE_HINT)
                        .desired_width(240.0),
                );
                ui.end_row();
                ui.label("Confirm passphrase");
                ui.add(
                    egui::TextEdit::singleline(&mut form.pass2)
                        .password(true)
                        .hint_text("Repeat passphrase")
                        .desired_width(240.0),
                );
                ui.end_row();
            });
        if let Some(e) = &form.error {
            ui.add_space(4.0);
            ui.colored_label(c.err, e);
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if theme::primary_button(ui, "Choose file & export…").clicked() {
                *action = Some(Action::DoExportIdentity);
            }
            if theme::secondary_button(ui, "Cancel").clicked() {
                *action = Some(Action::CancelExportIdentity);
            }
        });
    });
    if close {
        *action = Some(Action::CancelExportIdentity);
    }
}

/// Short suite name for the export picker chips.
#[cfg(feature = "pqc")]
fn suite_short(s: SuiteId) -> &'static str {
    match s {
        SuiteId::Classic => "Classic",
        SuiteId::Aes256Gcm => "AES-256-GCM",
        SuiteId::Hybrid => "Hybrid PQC",
        _ => "Other",
    }
}

fn export_window(s: &mut Session, ctx: &egui::Context, action: &mut Option<Action>) {
    let form = match &s.export {
        Some(f) => f,
        None => return,
    };
    let (close, ()) = theme::modal(ctx, "Send vault", |ui| {
        ui.label(
            "Choose recipients. Each will be able to open the container with their private key.",
        );
        ui.add_space(6.0);
        if s.contacts.contacts.is_empty() {
            ui.colored_label(
                MUTED,
                "You have no contacts yet — add one first, or just include yourself.",
            );
        }
        egui::ScrollArea::vertical()
            .max_height(200.0)
            .show(ui, |ui| {
                for c in &s.contacts.contacts {
                    let fpr_hex = hex(&c.fingerprint());
                    let mut checked = form.selected.contains(&fpr_hex);
                    let name = if c.identity.name.is_empty() {
                        "(unnamed)"
                    } else {
                        c.identity.name.as_str()
                    };
                    let label = match c.trust {
                        Trust::Verified => format!("{name} (verified)"),
                        Trust::Unverified => format!("{name} — unverified ⚠"),
                    };
                    if ui.checkbox(&mut checked, label).changed() {
                        *action = Some(Action::ToggleRecipient(fpr_hex));
                    }
                }
            });
        ui.separator();
        let mut include_self = form.include_self;
        if ui
            .checkbox(
                &mut include_self,
                "Also include myself (so I can re-open it)",
            )
            .changed()
        {
            *action = Some(Action::ToggleIncludeSelf);
        }
        // Algorithm-suite picker (post-quantum builds only). The classical
        // build has a single suite and shows no picker.
        #[cfg(feature = "pqc")]
        {
            // Hybrid needs a post-quantum *sender* identity; a non-migrated
            // classical identity can only pick the classical suites.
            let sender_hybrid = s.identity.is_hybrid_capable();
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Encryption suite:");
                for opt in [SuiteId::Classic, SuiteId::Aes256Gcm, SuiteId::Hybrid] {
                    let enabled = sender_hybrid || !opt.is_hybrid();
                    let resp = ui
                        .add_enabled_ui(enabled, |ui| {
                            ui.selectable_label(form.suite == opt, suite_short(opt))
                        })
                        .inner;
                    if enabled && resp.clicked() {
                        *action = Some(Action::SetExportSuite(opt));
                    }
                }
            });
            if !sender_hybrid {
                ui.label(
                    RichText::new(
                        "Hybrid PQC needs a post-quantum identity — upgrade yours in “My \
                             Identity” to enable it.",
                    )
                    .color(MUTED)
                    .small(),
                );
            }
            ui.label(RichText::new(form.suite.label()).color(MUTED).small());
            if form.suite.is_hybrid() {
                let missing: Vec<&str> = s
                    .contacts
                    .contacts
                    .iter()
                    .filter(|c| {
                        form.selected.contains(&hex(&c.fingerprint()))
                            && !c.identity.is_hybrid_capable()
                    })
                    .map(|c| {
                        if c.identity.name.is_empty() {
                            "(unnamed)"
                        } else {
                            c.identity.name.as_str()
                        }
                    })
                    .collect();
                if missing.is_empty() {
                    ui.colored_label(MUTED, "Every recipient also gets post-quantum protection.");
                } else {
                    ui.colored_label(
                            ERR_RED,
                            format!(
                                "⚠ No post-quantum key for: {}. Pick another suite or ask them to re-share.",
                                missing.join(", ")
                            ),
                        );
                }
            }
        }
        ui.add_space(6.0);
        // Downgrade/trust warning: spell out exactly which selected
        // recipients have not been verified out-of-band, so sending to an
        // unverified key is always a deliberate, informed choice.
        let unverified: Vec<&str> = s
            .contacts
            .contacts
            .iter()
            .filter(|c| {
                c.trust == Trust::Unverified && form.selected.contains(&hex(&c.fingerprint()))
            })
            .map(|c| {
                if c.identity.name.is_empty() {
                    "(unnamed)"
                } else {
                    c.identity.name.as_str()
                }
            })
            .collect();
        if !unverified.is_empty() {
            ui.colored_label(
                ERR_RED,
                format!("⚠ Unverified recipient(s): {}", unverified.join(", ")),
            );
            ui.label(
                    RichText::new(
                        "You haven't confirmed these keys out-of-band. Anyone could have supplied them.",
                    )
                    .color(MUTED)
                    .small(),
                );
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if theme::primary_button(ui, "Choose file & export").clicked() {
                *action = Some(Action::DoExport);
            }
            if theme::secondary_button(ui, "Cancel").clicked() {
                *action = Some(Action::CancelExport);
            }
        });
    });
    if close {
        *action = Some(Action::CancelExport);
    }
}

fn import_info_window(s: &mut Session, ctx: &egui::Context, action: &mut Option<Action>) {
    let info = match &s.last_import {
        Some(i) => i,
        None => return,
    };
    let (close, ()) = theme::modal(ctx, "Imported vault", |ui| {
        ui.label(RichText::new(format!("\"{}\"", info.vault_name)).strong());
        ui.label(format!("{} file(s)", info.file_count));
        ui.separator();
        ui.label("Sender's signature is cryptographically valid. Identity:");
        // `signature valid` only proves the bytes came from whoever holds
        // these keys — NOT that those keys belong to who you think. The
        // out-of-band safety-number check is what closes that gap, so the
        // dialog nudges toward it whenever the sender isn't verified.
        let fpr_hex = info.sender_fpr_hex.clone();
        match (&info.sender_name, info.verified) {
            (Some(name), true) => {
                ui.colored_label(OK_GREEN, format!("✔ {name} (verified contact)"));
            }
            (Some(name), false) => {
                ui.colored_label(
                    WARN_AMBER,
                    format!("● {name} — a known but UNVERIFIED contact"),
                );
                ui.label(
                    RichText::new("Verify their safety number before you trust this content.")
                        .color(MUTED)
                        .small(),
                );
            }
            (None, _) => {
                ui.colored_label(ERR_RED, "● Unknown sender — not in your contacts");
                ui.label(
                    RichText::new(
                        "Add them as a contact, then verify their safety number out-of-band.",
                    )
                    .color(MUTED)
                    .small(),
                );
            }
        }
        ui.label(
            RichText::new(format!("fingerprint: {}", info.sender_fpr_hex))
                .monospace()
                .small()
                .color(MUTED),
        );
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            match (&info.sender_name, info.verified) {
                // Known but unverified → jump straight into verification.
                (Some(_), false) => {
                    if theme::primary_button(ui, "Verify sender…").clicked() {
                        *action = Some(Action::BeginVerify(fpr_hex));
                    }
                }
                // Unknown → offer to add them as a contact first.
                (None, _) if theme::primary_button(ui, "Add sender to contacts…").clicked() => {
                    *action = Some(Action::AddSenderToContacts);
                }
                _ => {}
            }
            if theme::secondary_button(ui, "OK").clicked() {
                *action = Some(Action::DismissImportInfo);
            }
        });
    });
    if close {
        *action = Some(Action::DismissImportInfo);
    }
}

/// Confirmation step for a parsed-but-not-yet-saved contact key. Shows who the
/// key belongs to (name, fingerprint, safety number) and the trust implication
/// of adding it, so nothing is added — and no verified contact silently renamed
/// — without the user seeing it first.
fn contact_preview_window(s: &mut Session, ctx: &egui::Context, action: &mut Option<Action>) {
    let preview = match &s.contact_preview {
        Some(p) => p,
        None => return,
    };
    // The pasted key is untrusted: render its name only through the sanitizer so a
    // bidi/zero-width spoof can't disguise it as another contact or as system text.
    let name = preview.pubid.display_name();
    let is_self = matches!(preview.status, PreviewStatus::SelfKey);
    let (close, ()) = theme::modal(ctx, "Add contact?", |ui| {
        egui::Grid::new("preview_grid")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("Name");
                ui.label(RichText::new(&name).strong());
                ui.end_row();
                ui.label("Fingerprint");
                ui.label(
                    RichText::new(preview.pubid.fingerprint_hex())
                        .monospace()
                        .small(),
                );
                ui.end_row();
            });
        ui.add_space(4.0);
        ui.label("Safety number:");
        ui.label(
            RichText::new(preview.pubid.safety_number())
                .monospace()
                .color(ACCENT),
        );
        ui.add_space(8.0);
        ui.separator();
        match &preview.status {
            PreviewStatus::New => {
                ui.label(
                    RichText::new(
                        "New contact. You'll verify their safety number before trusting them.",
                    )
                    .color(MUTED),
                );
            }
            PreviewStatus::Existing { verified: true } => {
                ui.colored_label(
                    OK_GREEN,
                    "Already a verified contact — nothing will change.",
                );
            }
            PreviewStatus::Existing { verified: false } => {
                ui.colored_label(
                    MUTED,
                    "Already a contact (unverified) — nothing will change.",
                );
            }
            PreviewStatus::Renamed {
                old,
                verified: true,
            } => {
                ui.colored_label(
                    ERR_RED,
                    format!("⚠ This renames a VERIFIED contact: \"{old}\" → \"{name}\"."),
                );
                ui.label(
                        RichText::new(
                            "The keys are identical, so verification still holds — but confirm you expected this rename.",
                        )
                        .color(MUTED)
                        .small(),
                    );
            }
            PreviewStatus::Renamed {
                old,
                verified: false,
            } => {
                ui.colored_label(
                    WARN_AMBER,
                    format!("Display name will change: \"{old}\" → \"{name}\"."),
                );
            }
            PreviewStatus::SelfKey => {
                ui.colored_label(
                    ERR_RED,
                    "⚠ This is your OWN public key — you don't need to add yourself.",
                );
            }
        }
        ui.add_space(12.0);
        let c = theme::colors(ui);
        ui.horizontal(|ui| {
            let add_label = match &preview.status {
                PreviewStatus::Renamed { .. } => "Update contact",
                _ => "Add contact",
            };
            let btn = egui::Button::new(RichText::new(add_label).color(c.on_accent).strong())
                .fill(c.accent)
                .corner_radius(egui::CornerRadius::same(theme::RADIUS_SM))
                .min_size(egui::vec2(0.0, 32.0));
            if ui.add_enabled(!is_self, btn).clicked() {
                *action = Some(Action::ConfirmAddContact);
            }
            if theme::secondary_button(ui, "Cancel").clicked() {
                *action = Some(Action::CancelPreview);
            }
        });
    });
    if close {
        *action = Some(Action::CancelPreview);
    }
}

/// The verification dialog: compare a contact's safety number out-of-band. The
/// user can either type back what the other party reads (the app checks the
/// match, ignoring spacing/case) or tick the manual "I compared it" box. Either
/// path enables "Mark verified".
fn verify_window(s: &mut Session, ctx: &egui::Context, action: &mut Option<Action>) {
    let form = match &mut s.verify {
        Some(f) => f,
        None => return,
    };
    let fpr_hex = form.fpr_hex.clone();
    // Recompute the match each frame against the canonical number.
    let typed_match = !form.input.trim().is_empty()
        && filesec_core::util::normalize_safety_number(&form.input)
            == filesec_core::util::normalize_safety_number(&form.safety_number);
    let title = format!("Verify {}", form.name);
    let (close, ()) = theme::modal(ctx, &title, |ui| {
        ui.label(
                RichText::new(
                    "Compare this safety number with the contact over a trusted channel — in person, a video call, or a line you already trust. Mark verified only once both sides match exactly.",
                )
                .color(MUTED),
            );
        ui.add_space(8.0);
        ui.label("Their safety number should read:");
        ui.horizontal(|ui| {
            ui.label(RichText::new(&form.safety_number).monospace().color(ACCENT));
            if ui.small_button("Copy").clicked() {
                *action = Some(Action::CopyVerifySafetyNumber);
            }
        });
        ui.add_space(8.0);
        ui.label("Type what they read back (optional — the app checks it for you):");
        ui.add(
            egui::TextEdit::singleline(&mut form.input)
                .desired_width(f32::INFINITY)
                .hint_text("e.g. ABCD-EFGH-…"),
        );
        if !form.input.trim().is_empty() {
            if typed_match {
                ui.colored_label(OK_GREEN, "✔ Matches.");
            } else {
                ui.colored_label(ERR_RED, "✗ Does not match — do not verify.");
            }
        }
        ui.add_space(4.0);
        ui.checkbox(
            &mut form.manual_ok,
            "I compared it myself and it matches exactly.",
        );
        ui.add_space(12.0);
        let can_verify = typed_match || form.manual_ok;
        let cc = theme::colors(ui);
        ui.horizontal(|ui| {
            let btn =
                egui::Button::new(RichText::new("Mark verified").color(cc.on_accent).strong())
                    .fill(cc.accent)
                    .corner_radius(egui::CornerRadius::same(theme::RADIUS_SM))
                    .min_size(egui::vec2(0.0, 32.0));
            if ui.add_enabled(can_verify, btn).clicked() {
                *action = Some(Action::ConfirmVerify(fpr_hex.clone()));
            }
            if theme::secondary_button(ui, "Cancel").clicked() {
                *action = Some(Action::CancelVerify);
            }
        });
    });
    if close {
        *action = Some(Action::CancelVerify);
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Format a Unix timestamp (seconds) as a UTC `YYYY-MM-DD` date. Self-contained
/// (no chrono dependency) via Howard Hinnant's civil-from-days algorithm.
fn fmt_date(unix: i64) -> String {
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

fn decode_fpr(hex_str: &str) -> Option<[u8; 32]> {
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

fn file_mtime(path: &std::path::Path) -> Option<i64> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}

fn passphrase_policy_error(passphrase: &str) -> Option<String> {
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

fn has_long_repeated_run(chars: &[char]) -> bool {
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

fn passphrase_strength_score(passphrase: &str, chars: &[char], unique: usize) -> u32 {
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

fn read_bounded_file(
    path: &std::path::Path,
    max_len: u64,
    label: &'static str,
) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err(format!("{label} is not a file."));
    }
    if meta.len() > max_len {
        return Err(format!("{label} is too large."));
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > max_len {
        return Err(format!("{label} is too large."));
    }
    Ok(bytes)
}

fn read_bounded_text_file(
    path: &std::path::Path,
    max_len: u64,
    label: &'static str,
) -> Result<String, String> {
    let bytes = read_bounded_file(path, max_len, label)?;
    String::from_utf8(bytes).map_err(|_| format!("{label} is not valid UTF-8."))
}

/// Pick a vault path for `base` that does not collide with any path in
/// `existing`, appending " (n)" before the extension if needed.
fn unique_name_in(existing: &HashSet<String>, base: &str) -> String {
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
fn plan_additions(
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

fn sanitize_filename(name: &str) -> String {
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

/// Sanitize a filename leaf for a checkout temp file, **preserving the extension**
/// (dots are kept) so the OS opens it with the right application. Path separators
/// and other oddities become `_`; the store always prepends a random prefix, so
/// the result can never traverse or collide.
fn sanitize_leaf(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "file".to_string()
    } else {
        cleaned
    }
}

/// `CREATE_NO_WINDOW` (winbase.h). The `cmd /C start …` launcher we use to open
/// files in their default app would otherwise flash an empty console window over
/// the GUI every time. This flag suppresses that console without affecting the
/// app `start` ultimately launches (it gets its own window).
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Best-effort: open `path` in the OS default application, detached (we do not
/// wait for it to close). Uses platform launchers via `std::process::Command`
/// to avoid pulling an extra dependency.
fn open_in_default_app(path: &std::path::Path) -> std::io::Result<()> {
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
enum ViewLaunch {
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
fn start_view(path: &std::path::Path) -> ViewLaunch {
    let p = path.to_path_buf();
    #[cfg(target_os = "macos")]
    {
        match std::process::Command::new("open").arg("-W").arg(&p).spawn() {
            Ok(mut child) => {
                std::thread::spawn(move || {
                    let _ = child.wait();
                    let _ = crate::store::secure_wipe(&p);
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
                    let _ = crate::store::secure_wipe(&p);
                });
                ViewLaunch::WatchingForClose
            }
            Err(_) => ViewLaunch::Failed,
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        match std::process::Command::new("xdg-open").arg(&p).spawn() {
            Ok(_) => ViewLaunch::LaunchedNoWatch,
            Err(_) => ViewLaunch::Failed,
        }
    }
}

/// Securely wipe every active view's temp file and clear the list. Called when
/// leaving the vault (close/nav/lock) and on exit. Idempotent: `secure_wipe`
/// tolerates already-gone files, so a watcher that wiped first is harmless.
fn wipe_all_views(views: &mut Vec<ActiveView>) {
    for v in views.drain(..) {
        let _ = crate::store::secure_wipe(&v.temp_path);
    }
}

fn human_size(bytes: u64) -> String {
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
fn snapshot_entries(reader: &VaultReaderV2) -> Vec<(String, EntryKind, u64)> {
    reader
        .entries()
        .iter()
        .map(|e| (e.path.clone(), e.kind, e.size))
        .collect()
}

/// A short random hex tag that makes each trash token unique, so two deletions
/// of the same path (even in the same second) never collide.
fn trash_tag() -> StoreResult<String> {
    let bytes = filesec_core::secret::random_array::<4>().map_err(|e| e.to_string())?;
    Ok(hex(&bytes))
}

/// The parent directory of a normalized vault path ("" for a top-level entry).
fn parent_dir(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((parent, _)) => parent,
        None => "",
    }
}

/// The final path segment (the display name) of a vault path.
fn leaf_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Clamp `dir` to the nearest existing ancestor directory (or the root, ""), so a
/// folder removed/renamed out from under the browser never strands the view.
fn clamp_dir(entries: &[(String, EntryKind, u64)], dir: &str) -> String {
    let exists = |d: &str| {
        d.is_empty()
            || entries
                .iter()
                .any(|(p, k, _)| p == d && *k == EntryKind::Dir)
    };
    let mut cur = dir.to_string();
    while !cur.is_empty() && !exists(&cur) {
        cur = parent_dir(&cur).to_string();
    }
    cur
}

/// How many entries sit directly inside `dir`.
fn dir_child_count(entries: &[(String, EntryKind, u64)], dir: &str) -> usize {
    entries
        .iter()
        .filter(|(p, _, _)| parent_dir(p) == dir)
        .count()
}

/// A single browser row: a file or folder to display.
struct Row {
    path: String,
    kind: EntryKind,
    size: u64,
    /// For a folder, the number of entries directly inside it (0 for files).
    children: usize,
}

/// Build the ordered rows to show: either the direct children of `dir`, or — when
/// `search` is non-empty — every entry in the vault whose name matches, anywhere.
/// Directories always sort before files; `sort` orders within each group.
fn visible_rows(
    entries: &[(String, EntryKind, u64)],
    dir: &str,
    search: &str,
    sort: SortMode,
) -> Vec<Row> {
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
                dir_child_count(entries, p)
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
fn sort_rows(rows: &mut [Row], sort: SortMode) {
    rows.sort_by(|a, b| {
        let dirs_first = (a.kind != EntryKind::Dir).cmp(&(b.kind != EntryKind::Dir));
        dirs_first.then_with(|| {
            let an = leaf_name(&a.path).to_lowercase();
            let bn = leaf_name(&b.path).to_lowercase();
            match sort {
                SortMode::NameAsc => an.cmp(&bn),
                SortMode::NameDesc => bn.cmp(&an),
                SortMode::SizeDesc => b.size.cmp(&a.size).then(an.cmp(&bn)),
                SortMode::SizeAsc => a.size.cmp(&b.size).then(an.cmp(&bn)),
            }
        })
    });
}

/// A one-line summary of a browser view: "2 folders · 5 files · 4.2 MB", or
/// "N matches" while searching. Sizes count files only.
fn view_summary(rows: &[Row], searching: bool) -> String {
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
fn breadcrumb_segments(dir: &str) -> Vec<(String, String)> {
    let mut out = vec![("Home".to_string(), String::new())];
    let mut acc = String::new();
    for seg in dir.split('/').filter(|s| !s.is_empty()) {
        if acc.is_empty() {
            acc = seg.to_string();
        } else {
            acc = format!("{acc}/{seg}");
        }
        out.push((seg.to_string(), acc.clone()));
    }
    out
}

/// Broad file categories, used only to tint the file icon for quick scanning.
#[derive(PartialEq, Debug)]
enum FileCat {
    Image,
    Media,
    Archive,
    Code,
    Other,
}

/// Classify a filename by extension into a coarse [`FileCat`].
fn file_category(name: &str) -> FileCat {
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
fn file_tint(name: &str, c: theme::Colors) -> Color32 {
    match file_category(name) {
        FileCat::Image => c.ok,
        FileCat::Media => c.accent_hi,
        FileCat::Archive => c.warn,
        FileCat::Code => c.accent,
        FileCat::Other => c.text_muted,
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
struct TrashItem {
    /// Its current (hidden) path under `.trash/`.
    trashed_path: String,
    /// Where "Restore" will try to put it back (its original vault path).
    orig_path: String,
    /// Unix seconds it was moved to the trash.
    deleted_at: i64,
    kind: EntryKind,
    /// A file's own size, or the total size of a folder's contents.
    size: u64,
    /// For a folder, how many files it holds (0 for a file).
    files: usize,
}

/// Percent-encode the only two characters that can't appear raw in a single
/// trash path segment: `%` (the escape itself) and `/` (a separator). Spaces,
/// dots, and unicode pass through untouched.
fn pct_encode_seg(s: &str) -> String {
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
fn pct_decode_seg(s: &str) -> String {
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
fn trash_dest(deleted_at: i64, rand_hex: &str, orig: &str) -> String {
    format!(
        "{TRASH_DIR}/{deleted_at}-{rand_hex}-{}",
        pct_encode_seg(orig)
    )
}

/// Parse a top-level trash entry path (a direct child of `.trash`) back into its
/// `(deletion time, original path)`. Returns `None` for a malformed token, so a
/// hand-mangled manifest degrades gracefully instead of showing garbage.
fn parse_trash_token(trashed_path: &str) -> Option<(i64, String)> {
    let token = trashed_path.strip_prefix(".trash/")?;
    // Exactly three parts: <deleted_at>-<rand>-<encoded original path>. The
    // original path may itself contain '-', so only the first two are split off.
    let mut parts = token.splitn(3, '-');
    let deleted_at: i64 = parts.next()?.parse().ok()?;
    let _rand = parts.next()?;
    let encoded = parts.next()?;
    Some((deleted_at, pct_decode_seg(encoded)))
}

/// (file count, total size) of everything strictly inside a trashed folder.
fn trashed_subtree_totals(entries: &[(String, EntryKind, u64)], top: &str) -> (usize, u64) {
    let prefix = format!("{top}/");
    entries
        .iter()
        .filter(|(p, k, _)| *k == EntryKind::File && p.starts_with(&prefix))
        .fold((0, 0), |(n, sz), (_, _, s)| (n + 1, sz + s))
}

/// The soft-deleted entries (the direct children of `.trash`), most-recent
/// first. Malformed tokens are skipped rather than shown wrong.
fn trashed_items(entries: &[(String, EntryKind, u64)]) -> Vec<TrashItem> {
    let mut items: Vec<TrashItem> = entries
        .iter()
        .filter(|(p, _, _)| parent_dir(p) == TRASH_DIR)
        .filter_map(|(p, kind, size)| {
            let (deleted_at, orig_path) = parse_trash_token(p)?;
            let (files, total) = if *kind == EntryKind::Dir {
                trashed_subtree_totals(entries, p)
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

/// Whether the vault has any entry outside the trash. A vault holding only
/// trashed files should still read as "empty" in the browser.
fn has_live_entries(entries: &[(String, EntryKind, u64)]) -> bool {
    entries.iter().any(|(p, _, _)| !is_trashed(p))
}

/// (live file count, live total size) — i.e. excluding the trash — so a vault's
/// card shrinks the moment a file is trashed.
fn live_counts(entries: &[(String, EntryKind, u64)]) -> (u64, u64) {
    entries
        .iter()
        .filter(|(p, k, _)| *k == EntryKind::File && !is_trashed(p))
        .fold((0, 0), |(n, sz), (_, _, s)| (n + 1, sz + s))
}

/// Split a leaf into `(stem, extension-with-dot)`. A leading dot belongs to the
/// stem (`.bashrc` has no extension), matching common file-manager behaviour.
fn split_ext(leaf: &str) -> (&str, &str) {
    match leaf.rfind('.') {
        Some(i) if i > 0 => (&leaf[..i], &leaf[i..]),
        _ => (leaf, ""),
    }
}

/// A free vault path to restore `desired` to: it is used as-is when nothing
/// lives there, else " (restored)", " (restored 2)", … is inserted before the
/// extension until the name is unused. `taken` is the set of existing paths.
fn dedup_path(taken: &HashSet<String>, desired: &str) -> String {
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
fn prune_nested(paths: &[String]) -> Vec<String> {
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
fn move_folder_options(
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
        opts.push((d.to_string(), leaf_name(d).to_string(), depth));
    }
    opts
}

#[cfg(test)]
mod browse_tests {
    //! Unit tests for the pure file-browser model (navigation, filtering,
    //! sorting, classification) over synthetic vault metadata — no egui, no disk.
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
        let e = sample();
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
        assert!(has_live_entries(&e));
        assert_eq!(live_counts(&e), (1, 10)); // docs/a.txt only
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

#[cfg(test)]
mod ui_smoke {
    //! Headless render smoke tests: drive each redesigned screen and overlay
    //! through a real `egui` frame so the custom fonts, painter icon glyphs, and
    //! modal/toast code paths are exercised — a panic here fails the test.
    use super::*;

    fn test_ctx() -> egui::Context {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        ctx
    }

    fn test_session() -> Session {
        let id = Identity::generate("Tester", 0).expect("generate identity");
        Session::new(
            Arc::new(id),
            ContactBook::default(),
            Registry::default(),
            Vec::new(),
            false,
            "/tmp/filesec-ui-test".to_string(),
            None,
        )
    }

    /// Run one full frame with the given central-panel contents.
    fn frame(ctx: &egui::Context, add: impl FnOnce(&mut egui::Ui)) {
        ctx.begin_pass(egui::RawInput::default());
        egui::CentralPanel::default().show(ctx, add);
        let _ = ctx.end_pass();
    }

    #[test]
    fn passphrase_policy_rejects_short_and_weak_inputs() {
        assert_eq!(
            passphrase_policy_error("short").unwrap(),
            format!("Passphrase must be at least {MIN_PASSPHRASE_CHARS} characters.")
        );
        assert_eq!(
            passphrase_policy_error("password1234").unwrap(),
            PASSPHRASE_STRENGTH_MESSAGE
        );
        assert_eq!(
            passphrase_policy_error("aaaaaaaaaaaaaaaa").unwrap(),
            PASSPHRASE_STRENGTH_MESSAGE
        );
        assert_eq!(
            passphrase_policy_error("verylongbutonlylowercase").unwrap(),
            PASSPHRASE_STRENGTH_MESSAGE
        );
    }

    #[test]
    fn passphrase_policy_accepts_strong_local_passphrases() {
        assert!(passphrase_policy_error("correct horse battery staple").is_none());
        assert!(passphrase_policy_error("LongEnough123!").is_none());
    }

    /// The security-key card must describe an *alternative* unlock method, not a
    /// second factor. Guards against the wording drifting back to "in addition to
    /// your passphrase" / "two-factor" language, which would misrepresent the
    /// model (either the passphrase or the key opens the keystore). (F04)
    #[test]
    fn security_key_wording_says_alternative_not_two_factor() {
        let d = PASSKEY_ALT_UNLOCK_DESC.to_lowercase();
        assert!(
            d.contains("alternative"),
            "must call it an alternative unlock"
        );
        assert!(
            d.contains("not a second factor"),
            "must explicitly disclaim two-factor framing"
        );
        assert!(
            !d.contains("in addition to"),
            "must not imply layering on the passphrase"
        );
        assert!(
            !d.contains("two-factor") && !d.contains("two factor"),
            "must not call itself two-factor authentication"
        );
    }

    /// Auto-unlock's device-binding advisory is shown exactly when storage is
    /// available but not device-bound (Linux Secret Service), and stays silent
    /// when it is device-bound (macOS/Windows) or unsupported. Keeps the F09
    /// warning wired to the real platform property rather than hard-coded. (F09)
    #[test]
    fn device_binding_warning_matches_platform_support() {
        let warning = autounlock::device_binding_warning();
        if autounlock::SUPPORTED && !autounlock::DEVICE_BOUND {
            assert!(warning.is_some(), "non-device-bound storage must warn");
        } else {
            assert!(warning.is_none(), "device-bound/unsupported must not warn");
        }
    }

    #[test]
    fn bounded_identity_import_reads_reject_oversized_files() {
        let suffix = filesec_core::util::hex(&filesec_core::secret::random_array::<8>().unwrap());
        let dir = std::env::temp_dir().join(format!("filesec-gui-bounds-{suffix}"));
        std::fs::create_dir_all(&dir).unwrap();

        let pubkey = dir.join("oversized.fsecpub");
        std::fs::File::create(&pubkey)
            .unwrap()
            .set_len(MAX_PUBLIC_IDENTITY_FILE_LEN + 1)
            .unwrap();
        assert!(read_bounded_file(
            &pubkey,
            MAX_PUBLIC_IDENTITY_FILE_LEN,
            "FileSec public key file"
        )
        .is_err());

        let backup = dir.join("oversized.fsecid");
        std::fs::File::create(&backup)
            .unwrap()
            .set_len(MAX_IDENTITY_BACKUP_FILE_LEN + 1)
            .unwrap();
        assert!(read_bounded_text_file(
            &backup,
            MAX_IDENTITY_BACKUP_FILE_LEN,
            "FileSec identity backup"
        )
        .is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn screens_render_without_panic() {
        let ctx = test_ctx();
        let mut s = test_session();
        let mut action = None;
        frame(&ctx, |ui| {
            first_run_ui(&mut FirstRun::default(), ui, &mut action)
        });
        frame(&ctx, |ui| {
            unlock_ui(&mut Unlock::default(), ui, &mut action)
        });
        frame(&ctx, |ui| fatal_ui("boom", ui));
        frame(&ctx, |ui| vaults_ui(&mut s, ui, &mut action));
        frame(&ctx, |ui| contacts_ui(&mut s, ui, &mut action));
        frame(&ctx, |ui| identity_ui(&mut s, ui, &mut action));
        // First-run "restore from a backup" card (a backup file has been picked).
        let mut fr = FirstRun::default();
        fr.restore = Some(RestoreForm {
            path: "/tmp/alice.fsecid".into(),
            backup_pass: String::new(),
            new_pass: String::new(),
            new_pass2: String::new(),
            error: Some("The backup passphrase is incorrect.".into()),
        });
        frame(&ctx, |ui| first_run_ui(&mut fr, ui, &mut action));
        // The "export identity backup" modal owns the whole context.
        s.export_identity = Some(ExportIdentityForm::default());
        ctx.begin_pass(egui::RawInput::default());
        export_identity_window(&mut s, &ctx, &mut action);
        let _ = ctx.end_pass();
        s.export_identity = None;
        // The novel painter path: icon-font glyphs drawn directly.
        frame(&ctx, |ui| {
            sidebar_nav_item(ui, crate::theme::icon::VAULT, "Vaults", true);
            sidebar_nav_item(ui, crate::theme::icon::CONTACTS, "Contacts", false);
        });
    }

    #[test]
    fn widgets_and_overlays_render_without_panic() {
        let ctx = test_ctx();
        frame(&ctx, |ui| {
            crate::theme::card(ui, |ui| ui.label("card"));
            crate::theme::badge(ui, "Verified", crate::theme::BadgeKind::Ok);
            crate::theme::badge(ui, "Unverified", crate::theme::BadgeKind::Warn);
            crate::theme::empty_state(
                ui,
                crate::theme::icon::VAULT,
                "Empty",
                "Nothing here",
                |_| {},
            );
            let _ = crate::theme::primary_button(ui, "Primary");
            let _ = crate::theme::secondary_button(ui, "Secondary");
            let _ = crate::theme::danger_button(ui, "Danger");
        });
        // Overlays that own the whole context (Area + Modal).
        ctx.begin_pass(egui::RawInput::default());
        let _ = crate::theme::toast(&ctx, "Saved.", false);
        let _ = crate::theme::modal(&ctx, "Dialog", |ui| ui.label("body"));
        let _ = ctx.end_pass();
    }

    #[test]
    fn browser_renders_populated_vault_without_panic() {
        // A real on-disk vault so the file browser's reader / row / breadcrumb /
        // selection paths (custom allocate + new_child + painter, the sort combo)
        // run through real egui frames — a panic in any of them fails the test.
        let dir =
            std::env::temp_dir().join(format!("filesec-browser-smoke-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::at(&dir).expect("store");
        let id = Identity::generate("Tester", 0).expect("identity");
        let vid = new_vault_id().unwrap();
        store
            .save_vault(&id, &vid, &Vault::new("Demo", 0))
            .expect("save vault");
        // Stage source files to add (one nested in a folder, one image at root).
        let src = dir.join("src");
        std::fs::create_dir_all(&src).expect("src dir");
        std::fs::write(src.join("a.txt"), b"hello").expect("write a");
        std::fs::write(src.join("pic.png"), b"img").expect("write pic");
        let reader = store.open_vault(&id, &vid).expect("open");
        let added = vec![
            format::AddedFile {
                vault_path: "folder/a.txt".into(),
                source: src.join("a.txt"),
                mtime: None,
                mode: None,
            },
            format::AddedFile {
                vault_path: "pic.png".into(),
                source: src.join("pic.png"),
                mtime: None,
                mode: None,
            },
        ];
        store
            .append_files_to_vault(&id, &vid, &reader, &added, &["folder".to_string()])
            .expect("append");
        let reader = store.open_vault(&id, &vid).expect("reopen");

        let ctx = test_ctx();
        let mut s = Session::new(
            Arc::new(id),
            ContactBook::default(),
            Registry::default(),
            Vec::new(),
            false,
            dir.display().to_string(),
            None,
        );
        s.open = Some(OpenVault {
            id: vid.clone(),
            reader,
        });
        let mut action = None;
        // Root view: a folder row + a (type-tinted) file row, breadcrumb, combo.
        frame(&ctx, |ui| browser_ui(&mut s, ui, &mut action));
        // Inside the folder: scoped view + deeper breadcrumb.
        s.current_dir = "folder".to_string();
        frame(&ctx, |ui| browser_ui(&mut s, ui, &mut action));
        // Global search + an active selection (selection bar + a selected row).
        s.current_dir.clear();
        s.file_search = "a".to_string();
        s.selected.insert("folder/a.txt".to_string());
        frame(&ctx, |ui| browser_ui(&mut s, ui, &mut action));
        s.file_search.clear();
        s.selected.clear();
        // A multi-selection including a folder (folders are now selectable).
        s.selected.insert("folder".to_string());
        s.selected.insert("pic.png".to_string());
        s.select_anchor = Some("folder".to_string());
        frame(&ctx, |ui| browser_ui(&mut s, ui, &mut action));
        s.selected.clear();
        s.select_anchor = None;
        // The "new file" composer.
        s.show_new_file = true;
        s.new_file_name = "notes.txt".to_string();
        frame(&ctx, |ui| browser_ui(&mut s, ui, &mut action));
        s.show_new_file = false;
        s.new_file_name.clear();
        // The in-app text editor modal (owns the whole context).
        s.text_editor = Some(TextEditor {
            path: "pic.png".to_string(),
            leaf: "pic.png".to_string(),
            content: "hello\nworld".to_string(),
            original: "hello".to_string(),
        });
        ctx.begin_pass(egui::RawInput::default());
        text_editor_window(&mut s, &ctx, &mut action);
        let _ = ctx.end_pass();
        if let Some(mut te) = s.text_editor.take() {
            te.zeroize();
        }

        // Soft-delete a file, then drive the trash panel, the rename composer, and
        // the move dialog through real frames so each render path is exercised.
        let r = store
            .open_vault(s.identity.as_ref(), &vid)
            .expect("reopen2");
        let dest = trash_dest(123, "abcd", "pic.png");
        store
            .rename_in_vault(
                s.identity.as_ref(),
                &vid,
                &r,
                &[("pic.png".to_string(), dest)],
            )
            .expect("trash a file");
        let reader = store
            .open_vault(s.identity.as_ref(), &vid)
            .expect("reopen3");
        s.open = Some(OpenVault {
            id: vid.clone(),
            reader,
        });
        // Trash view: one trashed item with Restore / Delete forever + Empty Trash,
        // then again with the "empty the trash?" confirmation armed.
        s.show_trash = true;
        frame(&ctx, |ui| browser_ui(&mut s, ui, &mut action));
        s.confirm_empty_trash = true;
        frame(&ctx, |ui| browser_ui(&mut s, ui, &mut action));
        s.confirm_empty_trash = false;
        s.show_trash = false;
        // Inline rename composer over a still-live file.
        s.rename_target = Some("folder/a.txt".to_string());
        s.rename_input = "renamed.txt".to_string();
        frame(&ctx, |ui| browser_ui(&mut s, ui, &mut action));
        s.rename_target = None;
        s.rename_input.clear();
        // The move dialog (a modal that owns the whole context).
        s.move_form = Some(MoveForm {
            paths: vec!["folder/a.txt".to_string()],
            dest: String::new(),
        });
        ctx.begin_pass(egui::RawInput::default());
        move_window(&mut s, &ctx, &mut action);
        let _ = ctx.end_pass();
        s.move_form = None;

        // Empty-vault state.
        let empty_vid = new_vault_id().unwrap();
        store
            .save_vault(s.identity.as_ref(), &empty_vid, &Vault::new("Empty", 0))
            .expect("save empty");
        let empty_reader = store
            .open_vault(s.identity.as_ref(), &empty_vid)
            .expect("open empty");
        s.open = Some(OpenVault {
            id: empty_vid,
            reader: empty_reader,
        });
        frame(&ctx, |ui| browser_ui(&mut s, ui, &mut action));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
