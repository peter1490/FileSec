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
use filesec_core::format_v2::VaultReaderV2;
use filesec_core::identity::{Identity, PublicIdentity};
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::{KeystoreFile, PasskeyInfo, HMAC_SECRET_LEN};
use filesec_core::manifest::EntryKind;
use filesec_core::util::{hex, now_unix};
use filesec_core::vault::Vault;
use filesec_core::SuiteId;

use crate::autounlock;
use crate::passkey;
use crate::store::{new_vault_id, Registry, Store, VaultMeta};

use crate::theme::{self, ACCENT, ERR_RED, MUTED, OK_GREEN, WARN_AMBER};

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
    error: Option<String>,
}

impl Unlock {
    /// Build the unlock screen state, noting whether the keystore has passkeys
    /// and whether a passphrase is saved in the OS keychain for this device.
    fn for_store(store: &Store) -> Self {
        Self {
            pass: String::new(),
            pin: String::new(),
            has_passkeys: store
                .load_keystore()
                .map(|k| k.has_passkeys())
                .unwrap_or(false),
            has_saved: autounlock::is_saved(&store.data_dir().display().to_string()),
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
    data_dir: String,
}

impl Session {
    fn new(
        identity: Arc<Identity>,
        contacts: ContactBook,
        registry: Registry,
        passkeys: Vec<PasskeyInfo>,
        auto_unlock: bool,
        data_dir: String,
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
            data_dir,
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
    }
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
    /// Navigate the browser into a folder ("" = vault root).
    EnterDir(String),
    DeleteEntry(String),
    SaveEntryAs(String),
    ViewFile(String),
    CheckOut(String),
    CheckIn,
    Discard,
    ExtractAll,
    /// Toggle a file's membership in the browser selection.
    ToggleSelect(String),
    /// Select every file in the current folder view.
    SelectAllVisible,
    /// Clear the browser selection.
    ClearSelection,
    /// Remove every selected file (and selected nothing-else) from the vault.
    RemoveSelected,
    /// Decrypt every selected file to a chosen folder.
    ExtractSelected,
    /// Change the browser's sort order.
    SetSort(SortMode),
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
                } = *init;
                self.state = State::Unlocked(Box::new(Session::new(
                    Arc::new(identity),
                    contacts,
                    registry,
                    passkeys,
                    auto_unlock,
                    data_dir,
                )));
            }
            Outcome::FirstRunFailed(msg) => {
                if let State::FirstRun(f) = &mut self.state {
                    f.error = Some(msg);
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
                    // Selection and search are scoped to a folder view; leaving the
                    // folder (or a breadcrumb jump) starts fresh.
                    s.selected.clear();
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
            Action::ToggleSelect(path) => {
                if let State::Unlocked(s) = &mut self.state {
                    if !s.selected.insert(path.clone()) {
                        s.selected.remove(&path);
                    }
                }
            }
            Action::SelectAllVisible => {
                if let State::Unlocked(s) = &mut self.state {
                    if let Some(o) = &s.open {
                        let entries = snapshot_entries(&o.reader);
                        for row in visible_rows(&entries, &s.current_dir, &s.file_search, s.sort) {
                            if row.kind == EntryKind::File {
                                s.selected.insert(row.path);
                            }
                        }
                    }
                }
            }
            Action::ClearSelection => {
                if let State::Unlocked(s) = &mut self.state {
                    s.selected.clear();
                }
            }
            Action::SetSort(mode) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.sort = mode;
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
            Action::DeleteEntry(p) => self.spawn_delete_entry(ctx, p),
            Action::RemoveSelected => self.spawn_remove_selected(ctx),
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
            if f.pass.chars().count() < 8 {
                f.error = Some("Passphrase must be at least 8 characters.".into());
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
            // With the `pqc` feature the new identity is hybrid (classical keys
            // plus ML-DSA-65 / ML-KEM-768), so it can use any suite; otherwise it
            // is classical. Either way the keystore persists exactly what exists.
            #[cfg(feature = "pqc")]
            let generated = Identity::generate_hybrid(&name, now_unix());
            #[cfg(not(feature = "pqc"))]
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
                })),
                "Identity created. Your keys are protected by your passphrase.",
            )
        });
    }

    fn spawn_unlock(&mut self, ctx: &egui::Context) {
        let pass = match &mut self.state {
            State::Unlock(u) => {
                u.error = None;
                // Wiped after the worker uses it (see `spawn_create_identity`).
                Zeroizing::new(std::mem::take(&mut u.pass))
            }
            _ => return,
        };
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        self.spawn_job(ctx, "Unlocking…", move || {
            let ks = match store.load_keystore() {
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
            let contacts = store.load_contacts(&identity).unwrap_or_default();
            let registry = store.load_registry(&identity).unwrap_or_default();
            let passkeys = ks.passkey_slots();
            let data_dir = store.data_dir().display().to_string();
            // Securely wipe any checkout temp files orphaned by a prior crash,
            // plus any vault-migration scratch dirs left behind by a crash.
            store.clean_checkout_dir();
            store.clean_partial_dirs();
            JobReport::ok(
                Outcome::Unlocked(Box::new(SessionInit {
                    identity,
                    contacts,
                    registry,
                    passkeys,
                    auto_unlock: autounlock::is_saved(&data_dir),
                    data_dir,
                })),
                "Unlocked.",
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
                        let contacts = store.load_contacts(&identity).unwrap_or_default();
                        let registry = store.load_registry(&identity).unwrap_or_default();
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
        self.spawn_job(ctx, "Removing security key…", move || {
            let mut ks = match store.load_keystore() {
                Ok(k) => k,
                Err(e) => return JobReport::err(e),
            };
            if let Err(e) = ks.remove_passkey(index) {
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

    /// Unlock using the passphrase saved in the OS keychain for this data dir.
    /// If the saved secret is gone or stale it falls back to the passphrase
    /// prompt with a clear message (and drops a stale entry).
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
            let secret = match autounlock::load(&data_dir) {
                Ok(Some(s)) => s,
                Ok(None) => {
                    return JobReport {
                        outcome: Outcome::UnlockFailed(
                            "No saved passphrase for this device. Enter your passphrase.".into(),
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
            let identity = match ks.unlock(secret.as_slice()) {
                Ok(i) => i,
                Err(_) => {
                    // The saved secret no longer opens the keystore (e.g. the
                    // passphrase was changed elsewhere). Drop the stale entry.
                    let _ = autounlock::clear(&data_dir);
                    return JobReport {
                        outcome: Outcome::UnlockFailed(
                            "The saved passphrase no longer works and was removed. \
                             Enter your passphrase."
                                .into(),
                        ),
                        toast: None,
                    };
                }
            };
            let contacts = store.load_contacts(&identity).unwrap_or_default();
            let registry = store.load_registry(&identity).unwrap_or_default();
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
                })),
                "Unlocked from this device.",
            )
        });
    }

    /// Verify the entered passphrase against the keystore, then save it to the OS
    /// keychain so this device can auto-unlock.
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
            let ks = match store.load_keystore() {
                Ok(k) => k,
                Err(e) => return JobReport::err(e),
            };
            // Confirm the passphrase actually opens the keystore before saving it.
            if ks.unlock(pass.as_bytes()).is_err() {
                return JobReport::err("That passphrase is incorrect.");
            }
            let data_dir = store.data_dir().display().to_string();
            if let Err(e) = autounlock::save(&data_dir, pass.as_bytes()) {
                return JobReport::err(e.to_string());
            }
            JobReport::ok(
                Outcome::AutoUnlockChanged(true),
                "This device will now unlock automatically. Your passphrase still works.",
            )
        });
    }

    /// Forget the passphrase saved in the OS keychain for this data dir.
    fn spawn_disable_auto_unlock(&mut self, ctx: &egui::Context) {
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        self.spawn_job(ctx, "Updating this device…", move || {
            let data_dir = store.data_dir().display().to_string();
            if let Err(e) = autounlock::clear(&data_dir) {
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
            let id = new_vault_id();
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

    /// Remove every file in the browser selection in one streaming pass.
    fn spawn_remove_selected(&mut self, ctx: &egui::Context) {
        let paths: Vec<String> = match &self.state {
            State::Unlocked(s) => s.selected.iter().cloned().collect(),
            _ => return,
        };
        if paths.is_empty() {
            self.set_toast("Select files to remove first.", true);
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
        let n = paths.len();
        self.spawn_job(ctx, "Removing…", move || {
            if let Err(e) = store.remove_paths_from_vault(&identity, &id, &reader, &paths) {
                return JobReport::err(e);
            }
            finalize_after_save(
                &store,
                &identity,
                id,
                registry,
                format!("Removed {n} file(s)."),
            )
        });
    }

    /// Decrypt every file in the browser selection to a chosen folder, recreating
    /// each file's vault-relative path underneath it.
    fn spawn_extract_selected(&mut self, ctx: &egui::Context) {
        let mut paths: Vec<String> = match &self.state {
            State::Unlocked(s) => s.selected.iter().cloned().collect(),
            _ => return,
        };
        if paths.is_empty() {
            self.set_toast("Select files to extract first.", true);
            return;
        }
        paths.sort();
        let (_, reader) = match self.open_reader() {
            Some(x) => x,
            None => return,
        };
        let dest = match rfd::FileDialog::new().pick_folder() {
            Some(p) => p,
            None => return,
        };
        let n = paths.len();
        self.spawn_job(ctx, "Decrypting…", move || {
            let mut failed = 0usize;
            for path in &paths {
                // Paths are normalized (never absolute, never `..`), so joining is
                // confined to `dest`.
                let out_path = dest.join(path);
                if let Some(parent) = out_path.parent() {
                    if std::fs::create_dir_all(parent).is_err() {
                        failed += 1;
                        continue;
                    }
                }
                let out = match std::fs::File::create(&out_path) {
                    Ok(f) => f,
                    Err(_) => {
                        failed += 1;
                        continue;
                    }
                };
                let mut out = std::io::BufWriter::new(out);
                if reader.read_entry_to_writer(path, &mut out).is_err()
                    || std::io::Write::flush(&mut out).is_err()
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

    fn spawn_delete_entry(&mut self, ctx: &egui::Context, path: String) {
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        self.spawn_job(ctx, "Saving…", move || {
            // Stream the surviving data through and drop the removed entry — the
            // vault is never decrypted into memory.
            if let Err(e) =
                store.remove_paths_from_vault(&identity, &id, &reader, std::slice::from_ref(&path))
            {
                return JobReport::err(e);
            }
            finalize_after_save(&store, &identity, id, registry, "Removed.".into())
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
            match reader.extract_to(&dest) {
                Ok(()) => JobReport::ok(Outcome::Noop, format!("Extracted to {}", dest.display())),
                Err(e) => JobReport::err(e.to_string()),
            }
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
            // Stream this file's chunks straight to disk: peak memory is one
            // chunk, not the whole file.
            let out = match std::fs::File::create(&target) {
                Ok(f) => f,
                Err(e) => return JobReport::err(e.to_string()),
            };
            let mut out = std::io::BufWriter::new(out);
            if let Err(e) = reader.read_entry_to_writer(&path, &mut out) {
                return JobReport::err(e.to_string());
            }
            match std::io::Write::flush(&mut out) {
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
            let id = new_vault_id();
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
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                self.set_toast(e.to_string(), true);
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
                let name = if c.identity.name.is_empty() {
                    "(unnamed)".to_string()
                } else {
                    c.identity.name.clone()
                };
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
    registry.upsert(VaultMeta {
        id: id.clone(),
        name: new_reader.name().to_string(),
        created_at: new_reader.created_at(),
        modified_at: now_unix(),
        file_count: new_reader.file_count() as u64,
        total_size: new_reader.total_size(),
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
    let name = if pubid.name.is_empty() {
        "(unnamed)".to_string()
    } else {
        pubid.name.clone()
    };
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

        theme::card(ui, |ui| {
            field_label(ui, "Display name");
            theme::text_input(ui, &mut f.name, "e.g. Alice", false);
            ui.add_space(10.0);
            field_label(ui, "Passphrase");
            theme::text_input(ui, &mut f.pass, "At least 8 characters", true);
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
            let resp = theme::text_input(ui, &mut u.pass, "Passphrase", true);
            let submit = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            ui.add_space(8.0);
            if theme::primary_button_full(ui, "Unlock").clicked() || submit {
                *action = Some(Action::Unlock);
            }

            // Security-key (passkey) unlock, when one is enrolled and this build
            // supports the hardware.
            if u.has_passkeys && passkey::SUPPORTED {
                theme::divider_or(ui);
                theme::text_input(ui, &mut u.pin, "Security-key PIN (if set)", true);
                ui.add_space(6.0);
                if theme::secondary_button_full(ui, "🔑  Unlock with security key").clicked() {
                    *action = Some(Action::UnlockWithPasskey);
                }
            } else if u.has_passkeys {
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

            // Saved-passphrase (OS keychain) unlock, when one is stored for this
            // device and this build can read it.
            if u.has_saved && autounlock::SUPPORTED {
                theme::divider_or(ui);
                if theme::secondary_button_full(ui, "🔓  Unlock with saved passphrase").clicked()
                {
                    *action = Some(Action::UnlockWithKeyring);
                }
            } else if u.has_saved {
                ui.add_space(10.0);
                ui.label(
                    RichText::new(
                        "A passphrase is saved for this device, but this build can't use it \
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
        }
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
    // the current folder to one that still exists, and drop any selection whose
    // files were removed/renamed out from under us.
    s.current_dir = clamp_dir(&entries, &s.current_dir);
    {
        let files: HashSet<&str> = entries
            .iter()
            .filter(|(_, k, _)| *k == EntryKind::File)
            .map(|(p, _, _)| p.as_str())
            .collect();
        s.selected.retain(|p| files.contains(p.as_str()));
    }

    // Leaf of the file currently checked out for editing (if any). While set, all
    // other vault mutations are disabled and the user must check in / discard.
    let editing = s.checkout.as_ref().map(|c| c.leaf.clone());
    let viewing: Vec<String> = s.views.iter().map(|v| v.leaf.clone()).collect();
    let idle = editing.is_none();
    let c = theme::colors(ui);
    let cur = s.current_dir.clone();

    // ---- Header: back, title, and whole-vault actions ----
    ui.horizontal(|ui| {
        if theme::secondary_button(ui, "←  Vaults").clicked() {
            *action = Some(Action::CloseVault);
        }
        ui.add_space(4.0);
        ui.heading(&name);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme::primary_button(ui, "Send…").clicked() {
                *action = Some(Action::BeginExport(id.clone()));
            }
            if theme::secondary_button(ui, "Extract all…").clicked() {
                *action = Some(Action::ExtractAll);
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

    // ---- Drag-and-drop from the OS (into the current folder) ----
    let modal_open = s.export.is_some()
        || s.last_import.is_some()
        || s.contact_preview.is_some()
        || s.verify.is_some()
        || s.add_passkey.is_some()
        || s.auto_unlock_form.is_some();
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
    ui.add_space(6.0);

    // ---- Selection action bar ----
    if idle && !s.selected.is_empty() {
        let n = s.selected.len();
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
                    if theme::danger_button(ui, "Remove").clicked() {
                        *action = Some(Action::RemoveSelected);
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

    if entries.is_empty() {
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
        if searching {
            ui.label(
                RichText::new("Showing matches across the whole vault")
                    .color(c.text_muted)
                    .small(),
            );
            ui.add_space(2.0);
        } else if idle {
            // A subtle "select all" affordance for the current folder's files.
            let files_here = rows.iter().filter(|r| r.kind == EntryKind::File).count();
            if files_here > 1 {
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Select all").color(c.text_muted).small(),
                            )
                            .frame(false),
                        )
                        .clicked()
                    {
                        *action = Some(Action::SelectAllVisible);
                    }
                });
                ui.add_space(2.0);
            }
        }
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                for row in &rows {
                    let selected = s.selected.contains(&row.path);
                    entry_row(ui, c, row, selected, idle, searching, action);
                }
            });
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

/// One row in the file browser: a full-width, hover/selected-highlighted surface
/// with a type-tinted icon, a name + secondary line, and trailing quick actions
/// revealed on hover. Folders enter on click; files toggle selection on click and
/// open (view) on double-click.
fn entry_row(
    ui: &mut egui::Ui,
    c: theme::Colors,
    row: &Row,
    selected: bool,
    idle: bool,
    searching: bool,
    action: &mut Option<Action>,
) {
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
    // Trailing actions, ordered left→right as View · Edit · Save · Remove (added
    // right-to-left). Shown on hover or when the row is selected.
    cui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        let show = hovered || selected;
        if is_dir {
            if show && idle && theme::icon_button(ui, theme::icon::TRASH, "Remove folder").clicked()
            {
                *action = Some(Action::DeleteEntry(row.path.clone()));
            }
        } else {
            if show && idle && theme::icon_button(ui, theme::icon::TRASH, "Remove").clicked() {
                *action = Some(Action::DeleteEntry(row.path.clone()));
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

    if is_dir {
        if resp.clicked() {
            *action = Some(Action::EnterDir(row.path.clone()));
        }
    } else if idle {
        if resp.double_clicked() {
            *action = Some(Action::ViewFile(row.path.clone()));
        } else if resp.clicked() {
            *action = Some(Action::ToggleSelect(row.path.clone()));
        }
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

        // Security keys (passkeys). Shown when this build supports them, or
        // whenever any are already enrolled.
        if passkey::SUPPORTED || !s.passkeys.is_empty() {
            theme::card(ui, |ui| {
                ui.label(RichText::new("Security keys").size(16.0).strong());
                ui.label(
                    RichText::new(
                        "Unlock with a hardware security key (FIDO2) in addition to your \
                         passphrase. Your passphrase always keeps working — a lost key is \
                         never a lockout.",
                    )
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
                        "Save your passphrase in this computer's keychain so FileSec unlocks \
                         automatically here. Your passphrase still works and stays your \
                         recovery secret. Anyone with access to your logged-in account could \
                         then open FileSec, so only enable this on a trusted personal device.",
                    )
                    .color(cc.text_muted)
                    .small(),
                );
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
            "Enroll a FIDO2 hardware key (YubiKey, SoloKey, …) as an extra way to unlock. \
             You'll be asked to touch it twice — once to create the key, once to set up \
             unlock. Your passphrase keeps working too.",
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
                        .hint_text("optional — only if your key has one")
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
            "Save your passphrase in this computer's keychain so FileSec unlocks \
             automatically on this device. Your passphrase still works everywhere and \
             remains your recovery secret.",
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
    let name = if preview.pubid.name.is_empty() {
        "(unnamed)".to_string()
    } else {
        preview.pubid.name.clone()
    };
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
        // The empty "" is the window title arg so a path with spaces isn't
        // swallowed as the title.
        std::process::Command::new("cmd")
            .args(["/C", "start", ""])
            .arg(path)
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
        match std::process::Command::new("cmd")
            .args(["/C", "start", "/wait", ""])
            .arg(&p)
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
        )
    }

    /// Run one full frame with the given central-panel contents.
    fn frame(ctx: &egui::Context, add: impl FnOnce(&mut egui::Ui)) {
        ctx.begin_pass(egui::RawInput::default());
        egui::CentralPanel::default().show(ctx, add);
        let _ = ctx.end_pass();
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
        let vid = new_vault_id();
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
        );
        s.open = Some(OpenVault { id: vid, reader });
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
        // Empty-vault state.
        s.file_search.clear();
        s.selected.clear();
        let empty_vid = new_vault_id();
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
