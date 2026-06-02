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
use filesec_core::format::{self, ExportOptions, VaultReader};
use filesec_core::identity::{Identity, PublicIdentity};
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::KeystoreFile;
use filesec_core::manifest::EntryKind;
use filesec_core::util::{hex, now_unix};
use filesec_core::vault::Vault;
use filesec_core::SuiteId;

use crate::store::{new_vault_id, Registry, Store, VaultMeta};

const OK_GREEN: Color32 = Color32::from_rgb(0x3c, 0xb3, 0x71);
const ERR_RED: Color32 = Color32::from_rgb(0xd6, 0x5d, 0x5d);
const WARN_AMBER: Color32 = Color32::from_rgb(0xd6, 0xa5, 0x4d);
const MUTED: Color32 = Color32::from_rgb(0x99, 0x99, 0x99);
const ACCENT: Color32 = Color32::from_rgb(0x5a, 0x9b, 0xd4);

/// Top-level application.
pub struct App {
    store: Option<Arc<Store>>,
    state: State,
    toast: Option<Toast>,
    job: Option<Job>,
}

struct Toast {
    msg: String,
    error: bool,
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
    error: Option<String>,
}

/// Wipe the passphrase buffer when the unlock form is discarded. See [`FirstRun`].
impl Drop for Unlock {
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

struct OpenVault {
    id: String,
    reader: VaultReader,
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
    data_dir: String,
}

impl Session {
    fn new(
        identity: Arc<Identity>,
        contacts: ContactBook,
        registry: Registry,
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
            contact_paste: String::new(),
            contact_preview: None,
            verify: None,
            export: None,
            last_import: None,
            #[cfg(feature = "pqc")]
            migrate: None,
            data_dir,
        }
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
    NewFolder,
    DeleteEntry(String),
    SaveEntryAs(String),
    ViewFile(String),
    CheckOut(String),
    CheckIn,
    Discard,
    ExtractAll,
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
        reader: Box<VaultReader>,
    },
    SetOpen {
        id: String,
        reader: Box<VaultReader>,
    },
    /// Replace the open vault's reader after a successful mutate + re-encrypt.
    ReplaceOpen {
        id: String,
        reader: Box<VaultReader>,
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
        replace: Option<(String, Box<VaultReader>, Registry)>,
    },
    /// Register a read-only view after decrypting it to a temp file.
    StartView(Box<ActiveView>),
    Imported(Box<ImportData>),
    Contacts(ContactBook),
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
                let state = if store.keystore_exists() {
                    State::Unlock(Unlock::default())
                } else {
                    State::FirstRun(FirstRun::default())
                };
                App {
                    store: Some(Arc::new(store)),
                    state,
                    toast: None,
                    job: None,
                }
            }
            Err(e) => App {
                store: None,
                state: State::Fatal(e),
                toast: None,
                job: None,
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

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_enabled_ui(!busy, |ui| self.top_bar(ui, &mut action));
        });

        if let Some(t) = &self.toast {
            egui::TopBottomPanel::bottom("toast").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let color = if t.error { ERR_RED } else { OK_GREEN };
                    ui.colored_label(color, &t.msg);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("✕").clicked() {
                            action = Some(Action::DismissToast);
                        }
                    });
                });
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_enabled_ui(!busy, |ui| match &mut self.state {
                State::Fatal(msg) => {
                    ui.heading("FileSec could not start");
                    ui.colored_label(ERR_RED, msg.clone());
                }
                State::FirstRun(f) => first_run_ui(f, ui, &mut action),
                State::Unlock(u) => unlock_ui(u, ui, &mut action),
                State::Unlocked(s) => session_ui(s, ui, &mut action),
            });
        });

        if busy {
            let label = self
                .job
                .as_ref()
                .map(|j| j.label.clone())
                .unwrap_or_default();
            egui::Window::new("working")
                .title_bar(false)
                .resizable(false)
                .collapsible(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new());
                        ui.label(label);
                    });
                });
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
    fn top_bar(&self, ui: &mut egui::Ui, action: &mut Option<Action>) {
        ui.horizontal(|ui| {
            ui.heading(RichText::new("🔒 FileSec").color(ACCENT));
            ui.label(RichText::new("secure file exchange").color(MUTED).small());
            if let State::Unlocked(s) = &self.state {
                ui.separator();
                let mut nav_button = |ui: &mut egui::Ui, label: &str, nav: Nav| {
                    let selected = s.open.is_none() && s.nav == nav;
                    if ui.selectable_label(selected, label).clicked() {
                        *action = Some(Action::Nav(nav));
                    }
                };
                nav_button(ui, "Vaults", Nav::Vaults);
                nav_button(ui, "Contacts", Nav::Contacts);
                nav_button(ui, "My Identity", Nav::Identity);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Lock").clicked() {
                        *action = Some(Action::Lock);
                    }
                });
            }
        });
    }

    fn set_toast(&mut self, msg: impl Into<String>, error: bool) {
        self.toast = Some(Toast {
            msg: msg.into(),
            error,
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
    fn open_ctx(&self) -> Option<(String, VaultReader, Registry)> {
        if let State::Unlocked(s) = &self.state {
            if let Some(o) = &s.open {
                return Some((o.id.clone(), o.reader.clone(), s.registry.clone()));
            }
        }
        None
    }

    /// Snapshot the open vault for a *read-only* worker.
    fn open_reader(&self) -> Option<(String, VaultReader)> {
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
            self.toast = Some(Toast { msg, error });
        }
        match report.outcome {
            Outcome::Noop => {}
            Outcome::Unlocked(init) => {
                let SessionInit {
                    identity,
                    contacts,
                    registry,
                    data_dir,
                } = *init;
                self.state = State::Unlocked(Box::new(Session::new(
                    Arc::new(identity),
                    contacts,
                    registry,
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
                    s.open = Some(OpenVault {
                        id,
                        reader: *reader,
                    });
                }
            }
            Outcome::SetOpen { id, reader } => {
                if let State::Unlocked(s) = &mut self.state {
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
                self.state = State::Unlock(Unlock::default());
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
            Action::CreateVault => self.spawn_create_vault(ctx),
            Action::OpenVault(id) => self.spawn_open_vault(ctx, id),
            Action::DeleteVault(id) => self.spawn_delete_vault(ctx, id),
            Action::AddFiles => self.spawn_add_files(ctx),
            Action::AddFolder => self.spawn_add_folder(ctx),
            Action::NewFolder => self.spawn_new_folder(ctx),
            Action::DeleteEntry(p) => self.spawn_delete_entry(ctx, p),
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
            let data_dir = store.data_dir().display().to_string();
            // Securely wipe any checkout temp files orphaned by a prior crash.
            store.clean_checkout_dir();
            JobReport::ok(
                Outcome::Unlocked(Box::new(SessionInit {
                    identity,
                    contacts,
                    registry,
                    data_dir,
                })),
                "Unlocked.",
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

    fn spawn_add_files(&mut self, ctx: &egui::Context) {
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let files = match rfd::FileDialog::new().pick_files() {
            Some(f) => f,
            None => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        self.spawn_job(ctx, "Encrypting…", move || {
            // Stream each picked file straight from disk into the vault — neither
            // the files nor the existing vault are loaded into memory.
            let mut existing: HashSet<String> =
                reader.entries().iter().map(|e| e.path.clone()).collect();
            let mut added = Vec::new();
            let mut failed = 0usize;
            for path in files {
                if std::fs::File::open(&path).is_err() {
                    failed += 1;
                    continue;
                }
                let base = path
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "file".into());
                let name = unique_name_in(&existing, &base);
                existing.insert(name.clone());
                let mtime = file_mtime(&path);
                added.push(format::AddedFile {
                    vault_path: name,
                    source: path,
                    mtime,
                    mode: None,
                });
            }
            if added.is_empty() {
                return JobReport::err(if failed > 0 {
                    format!("{failed} file(s) could not be read.")
                } else {
                    "No files to add.".into()
                });
            }
            let n = added.len();
            if let Err(e) = store.append_files_to_vault(&identity, &id, &reader, &added, &[]) {
                return JobReport::err(e);
            }
            let msg = if failed > 0 {
                format!("Added {n} file(s); {failed} could not be read.")
            } else {
                format!("Added {n} file(s).")
            };
            finalize_after_save(&store, &identity, id, registry, msg)
        });
    }

    fn spawn_add_folder(&mut self, ctx: &egui::Context) {
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let base = match rfd::FileDialog::new().pick_folder() {
            Some(p) => p,
            None => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        self.spawn_job(ctx, "Encrypting…", move || {
            // Walk the folder and stream every file straight from disk — the
            // tree's contents are never held in memory at once.
            let root = base
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "folder".into());
            let existing: HashSet<String> =
                reader.entries().iter().map(|e| e.path.clone()).collect();
            let mut added = Vec::new();
            let mut dirs = Vec::new();
            for entry in walkdir::WalkDir::new(&base).into_iter().flatten() {
                let rel = match entry.path().strip_prefix(&base) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if rel.as_os_str().is_empty() {
                    continue;
                }
                let vault_path = format!("{root}/{}", rel.to_string_lossy());
                if existing.contains(&vault_path) {
                    continue; // skip collisions, as the old in-memory path did
                }
                if entry.file_type().is_dir() {
                    dirs.push(vault_path);
                } else if entry.file_type().is_file() && std::fs::File::open(entry.path()).is_ok() {
                    added.push(format::AddedFile {
                        vault_path,
                        source: entry.path().to_path_buf(),
                        mtime: file_mtime(entry.path()),
                        mode: None,
                    });
                }
            }
            let n = added.len();
            if let Err(e) = store.append_files_to_vault(&identity, &id, &reader, &added, &dirs) {
                return JobReport::err(e);
            }
            finalize_after_save(
                &store,
                &identity,
                id,
                registry,
                format!("Added folder \"{root}\" ({n} file(s))."),
            )
        });
    }

    fn spawn_new_folder(&mut self, ctx: &egui::Context) {
        let name = match &self.state {
            State::Unlocked(s) => s.new_folder_name.trim().to_string(),
            _ => return,
        };
        if name.is_empty() {
            self.set_toast("Enter a folder name.", true);
            return;
        }
        if let State::Unlocked(s) = &mut self.state {
            s.new_folder_name.clear();
        }
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        self.spawn_job(ctx, "Saving…", move || {
            // Stream the existing data through unchanged and just add the dir entry
            // — no need to decrypt the whole vault into memory.
            if let Err(e) =
                store.append_files_to_vault(&identity, &id, &reader, &[], &[name.clone()])
            {
                return JobReport::err(e);
            }
            finalize_after_save(
                &store,
                &identity,
                id,
                registry,
                format!("Created folder \"{name}\"."),
            )
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
            if let Err(e) = store.remove_paths_from_vault(&identity, &id, &reader, &[path.clone()])
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
            match reader.reexport_to_path(&identity, &recipients, &options, &target) {
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
                    data_dir,
                })),
                "Upgraded to post-quantum. Your safety number changed — re-share your \
                 public key so contacts can re-verify it.",
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
) -> Result<(String, VaultReader, Registry), String> {
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

fn first_run_ui(f: &mut FirstRun, ui: &mut egui::Ui, action: &mut Option<Action>) {
    ui.add_space(20.0);
    ui.vertical_centered(|ui| {
        ui.heading("Welcome to FileSec");
        ui.label(
            RichText::new("Create your identity. Your private keys never leave this device and are\nencrypted with your passphrase.")
                .color(MUTED),
        );
    });
    ui.add_space(16.0);
    egui::Grid::new("firstrun")
        .num_columns(2)
        .spacing([12.0, 10.0])
        .show(ui, |ui| {
            ui.label("Display name");
            ui.text_edit_singleline(&mut f.name);
            ui.end_row();
            ui.label("Passphrase");
            ui.add(egui::TextEdit::singleline(&mut f.pass).password(true));
            ui.end_row();
            ui.label("Confirm passphrase");
            ui.add(egui::TextEdit::singleline(&mut f.pass2).password(true));
            ui.end_row();
        });
    ui.add_space(12.0);
    if let Some(e) = &f.error {
        ui.colored_label(ERR_RED, e);
    }
    if ui
        .button(RichText::new("Create identity").strong())
        .clicked()
    {
        *action = Some(Action::CreateIdentity);
    }
    ui.add_space(8.0);
    ui.label(
        RichText::new("⚠ There is no password recovery. If you forget your passphrase, your vaults cannot be opened.")
            .color(MUTED)
            .small(),
    );
}

fn unlock_ui(u: &mut Unlock, ui: &mut egui::Ui, action: &mut Option<Action>) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        ui.heading("Unlock FileSec");
        ui.add_space(12.0);
        let resp = ui.add(
            egui::TextEdit::singleline(&mut u.pass)
                .password(true)
                .hint_text("Passphrase"),
        );
        let submit = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        ui.add_space(8.0);
        if ui.button(RichText::new("Unlock").strong()).clicked() || submit {
            *action = Some(Action::Unlock);
        }
        if let Some(e) = &u.error {
            ui.add_space(8.0);
            ui.colored_label(ERR_RED, e);
        }
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
}

fn vaults_ui(s: &mut Session, ui: &mut egui::Ui, action: &mut Option<Action>) {
    ui.horizontal(|ui| {
        ui.heading("Vaults");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Import .fsec…").clicked() {
                *action = Some(Action::ImportContainer);
            }
            if ui.button("➕ New vault").clicked() {
                *action = Some(Action::ToggleNewVault(!s.show_new_vault));
            }
        });
    });

    if s.show_new_vault {
        ui.horizontal(|ui| {
            ui.label("Name:");
            ui.text_edit_singleline(&mut s.new_vault_name);
            if ui.button("Create").clicked() {
                *action = Some(Action::CreateVault);
            }
            if ui.button("Cancel").clicked() {
                *action = Some(Action::ToggleNewVault(false));
            }
        });
    }

    ui.separator();
    if s.registry.vaults.is_empty() {
        ui.add_space(20.0);
        ui.vertical_centered(|ui| {
            ui.colored_label(
                MUTED,
                "No vaults yet. Create one, or import a .fsec someone sent you.",
            );
        });
        return;
    }

    egui::ScrollArea::vertical().show(ui, |ui| {
        let mut vaults = s.registry.vaults.clone();
        vaults.sort_by(|a, b| b.modified_at.cmp(&a.modified_at));
        for v in vaults {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new(&v.name).strong());
                        ui.colored_label(
                            MUTED,
                            format!("{} file(s) · {}", v.file_count, human_size(v.total_size)),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("🗑").on_hover_text("Delete vault").clicked() {
                            *action = Some(Action::DeleteVault(v.id.clone()));
                        }
                        if ui.button("Send…").clicked() {
                            *action = Some(Action::BeginExport(v.id.clone()));
                        }
                        if ui.button("Open").clicked() {
                            *action = Some(Action::OpenVault(v.id.clone()));
                        }
                    });
                });
            });
        }
    });
}

fn browser_ui(s: &mut Session, ui: &mut egui::Ui, action: &mut Option<Action>) {
    let (name, id) = match &s.open {
        Some(o) => (o.reader.name().to_string(), o.id.clone()),
        None => return,
    };
    // Drop any view whose temp a watcher already wiped (the app was closed), so
    // the banner reflects what is actually still open.
    s.views.retain(|v| v.temp_path.exists());
    // Leaf of the file currently checked out for editing (if any). While set,
    // all other vault mutations are disabled and the user must check in/discard.
    let editing = s.checkout.as_ref().map(|c| c.leaf.clone());
    let viewing: Vec<String> = s.views.iter().map(|v| v.leaf.clone()).collect();

    ui.horizontal(|ui| {
        if ui.button("← Vaults").clicked() {
            *action = Some(Action::CloseVault);
        }
        ui.heading(&name);
    });

    if let Some(leaf) = &editing {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.colored_label(ACCENT, format!("✏ Editing {leaf}"));
                ui.label(
                    RichText::new("— edit in your app, then:")
                        .color(MUTED)
                        .small(),
                );
                if ui.button("Check in").clicked() {
                    *action = Some(Action::CheckIn);
                }
                if ui.button("Discard").clicked() {
                    *action = Some(Action::Discard);
                }
            });
        });
    }

    if !viewing.is_empty() {
        let plural = if viewing.len() == 1 { "y" } else { "ies" };
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(
                    ACCENT,
                    format!("👁 Viewing {} read-only cop{plural}", viewing.len()),
                );
                ui.label(
                    RichText::new(format!("({})", viewing.join(", ")))
                        .color(MUTED)
                        .small(),
                );
                ui.label(
                    RichText::new("— wiped automatically on close, or when you leave the vault.")
                        .color(MUTED)
                        .small(),
                );
            });
        });
    }

    ui.add_enabled_ui(editing.is_none(), |ui| {
        ui.horizontal_wrapped(|ui| {
            if ui.button("➕ Add files…").clicked() {
                *action = Some(Action::AddFiles);
            }
            if ui.button("📁 Add folder…").clicked() {
                *action = Some(Action::AddFolder);
            }
            ui.label("New folder:");
            ui.add(egui::TextEdit::singleline(&mut s.new_folder_name).desired_width(120.0));
            if ui.button("Create").clicked() {
                *action = Some(Action::NewFolder);
            }
            ui.separator();
            if ui.button("⬇ Extract all…").clicked() {
                *action = Some(Action::ExtractAll);
            }
            if ui.button("📤 Send…").clicked() {
                *action = Some(Action::BeginExport(id.clone()));
            }
        });
    });
    ui.separator();

    let open = match &s.open {
        Some(o) => o,
        None => return,
    };
    if open.reader.is_empty() {
        ui.add_space(16.0);
        ui.colored_label(MUTED, "Empty vault. Add files or folders above.");
        return;
    }

    let mut rows: Vec<(String, EntryKind, u64)> = open
        .reader
        .entries()
        .iter()
        .map(|e| (e.path.clone(), e.kind, e.size))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    egui::ScrollArea::vertical().show(ui, |ui| {
        for (path, kind, size) in rows {
            let depth = path.matches('/').count();
            let indent = "    ".repeat(depth);
            let leaf = path.rsplit('/').next().unwrap_or(&path);
            ui.horizontal(|ui| {
                let label = match kind {
                    EntryKind::Dir => format!("{indent}📁 {leaf}"),
                    EntryKind::File => format!("{indent}📄 {leaf}"),
                };
                ui.label(label);
                if kind == EntryKind::File {
                    ui.colored_label(MUTED, human_size(size));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let idle = editing.is_none();
                    if ui
                        .add_enabled(idle, egui::Button::new("🗑").small())
                        .on_hover_text("Remove")
                        .clicked()
                    {
                        *action = Some(Action::DeleteEntry(path.clone()));
                    }
                    if kind == EntryKind::File && ui.small_button("Save as…").clicked() {
                        *action = Some(Action::SaveEntryAs(path.clone()));
                    }
                    if kind == EntryKind::File
                        && ui
                            .add_enabled(idle, egui::Button::new("✏").small())
                            .on_hover_text("Check out & edit")
                            .clicked()
                    {
                        *action = Some(Action::CheckOut(path.clone()));
                    }
                    if kind == EntryKind::File
                        && ui
                            .add_enabled(idle, egui::Button::new("👁").small())
                            .on_hover_text("View read-only (auto-wiped on close)")
                            .clicked()
                    {
                        *action = Some(Action::ViewFile(path.clone()));
                    }
                });
            });
        }
    });
}

fn contacts_ui(s: &mut Session, ui: &mut egui::Ui, action: &mut Option<Action>) {
    ui.heading("Contacts");
    ui.label(
        RichText::new("Import someone's public key, then verify their safety number out-of-band (in person or over a trusted channel) before sending them anything.")
            .color(MUTED),
    );
    ui.add_space(8.0);

    egui::CollapsingHeader::new("Add a contact")
        .default_open(s.contacts.contacts.is_empty())
        .show(ui, |ui| {
            if ui.button("Load from .fsecpub file…").clicked() {
                *action = Some(Action::PreviewContactFile);
            }
            ui.label("…or paste a public key:");
            ui.add(
                egui::TextEdit::multiline(&mut s.contact_paste)
                    .desired_rows(4)
                    .desired_width(f32::INFINITY)
                    .hint_text("-----BEGIN FILESEC PUBLIC KEY-----"),
            );
            if ui.button("Preview key…").clicked() {
                *action = Some(Action::PreviewContactPaste);
            }
            ui.label(
                RichText::new(
                    "You'll see who the key belongs to and can confirm before it's added.",
                )
                .color(MUTED)
                .small(),
            );
        });

    ui.separator();
    if s.contacts.contacts.is_empty() {
        ui.colored_label(MUTED, "No contacts yet.");
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
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(display_name).strong());
                            match c.trust {
                                Trust::Verified => ui.colored_label(OK_GREEN, "✔ verified"),
                                Trust::Unverified => ui.colored_label(ERR_RED, "● unverified"),
                            };
                        });
                        ui.label(
                            RichText::new(c.identity.safety_number())
                                .monospace()
                                .color(MUTED)
                                .small(),
                        );
                        if let (Trust::Verified, Some(t)) = (c.trust, c.verified_at) {
                            ui.label(
                                RichText::new(format!("verified {}", fmt_date(t)))
                                    .color(MUTED)
                                    .small(),
                            );
                        }
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("Remove").clicked() {
                            *action = Some(Action::RemoveContact(fpr_hex.clone()));
                        }
                        match c.trust {
                            Trust::Verified => {
                                if ui.small_button("Unverify").clicked() {
                                    *action =
                                        Some(Action::SetTrust(fpr_hex.clone(), Trust::Unverified));
                                }
                            }
                            Trust::Unverified => {
                                if ui.small_button("Verify…").clicked() {
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
    let pubid = s.identity.public();
    ui.heading("My Identity");
    ui.add_space(8.0);
    egui::Grid::new("ident")
        .num_columns(2)
        .spacing([12.0, 8.0])
        .show(ui, |ui| {
            ui.label("Name");
            ui.label(RichText::new(&s.identity.name).strong());
            ui.end_row();
            ui.label("Fingerprint");
            ui.label(RichText::new(pubid.fingerprint_hex()).monospace().small());
            ui.end_row();
        });
    ui.add_space(8.0);
    ui.label("Safety number (read this aloud to verify with others):");
    ui.label(
        RichText::new(pubid.safety_number())
            .monospace()
            .color(ACCENT),
    );
    // Post-quantum status + one-click upgrade (pqc builds only).
    #[cfg(feature = "pqc")]
    {
        ui.add_space(10.0);
        if s.identity.is_hybrid_capable() {
            ui.label(
                RichText::new("🛡 Post-quantum: hybrid X25519+ML-KEM-768 / Ed25519+ML-DSA-65")
                    .color(ACCENT),
            );
        } else {
            ui.label(RichText::new("Post-quantum: not enabled (classical identity)").color(MUTED));
            if ui
                .button(RichText::new("Upgrade to post-quantum…").strong())
                .clicked()
            {
                *action = Some(Action::BeginMigrate);
            }
        }
    }
    ui.add_space(12.0);
    ui.horizontal(|ui| {
        if ui.button("Copy public key").clicked() {
            *action = Some(Action::CopyPubKey);
        }
        if ui.button("Save public key…").clicked() {
            *action = Some(Action::SavePubKey);
        }
    });
    ui.add_space(8.0);
    ui.label(
        RichText::new("Share your public key with others so they can send you vaults. It contains no secrets.")
            .color(MUTED)
            .small(),
    );
    ui.add_space(12.0);
    ui.separator();
    ui.label(
        RichText::new(format!("Encrypted data is stored at: {}", s.data_dir))
            .color(MUTED)
            .small(),
    );
}

/// The "Upgrade to post-quantum" confirmation dialog.
#[cfg(feature = "pqc")]
fn migrate_window(s: &mut Session, ctx: &egui::Context, action: &mut Option<Action>) {
    let form = match &mut s.migrate {
        Some(f) => f,
        None => return,
    };
    let mut open = true;
    egui::Window::new("Upgrade to post-quantum")
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label(
                "This adds ML-KEM-768 and ML-DSA-65 keys to your identity and re-encrypts your \
                 whole local vault store under the hybrid post-quantum suite. Your existing \
                 X25519/Ed25519 keys are kept.",
            );
            ui.add_space(8.0);
            ui.colored_label(ERR_RED, "⚠ Your safety number will change.");
            ui.label(
                RichText::new(
                    "Your identity now commits to its post-quantum keys, so your fingerprint and \
                     safety number change. After upgrading, re-share your public key and have your \
                     contacts re-verify it.",
                )
                .color(MUTED)
                .small(),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Import any pending .fsec files first — containers others already sent to your \
                     old identity won't be openable afterwards.",
                )
                .color(MUTED)
                .small(),
            );
            ui.add_space(10.0);
            ui.label("Confirm your passphrase to re-seal the keystore:");
            ui.add(
                egui::TextEdit::singleline(&mut form.pass)
                    .password(true)
                    .desired_width(260.0),
            );
            if let Some(e) = &form.error {
                ui.colored_label(ERR_RED, e);
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Upgrade now").strong()).clicked() {
                    *action = Some(Action::DoMigrate);
                }
                if ui.button("Cancel").clicked() {
                    *action = Some(Action::CancelMigrate);
                }
            });
        });
    if !open {
        *action = Some(Action::CancelMigrate);
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
    let mut open = true;
    egui::Window::new("Send vault")
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label("Choose recipients. Each will be able to open the container with their private key.");
            ui.add_space(6.0);
            if s.contacts.contacts.is_empty() {
                ui.colored_label(MUTED, "You have no contacts yet — add one first, or just include yourself.");
            }
            egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
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
            if ui.checkbox(&mut include_self, "Also include myself (so I can re-open it)").changed() {
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
                        ui.colored_label(
                            MUTED,
                            "Every recipient also gets post-quantum protection.",
                        );
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
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Choose file & export").strong()).clicked() {
                    *action = Some(Action::DoExport);
                }
                if ui.button("Cancel").clicked() {
                    *action = Some(Action::CancelExport);
                }
            });
        });
    if !open {
        *action = Some(Action::CancelExport);
    }
}

fn import_info_window(s: &mut Session, ctx: &egui::Context, action: &mut Option<Action>) {
    let info = match &s.last_import {
        Some(i) => i,
        None => return,
    };
    let mut open = true;
    egui::Window::new("Imported vault")
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .show(ctx, |ui| {
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
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("OK").clicked() {
                    *action = Some(Action::DismissImportInfo);
                }
                match (&info.sender_name, info.verified) {
                    // Known but unverified → jump straight into verification.
                    (Some(_), false) => {
                        if ui.button("Verify sender…").clicked() {
                            *action = Some(Action::BeginVerify(fpr_hex));
                        }
                    }
                    // Unknown → offer to add them as a contact first.
                    (None, _) => {
                        if ui.button("Add sender to contacts…").clicked() {
                            *action = Some(Action::AddSenderToContacts);
                        }
                    }
                    _ => {}
                }
            });
        });
    if !open {
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
    let mut open = true;
    egui::Window::new("Add contact?")
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .show(ctx, |ui| {
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
                    ui.colored_label(OK_GREEN, "Already a verified contact — nothing will change.");
                }
                PreviewStatus::Existing { verified: false } => {
                    ui.colored_label(MUTED, "Already a contact (unverified) — nothing will change.");
                }
                PreviewStatus::Renamed { old, verified: true } => {
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
                PreviewStatus::Renamed { old, verified: false } => {
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
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                let add_label = match &preview.status {
                    PreviewStatus::Renamed { .. } => "Update contact",
                    _ => "Add contact",
                };
                if ui
                    .add_enabled(!is_self, egui::Button::new(RichText::new(add_label).strong()))
                    .clicked()
                {
                    *action = Some(Action::ConfirmAddContact);
                }
                if ui.button("Cancel").clicked() {
                    *action = Some(Action::CancelPreview);
                }
            });
        });
    if !open {
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
    let mut open = true;
    egui::Window::new(format!("Verify {}", form.name))
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label(
                RichText::new(
                    "Compare this safety number with the contact over a trusted channel — in person, a video call, or a line you already trust. Mark verified only once both sides match exactly.",
                )
                .color(MUTED),
            );
            ui.add_space(8.0);
            ui.label("Their safety number should read:");
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(&form.safety_number)
                        .monospace()
                        .color(ACCENT),
                );
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
            ui.add_space(10.0);
            let can_verify = typed_match || form.manual_ok;
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        can_verify,
                        egui::Button::new(RichText::new("Mark verified").strong()),
                    )
                    .clicked()
                {
                    *action = Some(Action::ConfirmVerify(fpr_hex.clone()));
                }
                if ui.button("Cancel").clicked() {
                    *action = Some(Action::CancelVerify);
                }
            });
        });
    if !open {
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
