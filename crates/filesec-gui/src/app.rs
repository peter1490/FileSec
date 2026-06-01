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

use filesec_core::contacts::{ContactBook, Trust};
use filesec_core::format::{self, ExportOptions, VaultReader};
use filesec_core::identity::Identity;
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::KeystoreFile;
use filesec_core::manifest::EntryKind;
use filesec_core::util::{hex, now_unix};
use filesec_core::vault::Vault;

use crate::store::{new_vault_id, Registry, Store, VaultMeta};

const OK_GREEN: Color32 = Color32::from_rgb(0x3c, 0xb3, 0x71);
const ERR_RED: Color32 = Color32::from_rgb(0xd6, 0x5d, 0x5d);
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

struct ExportForm {
    vault_id: String,
    selected: HashSet<String>,
    include_self: bool,
}

struct ImportInfo {
    sender_fpr_hex: String,
    sender_name: Option<String>,
    verified: bool,
    vault_name: String,
    file_count: usize,
}

/// Unlocked session state. The identity is reference-counted so it can be
/// shared (read-only) with background worker threads.
struct Session {
    identity: Arc<Identity>,
    contacts: ContactBook,
    registry: Registry,
    nav: Nav,
    open: Option<OpenVault>,
    new_vault_name: String,
    show_new_vault: bool,
    new_folder_name: String,
    contact_paste: String,
    export: Option<ExportForm>,
    last_import: Option<ImportInfo>,
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
            new_vault_name: String::new(),
            show_new_vault: false,
            new_folder_name: String::new(),
            contact_paste: String::new(),
            export: None,
            last_import: None,
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
    ExtractAll,
    BeginExport(String),
    CancelExport,
    DoExport,
    ToggleRecipient(String),
    ToggleIncludeSelf,
    ImportContactPaste,
    ImportContactFile,
    SetTrust(String, Trust),
    RemoveContact(String),
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
    sender_fpr: [u8; 32],
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
            Outcome::Imported(data) => {
                if let State::Unlocked(s) = &mut self.state {
                    let contact = s.contacts.find(&data.sender_fpr);
                    let sender_name = contact.map(|c| c.identity.name.clone());
                    let verified = matches!(contact.map(|c| c.trust), Some(Trust::Verified));
                    s.registry = data.registry;
                    s.last_import = Some(ImportInfo {
                        sender_fpr_hex: hex(&data.sender_fpr),
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

    fn dispatch(&mut self, action: Action, ctx: &egui::Context) {
        match action {
            // --- instant, UI-only actions ---
            Action::Lock => {
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
                if let State::Unlocked(s) = &mut self.state {
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
                if let State::Unlocked(s) = &mut self.state {
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
            Action::ImportContainer => self.spawn_import(ctx),
            Action::DoExport => self.spawn_export(ctx),
            Action::ImportContactPaste => self.spawn_import_contact_paste(ctx),
            Action::ImportContactFile => self.spawn_import_contact_file(ctx),
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
            let identity = match Identity::generate(&name, now_unix()) {
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
            if let Err(e) = store.append_files_to_vault(&identity, &id, &reader, &[], &[name.clone()]) {
                return JobReport::err(e);
            }
            finalize_after_save(&store, &identity, id, registry, format!("Created folder \"{name}\"."))
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
            if let Err(e) = store.remove_paths_from_vault(&identity, &id, &reader, &[path.clone()]) {
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
                    sender_fpr: sender.fingerprint,
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
                (form.vault_id.clone(), recipients, name)
            })
        } else {
            None
        };
        let (vault_id, recipients, name) = match gathered {
            Some(x) => x,
            None => return,
        };
        if recipients.is_empty() {
            self.set_toast("Select at least one recipient.", true);
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
            match reader.reexport_to_path(
                &identity,
                &recipients,
                &ExportOptions::default(),
                &target,
            ) {
                Ok(()) => JobReport::ok(
                    Outcome::Noop,
                    format!("Exported to {} for {count} recipient(s).", target.display()),
                ),
                Err(e) => JobReport::err(e.to_string()),
            }
        });
    }

    fn spawn_import_contact_paste(&mut self, ctx: &egui::Context) {
        let text = match &self.state {
            State::Unlocked(s) => s.contact_paste.trim().to_string(),
            _ => return,
        };
        if text.is_empty() {
            self.set_toast("Paste an armored public key first.", true);
            return;
        }
        let pubid = match filesec_core::PublicIdentity::from_armored(&text) {
            Ok(p) => p,
            Err(e) => {
                self.set_toast(e.to_string(), true);
                return;
            }
        };
        if let State::Unlocked(s) = &mut self.state {
            s.contact_paste.clear();
        }
        let contacts = match &self.state {
            State::Unlocked(s) => s.contacts.clone(),
            _ => return,
        };
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        self.spawn_job(ctx, "Saving contact…", move || {
            import_contact_job(&store, &identity, contacts, pubid)
        });
    }

    fn spawn_import_contact_file(&mut self, ctx: &egui::Context) {
        let path = match rfd::FileDialog::new()
            .add_filter("FileSec public key", &["fsecpub"])
            .pick_file()
        {
            Some(p) => p,
            None => return,
        };
        let contacts = match &self.state {
            State::Unlocked(s) => s.contacts.clone(),
            _ => return,
        };
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        self.spawn_job(ctx, "Importing contact…", move || {
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => return JobReport::err(e.to_string()),
            };
            let pubid = filesec_core::PublicIdentity::from_bytes(&bytes).or_else(|_| {
                String::from_utf8(bytes.clone())
                    .map_err(|_| filesec_core::Error::Format("not a public key"))
                    .and_then(|t| filesec_core::PublicIdentity::from_armored(&t))
            });
            match pubid {
                Ok(p) => import_contact_job(&store, &identity, contacts, p),
                Err(e) => JobReport::err(e.to_string()),
            }
        });
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
            contacts.set_trust(&fpr, trust);
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
/// persist the registry, and produce the `ReplaceOpen` outcome. Shared by the
/// in-memory mutate path and the streaming add path.
fn finalize_after_save(
    store: &Store,
    identity: &Identity,
    id: String,
    mut registry: Registry,
    msg: String,
) -> JobReport {
    let new_reader = match store.open_vault(identity, &id) {
        Ok(r) => r,
        Err(e) => return JobReport::err(e),
    };
    registry.upsert(VaultMeta {
        id: id.clone(),
        name: new_reader.name().to_string(),
        created_at: new_reader.created_at(),
        modified_at: now_unix(),
        file_count: new_reader.file_count() as u64,
        total_size: new_reader.total_size(),
    });
    if let Err(e) = store.save_registry(identity, &registry) {
        return JobReport::err(e);
    }
    JobReport::ok(
        Outcome::ReplaceOpen {
            id,
            reader: Box::new(new_reader),
            registry,
        },
        msg,
    )
}

/// Upsert a contact and persist the book (worker side).
fn import_contact_job(
    store: &Store,
    identity: &Identity,
    mut contacts: ContactBook,
    pubid: filesec_core::PublicIdentity,
) -> JobReport {
    let name = if pubid.name.is_empty() {
        "(unnamed)".to_string()
    } else {
        pubid.name.clone()
    };
    contacts.upsert(pubid, now_unix());
    match store.save_contacts(identity, &contacts) {
        Ok(()) => JobReport::ok(
            Outcome::Contacts(contacts),
            format!("Imported contact \"{name}\". Verify their safety number before trusting."),
        ),
        Err(e) => JobReport::err(e),
    }
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
    ui.horizontal(|ui| {
        if ui.button("← Vaults").clicked() {
            *action = Some(Action::CloseVault);
        }
        ui.heading(&name);
    });
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
                    if ui.small_button("🗑").on_hover_text("Remove").clicked() {
                        *action = Some(Action::DeleteEntry(path.clone()));
                    }
                    if kind == EntryKind::File && ui.small_button("Save as…").clicked() {
                        *action = Some(Action::SaveEntryAs(path.clone()));
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
            if ui.button("Import from .fsecpub file…").clicked() {
                *action = Some(Action::ImportContactFile);
            }
            ui.label("…or paste an armored public key:");
            ui.add(
                egui::TextEdit::multiline(&mut s.contact_paste)
                    .desired_rows(4)
                    .desired_width(f32::INFINITY)
                    .hint_text("-----BEGIN FILESEC PUBLIC KEY-----"),
            );
            if ui.button("Import pasted key").clicked() {
                *action = Some(Action::ImportContactPaste);
            }
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
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&c.identity.name).strong());
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
                                if ui.small_button("Mark verified").clicked() {
                                    *action =
                                        Some(Action::SetTrust(fpr_hex.clone(), Trust::Verified));
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
                    let label = match c.trust {
                        Trust::Verified => format!("{} (verified)", c.identity.name),
                        Trust::Unverified => format!("{} — unverified ⚠", c.identity.name),
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
            ui.add_space(6.0);
            if form.selected.iter().any(|fpr| {
                s.contacts
                    .contacts
                    .iter()
                    .any(|c| &hex(&c.fingerprint()) == fpr && c.trust == Trust::Unverified)
            }) {
                ui.colored_label(ERR_RED, "⚠ Some selected recipients are unverified.");
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
            ui.label("Sender (cryptographically verified):");
            match (&info.sender_name, info.verified) {
                (Some(name), true) => {
                    ui.colored_label(OK_GREEN, format!("✔ {name} (verified contact)"));
                }
                (Some(name), false) => {
                    ui.colored_label(ERR_RED, format!("● {name} (known but UNVERIFIED contact)"));
                }
                (None, _) => {
                    ui.colored_label(ERR_RED, "● Unknown sender — not in your contacts");
                }
            }
            ui.label(
                RichText::new(format!("fingerprint: {}", info.sender_fpr_hex))
                    .monospace()
                    .small()
                    .color(MUTED),
            );
            ui.add_space(8.0);
            if ui.button("OK").clicked() {
                *action = Some(Action::DismissImportInfo);
            }
        });
    if !open {
        *action = Some(Action::DismissImportInfo);
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

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
