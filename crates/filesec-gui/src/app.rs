//! The egui application: state machine, screens, and action handling.
//!
//! Rendering is immediate-mode and side-effect-free: each screen only *collects*
//! an [`Action`]. After the frame is laid out, [`App::handle`] applies the
//! action — performing crypto and I/O — so borrow scopes stay simple and the UI
//! never mutates persistent state mid-render.

use std::collections::HashSet;
use std::time::UNIX_EPOCH;

use eframe::egui::{self, Color32, RichText};

use filesec_core::contacts::{ContactBook, Trust};
use filesec_core::format::{self, ExportOptions};
use filesec_core::identity::Identity;
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::KeystoreFile;
use filesec_core::manifest::EntryKind;
use filesec_core::util::{hex, now_unix};
use filesec_core::vault::Vault;

use crate::store::{extract_vault, new_vault_id, Registry, Store, VaultMeta};

const OK_GREEN: Color32 = Color32::from_rgb(0x3c, 0xb3, 0x71);
const ERR_RED: Color32 = Color32::from_rgb(0xd6, 0x5d, 0x5d);
const MUTED: Color32 = Color32::from_rgb(0x99, 0x99, 0x99);
const ACCENT: Color32 = Color32::from_rgb(0x5a, 0x9b, 0xd4);

/// Top-level application.
pub struct App {
    store: Option<Store>,
    state: State,
    toast: Option<Toast>,
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

#[derive(Default)]
struct Unlock {
    pass: String,
    error: Option<String>,
}

#[derive(PartialEq, Clone, Copy)]
enum Nav {
    Vaults,
    Contacts,
    Identity,
}

struct OpenVault {
    id: String,
    vault: Vault,
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

/// Unlocked session state.
struct Session {
    identity: Identity,
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
        identity: Identity,
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
                    store: Some(store),
                    state,
                    toast: None,
                }
            }
            Err(e) => App {
                store: None,
                state: State::Fatal(e),
                toast: None,
            },
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut action: Option<Action> = None;

        egui::TopBottomPanel::top("top").show(ctx, |ui| self.top_bar(ui, &mut action));

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

        egui::CentralPanel::default().show(ctx, |ui| match &mut self.state {
            State::Fatal(msg) => {
                ui.heading("FileSec could not start");
                ui.colored_label(ERR_RED, msg.clone());
            }
            State::FirstRun(f) => first_run_ui(f, ui, &mut action),
            State::Unlock(u) => unlock_ui(u, ui, &mut action),
            State::Unlocked(s) => session_ui(s, ui, &mut action),
        });

        if let Some(a) = action {
            self.handle(a, ctx);
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

    fn handle(&mut self, action: Action, ctx: &egui::Context) {
        match action {
            Action::CreateIdentity => self.do_create_identity(),
            Action::Unlock => self.do_unlock(),
            Action::Lock => {
                self.state = State::Unlock(Unlock::default());
                self.toast = None;
            }
            Action::DismissToast => {
                self.toast = None;
            }
            Action::DismissImportInfo => {
                if let State::Unlocked(s) = &mut self.state {
                    s.last_import = None;
                }
            }
            other => self.handle_session(other, ctx),
        }
    }

    fn do_create_identity(&mut self) {
        // Validate without touching the store.
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
            (name, std::mem::take(&mut f.pass))
        };

        let identity = match Identity::generate(&name, now_unix()) {
            Ok(i) => i,
            Err(e) => {
                self.fail_first_run(e.to_string());
                return;
            }
        };
        let ks = match KeystoreFile::create(&identity, pass.as_bytes(), KdfParams::default()) {
            Ok(k) => k,
            Err(e) => {
                self.fail_first_run(e.to_string());
                return;
            }
        };
        let data_dir = self
            .store
            .as_ref()
            .map(|s| s.data_dir().display().to_string())
            .unwrap_or_default();
        if let Some(store) = &self.store {
            if let Err(e) = store.save_keystore(&ks) {
                self.fail_first_run(e);
                return;
            }
        }
        self.state = State::Unlocked(Box::new(Session::new(
            identity,
            ContactBook::default(),
            Registry::default(),
            data_dir,
        )));
        self.set_toast(
            "Identity created. Your keys are protected by your passphrase.",
            false,
        );
    }

    fn fail_first_run(&mut self, msg: String) {
        if let State::FirstRun(f) = &mut self.state {
            f.error = Some(msg);
        }
    }

    fn do_unlock(&mut self) {
        let pass = match &mut self.state {
            State::Unlock(u) => std::mem::take(&mut u.pass),
            _ => return,
        };
        let store = match &self.store {
            Some(s) => s,
            None => return,
        };
        let ks = match store.load_keystore() {
            Ok(k) => k,
            Err(e) => {
                self.fail_unlock(e);
                return;
            }
        };
        let identity = match ks.unlock(pass.as_bytes()) {
            Ok(i) => i,
            Err(e) => {
                self.fail_unlock(e.to_string());
                return;
            }
        };
        let contacts = store.load_contacts(&identity).unwrap_or_default();
        let registry = store.load_registry(&identity).unwrap_or_default();
        let data_dir = store.data_dir().display().to_string();
        self.state = State::Unlocked(Box::new(Session::new(
            identity, contacts, registry, data_dir,
        )));
        self.set_toast("Unlocked.", false);
    }

    fn fail_unlock(&mut self, msg: String) {
        if let State::Unlock(u) = &mut self.state {
            u.error = Some(msg);
        }
    }

    fn handle_session(&mut self, action: Action, ctx: &egui::Context) {
        let store = match &self.store {
            Some(s) => s,
            None => return,
        };
        let session = match &mut self.state {
            State::Unlocked(s) => s,
            _ => return,
        };
        let mut toast: Option<(String, bool)> = None;

        match action {
            Action::Nav(n) => {
                session.nav = n;
                session.open = None;
            }
            Action::ToggleNewVault(b) => {
                session.show_new_vault = b;
                if !b {
                    session.new_vault_name.clear();
                }
            }
            Action::CreateVault => report(&mut toast, session.create_vault(store)),
            Action::OpenVault(id) => report(&mut toast, session.open_vault(store, &id)),
            Action::CloseVault => session.open = None,
            Action::DeleteVault(id) => report(&mut toast, session.delete_vault(store, &id)),
            Action::ImportContainer => report(&mut toast, session.import_container(store)),
            Action::AddFiles => report(&mut toast, session.add_files(store)),
            Action::AddFolder => report(&mut toast, session.add_folder(store)),
            Action::NewFolder => report(&mut toast, session.new_folder(store)),
            Action::DeleteEntry(p) => report(&mut toast, session.delete_entry(store, &p)),
            Action::SaveEntryAs(p) => report(&mut toast, session.save_entry_as(&p)),
            Action::ExtractAll => report(&mut toast, session.extract_all()),
            Action::BeginExport(id) => session.begin_export(id),
            Action::CancelExport => session.export = None,
            Action::DoExport => report(&mut toast, session.do_export(store)),
            Action::ToggleRecipient(fpr) => session.toggle_recipient(&fpr),
            Action::ToggleIncludeSelf => {
                if let Some(e) = &mut session.export {
                    e.include_self = !e.include_self;
                }
            }
            Action::ImportContactPaste => report(&mut toast, session.import_contact_paste(store)),
            Action::ImportContactFile => report(&mut toast, session.import_contact_file(store)),
            Action::SetTrust(fpr, t) => report(&mut toast, session.set_trust(store, &fpr, t)),
            Action::RemoveContact(fpr) => report(&mut toast, session.remove_contact(store, &fpr)),
            Action::SavePubKey => report(&mut toast, session.save_pubkey()),
            Action::CopyPubKey => match session.identity.public().to_armored() {
                Ok(s) => {
                    ctx.copy_text(s);
                    toast = Some(("Public key copied to clipboard.".into(), false));
                }
                Err(e) => toast = Some((e.to_string(), true)),
            },
            // Handled in `handle`.
            Action::CreateIdentity
            | Action::Unlock
            | Action::Lock
            | Action::DismissImportInfo
            | Action::DismissToast => {}
        }

        if let Some((msg, error)) = toast {
            self.toast = Some(Toast { msg, error });
        }
    }
}

fn report(slot: &mut Option<(String, bool)>, result: Result<String, String>) {
    *slot = Some(match result {
        Ok(msg) => (msg, false),
        Err(e) => (e, true),
    });
}

// ---------------------------------------------------------------------------
// Session operations (perform crypto + I/O, return a user-facing message).
// ---------------------------------------------------------------------------

impl Session {
    fn persist_open(&mut self, store: &Store) -> Result<(), String> {
        if let Some(open) = &self.open {
            store.save_vault(&self.identity, &open.id, &open.vault)?;
            self.registry.upsert(VaultMeta {
                id: open.id.clone(),
                name: open.vault.name.clone(),
                created_at: open.vault.created_at,
                modified_at: now_unix(),
                file_count: open.vault.file_count() as u64,
                total_size: open.vault.total_size(),
            });
            store.save_registry(&self.identity, &self.registry)?;
        }
        Ok(())
    }

    fn create_vault(&mut self, store: &Store) -> Result<String, String> {
        let name = self.new_vault_name.trim().to_string();
        if name.is_empty() {
            return Err("Enter a vault name.".into());
        }
        let id = new_vault_id();
        let vault = Vault::new(&name, now_unix());
        store.save_vault(&self.identity, &id, &vault)?;
        self.registry.upsert(VaultMeta {
            id: id.clone(),
            name: name.clone(),
            created_at: vault.created_at,
            modified_at: now_unix(),
            file_count: 0,
            total_size: 0,
        });
        store.save_registry(&self.identity, &self.registry)?;
        self.new_vault_name.clear();
        self.show_new_vault = false;
        self.open = Some(OpenVault { id, vault });
        Ok(format!("Created vault \"{name}\"."))
    }

    fn open_vault(&mut self, store: &Store, id: &str) -> Result<String, String> {
        let vault = store.load_vault(&self.identity, id)?;
        let name = vault.name.clone();
        self.open = Some(OpenVault {
            id: id.to_string(),
            vault,
        });
        Ok(format!("Opened \"{name}\"."))
    }

    fn delete_vault(&mut self, store: &Store, id: &str) -> Result<String, String> {
        store.delete_vault_file(id)?;
        self.registry.remove(id);
        store.save_registry(&self.identity, &self.registry)?;
        if self.open.as_ref().map(|o| o.id == id).unwrap_or(false) {
            self.open = None;
        }
        Ok("Vault deleted.".into())
    }

    fn import_container(&mut self, store: &Store) -> Result<String, String> {
        let path = match rfd::FileDialog::new()
            .add_filter("FileSec container", &["fsec"])
            .pick_file()
        {
            Some(p) => p,
            None => return Ok(String::new()),
        };
        let imported =
            format::import_vault_from_path(&path, &self.identity).map_err(|e| e.to_string())?;

        // Resolve the (verified) sender against our contacts.
        let fpr = imported.sender_fingerprint;
        let contact = self.contacts.find(&fpr);
        let sender_name = contact.map(|c| c.identity.name.clone());
        let verified = matches!(contact.map(|c| c.trust), Some(Trust::Verified));

        let id = new_vault_id();
        store.save_vault(&self.identity, &id, &imported.vault)?;
        self.registry.upsert(VaultMeta {
            id: id.clone(),
            name: imported.vault.name.clone(),
            created_at: imported.vault.created_at,
            modified_at: now_unix(),
            file_count: imported.vault.file_count() as u64,
            total_size: imported.vault.total_size(),
        });
        store.save_registry(&self.identity, &self.registry)?;

        self.last_import = Some(ImportInfo {
            sender_fpr_hex: hex(&fpr),
            sender_name,
            verified,
            vault_name: imported.vault.name.clone(),
            file_count: imported.vault.file_count(),
        });
        Ok(String::new())
    }

    fn add_files(&mut self, store: &Store) -> Result<String, String> {
        let files = match rfd::FileDialog::new().pick_files() {
            Some(f) => f,
            None => return Ok(String::new()),
        };
        let open = self.open.as_mut().ok_or("No vault open.")?;
        let mut added = 0usize;
        let mut last_err = None;
        for path in files {
            match std::fs::read(&path) {
                Ok(bytes) => {
                    let base = path
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| "file".into());
                    let name = unique_name(&open.vault, &base);
                    let mtime = file_mtime(&path);
                    if open.vault.add_file(&name, bytes, mtime, None).is_ok() {
                        added += 1;
                    }
                }
                Err(e) => last_err = Some(format!("Could not read {}: {e}", path.display())),
            }
        }
        if added > 0 {
            self.persist_open(store)?;
        }
        if let Some(e) = last_err {
            return Err(e);
        }
        Ok(format!("Added {added} file(s)."))
    }

    fn add_folder(&mut self, store: &Store) -> Result<String, String> {
        let base = match rfd::FileDialog::new().pick_folder() {
            Some(p) => p,
            None => return Ok(String::new()),
        };
        let root = base
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "folder".into());
        let open = self.open.as_mut().ok_or("No vault open.")?;
        let mut added = 0usize;
        for entry in walkdir::WalkDir::new(&base).into_iter().flatten() {
            let rel = match entry.path().strip_prefix(&base) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if rel.as_os_str().is_empty() {
                continue;
            }
            let vault_path = format!("{root}/{}", rel.to_string_lossy());
            if entry.file_type().is_dir() {
                let _ = open.vault.add_dir(&vault_path);
            } else if entry.file_type().is_file() {
                if let Ok(bytes) = std::fs::read(entry.path()) {
                    let mtime = file_mtime(entry.path());
                    if open.vault.add_file(&vault_path, bytes, mtime, None).is_ok() {
                        added += 1;
                    }
                }
            }
        }
        self.persist_open(store)?;
        Ok(format!("Added folder \"{root}\" ({added} file(s))."))
    }

    fn new_folder(&mut self, store: &Store) -> Result<String, String> {
        let name = self.new_folder_name.trim().to_string();
        if name.is_empty() {
            return Err("Enter a folder name.".into());
        }
        {
            let open = self.open.as_mut().ok_or("No vault open.")?;
            open.vault.add_dir(&name).map_err(|e| e.to_string())?;
        }
        self.new_folder_name.clear();
        self.persist_open(store)?;
        Ok(format!("Created folder \"{name}\"."))
    }

    fn delete_entry(&mut self, store: &Store, path: &str) -> Result<String, String> {
        {
            let open = self.open.as_mut().ok_or("No vault open.")?;
            open.vault.remove(path);
        }
        self.persist_open(store)?;
        Ok("Removed.".into())
    }

    fn save_entry_as(&self, path: &str) -> Result<String, String> {
        let open = self.open.as_ref().ok_or("No vault open.")?;
        let entry = open.vault.get(path).ok_or("Entry not found.")?;
        if entry.kind != EntryKind::File {
            return Err("Only files can be saved.".into());
        }
        let suggested = path.rsplit('/').next().unwrap_or("file");
        let target = match rfd::FileDialog::new().set_file_name(suggested).save_file() {
            Some(p) => p,
            None => return Ok(String::new()),
        };
        std::fs::write(&target, &entry.content).map_err(|e| e.to_string())?;
        Ok(format!("Saved to {}", target.display()))
    }

    fn extract_all(&self) -> Result<String, String> {
        let open = self.open.as_ref().ok_or("No vault open.")?;
        let dest = match rfd::FileDialog::new().pick_folder() {
            Some(p) => p,
            None => return Ok(String::new()),
        };
        extract_vault(&open.vault, &dest)?;
        Ok(format!("Extracted to {}", dest.display()))
    }

    fn begin_export(&mut self, vault_id: String) {
        self.export = Some(ExportForm {
            vault_id,
            selected: HashSet::new(),
            include_self: false,
        });
    }

    fn toggle_recipient(&mut self, fpr_hex: &str) {
        if let Some(e) = &mut self.export {
            if !e.selected.insert(fpr_hex.to_string()) {
                e.selected.remove(fpr_hex);
            }
        }
    }

    fn do_export(&mut self, store: &Store) -> Result<String, String> {
        let form = self.export.as_ref().ok_or("No export in progress.")?;
        if form.selected.is_empty() && !form.include_self {
            return Err("Select at least one recipient.".into());
        }

        // Resolve selected recipients to public identities.
        let mut recipients = Vec::new();
        for c in &self.contacts.contacts {
            if form.selected.contains(&hex(&c.fingerprint())) {
                recipients.push(c.identity.clone());
            }
        }
        if form.include_self {
            recipients.push(self.identity.public());
        }
        if recipients.is_empty() {
            return Err("No matching recipients found.".into());
        }

        // Load the vault to export (use the open copy if it matches).
        let vault = match &self.open {
            Some(o) if o.id == form.vault_id => o.vault_ref(),
            _ => &store.load_vault(&self.identity, &form.vault_id)?,
        };

        let suggested = format!("{}.fsec", sanitize_filename(&vault.name));
        let target = match rfd::FileDialog::new()
            .add_filter("FileSec container", &["fsec"])
            .set_file_name(&suggested)
            .save_file()
        {
            Some(p) => p,
            None => return Ok(String::new()),
        };

        format::export_vault_to_path(
            vault,
            &self.identity,
            &recipients,
            &ExportOptions::default(),
            &target,
        )
        .map_err(|e| e.to_string())?;

        self.export = None;
        Ok(format!(
            "Exported to {} for {} recipient(s).",
            target.display(),
            recipients.len()
        ))
    }

    fn import_contact_from_bytes_or_text(
        &mut self,
        store: &Store,
        pubid: filesec_core::PublicIdentity,
    ) -> Result<String, String> {
        let name = if pubid.name.is_empty() {
            "(unnamed)".to_string()
        } else {
            pubid.name.clone()
        };
        self.contacts.upsert(pubid, now_unix());
        store.save_contacts(&self.identity, &self.contacts)?;
        Ok(format!(
            "Imported contact \"{name}\". Verify their safety number before trusting."
        ))
    }

    fn import_contact_paste(&mut self, store: &Store) -> Result<String, String> {
        let text = self.contact_paste.trim().to_string();
        if text.is_empty() {
            return Err("Paste an armored public key first.".into());
        }
        let pubid = filesec_core::PublicIdentity::from_armored(&text).map_err(|e| e.to_string())?;
        self.contact_paste.clear();
        self.import_contact_from_bytes_or_text(store, pubid)
    }

    fn import_contact_file(&mut self, store: &Store) -> Result<String, String> {
        let path = match rfd::FileDialog::new()
            .add_filter("FileSec public key", &["fsecpub"])
            .pick_file()
        {
            Some(p) => p,
            None => return Ok(String::new()),
        };
        let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        let pubid = filesec_core::PublicIdentity::from_bytes(&bytes)
            .or_else(|_| {
                String::from_utf8(bytes.clone())
                    .map_err(|_| filesec_core::Error::Format("not a public key"))
                    .and_then(|t| filesec_core::PublicIdentity::from_armored(&t))
            })
            .map_err(|e| e.to_string())?;
        self.import_contact_from_bytes_or_text(store, pubid)
    }

    fn set_trust(&mut self, store: &Store, fpr_hex: &str, trust: Trust) -> Result<String, String> {
        let fpr = match decode_fpr(fpr_hex) {
            Some(f) => f,
            None => return Err("Bad fingerprint.".into()),
        };
        self.contacts.set_trust(&fpr, trust);
        store.save_contacts(&self.identity, &self.contacts)?;
        Ok(match trust {
            Trust::Verified => "Marked as verified.".into(),
            Trust::Unverified => "Marked as unverified.".into(),
        })
    }

    fn remove_contact(&mut self, store: &Store, fpr_hex: &str) -> Result<String, String> {
        let fpr = match decode_fpr(fpr_hex) {
            Some(f) => f,
            None => return Err("Bad fingerprint.".into()),
        };
        self.contacts.remove(&fpr);
        store.save_contacts(&self.identity, &self.contacts)?;
        Ok("Contact removed.".into())
    }

    fn save_pubkey(&self) -> Result<String, String> {
        let bytes = self
            .identity
            .public()
            .to_bytes()
            .map_err(|e| e.to_string())?;
        let suggested = format!("{}.fsecpub", sanitize_filename(&self.identity.name));
        let target = match rfd::FileDialog::new()
            .add_filter("FileSec public key", &["fsecpub"])
            .set_file_name(&suggested)
            .save_file()
        {
            Some(p) => p,
            None => return Ok(String::new()),
        };
        std::fs::write(&target, &bytes).map_err(|e| e.to_string())?;
        Ok(format!("Public key saved to {}", target.display()))
    }
}

impl OpenVault {
    fn vault_ref(&self) -> &Vault {
        &self.vault
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
        Some(o) => (o.vault.name.clone(), o.id.clone()),
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
    if open.vault.entries().is_empty() {
        ui.add_space(16.0);
        ui.colored_label(MUTED, "Empty vault. Add files or folders above.");
        return;
    }

    let mut rows: Vec<(String, EntryKind, u64)> = open
        .vault
        .entries()
        .iter()
        .map(|e| (e.path.clone(), e.kind, e.size()))
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
    let bytes = data_encoding_hex_decode(hex_str)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn data_encoding_hex_decode(s: &str) -> Option<Vec<u8>> {
    // Mirror of core's hex encoding (lowercase, no separators).
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
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

fn unique_name(vault: &Vault, base: &str) -> String {
    if !vault.contains(base) {
        return base.to_string();
    }
    let (stem, ext) = match base.rsplit_once('.') {
        Some((s, e)) => (s.to_string(), format!(".{e}")),
        None => (base.to_string(), String::new()),
    };
    for i in 1..10_000 {
        let candidate = format!("{stem} ({i}){ext}");
        if !vault.contains(&candidate) {
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
