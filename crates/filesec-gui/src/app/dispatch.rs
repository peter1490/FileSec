//! [`FileSecApp::dispatch`]: applies one [`Action`] emitted by the UI.
//!
//! Instant, UI-only actions mutate state directly; everything that touches the
//! disk or does crypto hands off to a `spawn_*` job in [`super::jobs`].

use std::collections::HashSet;

use gpui_kit::{Context, Window};

use filesec_core::SuiteId;

use super::fields;
use super::jobs::build_contact_preview;
use super::model::*;
use super::*;

impl FileSecApp {
    pub(super) fn dispatch(&mut self, action: Action, window: &mut Window, cx: &mut Context<Self>) {
        // A running job, a held close, or an open file dialog makes the UI inert
        // (the overlay already blocks the mouse; this also covers the keyboard).
        if self.is_busy() {
            return;
        }
        self.dispatch_inner(action, window, cx);
        self.scrub_fields(window, cx);
        self.arm_toast_timer(cx);
        cx.notify();
    }

    fn dispatch_inner(&mut self, action: Action, window: &mut Window, cx: &mut Context<Self>) {
        match action {
            // --- instant, UI-only actions ---
            Action::Lock => {
                if self.checkout_active() {
                    self.set_toast("Check in or discard your edit first.", true);
                    return;
                }
                self.wipe_all_views();
                self.state = match &self.store {
                    Some(store) => State::Unlock(Unlock::for_store(store)),
                    None => State::Unlock(Unlock::default()),
                };
                self.toast = None;
                self.focus_first_field(window, cx);
            }
            #[cfg(feature = "net")]
            Action::StartListen => self.start_listen(cx),
            #[cfg(feature = "net")]
            Action::StopTransfer => self.stop_transfer(),
            #[cfg(feature = "net")]
            Action::StartSend => self.start_send(cx),
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
            #[cfg(feature = "net")]
            Action::SetRecvContact(fp) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.transfer.recv_contact = Some(fp);
                }
            }
            #[cfg(feature = "net")]
            Action::SetRecvInternet(b) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.transfer.recv_internet = b;
                }
            }
            #[cfg(feature = "net")]
            Action::SetSendContact(fp) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.transfer.send_contact = Some(fp);
                }
            }
            #[cfg(feature = "net")]
            Action::SetSendVault(id) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.transfer.send_vault = Some(id);
                }
            }
            #[cfg(feature = "net")]
            Action::SetSendAllowClassical(b) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.transfer.send_allow_classical = b;
                }
            }
            Action::CopyText(text) => {
                self.copy_to_clipboard(text, cx);
                self.set_toast("Copied to clipboard.", false);
            }
            Action::DismissToast => self.toast = None,
            Action::DismissImportInfo => {
                if let State::Unlocked(s) = &mut self.state {
                    s.last_import = None;
                }
            }
            Action::SetAnchorConfirmed(b) => {
                if let State::AnchorRecovery(r) = &mut self.state {
                    r.confirmed = b;
                }
            }
            Action::Nav(n) => {
                if self.checkout_active() {
                    self.set_toast("Check in or discard your edit first.", true);
                    return;
                }
                self.wipe_all_views();
                if let State::Unlocked(s) = &mut self.state {
                    s.nav = n;
                    s.open = None;
                    s.reset_browse();
                }
            }
            Action::SetTheme(choice) => {
                // Apply first: the appearance changes even if the write fails.
                theme::apply_choice(choice, cx);
                if let Some(store) = &self.store {
                    // Read-modify-write rather than writing a fresh `Prefs`, so
                    // a preference added by a newer build is not clobbered.
                    let mut prefs = store.load_prefs();
                    prefs.theme = choice;
                    if store.save_prefs(&prefs).is_err() {
                        self.set_toast(
                            "Theme changed, but it could not be saved for next time.",
                            true,
                        );
                    }
                }
            }
            Action::CopyDataDir => {
                let dir = if let State::Unlocked(s) = &self.state {
                    Some(s.data_dir.clone())
                } else {
                    None
                };
                if let Some(dir) = dir {
                    self.copy_to_clipboard(dir, cx);
                    self.set_toast("Data folder path copied to clipboard.", false);
                }
            }
            Action::RevealDataDir => {
                let dir = if let State::Unlocked(s) = &self.state {
                    Some(std::path::PathBuf::from(&s.data_dir))
                } else {
                    None
                };
                if let Some(dir) = dir {
                    if !reveal_in_file_manager(&dir) {
                        self.set_toast("Could not open the data folder.", true);
                    }
                }
            }
            Action::CopyBuildInfo => {
                self.copy_to_clipboard(build_info_line(), cx);
                self.set_toast("Build details copied to clipboard.", false);
            }
            Action::ToggleNewVault(b) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.show_new_vault = b;
                }
                if b {
                    self.fields
                        .new_vault_name
                        .update(cx, |input, cx| input.focus(window, cx));
                }
            }
            Action::CloseVault => {
                if self.checkout_active() {
                    self.set_toast("Check in or discard your edit first.", true);
                    return;
                }
                self.wipe_all_views();
                if let State::Unlocked(s) = &mut self.state {
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
                }
                fields::clear(&self.fields.file_search, window, cx);
                self.focus_browser(window, cx);
            }
            Action::RowClicked(at) => {
                let search = fields::value(&self.fields.file_search, cx).to_string();
                let mut follow = None;
                if let State::Unlocked(s) = &mut self.state {
                    if let Some(model) = s.browser_model() {
                        let dir = s.current_dir.clone();
                        let rows = s.visible_rows(&model, &dir, &search);
                        if let Some(idx) = rows.iter().position(|r| r.path == at.path) {
                            follow = apply_row_click(s, &rows, idx, at.click);
                        }
                    }
                }
                self.focus_browser(window, cx);
                if let Some(next) = follow {
                    self.dispatch_inner(next, window, cx);
                }
            }
            Action::ToggleNewFolder(b) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.show_new_folder = b;
                    if b {
                        s.show_new_file = false;
                    }
                }
                if b {
                    self.fields
                        .new_folder_name
                        .update(cx, |input, cx| input.focus(window, cx));
                }
            }
            Action::ToggleNewFile(b) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.show_new_file = b;
                    if b {
                        s.show_new_folder = false;
                    }
                }
                if b {
                    self.fields
                        .new_file_name
                        .update(cx, |input, cx| input.focus(window, cx));
                }
            }
            Action::CloseTextEditor => {
                if let State::Unlocked(s) = &mut self.state {
                    // `original` is zeroized on drop; `scrub_fields` empties the
                    // textarea.
                    s.text_editor = None;
                }
            }
            Action::SelectAllVisible => {
                let search = fields::value(&self.fields.file_search, cx).to_string();
                if let State::Unlocked(s) = &mut self.state {
                    if let Some(o) = &s.open {
                        let entries = snapshot_entries(&o.reader);
                        // Select every visible row — files and folders alike.
                        for row in visible_rows(&entries, &s.current_dir, &search, s.sort) {
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
            Action::ClearVaultSearch => fields::clear(&self.fields.vault_search, window, cx),
            Action::ClearContactSearch => fields::clear(&self.fields.contact_search, window, cx),
            Action::ClearFileSearch => {
                fields::clear(&self.fields.file_search, window, cx);
                if let State::Unlocked(s) = &mut self.state {
                    s.selected.clear();
                    s.select_anchor = None;
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
                    s.confirm_empty_trash = false;
                }
            }
            Action::PromptEmptyTrash(b) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.confirm_empty_trash = b;
                }
            }
            Action::BeginRename(path) => {
                // Pre-fill without invisible/bidi formatting characters, so
                // confirming the rename fixes a name an older version stored
                // (new names may not contain them).
                let draft: String = leaf_name(&path)
                    .chars()
                    .filter(|c| !filesec_core::util::is_spoofing_format_char(*c))
                    .collect();
                if let State::Unlocked(s) = &mut self.state {
                    s.rename_target = Some(path);
                }
                fields::set(&self.fields.rename, &draft, window, cx);
                self.fields
                    .rename
                    .update(cx, |input, cx| input.focus(window, cx));
            }
            Action::CancelRename => {
                if let State::Unlocked(s) = &mut self.state {
                    s.rename_target = None;
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
                        confirmed_unverified: HashSet::new(),
                        vault_id: id,
                        selected: HashSet::new(),
                        include_self: false,
                        suite: SuiteId::default(),
                    });
                }
            }
            Action::ConfirmUnverifiedRecipient(fpr, confirmed) => {
                if let State::Unlocked(s) = &mut self.state {
                    if let Some(e) = &mut s.export {
                        if confirmed {
                            e.confirmed_unverified.insert(fpr);
                        } else {
                            e.confirmed_unverified.remove(&fpr);
                        }
                    }
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
            Action::DoMigrate => self.spawn_migrate(cx),
            Action::CopyPubKey => {
                let armored = if let State::Unlocked(s) = &self.state {
                    Some(s.identity.public().to_armored())
                } else {
                    None
                };
                match armored {
                    Some(Ok(text)) => {
                        self.copy_to_clipboard(text, cx);
                        self.set_toast("Public key copied to clipboard.", false);
                    }
                    Some(Err(e)) => self.set_toast(e.to_string(), true),
                    None => {}
                }
            }
            Action::ToggleAddContact(b) => {
                if let State::Unlocked(s) = &mut self.state {
                    s.show_add_contact = b;
                }
            }
            Action::ToggleFingerprint => {
                if let State::Unlocked(s) = &mut self.state {
                    s.show_fingerprint = !s.show_fingerprint;
                }
            }
            Action::ToggleNotices => {
                if let State::Unlocked(s) = &mut self.state {
                    s.show_notices = !s.show_notices;
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
                let pass = self.fields.autounlock_pass.clone();
                window.focus(&gpui_kit::Focusable::focus_handle(pass.read(cx), cx), cx);
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
                if matches!(self.state, State::FirstRun(_)) {
                    // Pick the backup file up front; only open the restore card
                    // once a file is chosen (cancelling the picker is a no-op).
                    self.pick_paths(
                        open_file("Choose a FileSec identity backup (.fsecid)"),
                        window,
                        cx,
                        |paths| paths.into_iter().next().map(Action::RestoreFrom),
                    );
                }
            }
            Action::RestoreFrom(path) => {
                if let State::FirstRun(f) = &mut self.state {
                    f.error = None;
                    f.restore = Some(RestoreForm { path, error: None });
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
                let number = match &self.state {
                    State::Unlocked(s) => s.verify.as_ref().map(|v| v.safety_number.clone()),
                    _ => None,
                };
                if let Some(number) = number {
                    self.copy_to_clipboard(number, cx);
                    self.set_toast("Safety number copied to clipboard.", false);
                }
            }
            Action::SetVerifyManual(b) => {
                if let State::Unlocked(s) = &mut self.state {
                    if let Some(v) = &mut s.verify {
                        v.manual_ok = b;
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
            // --- background jobs (and the dialogs that feed them) ---
            Action::CreateIdentity => self.spawn_create_identity(cx),
            Action::Unlock => self.spawn_unlock(cx),
            Action::RecoverAnchors => self.spawn_recover_anchors(cx),
            Action::UnlockWithPasskey => self.spawn_unlock_passkey(cx),
            Action::AddPasskey => self.spawn_add_passkey(cx),
            Action::RemovePasskey(i) => self.spawn_remove_passkey(cx, i),
            Action::UnlockWithKeyring => self.spawn_unlock_keyring(cx),
            Action::ConfirmEnableAutoUnlock => self.spawn_enable_auto_unlock(cx),
            Action::DisableAutoUnlock => self.spawn_disable_auto_unlock(cx),
            Action::CreateVault => self.spawn_create_vault(cx),
            Action::OpenVault(id) => self.spawn_open_vault(cx, id),
            Action::RequestDeleteVault(id) => {
                if self.checkout_active() {
                    self.set_toast("Check in or discard your edit first.", true);
                    return;
                }
                if let State::Unlocked(s) = &mut self.state {
                    if s.registry.vaults.iter().any(|vault| vault.id == id) {
                        s.delete_vault = Some(DeleteVaultForm { vault_id: id });
                        // The safe choice has the keyboard: Enter cancels.
                        window.focus(&self.dialog_focus, cx);
                    }
                }
            }
            Action::CancelDeleteVault => {
                if let State::Unlocked(s) = &mut self.state {
                    s.delete_vault = None;
                }
            }
            Action::ConfirmDeleteVault => {
                let pending = match &mut self.state {
                    State::Unlocked(s) => s.delete_vault.take(),
                    _ => None,
                };
                if let Some(form) = pending {
                    self.spawn_delete_vault(cx, form.vault_id);
                }
            }
            Action::ImportContainer => {
                if matches!(self.state, State::Unlocked(_)) {
                    self.pick_paths(
                        open_file("Choose a FileSec container (.fsec) to import"),
                        window,
                        cx,
                        |paths| paths.into_iter().next().map(Action::ImportContainerFrom),
                    );
                }
            }
            Action::ImportContainerFrom(path) => self.spawn_import(cx, path),
            Action::AddFiles => {
                if self.open_ctx().is_some() {
                    self.pick_paths(open_files("Add files"), window, cx, |paths| {
                        Some(Action::DropPaths(paths))
                    });
                }
            }
            Action::AddFolder => {
                if self.open_ctx().is_some() {
                    self.pick_paths(open_folder("Add a folder"), window, cx, |paths| {
                        Some(Action::DropPaths(paths))
                    });
                }
            }
            Action::DropPaths(paths) => self.add_sources(cx, paths),
            Action::NewFolder => self.spawn_new_folder(cx),
            Action::NewFile => self.spawn_new_file(cx),
            Action::QuickEdit(p) => self.spawn_quick_edit(cx, p),
            Action::SaveTextFile => self.spawn_save_text_file(cx),
            Action::Trash(p) => self.spawn_trash_entry(cx, p),
            Action::TrashSelected => self.spawn_trash_selected(cx),
            Action::RestoreTrashed(p) => self.spawn_restore(cx, p),
            Action::PurgeTrashed(p) => self.spawn_purge(cx, p),
            Action::EmptyTrash => self.spawn_empty_trash(cx),
            Action::ConfirmRename => self.spawn_rename(cx),
            Action::ConfirmMove => self.spawn_move(cx),
            Action::ExtractSelected => self.begin_extract_selected(window, cx),
            Action::ExtractSelectedTo(dest) => self.spawn_extract_selected(cx, dest),
            Action::ExtractAll => {
                if self.open_reader().is_some() {
                    self.pick_paths(open_folder("Extract all files to…"), window, cx, |paths| {
                        paths.into_iter().next().map(Action::ExtractAllTo)
                    });
                }
            }
            Action::ExtractAllTo(dest) => self.spawn_extract_all(cx, dest),
            Action::SaveEntryAs(p) => self.begin_save_entry_as(window, cx, p),
            Action::SaveEntryTo(p, target) => self.spawn_save_entry_to(cx, p, target),
            Action::ViewFile(p) => self.spawn_view(cx, p),
            Action::CheckOut(p) => self.spawn_check_out(cx, p),
            Action::CheckIn => self.spawn_check_in(cx),
            Action::Discard => self.spawn_discard(cx),
            Action::DoExport => self.begin_export(window, cx),
            Action::ExportTo(target) => self.spawn_export_to(cx, target),
            Action::PreviewContactPaste => self.preview_contact_paste(cx),
            Action::PreviewContactFile => {
                if matches!(self.state, State::Unlocked(_)) {
                    self.pick_paths(
                        open_file("Choose a FileSec public key (.fsecpub)"),
                        window,
                        cx,
                        |paths| paths.into_iter().next().map(Action::PreviewContactFileFrom),
                    );
                }
            }
            Action::PreviewContactFileFrom(path) => self.preview_contact_file(path),
            Action::ConfirmAddContact => self.spawn_confirm_add_contact(window, cx),
            Action::ConfirmVerify(fpr) => self.confirm_verify(cx, fpr),
            Action::SetTrust(fpr, t) => self.spawn_set_trust(cx, fpr, t),
            Action::RemoveContact(fpr) => self.spawn_remove_contact(cx, fpr),
            Action::SavePubKey => self.begin_save_pubkey(window, cx),
            Action::SavePubKeyTo(target) => self.spawn_save_pubkey_to(cx, target),
            Action::DoExportIdentity => self.begin_export_identity(window, cx),
            Action::ExportIdentityTo(target) => self.spawn_export_identity_to(cx, target),
            Action::DoRestore => self.spawn_restore_identity(cx),
        }
    }
}

/// Resolve a row body click into the new selection (and any open action).
/// Double-click opens — enter a folder, view a file.
pub(super) fn apply_row_click(
    s: &mut Session,
    rows: &[Row],
    idx: usize,
    click: RowClick,
) -> Option<Action> {
    match click {
        RowClick::Double => {
            let path = rows[idx].path.clone();
            if rows[idx].kind == filesec_core::manifest::EntryKind::Dir {
                Some(Action::EnterDir(path))
            } else {
                s.selected.clear();
                s.selected.insert(path.clone());
                s.select_anchor = Some(path.clone());
                Some(Action::ViewFile(path))
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
            None
        }
    }
}
