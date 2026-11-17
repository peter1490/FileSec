//! Every text field in the app, as long-lived GPUI input entities.
//!
//! The egui app kept each field's text as a `String` inside its form struct.
//! GPUI inputs are stateful entities (cursor, selection, IME, focus), so the app
//! owns one entity per field for its whole lifetime and the form structs keep
//! only non-text state. Text is read when an action needs it, and
//! [`FileSecApp::scrub_fields`] empties every field whose form is no longer on
//! screen — the GPUI equivalent of a form's buffers being dropped.
//!
//! Passphrases and PINs are [`SecretInput`]s (zeroizing, masked, no clipboard
//! or undo history); everything else is a GPUI Component `Input`/`Textarea`.

use gpui_kit::component::input::{InputEvent, InputState, TextareaState};
use gpui_kit::{AppContext, Context, Entity, SharedString, Subscription, Window};

use crate::secret_input::{SecretInput, SecretInputEvent};

use super::FileSecApp;

/// Which field an input event came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FieldId {
    AnchorPass,
    FirstName,
    FirstPass,
    FirstPass2,
    RestoreBackupPass,
    RestoreNewPass,
    RestoreNewPass2,
    UnlockPass,
    UnlockPin,
    NewVaultName,
    VaultSearch,
    ContactSearch,
    FileSearch,
    NewFolderName,
    NewFileName,
    Rename,
    ContactPaste,
    VerifyInput,
    Editor,
    PasskeyLabel,
    PasskeyPass,
    PasskeyPin,
    AutoUnlockPass,
    ExportIdPass,
    ExportIdPass2,
    #[cfg(feature = "pqc")]
    MigratePass,
    #[cfg(feature = "net")]
    RecvPort,
    #[cfg(feature = "net")]
    SendHost,
    #[cfg(feature = "net")]
    SendPort,
    #[cfg(feature = "net")]
    SendPairing,
}

pub(super) struct Fields {
    // --- before unlock ---
    pub anchor_pass: Entity<SecretInput>,
    pub first_name: Entity<InputState>,
    pub first_pass: Entity<SecretInput>,
    pub first_pass2: Entity<SecretInput>,
    pub restore_backup_pass: Entity<SecretInput>,
    pub restore_new_pass: Entity<SecretInput>,
    pub restore_new_pass2: Entity<SecretInput>,
    pub unlock_pass: Entity<SecretInput>,
    pub unlock_pin: Entity<SecretInput>,
    // --- the unlocked session ---
    pub new_vault_name: Entity<InputState>,
    pub vault_search: Entity<InputState>,
    pub contact_search: Entity<InputState>,
    pub file_search: Entity<InputState>,
    pub new_folder_name: Entity<InputState>,
    pub new_file_name: Entity<InputState>,
    pub rename: Entity<InputState>,
    pub contact_paste: Entity<TextareaState>,
    pub verify_input: Entity<InputState>,
    pub editor: Entity<TextareaState>,
    pub passkey_label: Entity<InputState>,
    pub passkey_pass: Entity<SecretInput>,
    pub passkey_pin: Entity<SecretInput>,
    pub autounlock_pass: Entity<SecretInput>,
    pub export_id_pass: Entity<SecretInput>,
    pub export_id_pass2: Entity<SecretInput>,
    #[cfg(feature = "pqc")]
    pub migrate_pass: Entity<SecretInput>,
    #[cfg(feature = "net")]
    pub recv_port: Entity<InputState>,
    #[cfg(feature = "net")]
    pub send_host: Entity<InputState>,
    #[cfg(feature = "net")]
    pub send_port: Entity<InputState>,
    #[cfg(feature = "net")]
    pub send_pairing: Entity<InputState>,
}

fn input(
    placeholder: &'static str,
    window: &mut Window,
    cx: &mut Context<FileSecApp>,
) -> Entity<InputState> {
    cx.new(|cx| InputState::new(window, cx).placeholder(placeholder))
}

fn textarea(
    placeholder: &'static str,
    rows: usize,
    window: &mut Window,
    cx: &mut Context<FileSecApp>,
) -> Entity<TextareaState> {
    cx.new(|cx| {
        TextareaState::new(window, cx)
            .placeholder(placeholder)
            .rows(rows)
    })
}

fn secret(placeholder: &'static str, cx: &mut Context<FileSecApp>) -> Entity<SecretInput> {
    cx.new(|cx| SecretInput::new(placeholder, cx))
}

impl Fields {
    pub fn new(window: &mut Window, cx: &mut Context<FileSecApp>) -> Self {
        Self {
            anchor_pass: secret("Passphrase", cx),
            first_name: input("e.g. Alice", window, cx),
            first_pass: secret(super::PASSPHRASE_HINT, cx),
            first_pass2: secret("Repeat passphrase", cx),
            restore_backup_pass: secret("Passphrase that protects the backup", cx),
            restore_new_pass: secret(super::PASSPHRASE_HINT, cx),
            restore_new_pass2: secret("Repeat new passphrase", cx),
            unlock_pass: secret("Enter your passphrase", cx),
            unlock_pin: secret("Security-key PIN (if set)", cx),
            new_vault_name: input("e.g. Personal documents", window, cx),
            vault_search: input("Find a vault…", window, cx),
            contact_search: input("Find a contact by name or fingerprint…", window, cx),
            file_search: input("Search all files…", window, cx),
            new_folder_name: input("Folder name", window, cx),
            new_file_name: input("Name with extension, e.g. notes.txt", window, cx),
            rename: input("New name", window, cx),
            contact_paste: textarea("-----BEGIN FILESEC PUBLIC KEY-----", 3, window, cx),
            verify_input: input("e.g. ABCD-EFGH-…", window, cx),
            editor: textarea("", 16, window, cx),
            passkey_label: input("e.g. YubiKey 5C", window, cx),
            passkey_pass: secret("authorizes the change", cx),
            passkey_pin: secret("your key's PIN, if it uses one", cx),
            autounlock_pass: secret("Passphrase", cx),
            export_id_pass: secret(super::PASSPHRASE_HINT, cx),
            export_id_pass2: secret("Repeat passphrase", cx),
            #[cfg(feature = "pqc")]
            migrate_pass: secret("Current passphrase", cx),
            #[cfg(feature = "net")]
            recv_port: input("auto", window, cx),
            #[cfg(feature = "net")]
            send_host: input("IP or hostname", window, cx),
            #[cfg(feature = "net")]
            send_port: input("port", window, cx),
            #[cfg(feature = "net")]
            send_pairing: input("e.g. ABCD-EFGH-JKMN-…", window, cx),
        }
    }

    /// Route every field's events to the app. The returned subscriptions must
    /// be kept alive for as long as the app.
    pub fn subscribe(
        &self,
        window: &mut Window,
        cx: &mut Context<FileSecApp>,
    ) -> Vec<Subscription> {
        let mut subs = Vec::new();
        let mut text = |entity: &Entity<InputState>, id: FieldId, subs: &mut Vec<Subscription>| {
            subs.push(cx.subscribe_in(
                entity,
                window,
                move |this: &mut FileSecApp, _, event: &InputEvent, window, cx| match event {
                    InputEvent::Change => this.on_field_changed(id, window, cx),
                    InputEvent::PressEnter { .. } => this.on_field_submit(id, window, cx),
                    _ => {}
                },
            ));
        };
        text(&self.first_name, FieldId::FirstName, &mut subs);
        text(&self.new_vault_name, FieldId::NewVaultName, &mut subs);
        text(&self.vault_search, FieldId::VaultSearch, &mut subs);
        text(&self.contact_search, FieldId::ContactSearch, &mut subs);
        text(&self.file_search, FieldId::FileSearch, &mut subs);
        text(&self.new_folder_name, FieldId::NewFolderName, &mut subs);
        text(&self.new_file_name, FieldId::NewFileName, &mut subs);
        text(&self.rename, FieldId::Rename, &mut subs);
        text(&self.verify_input, FieldId::VerifyInput, &mut subs);
        text(&self.passkey_label, FieldId::PasskeyLabel, &mut subs);
        #[cfg(feature = "net")]
        {
            text(&self.recv_port, FieldId::RecvPort, &mut subs);
            text(&self.send_host, FieldId::SendHost, &mut subs);
            text(&self.send_port, FieldId::SendPort, &mut subs);
            text(&self.send_pairing, FieldId::SendPairing, &mut subs);
        }
        let mut area =
            |entity: &Entity<TextareaState>, id: FieldId, subs: &mut Vec<Subscription>| {
                subs.push(cx.subscribe_in(
                    entity,
                    window,
                    move |this: &mut FileSecApp, _, event: &InputEvent, window, cx| {
                        if matches!(event, InputEvent::Change) {
                            this.on_field_changed(id, window, cx);
                        }
                    },
                ));
            };
        area(&self.contact_paste, FieldId::ContactPaste, &mut subs);
        area(&self.editor, FieldId::Editor, &mut subs);
        let mut secret = |entity: &Entity<SecretInput>,
                          id: FieldId,
                          subs: &mut Vec<Subscription>| {
            subs.push(cx.subscribe_in(
                entity,
                window,
                move |this: &mut FileSecApp, _, event: &SecretInputEvent, window, cx| match event {
                    SecretInputEvent::Changed => this.on_field_changed(id, window, cx),
                    SecretInputEvent::Submit => this.on_field_submit(id, window, cx),
                },
            ));
        };
        secret(&self.anchor_pass, FieldId::AnchorPass, &mut subs);
        secret(&self.first_pass, FieldId::FirstPass, &mut subs);
        secret(&self.first_pass2, FieldId::FirstPass2, &mut subs);
        secret(
            &self.restore_backup_pass,
            FieldId::RestoreBackupPass,
            &mut subs,
        );
        secret(&self.restore_new_pass, FieldId::RestoreNewPass, &mut subs);
        secret(&self.restore_new_pass2, FieldId::RestoreNewPass2, &mut subs);
        secret(&self.unlock_pass, FieldId::UnlockPass, &mut subs);
        secret(&self.unlock_pin, FieldId::UnlockPin, &mut subs);
        secret(&self.passkey_pass, FieldId::PasskeyPass, &mut subs);
        secret(&self.passkey_pin, FieldId::PasskeyPin, &mut subs);
        secret(&self.autounlock_pass, FieldId::AutoUnlockPass, &mut subs);
        secret(&self.export_id_pass, FieldId::ExportIdPass, &mut subs);
        secret(&self.export_id_pass2, FieldId::ExportIdPass2, &mut subs);
        #[cfg(feature = "pqc")]
        secret(&self.migrate_pass, FieldId::MigratePass, &mut subs);
        subs
    }
}

/// The trimmed-or-not text of a plain input.
pub(super) fn value(entity: &Entity<InputState>, cx: &gpui_kit::App) -> SharedString {
    entity.read(cx).value()
}

/// Empty a plain input if it holds anything (no event, no history).
pub(super) fn clear(entity: &Entity<InputState>, window: &mut Window, cx: &mut gpui_kit::App) {
    if !entity.read(cx).value().is_empty() {
        entity.update(cx, |s, cx| s.set_value("", window, cx));
    }
}

/// Replace a plain input's text.
pub(super) fn set(
    entity: &Entity<InputState>,
    text: &str,
    window: &mut Window,
    cx: &mut gpui_kit::App,
) {
    let text = text.to_string();
    entity.update(cx, |s, cx| s.set_value(text, window, cx));
}

/// Empty a textarea if it holds anything.
pub(super) fn clear_area(
    entity: &Entity<TextareaState>,
    window: &mut Window,
    cx: &mut gpui_kit::App,
) {
    if !entity.read(cx).value().is_empty() {
        entity.update(cx, |s, cx| s.set_value("", window, cx));
    }
}

/// Wipe a secret field in place.
pub(super) fn wipe(entity: &Entity<SecretInput>, cx: &mut gpui_kit::App) {
    if !entity.read(cx).is_empty() {
        entity.update(cx, |s, cx| s.clear(cx));
    }
}
