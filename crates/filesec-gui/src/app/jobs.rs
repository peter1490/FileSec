//! The background jobs behind each action: validation on the UI thread, then
//! the crypto and disk work on a worker thread (see [`FileSecApp::spawn_job`]).
//! Native file dialogs are opened by the `begin_*` half of a job; the picked
//! path comes back as a continuation action handled by the `*_to` half.

use std::collections::HashSet;
use std::path::PathBuf;

use gpui_kit::{Context, Window};
use zeroize::Zeroizing;

use filesec_core::contacts::{ContactBook, Trust, UpsertOutcome};
use filesec_core::format::{self, ExportOptions};
use filesec_core::format_v2::{is_trashed, VaultReaderV2, TRASH_DIR};
use filesec_core::identity::{Identity, PublicIdentity};
use filesec_core::kdf::KdfParams;
use filesec_core::keystore::{KeystoreFile, HMAC_SECRET_LEN};
use filesec_core::manifest::EntryKind;
use filesec_core::util::{hex, now_unix};
use filesec_core::vault::Vault;

use crate::autounlock;
use crate::passkey;
#[cfg(feature = "pqc")]
use crate::store::MIGRATION_RESUME_PENDING;
use crate::store::{new_vault_id, write_private_export, Registry, Store, StoreResult, VaultMeta};

use super::fields;
use super::model::*;
use super::*;

impl FileSecApp {
    pub(super) fn spawn_create_identity(&mut self, cx: &mut Context<Self>) {
        let name = fields::value(&self.fields.first_name, cx)
            .trim()
            .to_string();
        let policy = passphrase_policy_error(self.fields.first_pass.read(cx).value());
        let matches =
            self.fields.first_pass.read(cx).value() == self.fields.first_pass2.read(cx).value();
        {
            let f = match &mut self.state {
                State::FirstRun(f) => f,
                _ => return,
            };
            if name.is_empty() {
                f.error = Some("Please enter a display name.".into());
                return;
            }
            if let Some(error) = policy {
                f.error = Some(error);
                return;
            }
            if !matches {
                f.error = Some("Passphrases do not match.".into());
                return;
            }
            f.error = None;
        }
        fields::wipe(&self.fields.first_pass2, cx);
        // Move the passphrase into a zeroizing buffer so it is wiped after the
        // worker hands it to the keystore, not just dropped.
        let pass = self.fields.first_pass.update(cx, |p, cx| p.take(cx));
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        self.spawn_job(cx, "Creating identity…", move || {
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

    pub(super) fn spawn_unlock(&mut self, cx: &mut Context<Self>) {
        let legacy_recovery = match &mut self.state {
            State::Unlock(u) => {
                u.error = None;
                u.legacy_recovery
            }
            _ => return,
        };
        // Wiped after the worker uses it (see `spawn_create_identity`).
        let pass = self.fields.unlock_pass.update(cx, |p, cx| p.take(cx));
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        let label = if legacy_recovery {
            "Recovering and upgrading local state…"
        } else {
            "Unlocking…"
        };
        self.spawn_job(cx, label, move || {
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
            if let Err(e) = store.confirm_unlocked_keystore(&ks, &identity) {
                return JobReport {
                    outcome: Outcome::UnlockFailed(e),
                    toast: None,
                };
            }
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
            // drop interrupted scratch dirs, and reconcile the vault list.
            let (registry, repair_note) = finish_unlock(&store, &identity, registry);
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
                with_note(
                    if legacy_recovery {
                        "Legacy local state recovered and upgraded with rollback protection."
                    } else {
                        "Unlocked."
                    },
                    &repair_note,
                ),
            )
        });
    }

    /// Re-establish rollback anchors from the current, passphrase-authenticated
    /// on-disk state. Only reachable from the [`State::AnchorRecovery`] screen,
    /// after the user explicitly confirmed this directory is the copy to keep.
    pub(super) fn spawn_recover_anchors(&mut self, cx: &mut Context<Self>) {
        let empty = self.fields.anchor_pass.read(cx).is_empty();
        match &mut self.state {
            State::AnchorRecovery(r) => {
                r.error = None;
                if !r.confirmed {
                    r.error = Some(
                        "Confirm that this data directory is the copy you intend to keep.".into(),
                    );
                    return;
                }
                if empty {
                    r.error = Some("Enter your passphrase.".into());
                    return;
                }
            }
            _ => return,
        }
        let pass = self.fields.anchor_pass.update(cx, |p, cx| p.take(cx));
        self.spawn_job(cx, "Re-establishing rollback protection…", move || {
            let result = Store::default_data_dir().and_then(|dir| {
                Store::recover_rollback_anchors(
                    dir,
                    crate::anchors::platform_storage(),
                    pass.as_bytes(),
                )
            });
            match result {
                Ok(store) => JobReport::ok(
                    Outcome::AnchorsRecovered(Box::new(store)),
                    "Rollback protection re-established from the current local state.",
                ),
                Err(e) => JobReport {
                    outcome: Outcome::AnchorRecoveryFailed(e),
                    toast: None,
                },
            }
        });
    }

    /// Unlock by deriving a key from an enrolled security key (passkey). Tries
    /// each enrolled slot against the connected key; the first that the present
    /// authenticator satisfies opens the keystore.
    pub(super) fn spawn_unlock_passkey(&mut self, cx: &mut Context<Self>) {
        match &mut self.state {
            State::Unlock(u) => u.error = None,
            _ => return,
        }
        let pin = {
            let pin = Zeroizing::new(self.fields.unlock_pin.read(cx).value().trim().to_string());
            (!pin.is_empty()).then_some(pin)
        };
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        self.spawn_job(cx, "Waiting for your security key…", move || {
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
                        if let Err(e) = store.confirm_unlocked_keystore(&ks, &identity) {
                            return JobReport {
                                outcome: Outcome::UnlockFailed(e),
                                toast: None,
                            };
                        }
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
                        let (registry, repair_note) = finish_unlock(&store, &identity, registry);
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
                            with_note("Unlocked with your security key.", &repair_note),
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
    pub(super) fn spawn_add_passkey(&mut self, cx: &mut Context<Self>) {
        let label = fields::value(&self.fields.passkey_label, cx)
            .trim()
            .to_string();
        let pass_empty = self.fields.passkey_pass.read(cx).is_empty();
        match &mut self.state {
            State::Unlocked(s) => match &mut s.add_passkey {
                Some(f) => {
                    if label.is_empty() {
                        f.error = Some("Give this key a name so you can recognize it.".into());
                        return;
                    }
                    if pass_empty {
                        f.error = Some("Enter your passphrase to authorize this change.".into());
                        return;
                    }
                    f.error = None;
                }
                None => return,
            },
            _ => return,
        }
        let pin = {
            let pin = Zeroizing::new(self.fields.passkey_pin.read(cx).value().trim().to_string());
            (!pin.is_empty()).then_some(pin)
        };
        let pass = self.fields.passkey_pass.update(cx, |p, cx| p.take(cx));
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        self.spawn_job(
            cx,
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
    pub(super) fn spawn_remove_passkey(&mut self, cx: &mut Context<Self>, index: usize) {
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        let identity = match self.ident_arc() {
            Some(identity) => identity,
            None => return,
        };
        self.spawn_job(cx, "Removing security key…", move || {
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
    pub(super) fn spawn_unlock_keyring(&mut self, cx: &mut Context<Self>) {
        if let State::Unlock(u) = &mut self.state {
            u.error = None;
        }
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        self.spawn_job(cx, "Unlocking from this device…", move || {
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
            if let Err(e) = store.confirm_unlocked_keystore(&ks, &identity) {
                return JobReport {
                    outcome: Outcome::UnlockFailed(e),
                    toast: None,
                };
            }
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
            let (registry, repair_note) = finish_unlock(&store, &identity, registry);
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
                with_note("Unlocked from this device.", &repair_note),
            )
        });
    }

    /// Verify the entered passphrase, then enroll a random device token: it wraps
    /// the keystore's data key in a device keyslot and is saved to the OS
    /// keychain. The passphrase itself is never stored (F09).
    pub(super) fn spawn_enable_auto_unlock(&mut self, cx: &mut Context<Self>) {
        let empty = self.fields.autounlock_pass.read(cx).is_empty();
        match &mut self.state {
            State::Unlocked(s) => match &mut s.auto_unlock_form {
                Some(f) => {
                    if empty {
                        f.error = Some("Enter your passphrase to confirm.".into());
                        return;
                    }
                    f.error = None;
                }
                None => return,
            },
            _ => return,
        }
        // Wiped after the worker uses it (see `spawn_create_identity`).
        let pass = self.fields.autounlock_pass.update(cx, |p, cx| p.take(cx));
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        self.spawn_job(cx, "Saving to this device…", move || {
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
    pub(super) fn spawn_disable_auto_unlock(&mut self, cx: &mut Context<Self>) {
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        let identity = match self.ident_arc() {
            Some(i) => i,
            None => return,
        };
        self.spawn_job(cx, "Updating this device…", move || {
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

    pub(super) fn spawn_create_vault(&mut self, cx: &mut Context<Self>) {
        let name = fields::value(&self.fields.new_vault_name, cx)
            .trim()
            .to_string();
        let registry = match &self.state {
            State::Unlocked(s) => s.registry.clone(),
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
        self.spawn_job(cx, "Creating vault…", move || {
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
                return JobReport::err(format!(
                    "The vault was created but the vault list could not be updated ({e}). \
                     It will be recovered automatically the next time you unlock."
                ));
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

    pub(super) fn spawn_open_vault(&mut self, cx: &mut Context<Self>, id: String) {
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        self.spawn_job(cx, "Opening vault…", move || {
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

    pub(super) fn spawn_delete_vault(&mut self, cx: &mut Context<Self>, id: String) {
        let registry = match &self.state {
            State::Unlocked(s) => s.registry.clone(),
            _ => return,
        };
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        self.spawn_job(cx, "Deleting vault…", move || {
            // Tombstone → registry commit → retire: a failure leaves the vault
            // intact and listed; an interruption is finished on the next unlock.
            let registry = match store.delete_vault(&identity, &registry, &id) {
                Ok(registry) => registry,
                Err(e) => return JobReport::err(format!("The vault was not deleted: {e}")),
            };
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
    pub(super) fn current_dir(&self) -> String {
        if let State::Unlocked(s) = &self.state {
            s.current_dir.clone()
        } else {
            String::new()
        }
    }

    /// Shared core for adding OS files/folders into the open vault at the current
    /// folder — used by "Add files…", "Add folder…", and drag-and-drop. Each
    /// source streams straight from disk; nothing is held in memory at once.
    pub(super) fn add_sources(&mut self, cx: &mut Context<Self>, sources: Vec<PathBuf>) {
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
        self.spawn_job(cx, "Encrypting…", move || {
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
                format!(" to {}", shown(leaf_name(&into)))
            };
            let msg = if failed > 0 {
                format!("Added {n} file(s){dest}; {failed} could not be read.")
            } else {
                format!("Added {n} file(s){dest}.")
            };
            finalize_after_save(&store, &identity, id, registry, msg)
        });
    }

    pub(super) fn spawn_new_folder(&mut self, cx: &mut Context<Self>) {
        let leaf = fields::value(&self.fields.new_folder_name, cx)
            .trim()
            .to_string();
        let into = match &self.state {
            State::Unlocked(s) => s.current_dir.clone(),
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
        self.spawn_job(cx, "Saving…", move || {
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
    pub(super) fn spawn_new_file(&mut self, cx: &mut Context<Self>) {
        let leaf = fields::value(&self.fields.new_file_name, cx)
            .trim()
            .to_string();
        let into = match &self.state {
            State::Unlocked(s) => s.current_dir.clone(),
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
        self.spawn_job(cx, "Creating…", move || {
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
    pub(super) fn spawn_quick_edit(&mut self, cx: &mut Context<Self>, path: String) {
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
        self.spawn_job(cx, "Opening…", move || {
            let bytes = match reader.read_entry(&path) {
                Ok(b) => b,
                Err(e) => return JobReport::err(e.to_string()),
            };
            let bytes = Zeroizing::new(bytes);
            match std::str::from_utf8(&bytes) {
                Ok(text) => JobReport::ok(
                    Outcome::OpenTextEditor(Box::new(LoadedText {
                        path,
                        leaf,
                        text: Zeroizing::new(text.to_string()),
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
    pub(super) fn spawn_save_text_file(&mut self, cx: &mut Context<Self>) {
        // The worker's copy of the plaintext is wiped when the job ends, like the
        // editor's own buffers (hygiene; live-memory attackers are out of scope).
        let path = match &self.state {
            State::Unlocked(s) => match &s.text_editor {
                Some(te) => te.path.clone(),
                None => return,
            },
            _ => return,
        };
        let content = Zeroizing::new(self.fields.editor.read(cx).value().to_string());
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        let leaf = leaf_name(&path).to_string();
        self.spawn_job(cx, "Saving…", move || {
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
    pub(super) fn spawn_trash_selected(&mut self, cx: &mut Context<Self>) {
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
        self.spawn_job(cx, "Moving to Trash…", move || {
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
    /// Validate the selection, then ask where to extract it.
    pub(super) fn begin_extract_selected(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.extract_selection_paths().is_none() {
            return;
        }
        self.pick_paths(
            open_folder("Extract the selection to…"),
            window,
            cx,
            |paths| paths.into_iter().next().map(Action::ExtractSelectedTo),
        );
    }

    /// The selected files, with folders expanded into the files they contain,
    /// or `None` (after a toast) when there is nothing to extract.
    fn extract_selection_paths(&mut self) -> Option<(VaultReaderV2, Vec<String>)> {
        let selected: Vec<String> = match &self.state {
            State::Unlocked(s) => s.selected.iter().cloned().collect(),
            _ => return None,
        };
        if selected.is_empty() {
            self.set_toast("Select something to extract first.", true);
            return None;
        }
        let (_, reader) = self.open_reader()?;
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
            return None;
        }
        Some((reader, paths))
    }

    /// Decrypt the selection into `dest`, recreating each file's vault-relative
    /// path underneath it.
    pub(super) fn spawn_extract_selected(&mut self, cx: &mut Context<Self>, dest: PathBuf) {
        let Some((reader, paths)) = self.extract_selection_paths() else {
            return;
        };
        let n = paths.len();
        self.spawn_job(cx, "Decrypting…", move || {
            // Nothing is written if two selected files would land on one file
            // (case/Unicode aliases) or would replace a file already there.
            if let Err(e) = filesec_core::vault::preflight_extraction(
                &dest,
                paths.iter().map(|p| (p.as_str(), EntryKind::File)),
            ) {
                return JobReport::err(format!(
                    "Nothing was extracted: {e}. Rename the entries or pick an empty folder."
                ));
            }
            let total: u64 = reader
                .entries()
                .iter()
                .filter(|e| paths.binary_search(&e.path).is_ok())
                .map(|e| e.size)
                .sum();
            if let Err(e) = crate::store::ensure_free_space(&dest, total, "extracting these files")
            {
                return JobReport::err(format!("Nothing was extracted: {e}."));
            }
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
    pub(super) fn spawn_trash_entry(&mut self, cx: &mut Context<Self>, path: String) {
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
        self.spawn_job(cx, "Moving to Trash…", move || {
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
    pub(super) fn spawn_restore(&mut self, cx: &mut Context<Self>, trashed_path: String) {
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
        self.spawn_job(cx, "Restoring…", move || {
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
    pub(super) fn spawn_purge(&mut self, cx: &mut Context<Self>, trashed_path: String) {
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let (id, reader, registry) = match self.open_ctx() {
            Some(x) => x,
            None => return,
        };
        self.spawn_job(cx, "Deleting…", move || {
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
    pub(super) fn spawn_empty_trash(&mut self, cx: &mut Context<Self>) {
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
        self.spawn_job(cx, "Emptying Trash…", move || {
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
    pub(super) fn spawn_rename(&mut self, cx: &mut Context<Self>) {
        let leaf = fields::value(&self.fields.rename, cx).trim().to_string();
        let from = match &self.state {
            State::Unlocked(s) => match &s.rename_target {
                Some(p) => p.clone(),
                None => return,
            },
            _ => return,
        };
        // Close the composer up front; validation errors surface as a toast.
        if let State::Unlocked(s) = &mut self.state {
            s.rename_target = None;
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
        self.spawn_job(cx, "Renaming…", move || {
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
    pub(super) fn spawn_move(&mut self, cx: &mut Context<Self>) {
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
        self.spawn_job(cx, "Moving…", move || {
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
                        shown(leaf_name(from))
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
                format!("“{}”", shown(leaf_name(&dest)))
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

    pub(super) fn spawn_extract_all(&mut self, cx: &mut Context<Self>, dest: PathBuf) {
        let (_, reader) = match self.open_reader() {
            Some(x) => x,
            None => return,
        };
        self.spawn_job(cx, "Decrypting…", move || {
            // Extract the live tree only — soft-deleted files stay in the trash
            // and are never written to disk (matching what "Send…" exports).
            let live: Vec<(String, EntryKind)> = snapshot_entries(&reader)
                .into_iter()
                .filter(|(path, _, _)| !is_trashed(path))
                .map(|(path, kind, _)| (path, kind))
                .collect();
            // Nothing is written if two entries would land on one file
            // (case/Unicode aliases) or would replace a file already there.
            if let Err(e) = filesec_core::vault::preflight_extraction(
                &dest,
                live.iter().map(|(p, k)| (p.as_str(), *k)),
            ) {
                return JobReport::err(format!(
                    "Nothing was extracted: {e}. Rename the entries or pick an empty folder."
                ));
            }
            let total: u64 = reader
                .entries()
                .iter()
                .filter(|e| e.kind == EntryKind::File && !is_trashed(&e.path))
                .map(|e| e.size)
                .sum();
            if let Err(e) = crate::store::ensure_free_space(&dest, total, "extracting this vault") {
                return JobReport::err(format!("Nothing was extracted: {e}."));
            }
            let mut failed = 0usize;
            let mut files = 0usize;
            for (path, kind) in live {
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

    /// Check the entry is a file (metadata only), then ask where to save it.
    pub(super) fn begin_save_entry_as(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
        path: String,
    ) {
        if !self.entry_is_saveable(&path) {
            return;
        }
        let suggested = path.rsplit('/').next().unwrap_or("file").to_string();
        self.pick_save(
            &suggested,
            None,
            window,
            cx,
            move |target| Action::SaveEntryTo(path, target),
            None,
        );
    }

    fn entry_is_saveable(&mut self, path: &str) -> bool {
        // Validate the entry kind from metadata (no decryption) on the UI thread.
        let kind = match &self.state {
            State::Unlocked(s) => match &s.open {
                Some(o) => o
                    .reader
                    .entries()
                    .iter()
                    .find(|e| e.path == path)
                    .map(|e| e.kind),
                None => return false,
            },
            _ => return false,
        };
        match kind {
            Some(EntryKind::File) => true,
            Some(EntryKind::Dir) => {
                self.set_toast("Only files can be saved.", true);
                false
            }
            None => {
                self.set_toast("Entry not found.", true);
                false
            }
        }
    }

    /// Decrypt one entry to the picked `target`.
    pub(super) fn spawn_save_entry_to(
        &mut self,
        cx: &mut Context<Self>,
        path: String,
        target: PathBuf,
    ) {
        if !self.entry_is_saveable(&path) {
            return;
        }
        let (_, reader) = match self.open_reader() {
            Some(x) => x,
            None => return,
        };
        self.spawn_job(cx, "Decrypting file…", move || {
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
    pub(super) fn spawn_view(&mut self, cx: &mut Context<Self>, path: String) {
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
        let wiper = self.wiper.handle();
        let view_repaint = self.repaint.clone();
        self.spawn_job(cx, "Opening…", move || {
            // Decrypt the one file into a private temp, then drop it to read-only.
            // The temp is named `<random>.<ext>` — never the vault's own filename.
            let size = reader
                .entries()
                .iter()
                .find(|e| e.path == path)
                .map_or(0, |e| e.size);
            if let Err(e) =
                crate::store::ensure_free_space(store.checkout_dir(), size, "opening this file")
            {
                return JobReport::err(e);
            }
            let temp_path = match store.create_private_checkout_file(&leaf) {
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
            let msg = match start_view(&temp_path, &wiper, &view_repaint) {
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
    pub(super) fn spawn_check_out(&mut self, cx: &mut Context<Self>, path: String) {
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
        self.spawn_job(cx, "Checking out…", move || {
            // Create the private (0600-from-creation) temp file, then stream the
            // one file's plaintext into it. Wipe on any failure so no partial
            // plaintext is left behind. The temp is named `<random>.<ext>`, so the
            // editor's title bar and the OS recent-items list never see the real
            // name — the in-app banner is where you see what you are editing.
            let size = reader
                .entries()
                .iter()
                .find(|e| e.path == path)
                .map_or(0, |e| e.size);
            if let Err(e) =
                crate::store::ensure_free_space(store.checkout_dir(), size, "editing this file")
            {
                return JobReport::err(e);
            }
            let temp_path = match store.create_private_checkout_file(&leaf) {
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
    pub(super) fn spawn_check_in(&mut self, cx: &mut Context<Self>) {
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
        self.spawn_job(cx, "Checking in…", move || {
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
    pub(super) fn spawn_discard(&mut self, cx: &mut Context<Self>) {
        let temp_path = match &self.state {
            State::Unlocked(s) => match &s.checkout {
                Some(c) => c.temp_path.clone(),
                None => return,
            },
            _ => return,
        };
        self.spawn_job(cx, "Discarding…", move || {
            let _ = crate::store::secure_wipe(&temp_path);
            JobReport::ok(Outcome::EndCheckout { replace: None }, "Edit discarded.")
        });
    }

    pub(super) fn spawn_import(&mut self, cx: &mut Context<Self>, path: PathBuf) {
        let registry = match &self.state {
            State::Unlocked(s) => s.registry.clone(),
            _ => return,
        };
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        self.spawn_job(cx, "Verifying & decrypting…", move || {
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
                return JobReport::err(format!(
                    "The vault was imported but the vault list could not be updated ({e}). \
                     It will be recovered automatically the next time you unlock."
                ));
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

    /// Validate the open export dialog, then ask where to save the container.
    pub(super) fn begin_export(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some((_, _, name, _)) = self.gather_export() else {
            return;
        };
        let suggested = format!("{}.fsec", sanitize_filename(&name));
        self.pick_save(&suggested, Some("fsec"), window, cx, Action::ExportTo, None);
    }

    /// The validated export request (vault, recipients, name, suite), or
    /// `None` after a toast explaining what is missing.
    fn gather_export(
        &mut self,
    ) -> Option<(String, Vec<PublicIdentity>, String, filesec_core::SuiteId)> {
        let unconfirmed = match &self.state {
            State::Unlocked(s) => s
                .export
                .as_ref()
                .map(|form| unconfirmed_unverified(form, &s.contacts))
                .unwrap_or_default(),
            _ => return None,
        };
        if !unconfirmed.is_empty() {
            self.set_toast(
                format!(
                    "Confirm each unverified recipient for this export (or verify them first): {}",
                    unconfirmed.join(", ")
                ),
                true,
            );
            return None;
        }
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
        let (vault_id, recipients, name, suite) = gathered?;
        if recipients.is_empty() {
            self.set_toast("Select at least one recipient.", true);
            return None;
        }
        // Hybrid PQC needs every recipient (and the sender) to carry post-quantum
        // keys. Catch it here with a clear message rather than failing mid-export.
        if suite.is_hybrid() && recipients.iter().any(|r| !r.is_hybrid_capable()) {
            self.set_toast(
                "Hybrid PQC requires every recipient to have post-quantum keys. \
                 Ask them to re-share an updated public key, or pick another suite.",
                true,
            );
            return None;
        }
        Some((vault_id, recipients, name, suite))
    }

    /// Encrypt and export the vault to the picked `target`.
    pub(super) fn spawn_export_to(&mut self, cx: &mut Context<Self>, target: PathBuf) {
        let Some((vault_id, recipients, _name, suite)) = self.gather_export() else {
            return;
        };
        if let State::Unlocked(s) = &mut self.state {
            s.export = None;
        }
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let count = recipients.len();
        self.spawn_job(cx, "Encrypting & exporting…", move || {
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
    pub(super) fn spawn_migrate(&mut self, cx: &mut Context<Self>) {
        let empty = self.fields.migrate_pass.read(cx).is_empty();
        let data_dir = if let State::Unlocked(s) = &mut self.state {
            match &mut s.migrate {
                Some(f) if empty => {
                    f.error = Some("Enter your passphrase to confirm.".into());
                    return;
                }
                Some(_) => s.data_dir.clone(),
                None => return,
            }
        } else {
            return;
        };
        let pass = self.fields.migrate_pass.update(cx, |p, cx| p.take(cx));
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        if let State::Unlocked(s) = &mut self.state {
            s.migrate = None;
        }
        self.spawn_job(cx, "Upgrading to post-quantum…", move || {
            let new = match store.migrate_to_hybrid(&identity, pass.as_bytes()) {
                Ok(n) => n,
                Err(e) if e.starts_with(MIGRATION_RESUME_PENDING) => {
                    // Committed: the next launch finishes it before anything
                    // loads. Continuing this session on the old identity would
                    // only show a half-moved store.
                    return JobReport {
                        outcome: Outcome::Fatal(format!(
                            "{e}\n\nNothing was lost. Quit and reopen FileSec to finish the upgrade."
                        )),
                        toast: None,
                    };
                }
                Err(e) if e.contains("incorrect passphrase") => {
                    return JobReport::err(
                        "Incorrect passphrase — nothing was changed. Enter your current passphrase to upgrade.",
                    )
                }
                Err(e) => return JobReport::err(e),
            };
            let passkeys = store
                .load_keystore()
                .map(|ks| ks.passkey_slots())
                .unwrap_or_default();
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
                    // Migration keeps the keystore's data key, so the passphrase,
                    // enrolled security keys, and this device's saved unlock all
                    // carry over unchanged.
                    passkeys,
                    auto_unlock: autounlock::is_saved(&data_dir),
                    data_dir,
                    rollback_warning: store.rollback_protection_warning().map(str::to_string),
                })),
                "Upgraded to post-quantum. Your safety number changed — re-share your \
                 public key so contacts can re-verify it.",
            )
        });
    }

    /// Parse the paste box into a staged [`ContactPreview`] (no disk I/O, so it
    /// runs inline rather than on the worker). The user confirms from the
    /// preview window before anything is saved.
    pub(super) fn preview_contact_paste(&mut self, cx: &mut Context<Self>) {
        if !matches!(self.state, State::Unlocked(_)) {
            return;
        }
        let text = self
            .fields
            .contact_paste
            .read(cx)
            .value()
            .trim()
            .to_string();
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
    pub(super) fn preview_contact_file(&mut self, path: PathBuf) {
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
    pub(super) fn spawn_confirm_add_contact(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
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
        }
        fields::clear_area(&self.fields.contact_paste, window, cx);
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        self.spawn_job(cx, "Saving contact…", move || {
            import_contact_job(&store, &identity, contacts, pubid)
        });
    }

    /// Open the verification dialog for a contact identified by hex fingerprint.
    pub(super) fn begin_verify(&mut self, fpr_hex: String) {
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
                    manual_ok: false,
                });
                // If verification was launched from the import dialog, close it.
                s.last_import = None;
            }
        }
    }

    /// Finish verification: close the dialog and mark the contact verified.
    pub(super) fn confirm_verify(&mut self, cx: &mut Context<Self>, fpr_hex: String) {
        if let State::Unlocked(s) = &mut self.state {
            s.verify = None;
        }
        self.spawn_set_trust(cx, fpr_hex, Trust::Verified);
    }

    pub(super) fn spawn_set_trust(
        &mut self,
        cx: &mut Context<Self>,
        fpr_hex: String,
        trust: Trust,
    ) {
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
        self.spawn_job(cx, "Saving…", move || {
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

    pub(super) fn spawn_remove_contact(&mut self, cx: &mut Context<Self>, fpr_hex: String) {
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
        self.spawn_job(cx, "Saving…", move || {
            let mut contacts = contacts;
            contacts.remove(&fpr);
            match store.save_contacts(&identity, &contacts) {
                Ok(()) => JobReport::ok(Outcome::Contacts(contacts), "Contact removed."),
                Err(e) => JobReport::err(e),
            }
        });
    }

    /// Ask where to save the public key file.
    pub(super) fn begin_save_pubkey(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let name = match &self.state {
            State::Unlocked(s) => s.identity.name.clone(),
            _ => return,
        };
        let suggested = format!("{}.fsecpub", sanitize_filename(&name));
        self.pick_save(
            &suggested,
            Some("fsecpub"),
            window,
            cx,
            Action::SavePubKeyTo,
            None,
        );
    }

    /// Write the public key to the picked `target`.
    pub(super) fn spawn_save_pubkey_to(&mut self, cx: &mut Context<Self>, target: PathBuf) {
        let prepared = if let State::Unlocked(s) = &self.state {
            Some((s.identity.public().to_bytes(), s.identity.name.clone()))
        } else {
            None
        };
        let (bytes_res, _name) = match prepared {
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

        self.spawn_job(cx, "Saving…", move || {
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
    pub(super) fn begin_export_identity(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        // Validate the backup passphrase from the dialog before doing anything.
        if !self.export_identity_valid(cx) {
            return;
        }
        let name = match self.ident_arc() {
            Some(i) => i.name.clone(),
            None => return,
        };
        let suggested = format!("{}.fsecid", sanitize_filename(&name));
        // Backing out of the save dialog closes the export dialog cleanly.
        self.pick_save(
            &suggested,
            Some("fsecid"),
            window,
            cx,
            Action::ExportIdentityTo,
            Some(Action::CancelExportIdentity),
        );
    }

    /// Check the backup passphrase pair, recording the error on the form.
    fn export_identity_valid(&mut self, cx: &mut Context<Self>) -> bool {
        let policy = passphrase_policy_error(self.fields.export_id_pass.read(cx).value());
        let matches = self.fields.export_id_pass.read(cx).value()
            == self.fields.export_id_pass2.read(cx).value();
        match &mut self.state {
            State::Unlocked(s) => match &mut s.export_identity {
                Some(f) => {
                    if let Some(error) = policy {
                        f.error = Some(error);
                        return false;
                    }
                    if !matches {
                        f.error = Some("Passphrases do not match.".into());
                        return false;
                    }
                    f.error = None;
                    true
                }
                None => false,
            },
            _ => false,
        }
    }

    /// Seal the identity under the backup passphrase and write it to `target`.
    pub(super) fn spawn_export_identity_to(&mut self, cx: &mut Context<Self>, target: PathBuf) {
        if !self.export_identity_valid(cx) {
            return;
        }
        let identity = match self.ident_arc() {
            Some(i) => i,
            None => return,
        };
        fields::wipe(&self.fields.export_id_pass2, cx);
        // Wiped after the worker uses it (see `spawn_create_identity`).
        let pass = self.fields.export_id_pass.update(cx, |p, cx| p.take(cx));
        self.spawn_job(cx, "Exporting identity…", move || {
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
    pub(super) fn spawn_restore_identity(&mut self, cx: &mut Context<Self>) {
        let backup_empty = self.fields.restore_backup_pass.read(cx).is_empty();
        let policy = passphrase_policy_error(self.fields.restore_new_pass.read(cx).value());
        let matches = self.fields.restore_new_pass.read(cx).value()
            == self.fields.restore_new_pass2.read(cx).value();
        let path = match &mut self.state {
            State::FirstRun(f) => match &mut f.restore {
                Some(r) => {
                    if backup_empty {
                        r.error = Some("Enter the backup's passphrase.".into());
                        return;
                    }
                    if let Some(error) = policy {
                        r.error = Some(error);
                        return;
                    }
                    if !matches {
                        r.error = Some("New passphrases do not match.".into());
                        return;
                    }
                    r.error = None;
                    r.path.clone()
                }
                None => return,
            },
            _ => return,
        };
        fields::wipe(&self.fields.restore_new_pass2, cx);
        let backup_pass = self
            .fields
            .restore_backup_pass
            .update(cx, |p, cx| p.take(cx));
        let new_pass = self.fields.restore_new_pass.update(cx, |p, cx| p.take(cx));
        let store = match self.store_arc() {
            Some(s) => s,
            None => return,
        };
        self.spawn_job(cx, "Restoring identity…", move || {
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
pub(super) fn reopen_after_save(
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
pub(super) fn finalize_after_save(
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
pub(super) fn import_contact_job(
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
pub(super) fn build_contact_preview(s: &Session, pubid: PublicIdentity) -> ContactPreview {
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

/// Post-unlock housekeeping shared by every unlock path: shred stale checkout
/// temps, drop interrupted scratch directories, and reconcile the registry with
/// the vault directories (FS-11). Returns the registry the session should use
/// and a note about anything that was repaired.
pub(super) fn finish_unlock(
    store: &Store,
    identity: &Identity,
    registry: Registry,
) -> (Registry, String) {
    store.clean_checkout_dir();
    store.clean_partial_dirs();
    match store.reconcile_vaults(identity, registry.clone()) {
        Ok((registry, notes)) => (registry, notes.join(" ")),
        Err(e) => (
            registry,
            format!("Could not check the vault list for interrupted operations: {e}"),
        ),
    }
}

/// `message`, followed by `note` when there is one.
pub(super) fn with_note(message: &str, note: &str) -> String {
    if note.is_empty() {
        message.to_string()
    } else {
        format!("{message} {note}")
    }
}
