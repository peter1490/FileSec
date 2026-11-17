//! The screens before a session exists: fatal start-up error, rollback-anchor
//! recovery, first run (create or restore an identity), and unlock.

use gpui_kit::{div, prelude::*, px, Div, Entity, Pixels, SharedString};

use crate::autounlock;
use crate::passkey;
use crate::secret_input::SecretInput;
use crate::theme::{self, icon, Colors};

use super::{checkbox, labelled, text_input, View};
use crate::app::model::passphrase_policy_error;
use crate::app::{Action, AnchorRecovery, FirstRun, Unlock};

/// A scrolling page with a centred column of at most `max_w`.
fn centered(id: &'static str, max_w: Pixels, top: Pixels, body: Div) -> impl IntoElement {
    super::page_scroll(id).items_center().child(
        div()
            .w_full()
            .max_w(max_w)
            .pt(top)
            .pb(px(24.0))
            .flex()
            .flex_col()
            .items_center()
            .gap(px(6.0))
            .child(body),
    )
}

fn hero(glyph: &'static str, color: gpui_kit::Hsla, title: &'static str, c: Colors) -> Div {
    div()
        .w_full()
        .flex()
        .flex_col()
        .items_center()
        .gap(px(6.0))
        .child(theme::icon_text(glyph, 40.0, color))
        .child(theme::strong(title, theme::TEXT_HEADING, c.text))
}

fn error_text(e: &str, c: Colors) -> Div {
    theme::text(e.to_string(), c.err).w_full()
}

pub(in crate::app) fn fatal(msg: &str, v: &View) -> impl IntoElement {
    let c = v.c;
    div()
        .w_full()
        .pt(px(40.0))
        .flex()
        .flex_col()
        .items_center()
        .gap(px(8.0))
        .child(theme::strong(
            "FileSec could not start",
            theme::TEXT_HEADING,
            c.text,
        ))
        .child(
            theme::text(msg.to_string(), c.err)
                .text_center()
                .max_w(px(560.0)),
        )
}

pub(in crate::app) fn anchor_recovery(r: &AnchorRecovery, v: &View) -> impl IntoElement {
    let c = v.c;
    let ready = r.confirmed && !v.fields.anchor_pass.read(v.cx).is_empty();
    let card = theme::card(c)
        .child(theme::text(r.reason.clone(), c.err))
        .child(theme::text(
            "FileSec keeps a record of the newest version of your keystore, contacts, \
             registry, and vaults outside this data directory, so an older copy cannot \
             be swapped in unnoticed. That record could not be trusted as found.\n\n\
             If you did not expect this (no keychain reset, no move to a new machine), \
             stop here and check where this data directory came from. Recovering trusts \
             the files on disk now as the newest state: an older copy recovered here \
             becomes the new reference point. Nothing is deleted or re-encrypted.",
            c.text_muted,
        ))
        .child(checkbox(
            "anchor-confirm",
            "This data directory is the current copy I intend to keep",
            r.confirmed,
            v.on_check(Action::SetAnchorConfirmed),
        ))
        .child(v.fields.anchor_pass.clone())
        .child(
            theme::enabled(
                theme::primary_button_full("anchor-recover", "Re-establish rollback protection"),
                ready,
            )
            .on_click(v.on(Action::RecoverAnchors)),
        )
        .children(r.error.as_deref().map(|e| error_text(e, c)));
    centered(
        "anchor-recovery",
        px(480.0),
        px(20.0),
        div()
            .w_full()
            .flex()
            .flex_col()
            .gap(px(12.0))
            .child(hero(
                icon::LOCK_KEY,
                c.warn,
                "Rollback protection needs attention",
                c,
            ))
            .child(card),
    )
}

/// Live guidance under a new passphrase.
fn passphrase_feedback(pass: &Entity<SecretInput>, v: &View) -> Div {
    let c = v.c;
    let pass = pass.read(v.cx).value();
    let (message, color): (SharedString, _) = if pass.is_empty() {
        (
            "Use at least 12 characters. Several unrelated words work well.".into(),
            c.text_muted,
        )
    } else if let Some(error) = passphrase_policy_error(pass) {
        (error.into(), c.warn)
    } else {
        ("Passphrase meets the requirements.".into(), c.ok)
    };
    theme::small(message, color).w_full()
}

/// "Passphrases match" / "do not match yet" under a confirmation field.
fn passphrase_match_feedback(
    pass: &Entity<SecretInput>,
    confirmation: &Entity<SecretInput>,
    v: &View,
) -> Option<Div> {
    let c = v.c;
    let confirm = confirmation.read(v.cx).value();
    if confirm.is_empty() {
        return None;
    }
    let (text, color) = if pass.read(v.cx).value() == confirm {
        ("Passphrases match.", c.ok)
    } else {
        ("Passphrases do not match yet.", c.warn)
    };
    Some(theme::small(text, color))
}

pub(in crate::app) fn first_run(f: &FirstRun, v: &View) -> impl IntoElement {
    let c = v.c;
    let fl = v.fields;
    let card =
        match &f.restore {
            // Restore-from-backup flow: a `.fsecid` file has been picked.
            Some(r) => {
                let name = r
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| r.path.display().to_string());
                let new_pass = fl.restore_new_pass.read(v.cx).value();
                let ready = !fl.restore_backup_pass.read(v.cx).is_empty()
                    && passphrase_policy_error(new_pass).is_none()
                    && new_pass == fl.restore_new_pass2.read(v.cx).value();
                theme::card(c)
                    .child(theme::strong("Restore from a backup", px(16.0), c.text))
                    .child(theme::muted(format!("Restoring from {name}"), c))
                    .child(labelled(
                        "Backup passphrase",
                        fl.restore_backup_pass.clone(),
                        c,
                    ))
                    .child(labelled(
                        "New passphrase for this device",
                        fl.restore_new_pass.clone(),
                        c,
                    ))
                    .child(passphrase_feedback(&fl.restore_new_pass, v))
                    .child(labelled(
                        "Confirm new passphrase",
                        fl.restore_new_pass2.clone(),
                        c,
                    ))
                    .children(passphrase_match_feedback(
                        &fl.restore_new_pass,
                        &fl.restore_new_pass2,
                        v,
                    ))
                    .children(r.error.as_deref().map(|e| error_text(e, c)))
                    .child(
                        theme::enabled(
                            theme::primary_button_full("restore-identity", "Restore identity"),
                            ready,
                        )
                        .on_click(v.on(Action::DoRestore)),
                    )
                    .child(
                        theme::secondary_button_full("restore-cancel", "Cancel")
                            .on_click(v.on(Action::CancelRestore)),
                    )
                    .into_any_element()
            }
            // Default: create a brand-new identity.
            None => {
                let pass = fl.first_pass.read(v.cx).value();
                let ready = !v.text(&fl.first_name).trim().is_empty()
                    && passphrase_policy_error(pass).is_none()
                    && pass == fl.first_pass2.read(v.cx).value();
                div()
                .w_full()
                .flex()
                .flex_col()
                .gap(px(12.0))
                .child(
                    theme::card(c)
                        .child(labelled("Display name", text_input(&fl.first_name), c))
                        .child(labelled("Passphrase", fl.first_pass.clone(), c))
                        .child(passphrase_feedback(&fl.first_pass, v))
                        .child(labelled("Confirm passphrase", fl.first_pass2.clone(), c))
                        .children(passphrase_match_feedback(&fl.first_pass, &fl.first_pass2, v))
                        .children(f.error.as_deref().map(|e| error_text(e, c)))
                        .child(
                            theme::enabled(
                                theme::primary_button_full("create-identity", "Create identity"),
                                ready,
                            )
                            .on_click(v.on(Action::CreateIdentity)),
                        )
                        .child(
                            theme::secondary_button_full("begin-restore", "Restore from a backup…")
                                .on_click(v.on(Action::BeginRestore)),
                        ),
                )
                .child(
                    theme::row()
                        .w_full()
                        .items_start()
                        .child(theme::icon_text(icon::WARNING, 14.0, c.warn))
                        .child(
                            theme::small(
                                "There is no password recovery. If you forget your passphrase, \
                                 your vaults cannot be opened.",
                                c.warn,
                            )
                            .flex_1()
                            .min_w_0(),
                        ),
                )
                .into_any_element()
            }
        };
    centered(
        "first-run",
        px(440.0),
        (v.height * 0.04).min(px(24.0)),
        div()
            .w_full()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .child(hero(icon::LOCK_KEY, c.accent, "Welcome to FileSec", c))
            .child(
                theme::text(
                    "Your identity lets others send files securely to you. \
                     Your private keys are encrypted on this device.",
                    c.text_muted,
                )
                .text_center(),
            )
            .child(div().h(px(12.0)))
            .child(card),
    )
}

pub(in crate::app) fn unlock(u: &Unlock, v: &View) -> impl IntoElement {
    let c = v.c;
    let fl = v.fields;
    let has_pass = !fl.unlock_pass.read(v.cx).is_empty();
    let button = if u.legacy_recovery {
        "Recover and upgrade local state"
    } else {
        "Unlock"
    };
    let mut card = theme::card(c);
    if u.legacy_recovery {
        card = card.child(theme::text(
            "One-time security upgrade required. FileSec found authenticated local \
             state from before rollback protection was introduced. Enter your \
             passphrase and confirm recovery; the keystore, contacts, registry, \
             and registered vaults will be re-anchored immediately.",
            c.warn,
        ));
    }
    card = card
        .child(labelled("Passphrase", fl.unlock_pass.clone(), c))
        .children(u.error.as_deref().map(|e| error_text(e, c)))
        .child(
            theme::enabled(theme::primary_button_full("unlock", button), has_pass)
                .on_click(v.on(Action::Unlock)),
        );

    // Security-key (passkey) unlock, when one is enrolled and this build
    // supports the hardware.
    if !u.legacy_recovery && u.has_passkeys && passkey::SUPPORTED {
        card = card
            .child(theme::divider_or(c))
            .child(fl.unlock_pin.clone())
            .child(
                theme::secondary_button_full("unlock-passkey", "Unlock with security key")
                    .on_click(v.on(Action::UnlockWithPasskey)),
            );
    } else if !u.legacy_recovery && u.has_passkeys {
        card = card.child(theme::muted(
            "This identity has a security key enrolled, but this build can't use it \
             (rebuild with --features passkey). Use your passphrase.",
            c,
        ));
    }

    // This-device (OS keychain) unlock, when a device token is stored for this
    // device and this build can read it.
    if !u.legacy_recovery && u.has_saved && autounlock::SUPPORTED {
        card = card.child(theme::divider_or(c)).child(
            theme::secondary_button_full("unlock-device", "Unlock on this device")
                .on_click(v.on(Action::UnlockWithKeyring)),
        );
    } else if !u.legacy_recovery && u.has_saved {
        card = card.child(theme::muted(
            "This device has a saved unlock, but this build can't use it \
             (rebuild with --features keyring). Use your passphrase.",
            c,
        ));
    }

    centered(
        "unlock",
        px(420.0),
        (v.height * 0.10).min(px(60.0)),
        div()
            .w_full()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .child(hero(icon::LOCK, c.accent, "Welcome back", c))
            .child(
                theme::text("Unlock your identity to access your vaults.", c.text_muted)
                    .text_center(),
            )
            .child(div().h(px(10.0)))
            .child(card),
    )
}
