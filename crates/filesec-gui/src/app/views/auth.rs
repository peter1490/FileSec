//! The screens before a session exists: fatal start-up error, rollback-anchor
//! recovery, first run (create or restore an identity), and unlock.
//!
//! They share one layout: the FileSec mark, a title and one line of context,
//! a single card holding the form, and a short reassurance underneath.

use gpui_kit::{div, prelude::*, px, AnyElement, Div, Entity, Hsla, Pixels, SharedString};

use crate::autounlock;
use crate::passkey;
use crate::secret_input::SecretInput;
use crate::theme::{self, icon, Colors};

use super::{any, checkbox, labelled, text_input, View};
use crate::app::model::passphrase_policy_error;
use crate::app::{Action, AnchorRecovery, FirstRun, Unlock};

/// A scrolling page with a centred column of at most `max_w`, vertically
/// centred when it fits.
fn centered(id: &'static str, max_w: Pixels, body: Div) -> impl IntoElement {
    div()
        .id(id)
        .size_full()
        .overflow_y_scroll()
        .flex()
        .flex_col()
        .items_center()
        .child(div().flex_1().min_h(px(56.0)))
        .child(
            div()
                .w_full()
                .max_w(max_w)
                .px(px(20.0))
                .flex()
                .flex_col()
                .items_center()
                .child(body),
        )
        .child(div().flex_1().min_h(px(40.0)))
}

/// The mark (or a status tile), the title, and the line of context.
fn hero(tile: Div, title: &'static str, subtitle: &'static str, c: Colors) -> Div {
    div()
        .w_full()
        .flex()
        .flex_col()
        .items_center()
        .child(tile)
        .child(div().h(px(18.0)))
        .child(theme::strong(title, theme::TEXT_TITLE, c.text).text_center())
        .child(div().h(px(6.0)))
        .child(theme::text(subtitle, c.text_muted).text_center())
        .child(div().h(px(24.0)))
}

/// The form card.
fn form_card(c: Colors) -> Div {
    theme::card(c)
        .p(px(24.0))
        .gap(px(16.0))
        .rounded(theme::RADIUS_LG)
}

/// A one-line reassurance under the card.
fn footnote(glyph: icon::Glyph, s: &'static str, color: Hsla, c: Colors) -> Div {
    theme::row()
        .w_full()
        .pt(px(18.0))
        .items_start()
        .justify_center()
        .child(theme::icon_text(glyph, 14.0, color).mt(px(1.0)))
        .child(theme::small(s, c.text_muted).max_w(px(340.0)))
}

fn error_text(e: &str, c: Colors) -> Div {
    theme::row()
        .w_full()
        .items_start()
        .child(theme::icon_text(icon::ERROR, 15.0, c.err).mt(px(2.0)))
        .child(theme::text(e.to_string(), c.err).flex_1().min_w_0())
}

/// A small status line with an icon (passphrase guidance).
fn hint(glyph: icon::Glyph, s: impl Into<SharedString>, color: Hsla) -> Div {
    theme::row()
        .w_full()
        .gap(px(6.0))
        .child(theme::icon_text(glyph, 13.0, color))
        .child(theme::small(s, color).flex_1().min_w_0())
}

pub(in crate::app) fn fatal(msg: &str, v: &View) -> impl IntoElement {
    let c = v.c;
    centered(
        "fatal",
        px(520.0),
        div()
            .w_full()
            .flex()
            .flex_col()
            .items_center()
            .child(hero(
                theme::icon_tile(
                    icon::WARNING_CIRCLE,
                    52.0,
                    c.err,
                    theme::with_alpha(c.err, 30),
                ),
                "FileSec couldn't start",
                "Nothing was changed. The details below say what went wrong.",
                c,
            ))
            .child(
                form_card(c)
                    .child(theme::mono(msg.to_string(), theme::TEXT_SMALL, c.text, v.cx).w_full()),
            ),
    )
}

pub(in crate::app) fn anchor_recovery(r: &AnchorRecovery, v: &View) -> impl IntoElement {
    let c = v.c;
    let ready = r.confirmed && !v.fields.anchor_pass.read(v.cx).is_empty();
    let card = form_card(c)
        .child(theme::callout(icon::WARNING, r.reason.clone(), c.err, c))
        .child(theme::text(
            "FileSec keeps a record of the newest version of your keystore, contacts, \
             registry, and vaults outside this data directory, so an older copy can't be \
             swapped in unnoticed. That record couldn't be trusted as found.",
            c.text_muted,
        ))
        .child(theme::text(
            "If you didn't expect this (no keychain reset, no move to a new machine), stop \
             here and check where this data directory came from. Recovering trusts the files \
             on disk now as the newest state. Nothing is deleted or re-encrypted.",
            c.text_muted,
        ))
        .child(checkbox(
            "anchor-confirm",
            "This data directory is the current copy I intend to keep",
            r.confirmed,
            v.on_check(Action::SetAnchorConfirmed),
        ))
        .child(labelled("Passphrase", v.fields.anchor_pass.clone(), c))
        .children(r.error.as_deref().map(|e| error_text(e, c)))
        .child(
            theme::enabled(
                theme::primary_button_full("anchor-recover", "Re-establish rollback protection"),
                ready,
            )
            .on_click(v.on(Action::RecoverAnchors)),
        );
    centered(
        "anchor-recovery",
        px(500.0),
        div()
            .w_full()
            .flex()
            .flex_col()
            .child(hero(
                theme::icon_tile(icon::LOCK_KEY, 52.0, c.warn, theme::with_alpha(c.warn, 30)),
                "Rollback protection needs attention",
                "Confirm this is the data you mean to keep before continuing.",
                c,
            ))
            .child(card),
    )
}

/// Live guidance under a new passphrase.
fn passphrase_feedback(pass: &Entity<SecretInput>, v: &View) -> Div {
    let c = v.c;
    let pass = pass.read(v.cx).value();
    if pass.is_empty() {
        hint(
            icon::INFO,
            "At least 12 characters. Several unrelated words work well.",
            c.text_muted,
        )
    } else if let Some(error) = passphrase_policy_error(pass) {
        hint(icon::WARNING, error, c.warn)
    } else {
        hint(icon::CHECK_CIRCLE, "Meets the requirements.", c.ok)
    }
}

/// "Passphrases match" / "don't match yet" under a confirmation field.
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
    Some(if pass.read(v.cx).value() == confirm {
        hint(icon::CHECK_CIRCLE, "Passphrases match.", c.ok)
    } else {
        hint(icon::WARNING, "Passphrases don't match yet.", c.warn)
    })
}

/// A field with its live guidance directly under it.
fn field_with(label: &'static str, field: impl IntoElement, under: Vec<Div>, c: Colors) -> Div {
    div()
        .w_full()
        .flex()
        .flex_col()
        .gap(px(6.0))
        .child(labelled(label, field, c))
        .children(under)
}

pub(in crate::app) fn first_run(f: &FirstRun, v: &View) -> impl IntoElement {
    let c = v.c;
    let fl = v.fields;
    let (hero_el, card, note): (Div, AnyElement, Div) = match &f.restore {
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
            let card = form_card(c)
                .child(
                    theme::row()
                        .w_full()
                        .p(px(10.0))
                        .rounded(theme::RADIUS)
                        .bg(c.surface_hi)
                        .border_1()
                        .border_color(c.border_subtle)
                        .child(theme::icon_text(icon::KEY, 16.0, c.text_muted))
                        .child(theme::one_line(theme::text(name, c.text)).flex_1()),
                )
                .child(labelled(
                    "Backup passphrase",
                    fl.restore_backup_pass.clone(),
                    c,
                ))
                .child(theme::separator(c))
                .child(field_with(
                    "New passphrase for this device",
                    fl.restore_new_pass.clone(),
                    vec![passphrase_feedback(&fl.restore_new_pass, v)],
                    c,
                ))
                .child(field_with(
                    "Confirm new passphrase",
                    fl.restore_new_pass2.clone(),
                    passphrase_match_feedback(&fl.restore_new_pass, &fl.restore_new_pass2, v)
                        .into_iter()
                        .collect(),
                    c,
                ))
                .children(r.error.as_deref().map(|e| error_text(e, c)))
                .child(
                    div()
                        .w_full()
                        .flex()
                        .flex_col()
                        .gap(px(8.0))
                        .child(
                            theme::enabled(
                                theme::primary_button_full("restore-identity", "Restore identity"),
                                ready,
                            )
                            .on_click(v.on(Action::DoRestore)),
                        )
                        .child(
                            theme::ghost_button("restore-cancel", "Cancel")
                                .w_full()
                                .on_click(v.on(Action::CancelRestore)),
                        ),
                );
            (
                hero(
                    theme::logo_mark(48.0, c),
                    "Restore your identity",
                    "Unlock the backup, then choose the passphrase you'll use on this device.",
                    c,
                ),
                any(card),
                footnote(
                    icon::LOCK,
                    "Your private keys are decrypted and re-sealed on this device only.",
                    c.text_subtle,
                    c,
                ),
            )
        }
        // Default: create a brand-new identity.
        None => {
            let pass = fl.first_pass.read(v.cx).value();
            let ready = !v.text(&fl.first_name).trim().is_empty()
                && passphrase_policy_error(pass).is_none()
                && pass == fl.first_pass2.read(v.cx).value();
            let card = form_card(c)
                .child(labelled("Your name", text_input(&fl.first_name), c))
                .child(field_with(
                    "Passphrase",
                    fl.first_pass.clone(),
                    vec![passphrase_feedback(&fl.first_pass, v)],
                    c,
                ))
                .child(field_with(
                    "Confirm passphrase",
                    fl.first_pass2.clone(),
                    passphrase_match_feedback(&fl.first_pass, &fl.first_pass2, v)
                        .into_iter()
                        .collect(),
                    c,
                ))
                .children(f.error.as_deref().map(|e| error_text(e, c)))
                .child(
                    theme::enabled(
                        theme::primary_button_full("create-identity", "Create identity"),
                        ready,
                    )
                    .on_click(v.on(Action::CreateIdentity)),
                )
                .child(theme::divider_or(c))
                .child(
                    theme::secondary_button_full("begin-restore", "Restore from a backup…")
                        .on_click(v.on(Action::BeginRestore)),
                );
            (
                hero(
                    theme::logo_mark(48.0, c),
                    "Welcome to FileSec",
                    "Create the identity others will use to send you files securely.",
                    c,
                ),
                any(card),
                footnote(
                    icon::WARNING,
                    "There's no passphrase recovery. If you forget it, your vaults can't be \
                     opened — export a backup once you're set up.",
                    c.warn,
                    c,
                ),
            )
        }
    };
    centered(
        "first-run",
        px(440.0),
        div()
            .w_full()
            .flex()
            .flex_col()
            .child(hero_el)
            .child(card)
            .child(note),
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
    let mut card = form_card(c);
    if u.legacy_recovery {
        card = card.child(theme::callout(
            icon::INFO,
            "One-time security upgrade. FileSec found authenticated local state from before \
             rollback protection existed. Enter your passphrase to confirm; the keystore, \
             contacts, registry, and registered vaults will be re-anchored right away.",
            c.warn,
            c,
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
            .child(labelled("Security key PIN", fl.unlock_pin.clone(), c))
            .child(
                theme::secondary_button_full("unlock-passkey", "Unlock with security key")
                    .icon(theme::ico(icon::USB))
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
                .icon(theme::ico(icon::LAPTOP))
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
        px(400.0),
        div()
            .w_full()
            .flex()
            .flex_col()
            .child(hero(
                theme::logo_mark(48.0, c),
                "Welcome back",
                "Unlock your identity to open your vaults.",
                c,
            ))
            .child(card)
            .child(footnote(
                icon::LOCK,
                "Your keys stay encrypted on this device under your passphrase.",
                c.text_subtle,
                c,
            )),
    )
}
