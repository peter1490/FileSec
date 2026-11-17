//! Modal dialogs over the unlocked session. Each is drawn on a dimmed,
//! click-blocking backdrop; clicking the backdrop or pressing Escape runs the
//! dialog's cancel action (see `FileSecApp::on_key_down`), except for the text
//! editor, which only its own buttons close so a stray click never discards an
//! edit.

use gpui_kit::component::input::Textarea;
use gpui_kit::{div, prelude::*, px, AnyElement, Div, SharedString, TestSupportExt};

use filesec_core::contacts::Trust;
use filesec_core::util::hex;
#[cfg(feature = "pqc")]
use filesec_core::SuiteId;

use crate::theme::{self, icon};

use super::{checkbox, chip, labelled, text_input, View};
use crate::app::model::{human_size, move_folder_options};
use crate::app::{Action, PreviewStatus, Session};

/// A centred modal: backdrop + titled card with a scrolling body. `close` is
/// what a click on the backdrop does (`None`: nothing).
fn modal(
    id: &'static str,
    title: impl Into<SharedString>,
    close: Option<Action>,
    body: Div,
    v: &View,
) -> AnyElement {
    let c = v.c;
    let width = (v.window_width - px(64.0)).clamp(px(160.0), px(460.0));
    let max_h = (v.height - px(48.0)).max(px(160.0));
    let card = theme::modal_card(
        SharedString::from(format!("{id}-card")),
        title,
        width,
        max_h,
        c,
    )
    // Clicks inside the card must not reach the backdrop's dismiss.
    .on_click(|_, _, cx| cx.stop_propagation())
    .child(
        div()
            .id(SharedString::from(format!("{id}-body")))
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .child(body.w_full()),
    );
    let mut backdrop = theme::backdrop(SharedString::from(format!("{id}-backdrop")), 130);
    if let Some(close) = close {
        backdrop = backdrop.on_click(v.on(close));
    }
    backdrop.child(card).test_support().into_any_element()
}

fn body() -> Div {
    div().flex().flex_col().gap(px(8.0))
}

fn buttons() -> Div {
    theme::wrap_row().pt(px(6.0))
}

/// Every dialog that is open over the session, bottom to top.
pub(in crate::app) fn session_dialogs(s: &mut Session, v: &View) -> Vec<AnyElement> {
    let mut out = Vec::new();
    if s.delete_vault.is_some() {
        out.extend(delete_vault(s, v));
    }
    if s.move_form.is_some() {
        out.extend(move_dialog(s, v));
    }
    if s.text_editor.is_some() {
        out.extend(text_editor(s, v));
    }
    if s.export.is_some() {
        out.extend(export(s, v));
    }
    if s.last_import.is_some() {
        out.extend(import_info(s, v));
    }
    if s.contact_preview.is_some() {
        out.extend(contact_preview(s, v));
    }
    if s.verify.is_some() {
        out.extend(verify(s, v));
    }
    #[cfg(feature = "pqc")]
    if s.migrate.is_some() {
        out.extend(migrate(s, v));
    }
    if s.add_passkey.is_some() {
        out.extend(add_passkey(s, v));
    }
    if s.auto_unlock_form.is_some() {
        out.extend(autounlock(s, v));
    }
    if s.export_identity.is_some() {
        out.extend(export_identity(s, v));
    }
    #[cfg(feature = "net")]
    out.extend(crate::app::transfer::offer_dialog(s, v));
    out
}

fn error_line(e: &Option<String>, v: &View) -> Option<Div> {
    e.as_deref().map(|e| theme::text(e.to_string(), v.c.err))
}

fn delete_vault(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let form = s.delete_vault.as_ref()?;
    let vault = s.registry.vaults.iter().find(|vm| vm.id == form.vault_id)?;
    let b = body()
        .child(theme::strong(vault.name.clone(), px(17.0), c.text))
        .child(theme::muted(
            format!(
                "{} files · {}",
                vault.file_count,
                human_size(vault.total_size)
            ),
            c,
        ))
        .child(theme::text(
            "This permanently deletes this vault and all files in it, including items in its \
             Trash. This cannot be undone.",
            c.text,
        ))
        .child(
            buttons()
                .child(
                    theme::secondary_button("delete-vault-cancel", "Cancel")
                        .track_focus(&v.dialog_focus)
                        .on_click(v.on(Action::CancelDeleteVault)),
                )
                .child(
                    theme::danger_button("delete-vault-confirm", "Delete vault permanently", v.cx)
                        .on_click(v.on(Action::ConfirmDeleteVault)),
                ),
        );
    Some(modal(
        "delete-vault",
        "Delete vault?",
        Some(Action::CancelDeleteVault),
        b,
        v,
    ))
}

fn move_dialog(s: &mut Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let model = s.browser_model()?;
    let form = s.move_form.as_ref()?;
    let options = move_folder_options(&model.entries, &form.paths);
    let n = form.paths.len();
    let list = div()
        .id("move-options")
        .max_h(px(280.0))
        .overflow_y_scroll()
        .flex()
        .flex_col()
        .gap(px(2.0))
        .children(options.into_iter().map(|(path, label, depth)| {
            div().pl(px(depth as f32 * 16.0)).child(chip(
                SharedString::from(format!("move-to:{path}")),
                label,
                form.dest == path,
                true,
                v.on(Action::SetMoveDest(path.clone())),
            ))
        }));
    let b = body()
        .child(theme::text(
            format!(
                "Moving {n} item{}. Choose a destination folder:",
                if n == 1 { "" } else { "s" }
            ),
            c.text_muted,
        ))
        .child(list)
        .child(
            buttons()
                .child(
                    theme::primary_button("move-here", "Move here")
                        .on_click(v.on(Action::ConfirmMove)),
                )
                .child(
                    theme::secondary_button("move-cancel", "Cancel")
                        .on_click(v.on(Action::CancelMove)),
                ),
        );
    Some(modal("move", "Move to…", Some(Action::CancelMove), b, v))
}

/// The in-app quick text editor: a wide modal holding the file's plaintext in
/// an editable area, with Save / Close. The backdrop and Esc deliberately do
/// *not* dismiss it — only the buttons close it.
fn text_editor(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let te = s.text_editor.as_ref()?;
    let width = (v.window_width - px(160.0)).clamp(px(360.0), px(900.0));
    let editor_h = (v.height - px(200.0)).max(px(160.0));
    let close_label = if te.dirty { "Discard & close" } else { "Close" };
    let card = div()
        .id("text-editor")
        .occlude()
        .w(width)
        .flex()
        .flex_col()
        .gap(px(10.0))
        .bg(c.surface)
        .border_1()
        .border_color(c.border)
        .rounded(theme::RADIUS)
        .p(px(16.0))
        .child(
            theme::row()
                .child(theme::icon_text(icon::EDIT, 16.0, c.accent))
                .child(theme::strong(format!("Edit {}", te.leaf), px(16.0), c.text))
                .when(te.dirty, |r| r.child(theme::small("• unsaved", c.warn))),
        )
        .child(
            div().h(editor_h).w_full().child(
                Textarea::new(&v.fields.editor)
                    .w_full()
                    .h_full()
                    .font_family(
                        gpui_kit::component::ActiveTheme::theme(v.cx)
                            .mono_font_family
                            .clone(),
                    ),
            ),
        )
        .child(
            buttons()
                .child(
                    theme::primary_button("editor-save", "Save")
                        .on_click(v.on(Action::SaveTextFile)),
                )
                .child(
                    theme::secondary_button("editor-close", close_label)
                        .on_click(v.on(Action::CloseTextEditor)),
                ),
        );
    Some(
        theme::backdrop("text-editor-backdrop", 130)
            .child(card)
            .into_any_element(),
    )
}

fn export(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let form = s.export.as_ref()?;
    let mut b = body().child(theme::text(
        "Choose recipients. Each will be able to open the container with their private key.",
        c.text,
    ));
    if s.contacts.contacts.is_empty() {
        b = b.child(theme::text(
            "You have no contacts yet — add one first, or just include yourself.",
            c.text_muted,
        ));
    }
    b = b.child(
        div()
            .id("export-recipients")
            .max_h(px(200.0))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .children(s.contacts.contacts.iter().map(|ct| {
                let fpr_hex = hex(&ct.fingerprint());
                let name = if ct.identity.name.is_empty() {
                    "(unnamed)"
                } else {
                    ct.identity.name.as_str()
                };
                let label = match ct.trust {
                    Trust::Verified => format!("{name} (verified)"),
                    Trust::Unverified => format!("{name} — unverified ⚠"),
                };
                checkbox(
                    SharedString::from(format!("recipient:{fpr_hex}")),
                    label,
                    form.selected.contains(&fpr_hex),
                    {
                        let fpr_hex = fpr_hex.clone();
                        v.on_check(move |_| Action::ToggleRecipient(fpr_hex.clone()))
                    },
                )
            })),
    );
    b = b.child(theme::separator(c)).child(checkbox(
        "include-self",
        "Also include myself (so I can re-open it)",
        form.include_self,
        v.on_check(|_| Action::ToggleIncludeSelf),
    ));

    // Algorithm-suite picker (post-quantum builds only). The classical build
    // has a single suite and shows no picker.
    #[cfg(feature = "pqc")]
    {
        // Hybrid needs a post-quantum *sender* identity; a non-migrated
        // classical identity can only pick the classical suites.
        let sender_hybrid = s.identity.is_hybrid_capable();
        b = b.child(
            theme::wrap_row()
                .child(theme::text("Encryption suite:", c.text))
                .children(
                    [SuiteId::Classic, SuiteId::Aes256Gcm, SuiteId::Hybrid].map(|opt| {
                        let enabled = sender_hybrid || !opt.is_hybrid();
                        chip(
                            SharedString::from(format!(
                                "suite-{}",
                                crate::app::model::suite_short(opt)
                            )),
                            crate::app::model::suite_short(opt),
                            form.suite == opt,
                            enabled,
                            v.on(Action::SetExportSuite(opt)),
                        )
                    }),
                ),
        );
        if !sender_hybrid {
            b = b.child(theme::muted(
                "Hybrid PQC needs a post-quantum identity — upgrade yours in “My \
                 Identity” to enable it.",
                c,
            ));
        }
        b = b.child(theme::muted(form.suite.label(), c));
        if form.suite.is_hybrid() {
            let missing: Vec<&str> = s
                .contacts
                .contacts
                .iter()
                .filter(|ct| {
                    form.selected.contains(&hex(&ct.fingerprint()))
                        && !ct.identity.is_hybrid_capable()
                })
                .map(|ct| {
                    if ct.identity.name.is_empty() {
                        "(unnamed)"
                    } else {
                        ct.identity.name.as_str()
                    }
                })
                .collect();
            b = b.child(if missing.is_empty() {
                theme::text(
                    "Every recipient also gets post-quantum protection.",
                    c.text_muted,
                )
            } else {
                theme::text(
                    format!(
                        "⚠ No post-quantum key for: {}. Pick another suite or ask them to \
                         re-share.",
                        missing.join(", ")
                    ),
                    c.err,
                )
            });
        }
    }

    // Unverified recipients need an explicit, per-export confirmation that names
    // the exact key (its safety number) — the export button refuses until each
    // one is ticked. Verifying them in Contacts avoids this.
    let unverified: Vec<(String, String, String)> = s
        .contacts
        .contacts
        .iter()
        .filter(|ct| {
            ct.trust == Trust::Unverified && form.selected.contains(&hex(&ct.fingerprint()))
        })
        .map(|ct| {
            (
                hex(&ct.fingerprint()),
                ct.identity.display_name(),
                ct.identity.safety_number(),
            )
        })
        .collect();
    if !unverified.is_empty() {
        b = b
            .child(theme::text("⚠ Unverified recipients", c.err))
            .child(theme::muted(
                "You haven't confirmed these keys out-of-band, so anyone could have \
                 supplied them. Confirm each one for this export only, or verify it in \
                 Contacts first.",
                c,
            ));
        for (fpr, name, safety) in unverified {
            let confirmed = form.confirmed_unverified.contains(&fpr);
            b = b
                .child(checkbox(
                    SharedString::from(format!("confirm-unverified:{fpr}")),
                    format!("Encrypt to {name} anyway"),
                    confirmed,
                    {
                        let fpr = fpr.clone();
                        v.on_check(move |checked| {
                            Action::ConfirmUnverifiedRecipient(fpr.clone(), checked)
                        })
                    },
                ))
                .child(theme::mono(safety, theme::TEXT_SMALL, c.text_muted, v.cx));
        }
    }
    b = b.child(
        buttons()
            .child(
                theme::primary_button("export-go", "Choose file & export")
                    .on_click(v.on(Action::DoExport)),
            )
            .child(
                theme::secondary_button("export-cancel", "Cancel")
                    .on_click(v.on(Action::CancelExport)),
            ),
    );
    Some(modal(
        "export",
        "Send vault",
        Some(Action::CancelExport),
        b,
        v,
    ))
}

fn import_info(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let info = s.last_import.as_ref()?;
    let fpr_hex = info.sender_fpr_hex.clone();
    let mut b = body()
        .child(theme::strong(
            format!("\"{}\"", info.vault_name),
            theme::TEXT_BODY,
            c.text,
        ))
        .child(theme::text(format!("{} file(s)", info.file_count), c.text))
        .child(theme::separator(c))
        .child(theme::text(
            "Sender's signature is cryptographically valid. Identity:",
            c.text,
        ));
    // `signature valid` only proves the bytes came from whoever holds these
    // keys — NOT that those keys belong to who you think. The out-of-band
    // safety-number check is what closes that gap, so the dialog nudges toward
    // it whenever the sender isn't verified.
    b = match (&info.sender_name, info.verified) {
        (Some(name), true) => b.child(theme::text(format!("✔ {name} (verified contact)"), c.ok)),
        (Some(name), false) => b
            .child(theme::text(
                format!("● {name} — a known but UNVERIFIED contact"),
                c.warn,
            ))
            .child(theme::muted(
                "Verify their safety number before you trust this content.",
                c,
            )),
        (None, _) => b
            .child(theme::text(
                "● Unknown sender — not in your contacts",
                c.err,
            ))
            .child(theme::muted(
                "Add them as a contact, then verify their safety number out-of-band.",
                c,
            )),
    };
    b = b.child(theme::mono(
        format!("fingerprint: {}", info.sender_fpr_hex),
        theme::TEXT_SMALL,
        c.text_muted,
        v.cx,
    ));
    let mut row = buttons();
    match (&info.sender_name, info.verified) {
        // Known but unverified → jump straight into verification.
        (Some(_), false) => {
            row = row.child(
                theme::primary_button("verify-sender", "Verify sender…")
                    .on_click(v.on(Action::BeginVerify(fpr_hex))),
            );
        }
        // Unknown → offer to add them as a contact first.
        (None, _) => {
            row = row.child(
                theme::primary_button("add-sender", "Add sender to contacts…")
                    .on_click(v.on(Action::AddSenderToContacts)),
            );
        }
        _ => {}
    }
    row = row.child(
        theme::secondary_button("import-ok", "OK").on_click(v.on(Action::DismissImportInfo)),
    );
    Some(modal(
        "import-info",
        "Imported vault",
        Some(Action::DismissImportInfo),
        b.child(row),
        v,
    ))
}

/// Confirmation step for a parsed-but-not-yet-saved contact key. Shows who the
/// key belongs to (name, fingerprint, safety number) and the trust implication
/// of adding it, so nothing is added — and no verified contact silently renamed
/// — without the user seeing it first.
fn contact_preview(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let preview = s.contact_preview.as_ref()?;
    // The pasted key is untrusted: render its name only through the sanitizer so
    // a bidi/zero-width spoof can't disguise it as another contact or as system
    // text.
    let name = preview.pubid.display_name();
    let is_self = matches!(preview.status, PreviewStatus::SelfKey);
    let label_w = px(96.0);
    let mut b = body()
        .child(
            theme::row()
                .child(div().w(label_w).child(theme::text("Name", c.text_muted)))
                .child(theme::strong(name.clone(), theme::TEXT_BODY, c.text)),
        )
        .child(
            theme::row()
                .items_start()
                .child(
                    div()
                        .w(label_w)
                        .flex_none()
                        .child(theme::text("Fingerprint", c.text_muted)),
                )
                .child(div().flex_1().min_w_0().child(theme::mono(
                    preview.pubid.fingerprint_hex(),
                    theme::TEXT_SMALL,
                    c.text,
                    v.cx,
                ))),
        )
        .child(theme::text("Safety number:", c.text))
        .child(theme::mono(
            preview.pubid.safety_number(),
            theme::TEXT_MONO,
            c.accent,
            v.cx,
        ))
        .child(theme::separator(c));
    b = match &preview.status {
        PreviewStatus::New => b.child(theme::text(
            "New contact. You'll verify their safety number before trusting them.",
            c.text_muted,
        )),
        PreviewStatus::Existing { verified: true } => b.child(theme::text(
            "Already a verified contact — nothing will change.",
            c.ok,
        )),
        PreviewStatus::Existing { verified: false } => b.child(theme::text(
            "Already a contact (unverified) — nothing will change.",
            c.text_muted,
        )),
        PreviewStatus::Renamed {
            old,
            verified: true,
        } => b
            .child(theme::text(
                format!("⚠ This renames a VERIFIED contact: \"{old}\" → \"{name}\"."),
                c.err,
            ))
            .child(theme::muted(
                "The keys are identical, so verification still holds — but confirm you \
                 expected this rename.",
                c,
            )),
        PreviewStatus::Renamed {
            old,
            verified: false,
        } => b.child(theme::text(
            format!("Display name will change: \"{old}\" → \"{name}\"."),
            c.warn,
        )),
        PreviewStatus::SelfKey => b.child(theme::text(
            "⚠ This is your OWN public key — you don't need to add yourself.",
            c.err,
        )),
    };
    let add_label = match &preview.status {
        PreviewStatus::Renamed { .. } => "Update contact",
        _ => "Add contact",
    };
    b = b.child(
        buttons()
            .child(
                theme::enabled(theme::primary_button("add-contact", add_label), !is_self)
                    .on_click(v.on(Action::ConfirmAddContact)),
            )
            .child(
                theme::secondary_button("preview-cancel", "Cancel")
                    .on_click(v.on(Action::CancelPreview)),
            ),
    );
    Some(modal(
        "contact-preview",
        "Add contact?",
        Some(Action::CancelPreview),
        b,
        v,
    ))
}

/// The verification dialog: compare a contact's safety number out-of-band. The
/// user can either type back what the other party reads (the app checks the
/// match, ignoring spacing/case) or tick the manual "I compared it" box. Either
/// path enables "Mark verified".
fn verify(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let form = s.verify.as_ref()?;
    let typed = v.text(&v.fields.verify_input);
    // Recompute the match each render against the canonical number.
    let typed_match = !typed.trim().is_empty()
        && filesec_core::util::normalize_safety_number(&typed)
            == filesec_core::util::normalize_safety_number(&form.safety_number);
    let can_verify = typed_match || form.manual_ok;
    let mut b = body()
        .child(theme::text(
            "Compare this safety number with the contact over a trusted channel — in person, \
             a video call, or a line you already trust. Mark verified only once both sides \
             match exactly.",
            c.text_muted,
        ))
        .child(theme::text("Their safety number should read:", c.text))
        .child(
            theme::wrap_row()
                .child(theme::mono(
                    form.safety_number.clone(),
                    theme::TEXT_MONO,
                    c.accent,
                    v.cx,
                ))
                .child(
                    theme::small_button("copy-safety", "Copy")
                        .on_click(v.on(Action::CopyVerifySafetyNumber)),
                ),
        )
        .child(theme::text(
            "Type what they read back (optional — the app checks it for you):",
            c.text,
        ))
        .child(text_input(&v.fields.verify_input));
    if !typed.trim().is_empty() {
        b = b.child(if typed_match {
            theme::text("✔ Matches.", c.ok)
        } else {
            theme::text("✗ Does not match — do not verify.", c.err)
        });
    }
    b = b
        .child(checkbox(
            "verify-manual",
            "I compared it myself and it matches exactly.",
            form.manual_ok,
            v.on_check(Action::SetVerifyManual),
        ))
        .child(
            buttons()
                .child(
                    theme::enabled(
                        theme::primary_button("mark-verified", "Mark verified"),
                        can_verify,
                    )
                    .on_click(v.on(Action::ConfirmVerify(form.fpr_hex.clone()))),
                )
                .child(
                    theme::secondary_button("verify-cancel", "Cancel")
                        .on_click(v.on(Action::CancelVerify)),
                ),
        );
    Some(modal(
        "verify",
        format!("Verify {}", form.name),
        Some(Action::CancelVerify),
        b,
        v,
    ))
}

/// The "Upgrade to post-quantum" confirmation dialog.
#[cfg(feature = "pqc")]
fn migrate(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let form = s.migrate.as_ref()?;
    let b = body()
        .child(theme::text(
            "This adds ML-KEM-768 and ML-DSA-65 keys to your identity and re-encrypts your \
             whole local vault store under the hybrid post-quantum suite. Your existing \
             X25519/Ed25519 keys are kept.",
            c.text,
        ))
        .child(theme::text("⚠ Your safety number will change.", c.err))
        .child(theme::muted(
            "Your identity now commits to its post-quantum keys, so your fingerprint and \
             safety number change. After upgrading, re-share your public key and have your \
             contacts re-verify it.",
            c,
        ))
        .child(theme::muted(
            "Import any pending .fsec files first — containers others already sent to your \
             old identity won't be openable afterwards.",
            c,
        ))
        .child(theme::text(
            "Enter your current passphrase to confirm (it stays your passphrase):",
            c.text,
        ))
        .child(v.fields.migrate_pass.clone())
        .children(error_line(&form.error, v))
        .child(
            buttons()
                .child(
                    theme::primary_button("migrate-go", "Upgrade now")
                        .on_click(v.on(Action::DoMigrate)),
                )
                .child(
                    theme::secondary_button("migrate-cancel", "Cancel")
                        .on_click(v.on(Action::CancelMigrate)),
                ),
        );
    Some(modal(
        "migrate",
        "Upgrade to post-quantum",
        Some(Action::CancelMigrate),
        b,
        v,
    ))
}

fn add_passkey(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let form = s.add_passkey.as_ref()?;
    let b = body()
        .child(theme::text(
            "Enroll a FIDO2 hardware key (YubiKey, SoloKey, …) as an alternative way to \
             unlock. You'll be asked to verify (PIN or biometric) and touch it — once to \
             create the key, once to set up unlock. Your passphrase keeps working too.",
            c.text,
        ))
        .child(labelled("Name", text_input(&v.fields.passkey_label), c))
        .child(labelled("Passphrase", v.fields.passkey_pass.clone(), c))
        .child(labelled("Key PIN", v.fields.passkey_pin.clone(), c))
        .children(error_line(&form.error, v))
        .child(
            buttons()
                .child(
                    theme::primary_button("passkey-enroll", "Touch key to enroll")
                        .on_click(v.on(Action::AddPasskey)),
                )
                .child(
                    theme::secondary_button("passkey-cancel", "Cancel")
                        .on_click(v.on(Action::CancelAddPasskey)),
                ),
        );
    Some(modal(
        "add-passkey",
        "Add security key",
        Some(Action::CancelAddPasskey),
        b,
        v,
    ))
}

/// The "Remember on this device" dialog: confirm the passphrase before saving a
/// device unlock key to the OS keychain.
fn autounlock(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let form = s.auto_unlock_form.as_ref()?;
    let b = body()
        .child(theme::text(
            "Save a device unlock key in this computer's keychain so FileSec unlocks \
             automatically on this device. Your passphrase is not stored — it still works \
             everywhere and remains your recovery secret.",
            c.text,
        ))
        .child(theme::small(
            "Only do this on a trusted personal device: anyone who can use your \
             logged-in account could then open FileSec here.",
            c.warn,
        ))
        .child(labelled(
            "Confirm your passphrase",
            v.fields.autounlock_pass.clone(),
            c,
        ))
        .children(error_line(&form.error, v))
        .child(
            buttons()
                .child(
                    theme::primary_button("autounlock-save", "Save on this device")
                        .on_click(v.on(Action::ConfirmEnableAutoUnlock)),
                )
                .child(
                    theme::secondary_button("autounlock-cancel", "Cancel")
                        .on_click(v.on(Action::CancelEnableAutoUnlock)),
                ),
        );
    Some(modal(
        "autounlock",
        "Remember on this device",
        Some(Action::CancelEnableAutoUnlock),
        b,
        v,
    ))
}

/// The "Export identity backup" dialog: choose a backup passphrase to seal the
/// `.fsecid` file (independent of the daily passphrase).
fn export_identity(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let form = s.export_identity.as_ref()?;
    let b = body()
        .child(theme::text(
            "Choose a passphrase to protect this backup. You'll need it (not your \
             everyday passphrase) to restore the identity later, so it can differ from \
             the one you use day to day.",
            c.text,
        ))
        .child(theme::small(
            "The backup file holds your private keys. Anyone with the file and this \
             passphrase becomes you — keep both safe.",
            c.warn,
        ))
        .child(labelled(
            "Backup passphrase",
            v.fields.export_id_pass.clone(),
            c,
        ))
        .child(labelled(
            "Confirm passphrase",
            v.fields.export_id_pass2.clone(),
            c,
        ))
        .children(error_line(&form.error, v))
        .child(
            buttons()
                .child(
                    theme::primary_button("export-identity-go", "Choose file & export…")
                        .on_click(v.on(Action::DoExportIdentity)),
                )
                .child(
                    theme::secondary_button("export-identity-cancel", "Cancel")
                        .on_click(v.on(Action::CancelExportIdentity)),
                ),
        );
    Some(modal(
        "export-identity",
        "Export identity backup",
        Some(Action::CancelExportIdentity),
        b,
        v,
    ))
}
