//! Modal dialogs over the unlocked session. Each is drawn on a dimmed,
//! click-blocking backdrop; clicking the backdrop, the close button, or
//! pressing Escape runs the dialog's cancel action (see
//! `FileSecApp::on_key_down`), except for the text editor, which only its own
//! buttons close so a stray click never discards an edit.
//!
//! Every dialog has the same anatomy: a title bar (with a close button when
//! the dialog can be dismissed), a scrolling body, and a footer whose buttons
//! sit on the right — the cancel action first, the confirming action last.

use gpui_kit::component::button::{Button, ButtonVariants};
use gpui_kit::component::input::Textarea;
use gpui_kit::component::Sizable;
use gpui_kit::{div, prelude::*, px, AnyElement, Div, FontWeight, SharedString, TestSupportExt};

use filesec_core::contacts::Trust;
use filesec_core::util::hex;
#[cfg(feature = "pqc")]
use filesec_core::SuiteId;

use crate::theme::{self, ico, icon, BadgeKind};

use super::contacts::safety_number;
use super::{any, checkbox, labelled, text_input, View};
use crate::app::model::{human_size, move_folder_options};
use crate::app::{Action, PreviewStatus, Session};

/// Default dialog width.
const DIALOG_W: f32 = 480.0;

/// A centred modal: backdrop + surface with a title bar, a scrolling body,
/// and a footer. `close` is what the close button and a click on the
/// backdrop do (`None`: neither exists).
pub(in crate::app) fn modal(
    id: &'static str,
    title: impl Into<SharedString>,
    close: Option<Action>,
    body: Div,
    footer: Div,
    v: &View,
) -> AnyElement {
    modal_sized(id, title, close, body, footer, DIALOG_W, v)
}

fn modal_sized(
    id: &'static str,
    title: impl Into<SharedString>,
    close: Option<Action>,
    body: Div,
    footer: Div,
    width: f32,
    v: &View,
) -> AnyElement {
    let c = v.c;
    let width = (v.window_width - px(48.0)).clamp(px(160.0), px(width));
    let max_h = (v.height - px(48.0)).max(px(160.0));
    let title_bar = theme::row()
        .flex_none()
        .w_full()
        .pl(px(22.0))
        .pr(px(12.0))
        .pt(px(16.0))
        .pb(px(4.0))
        .child(theme::one_line(theme::strong(title, px(16.0), c.text)).flex_1())
        .children(close.clone().map(|action| {
            theme::icon_button(
                SharedString::from(format!("{id}-close")),
                icon::CLOSE,
                "Close",
                c,
            )
            .small()
            .on_click(v.on(action))
        }));
    let card = theme::dialog_surface(SharedString::from(format!("{id}-card")), width, max_h, c)
        // Clicks inside the card must not reach the backdrop's dismiss.
        .on_click(|_, _, cx| cx.stop_propagation())
        .child(title_bar)
        .child(
            div()
                .id(SharedString::from(format!("{id}-body")))
                .flex_1()
                .min_h_0()
                .overflow_y_scroll()
                .child(body.w_full().px(px(22.0)).pt(px(8.0)).pb(px(20.0))),
        )
        .child(
            footer
                .flex_none()
                .w_full()
                .px(px(22.0))
                .py(px(14.0))
                .border_t_1()
                .border_color(c.border_subtle),
        );
    let mut backdrop = theme::backdrop(
        SharedString::from(format!("{id}-backdrop")),
        if c.dark { 150 } else { 90 },
    );
    if let Some(close) = close {
        backdrop = backdrop.on_click(v.on(close));
    }
    backdrop.child(card).test_support().into_any_element()
}

fn body() -> Div {
    div().flex().flex_col().gap(px(14.0))
}

/// The footer button row: right-aligned, wrapping on narrow windows.
pub(in crate::app) fn footer() -> Div {
    theme::wrap_row().justify_end()
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

/// An inline error under a form: what went wrong, in the error colour.
fn error_line(e: &Option<String>, v: &View) -> Option<Div> {
    let c = v.c;
    e.as_deref().map(|e| {
        theme::row()
            .w_full()
            .items_start()
            .child(theme::icon_text(icon::ERROR, 15.0, c.err).mt(px(2.0)))
            .child(theme::text(e.to_string(), c.err).flex_1().min_w_0())
    })
}

/// A two-column "label  value" line inside a dialog.
fn detail_row(label: &'static str, value: impl IntoElement, v: &View) -> Div {
    theme::row()
        .w_full()
        .items_start()
        .gap(px(12.0))
        .child(
            div()
                .w(px(92.0))
                .flex_none()
                .child(theme::text(label, v.c.text_muted)),
        )
        .child(div().flex_1().min_w_0().child(value))
}

/// The safety number on an inset surface, ready to compare.
fn safety_inset(number: &str, trailing: Option<AnyElement>, v: &View) -> Div {
    let c = v.c;
    theme::row()
        .w_full()
        .items_start()
        .p(px(12.0))
        .rounded(theme::RADIUS)
        .bg(c.surface_hi)
        .border_1()
        .border_color(c.border_subtle)
        .child(div().flex_1().min_w_0().child(safety_number(number, v)))
        .children(trailing)
}

fn delete_vault(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let form = s.delete_vault.as_ref()?;
    let vault = s.registry.vaults.iter().find(|vm| vm.id == form.vault_id)?;
    let b = body()
        .child(
            theme::row()
                .w_full()
                .gap(px(12.0))
                .p(px(12.0))
                .rounded(theme::RADIUS)
                .border_1()
                .border_color(c.border_subtle)
                .child(theme::icon_tile(
                    icon::VAULT,
                    36.0,
                    c.err,
                    theme::with_alpha(c.err, 26),
                ))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .child(theme::one_line(theme::strong(
                            vault.name.clone(),
                            theme::TEXT_BODY,
                            c.text,
                        )))
                        .child(theme::muted(
                            format!(
                                "{} file{} · {}",
                                vault.file_count,
                                if vault.file_count == 1 { "" } else { "s" },
                                human_size(vault.total_size)
                            ),
                            c,
                        )),
                ),
        )
        .child(theme::text(
            "This permanently deletes the vault and every file in it, including items in its \
             Trash. It can't be undone.",
            c.text,
        ));
    let f = footer()
        .child(
            theme::secondary_button("delete-vault-cancel", "Cancel")
                .track_focus(&v.dialog_focus)
                .on_click(v.on(Action::CancelDeleteVault)),
        )
        .child(
            theme::danger_button("delete-vault-confirm", "Delete vault", v.cx)
                .on_click(v.on(Action::ConfirmDeleteVault)),
        );
    Some(modal(
        "delete-vault",
        "Delete this vault?",
        Some(Action::CancelDeleteVault),
        b,
        f,
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
        .max_h(px(300.0))
        .overflow_y_scroll()
        .p(px(4.0))
        .rounded(theme::RADIUS)
        .border_1()
        .border_color(c.border)
        .flex()
        .flex_col()
        .gap(px(2.0))
        .children(options.into_iter().map(|(path, label, depth)| {
            let selected = form.dest == path;
            Button::new(SharedString::from(format!("move-to:{path}")))
                .ghost()
                .w_full()
                .h(px(32.0))
                .when(selected, |b| b.bg(theme::accent_soft(c)))
                .child(
                    theme::row()
                        .w_full()
                        .pl(px(depth as f32 * 16.0))
                        .child(theme::icon_text(
                            if path.is_empty() {
                                icon::VAULT
                            } else {
                                icon::FOLDER
                            },
                            15.0,
                            if selected { c.accent } else { c.text_muted },
                        ))
                        .child(
                            theme::one_line(theme::text(label, c.text))
                                .flex_1()
                                .when(selected, |t| t.font_weight(FontWeight::SEMIBOLD)),
                        )
                        .when(selected, |r| {
                            r.child(theme::icon_text(icon::CHECK, 15.0, c.accent))
                        }),
                )
                .on_click(v.on(Action::SetMoveDest(path.clone())))
        }));
    let b = body()
        .child(theme::text(
            format!(
                "Choose where to move {n} item{}.",
                if n == 1 { "" } else { "s" }
            ),
            c.text_muted,
        ))
        .child(list);
    let f = footer()
        .child(theme::secondary_button("move-cancel", "Cancel").on_click(v.on(Action::CancelMove)))
        .child(theme::primary_button("move-here", "Move here").on_click(v.on(Action::ConfirmMove)));
    Some(modal("move", "Move to…", Some(Action::CancelMove), b, f, v))
}

/// The in-app quick text editor: a wide dialog holding the file's plaintext
/// in an editable area, with Save / Close. The backdrop and Esc deliberately
/// do *not* dismiss it — only the buttons close it.
fn text_editor(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let te = s.text_editor.as_ref()?;
    let width = (v.window_width - px(96.0)).clamp(px(360.0), px(920.0));
    let editor_h = (v.height - px(200.0)).max(px(160.0));
    let close_label = if te.dirty { "Discard & close" } else { "Close" };
    let card = theme::dialog_surface("text-editor", width, v.height - px(32.0), c)
        .child(
            theme::row()
                .w_full()
                .px(px(20.0))
                .py(px(14.0))
                .border_b_1()
                .border_color(c.border_subtle)
                .child(theme::icon_text(icon::FILE_TEXT, 16.0, c.text_muted))
                .child(theme::one_line(theme::strong(te.leaf.clone(), px(15.0), c.text)).flex_1())
                .child(if te.dirty {
                    theme::badge("Unsaved changes", BadgeKind::Warn, c)
                } else {
                    theme::badge("Saved", BadgeKind::Neutral, c)
                }),
        )
        .child(
            div().h(editor_h).w_full().p(px(12.0)).child(
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
            theme::row()
                .w_full()
                .px(px(20.0))
                .py(px(12.0))
                .border_t_1()
                .border_color(c.border_subtle)
                .child(
                    theme::row()
                        .flex_1()
                        .min_w_0()
                        .child(theme::icon_text(icon::LOCK, 13.0, c.text_subtle))
                        .child(theme::one_line(theme::small(
                            "Edited in memory only — never written to disk unencrypted.",
                            c.text_muted,
                        ))),
                )
                .child(
                    theme::secondary_button("editor-close", close_label)
                        .on_click(v.on(Action::CloseTextEditor)),
                )
                .child(
                    theme::primary_button("editor-save", "Save")
                        .icon(ico(icon::SAVE))
                        .on_click(v.on(Action::SaveTextFile)),
                ),
        );
    Some(
        theme::backdrop("text-editor-backdrop", if c.dark { 150 } else { 90 })
            .child(card)
            .into_any_element(),
    )
}

fn export(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let form = s.export.as_ref()?;
    let mut b = body().child(theme::text(
        "Choose who can open it. Each recipient opens the sent file with their own private key.",
        c.text_muted,
    ));

    let mut recipients = div()
        .id("export-recipients")
        .max_h(px(220.0))
        .overflow_y_scroll()
        .rounded(theme::RADIUS)
        .border_1()
        .border_color(c.border)
        .flex()
        .flex_col();
    if s.contacts.contacts.is_empty() {
        recipients = recipients.child(div().px(px(14.0)).py(px(12.0)).child(theme::muted(
            "You have no contacts yet — add one in Contacts, or include just yourself below.",
            c,
        )));
    }
    for (i, ct) in s.contacts.contacts.iter().enumerate() {
        let fpr_hex = hex(&ct.fingerprint());
        let name = if ct.identity.name.is_empty() {
            "(unnamed)".to_string()
        } else {
            ct.identity.name.clone()
        };
        let badge = match ct.trust {
            Trust::Verified => theme::badge("Verified", BadgeKind::Ok, c),
            Trust::Unverified => theme::badge("Unverified", BadgeKind::Warn, c),
        };
        recipients = recipients.child(theme::list_row_divider(
            i,
            theme::row()
                .w_full()
                .px(px(14.0))
                .py(px(10.0))
                .child(div().flex_1().min_w_0().child(checkbox(
                    SharedString::from(format!("recipient:{fpr_hex}")),
                    name,
                    form.selected.contains(&fpr_hex),
                    {
                        let fpr_hex = fpr_hex.clone();
                        v.on_check(move |_| Action::ToggleRecipient(fpr_hex.clone()))
                    },
                )))
                .child(badge),
            c,
        ));
    }
    b = b
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(6.0))
                .child(theme::caption("Recipients", c))
                .child(recipients),
        )
        .child(checkbox(
            "include-self",
            "Also include me, so I can open it later",
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
        let mut suite = div()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .child(theme::caption("Encryption", c))
            .child(theme::wrap_row().gap(px(4.0)).children(
                [SuiteId::Classic, SuiteId::Aes256Gcm, SuiteId::Hybrid].map(|opt| {
                    let enabled = sender_hybrid || !opt.is_hybrid();
                    super::chip(
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
            ))
            .child(theme::muted(form.suite.label(), c));
        if !sender_hybrid {
            suite = suite.child(theme::muted(
                "Hybrid post-quantum needs a post-quantum identity — upgrade yours in My \
                 identity to enable it.",
                c,
            ));
        }
        b = b.child(suite);
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
                theme::callout(
                    icon::SHIELD,
                    "Every recipient also gets post-quantum protection.",
                    c.ok,
                    c,
                )
            } else {
                theme::callout(
                    icon::WARNING,
                    format!(
                        "No post-quantum key for: {}. Pick another suite, or ask them to \
                         re-share their key.",
                        missing.join(", ")
                    ),
                    c.err,
                    c,
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
        let mut warn = theme::banner(c.warn).child(
            theme::row()
                .w_full()
                .items_start()
                .gap(px(10.0))
                .child(theme::icon_text(icon::WARNING, 16.0, c.warn).mt(px(1.0)))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .gap(px(2.0))
                        .child(theme::strong(
                            "Some recipients aren't verified",
                            theme::TEXT_BODY,
                            c.text,
                        ))
                        .child(theme::muted(
                            "You haven't confirmed these keys out-of-band, so anyone could have \
                             supplied them. Confirm each one for this send only, or verify it \
                             in Contacts first.",
                            c,
                        )),
                ),
        );
        for (fpr, name, safety) in unverified {
            let confirmed = form.confirmed_unverified.contains(&fpr);
            warn = warn.child(
                div()
                    .pl(px(26.0))
                    .pt(px(10.0))
                    .flex()
                    .flex_col()
                    .gap(px(4.0))
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
                    .child(theme::mono(safety, px(11.5), c.text_muted, v.cx).pl(px(26.0))),
            );
        }
        b = b.child(warn);
    }
    let f = footer()
        .child(
            theme::secondary_button("export-cancel", "Cancel").on_click(v.on(Action::CancelExport)),
        )
        .child(
            theme::primary_button("export-go", "Choose file & send…")
                .icon(ico(icon::SEND))
                .on_click(v.on(Action::DoExport)),
        );
    Some(modal_sized(
        "export",
        "Send vault",
        Some(Action::CancelExport),
        b,
        f,
        540.0,
        v,
    ))
}

fn import_info(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let info = s.last_import.as_ref()?;
    let fpr_hex = info.sender_fpr_hex.clone();
    let mut b = body().child(
        theme::row()
            .w_full()
            .gap(px(12.0))
            .child(theme::icon_tile(
                icon::VAULT,
                40.0,
                c.accent,
                theme::accent_soft(c),
            ))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .child(theme::one_line(theme::strong(
                        info.vault_name.clone(),
                        theme::TEXT_BODY,
                        c.text,
                    )))
                    .child(theme::muted(
                        format!(
                            "{} file{} · signature valid",
                            info.file_count,
                            if info.file_count == 1 { "" } else { "s" }
                        ),
                        c,
                    )),
            ),
    );
    // `signature valid` only proves the bytes came from whoever holds these
    // keys — NOT that those keys belong to who you think. The out-of-band
    // safety-number check is what closes that gap, so the dialog nudges toward
    // it whenever the sender isn't verified.
    let sender = match (&info.sender_name, info.verified) {
        (Some(name), true) => theme::callout(
            icon::CHECK_CIRCLE,
            format!("Sent by {name}, a verified contact."),
            c.ok,
            c,
        ),
        (Some(name), false) => theme::callout(
            icon::WARNING,
            format!(
                "Sent by {name}, a known but unverified contact. Verify their safety number \
                 before you trust this content."
            ),
            c.warn,
            c,
        ),
        (None, _) => theme::callout(
            icon::WARNING_CIRCLE,
            "Sent by someone who isn't in your contacts. Add them, then verify their safety \
             number out-of-band before you trust this content.",
            c.err,
            c,
        ),
    };
    b = b.child(sender).child(detail_row(
        "Fingerprint",
        theme::mono(info.sender_fpr_hex.clone(), px(11.5), c.text_muted, v.cx),
        v,
    ));
    let mut f = footer();
    let follow_up = match (&info.sender_name, info.verified) {
        // Known but unverified → jump straight into verification.
        (Some(_), false) => Some(
            theme::primary_button("verify-sender", "Verify sender…")
                .icon(ico(icon::SHIELD))
                .on_click(v.on(Action::BeginVerify(fpr_hex))),
        ),
        // Unknown → offer to add them as a contact first.
        (None, _) => Some(
            theme::primary_button("add-sender", "Add to contacts…")
                .icon(ico(icon::PLUS))
                .on_click(v.on(Action::AddSenderToContacts)),
        ),
        _ => None,
    };
    let ok = if follow_up.is_some() {
        theme::secondary_button("import-ok", "Done")
    } else {
        theme::primary_button("import-ok", "Done")
    };
    f = f
        .child(ok.on_click(v.on(Action::DismissImportInfo)))
        .children(follow_up);
    Some(modal(
        "import-info",
        "Vault imported",
        Some(Action::DismissImportInfo),
        b,
        f,
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
    let mut b = body()
        .child(
            theme::row()
                .w_full()
                .gap(px(12.0))
                .child(theme::avatar(&name, 40.0, c))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .child(theme::one_line(theme::strong(
                            name.clone(),
                            theme::TEXT_BODY,
                            c.text,
                        )))
                        .child(theme::muted("From the public key you provided", c)),
                ),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(6.0))
                .child(theme::caption("Safety number", c))
                .child(safety_inset(&preview.pubid.safety_number(), None, v)),
        )
        .child(detail_row(
            "Fingerprint",
            theme::mono(
                preview.pubid.fingerprint_hex(),
                px(11.5),
                c.text_muted,
                v.cx,
            ),
            v,
        ));
    b = b.child(match &preview.status {
        PreviewStatus::New => theme::callout(
            icon::INFO,
            "New contact. You'll verify their safety number before trusting them.",
            c.text_muted,
            c,
        ),
        PreviewStatus::Existing { verified: true } => theme::callout(
            icon::CHECK_CIRCLE,
            "Already a verified contact — nothing will change.",
            c.ok,
            c,
        ),
        PreviewStatus::Existing { verified: false } => theme::callout(
            icon::INFO,
            "Already a contact (unverified) — nothing will change.",
            c.text_muted,
            c,
        ),
        PreviewStatus::Renamed {
            old,
            verified: true,
        } => theme::callout(
            icon::WARNING,
            format!(
                "This renames a verified contact: “{old}” → “{name}”. The keys are identical, \
                 so verification still holds — but confirm you expected this rename."
            ),
            c.err,
            c,
        ),
        PreviewStatus::Renamed {
            old,
            verified: false,
        } => theme::callout(
            icon::INFO,
            format!("The display name will change: “{old}” → “{name}”."),
            c.warn,
            c,
        ),
        PreviewStatus::SelfKey => theme::callout(
            icon::WARNING_CIRCLE,
            "This is your own public key — you don't need to add yourself.",
            c.err,
            c,
        ),
    });
    let add_label = match &preview.status {
        PreviewStatus::Renamed { .. } => "Update contact",
        _ => "Add contact",
    };
    let f = footer()
        .child(
            theme::secondary_button("preview-cancel", "Cancel")
                .on_click(v.on(Action::CancelPreview)),
        )
        .child(
            theme::enabled(theme::primary_button("add-contact", add_label), !is_self)
                .on_click(v.on(Action::ConfirmAddContact)),
        );
    Some(modal(
        "contact-preview",
        "Review contact",
        Some(Action::CancelPreview),
        b,
        f,
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
            "Compare this number with them over a trusted channel — in person, on a video \
             call, or a line you already trust. Mark verified only when both sides match \
             exactly.",
            c.text_muted,
        ))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(6.0))
                .child(theme::caption("Their safety number should read", c))
                .child(safety_inset(
                    &form.safety_number,
                    Some(any(theme::icon_button(
                        "copy-safety",
                        icon::COPY,
                        "Copy safety number",
                        c,
                    )
                    .small()
                    .on_click(v.on(Action::CopyVerifySafetyNumber)))),
                    v,
                )),
        )
        .child(labelled(
            "What they read back (optional — FileSec checks it for you)",
            text_input(&v.fields.verify_input),
            c,
        ));
    if !typed.trim().is_empty() {
        b = b.child(if typed_match {
            theme::row()
                .child(theme::icon_text(icon::CHECK_CIRCLE, 15.0, c.ok))
                .child(theme::text("Matches.", c.ok))
        } else {
            theme::row()
                .child(theme::icon_text(icon::ERROR, 15.0, c.err))
                .child(theme::text("Doesn't match — don't verify.", c.err))
        });
    }
    b = b.child(checkbox(
        "verify-manual",
        "I compared it myself and it matches exactly",
        form.manual_ok,
        v.on_check(Action::SetVerifyManual),
    ));
    let f = footer()
        .child(
            theme::secondary_button("verify-cancel", "Cancel").on_click(v.on(Action::CancelVerify)),
        )
        .child(
            theme::enabled(
                theme::primary_button("mark-verified", "Mark verified").icon(ico(icon::SHIELD)),
                can_verify,
            )
            .on_click(v.on(Action::ConfirmVerify(form.fpr_hex.clone()))),
        );
    Some(modal(
        "verify",
        format!("Verify {}", form.name),
        Some(Action::CancelVerify),
        b,
        f,
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
        .child(theme::callout(
            icon::WARNING,
            "Your safety number will change. Afterwards, re-share your public key and ask \
             your contacts to verify it again. Import any pending .fsec files first — files \
             sent to your old identity can't be opened after the upgrade.",
            c.warn,
            c,
        ))
        .child(labelled(
            "Current passphrase (it stays your passphrase)",
            v.fields.migrate_pass.clone(),
            c,
        ))
        .children(error_line(&form.error, v));
    let f = footer()
        .child(
            theme::secondary_button("migrate-cancel", "Cancel")
                .on_click(v.on(Action::CancelMigrate)),
        )
        .child(
            theme::primary_button("migrate-go", "Upgrade now")
                .icon(ico(icon::SHIELD))
                .on_click(v.on(Action::DoMigrate)),
        );
    Some(modal(
        "migrate",
        "Upgrade to post-quantum",
        Some(Action::CancelMigrate),
        b,
        f,
        v,
    ))
}

fn add_passkey(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let form = s.add_passkey.as_ref()?;
    let b = body()
        .child(theme::text(
            "Enroll a FIDO2 hardware key (YubiKey, SoloKey, …) as another way to unlock. \
             You'll verify (PIN or biometric) and touch it twice — once to create the key, \
             once to set up unlock. Your passphrase keeps working too.",
            c.text_muted,
        ))
        .child(labelled("Name", text_input(&v.fields.passkey_label), c))
        .child(labelled("Passphrase", v.fields.passkey_pass.clone(), c))
        .child(labelled("Key PIN", v.fields.passkey_pin.clone(), c))
        .children(error_line(&form.error, v));
    let f = footer()
        .child(
            theme::secondary_button("passkey-cancel", "Cancel")
                .on_click(v.on(Action::CancelAddPasskey)),
        )
        .child(
            theme::primary_button("passkey-enroll", "Touch key to enroll")
                .icon(ico(icon::USB))
                .on_click(v.on(Action::AddPasskey)),
        );
    Some(modal(
        "add-passkey",
        "Add security key",
        Some(Action::CancelAddPasskey),
        b,
        f,
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
             automatically here. Your passphrase isn't stored — it still works everywhere \
             and stays your recovery secret.",
            c.text_muted,
        ))
        .child(theme::callout(
            icon::WARNING,
            "Only do this on a trusted personal device: anyone who can use your logged-in \
             account could then open FileSec here.",
            c.warn,
            c,
        ))
        .child(labelled(
            "Confirm your passphrase",
            v.fields.autounlock_pass.clone(),
            c,
        ))
        .children(error_line(&form.error, v));
    let f = footer()
        .child(
            theme::secondary_button("autounlock-cancel", "Cancel")
                .on_click(v.on(Action::CancelEnableAutoUnlock)),
        )
        .child(
            theme::primary_button("autounlock-save", "Remember this device")
                .on_click(v.on(Action::ConfirmEnableAutoUnlock)),
        );
    Some(modal(
        "autounlock",
        "Remember on this device",
        Some(Action::CancelEnableAutoUnlock),
        b,
        f,
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
            "Choose a passphrase for this backup. You'll need it — not your everyday \
             passphrase — to restore the identity later, so it can be different.",
            c.text_muted,
        ))
        .child(theme::callout(
            icon::WARNING,
            "The backup file holds your private keys. Anyone with the file and this \
             passphrase can act as you — keep both safe.",
            c.warn,
            c,
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
        .children(error_line(&form.error, v));
    let f = footer()
        .child(
            theme::secondary_button("export-identity-cancel", "Cancel")
                .on_click(v.on(Action::CancelExportIdentity)),
        )
        .child(
            theme::primary_button("export-identity-go", "Choose file & export…")
                .icon(ico(icon::SAVE))
                .on_click(v.on(Action::DoExportIdentity)),
        );
    Some(modal(
        "export-identity",
        "Export identity backup",
        Some(Action::CancelExportIdentity),
        b,
        f,
        v,
    ))
}
