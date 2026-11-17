//! "Contacts": add a contact (file or pasted key), and the contact list with
//! each contact's safety number and trust actions.

use gpui_kit::component::input::Textarea;
use gpui_kit::component::Sizable;
use gpui_kit::{div, prelude::*, px, AnyElement, Div, ElementId, SharedString};

use filesec_core::contacts::{Contact, Trust};
use filesec_core::util::hex;

use crate::theme::{self, ico, icon, BadgeKind};

use super::{any, page, search_field, tooltip_text, View};
use crate::app::model::fmt_date;
use crate::app::{Action, Session};

/// A safety number, in groups of four blocks that wrap together on narrow
/// windows. `strong` renders it at reading size in the accent colour (for
/// comparing); otherwise it is a quiet secondary line.
pub(in crate::app) fn safety_number_styled(number: &str, strong: bool, v: &View) -> Div {
    let groups: Vec<_> = number.split('-').collect();
    let (size, color) = if strong {
        (theme::TEXT_MONO, v.c.text)
    } else {
        (px(12.0), v.c.text_muted)
    };
    theme::wrap_row()
        .gap_x(px(0.0))
        .gap_y(px(2.0))
        .children(groups.chunks(4).map(|g| {
            theme::mono(g.join(" "), size, color, v.cx).mr(px(if strong { 10.0 } else { 8.0 }))
        }))
}

/// The prominent safety number used where it is compared.
pub(in crate::app) fn safety_number(number: &str, v: &View) -> Div {
    safety_number_styled(number, true, v)
}

pub(in crate::app) fn contacts(s: &Session, v: &View) -> impl IntoElement {
    let open = s.show_add_contact;
    let action = if open {
        theme::ghost_button("add-contact-toggle", "Close")
            .on_click(v.on(Action::ToggleAddContact(false)))
    } else {
        // The empty state carries its own primary call to action.
        let b = if s.contacts.contacts.is_empty() {
            theme::secondary_button("add-contact-toggle", "Add contact")
        } else {
            theme::primary_button("add-contact-toggle", "Add contact")
        };
        b.icon(ico(icon::PLUS))
            .on_click(v.on(Action::ToggleAddContact(true)))
    };
    page(
        "contacts-scroll",
        "Contacts",
        Some(any(action)),
        contact_list(s, v),
        v,
    )
}

fn add_contact_panel(v: &View) -> Div {
    let c = v.c;
    let has_paste = !v.fields.contact_paste.read(v.cx).value().trim().is_empty();
    theme::card(c)
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(2.0))
                .child(theme::strong("Add a contact", theme::TEXT_H2, c.text))
                .child(theme::muted(
                    "Use the public key they shared with you — a .fsecpub file or the pasted \
                     text. You'll review who it belongs to before anything is saved.",
                    c,
                )),
        )
        .child(
            theme::row().child(
                theme::secondary_button("choose-pubkey", "Choose public key file…")
                    .icon(ico(icon::FILE))
                    .on_click(v.on(Action::PreviewContactFile)),
            ),
        )
        .child(theme::divider_or(c))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(6.0))
                .child(theme::caption("Paste a public key", c))
                .child(Textarea::new(&v.fields.contact_paste).w_full().h(px(96.0))),
        )
        .child(
            theme::row().justify_end().child(
                theme::enabled(
                    theme::primary_button("preview-contact", "Review contact…"),
                    has_paste,
                )
                .on_click(v.on(Action::PreviewContactPaste)),
            ),
        )
}

fn contact_list(s: &Session, v: &View) -> Vec<AnyElement> {
    let c = v.c;
    let mut out = Vec::new();
    out.push(any(theme::page_description(
        "The people you can send vaults to. Before you mark someone verified, compare \
         safety numbers in person or over a channel you already trust.",
        c,
    )));
    if s.show_add_contact {
        out.push(any(add_contact_panel(v)));
    }
    if s.contacts.contacts.is_empty() {
        if !s.show_add_contact {
            out.push(any(theme::empty_state(
                icon::CONTACTS,
                "Secure sharing starts with a contact",
                "Ask someone for their FileSec public key, then add it here.",
                Some(any(theme::primary_button(
                    "add-contact-empty",
                    "Add contact",
                )
                .icon(ico(icon::PLUS))
                .on_click(v.on(Action::ToggleAddContact(true))))),
                c,
            )));
        }
        return out;
    }
    let verified = s
        .contacts
        .contacts
        .iter()
        .filter(|ct| ct.trust == Trust::Verified)
        .count();
    out.push(any(theme::wrap_row()
        .w_full()
        .justify_between()
        .gap(px(12.0))
        .child(div().w(px(280.0)).max_w_full().child(search_field(
            "clear-contact-search",
            &v.fields.contact_search,
            Action::ClearContactSearch,
            v,
        )))
        .child(theme::muted(
            format!(
                "{} contact{} · {verified} verified",
                s.contacts.contacts.len(),
                if s.contacts.contacts.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            c,
        ))));
    let query = v.text(&v.fields.contact_search).trim().to_lowercase();
    let mut contacts: Vec<_> = s
        .contacts
        .contacts
        .iter()
        .filter(|contact| {
            contact.identity.name.to_lowercase().contains(&query)
                || hex(&contact.fingerprint()).contains(&query)
        })
        .collect();
    contacts.sort_by_cached_key(|contact| contact.identity.name.to_lowercase());
    if contacts.is_empty() {
        out.push(any(theme::empty_state(
            icon::SEARCH,
            "No matching contacts",
            "Try another name or fingerprint.",
            Some(any(theme::secondary_button(
                "clear-contacts-empty",
                "Clear search",
            )
            .on_click(v.on(Action::ClearContactSearch)))),
            c,
        )));
        return out;
    }
    let mut list = theme::list_container(c);
    for (i, contact) in contacts.into_iter().enumerate() {
        list = list.child(theme::list_row_divider(i, contact_row(contact, v), c));
    }
    out.push(any(list));
    out
}

fn contact_row(contact: &Contact, v: &View) -> Div {
    let c = v.c;
    let fpr_hex = hex(&contact.fingerprint());
    let name = if contact.identity.name.is_empty() {
        "Unnamed contact".to_string()
    } else {
        contact.identity.name.clone()
    };
    let badge = match contact.trust {
        Trust::Verified => theme::badge("Verified", BadgeKind::Ok, c),
        Trust::Unverified => theme::badge("Unverified", BadgeKind::Warn, c),
    };
    let trust_action = match contact.trust {
        Trust::Verified => theme::ghost_button(
            SharedString::from(format!("unverify:{fpr_hex}")),
            "Mark unverified",
        )
        .small()
        .on_click(v.on(Action::SetTrust(fpr_hex.clone(), Trust::Unverified))),
        Trust::Unverified => {
            theme::secondary_button(SharedString::from(format!("verify:{fpr_hex}")), "Verify…")
                .small()
                .icon(ico(icon::SHIELD))
                .on_click(v.on(Action::BeginVerify(fpr_hex.clone())))
        }
    };
    let subtitle = match (contact.trust, contact.verified_at) {
        (Trust::Verified, Some(t)) => Some(format!("Verified {}", fmt_date(t))),
        _ => None,
    };
    theme::row()
        .w_full()
        .items_start()
        .px(px(16.0))
        .py(px(14.0))
        .gap(px(12.0))
        .child(theme::avatar(&name, 36.0, c))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .flex_col()
                .gap(px(4.0))
                .child(
                    theme::row()
                        .w_full()
                        .child(
                            div()
                                .id(ElementId::Name(format!("contact-name:{fpr_hex}").into()))
                                .min_w_0()
                                .tooltip(tooltip_text(name.clone()))
                                .child(theme::one_line(theme::strong(
                                    name,
                                    theme::TEXT_BODY,
                                    c.text,
                                ))),
                        )
                        .child(badge)
                        .children(subtitle.map(|t| theme::small(t, c.text_subtle))),
                )
                .child(safety_number_styled(
                    &contact.identity.safety_number(),
                    false,
                    v,
                )),
        )
        .child(
            theme::row()
                .flex_none()
                .gap(px(4.0))
                .child(trust_action)
                .child(
                    theme::icon_button(
                        SharedString::from(format!("remove-contact:{fpr_hex}")),
                        icon::TRASH,
                        "Remove contact…",
                        c,
                    )
                    .small()
                    .on_click(v.on(Action::RemoveContact(fpr_hex.clone()))),
                ),
        )
}
