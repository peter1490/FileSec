//! "Contacts": add a contact (file or pasted key), and the contact cards with
//! their safety numbers and trust actions.

use gpui_kit::component::input::Textarea;
use gpui_kit::{div, prelude::*, px, AnyElement, Div, ElementId, SharedString};

use filesec_core::contacts::Trust;
use filesec_core::util::hex;

use crate::theme::{self, icon, BadgeKind};

use super::{any, disclosure, search_field, tooltip_text, View};
use crate::app::model::fmt_date;
use crate::app::{Action, Session};

/// Keep safety-number groups intact while allowing a narrow window to wrap them.
pub(in crate::app) fn safety_number(number: &str, v: &View) -> Div {
    let groups: Vec<_> = number.split('-').collect();
    theme::wrap_row().gap(px(10.0)).children(
        groups
            .chunks(4)
            .map(|g| theme::mono(g.join("-"), theme::TEXT_MONO, v.c.accent, v.cx)),
    )
}

pub(in crate::app) fn contacts(s: &Session, v: &View) -> impl IntoElement {
    let c = v.c;
    div()
        .size_full()
        .flex()
        .flex_col()
        .child(theme::section_header("Contacts", None, v.wide(), c))
        .child(theme::page_description(
            "Choose who can receive your vaults. Compare safety numbers in person or over \
             a trusted channel before marking a contact as verified.",
            c,
        ))
        .child(super::page_scroll("contacts-scroll").children(contact_list(s, v)))
}

fn add_contact_card(s: &Session, v: &View) -> Div {
    let c = v.c;
    let open = s.show_add_contact;
    let mut card = theme::card(c).child(disclosure(
        "add-contact-toggle",
        "Add a contact",
        open,
        v.on(Action::ToggleAddContact(!open)),
        c,
    ));
    if open {
        let has_paste = !v.fields.contact_paste.read(v.cx).value().trim().is_empty();
        card = card
            .child(
                theme::row().child(
                    theme::secondary_button("choose-pubkey", "Choose public key file…")
                        .on_click(v.on(Action::PreviewContactFile)),
                ),
            )
            .child(theme::muted(
                "Accepts .fsecpub files, or paste a public key below.",
                c,
            ))
            .child(Textarea::new(&v.fields.contact_paste).w_full())
            .child(
                theme::row().child(
                    theme::enabled(
                        theme::primary_button("preview-contact", "Preview contact…"),
                        has_paste,
                    )
                    .on_click(v.on(Action::PreviewContactPaste)),
                ),
            )
            .child(theme::muted(
                "Review the identity before adding it to your contacts.",
                c,
            ));
    }
    card
}

fn contact_list(s: &Session, v: &View) -> Vec<AnyElement> {
    let c = v.c;
    let mut out = vec![any(add_contact_card(s, v))];
    if s.contacts.contacts.is_empty() {
        out.push(any(theme::empty_state(
            icon::CONTACTS,
            "Secure sharing starts with a contact",
            "Ask someone for their FileSec public key and add it above.",
            None,
            c,
        )));
        return out;
    }
    let verified = s
        .contacts
        .contacts
        .iter()
        .filter(|ct| ct.trust == Trust::Verified)
        .count();
    out.push(any(theme::muted(
        format!(
            "{} contacts · {verified} verified",
            s.contacts.contacts.len()
        ),
        c,
    )));
    out.push(any(search_field(
        "clear-contact-search",
        &v.fields.contact_search,
        Action::ClearContactSearch,
        v,
    )));
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
            icon::CONTACTS,
            "No matching contacts",
            "Try another name or fingerprint.",
            Some(any(theme::secondary_button(
                "clear-contacts-empty",
                "Clear search",
            )
            .on_click(v.on(Action::ClearContactSearch)))),
            c,
        )));
    }
    for contact in contacts {
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
            Trust::Verified => theme::secondary_button(
                SharedString::from(format!("unverify:{fpr_hex}")),
                "Mark unverified",
            )
            .on_click(v.on(Action::SetTrust(fpr_hex.clone(), Trust::Unverified))),
            Trust::Unverified => theme::primary_button(
                SharedString::from(format!("verify:{fpr_hex}")),
                "Verify contact…",
            )
            .on_click(v.on(Action::BeginVerify(fpr_hex.clone()))),
        };
        let card = theme::card(c)
            .child(
                theme::row()
                    .w_full()
                    .child(theme::icon_text(icon::CONTACTS, 22.0, c.accent))
                    .child(
                        div()
                            .id(ElementId::Name(format!("contact-name:{fpr_hex}").into()))
                            .flex_1()
                            .min_w_0()
                            .tooltip(tooltip_text(name.clone()))
                            .child(theme::one_line(theme::strong(name, px(16.0), c.text))),
                    )
                    .child(badge),
            )
            .child(theme::small("Safety number", c.text_muted))
            .child(safety_number(&contact.identity.safety_number(), v))
            .children(match (contact.trust, contact.verified_at) {
                (Trust::Verified, Some(t)) => {
                    Some(theme::muted(format!("Verified {}", fmt_date(t)), c))
                }
                _ => None,
            })
            .child(
                theme::row()
                    .w_full()
                    .child(trust_action)
                    .child(div().flex_1())
                    .child(
                        theme::icon_button(
                            SharedString::from(format!("remove-contact:{fpr_hex}")),
                            icon::TRASH,
                            "Remove contact…",
                            c,
                        )
                        .on_click(v.on(Action::RemoveContact(fpr_hex.clone()))),
                    ),
            );
        out.push(any(card));
    }
    out
}
