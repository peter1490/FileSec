//! "Your vaults": the vault list, the new-vault composer, and each vault's card.

use gpui_kit::{div, prelude::*, px, Div, ElementId, SharedString, TestSupportExt};

use crate::store::VaultMeta;
use crate::theme::{self, icon};

use super::{any, search_field, text_input, tooltip_text, View};
use crate::app::model::{fmt_date, human_size};
use crate::app::{Action, Session};

pub(in crate::app) fn vaults(s: &Session, v: &View) -> impl IntoElement {
    let c = v.c;
    let actions = theme::row()
        .child(
            theme::primary_button("new-vault", "+  New vault")
                .on_click(v.on(Action::ToggleNewVault(!s.show_new_vault))),
        )
        .child(
            theme::secondary_button("import-fsec", "Import .fsec…")
                .on_click(v.on(Action::ImportContainer)),
        );
    div()
        .size_full()
        .flex()
        .flex_col()
        .child(theme::section_header(
            "Your vaults",
            Some(any(actions)),
            v.wide(),
            c,
        ))
        .child(theme::page_description(
            "Keep files in encrypted vaults. Share a vault securely with the people you choose.",
            c,
        ))
        .child(super::page_scroll("vault-list").children(vault_list(s, v)))
}

fn stat(value: String, label: &'static str, v: &View) -> Div {
    let c = v.c;
    theme::card(c)
        .flex_1()
        .gap(px(2.0))
        .child(theme::strong(value, px(24.0), c.text))
        .child(theme::small(label, c.text_muted))
}

fn vault_list(s: &Session, v: &View) -> Vec<gpui_kit::AnyElement> {
    let c = v.c;
    let mut out = Vec::new();
    if !s.registry.vaults.is_empty() {
        let files = s
            .registry
            .vaults
            .iter()
            .fold(0u64, |total, v| total.saturating_add(v.file_count));
        let bytes = s
            .registry
            .vaults
            .iter()
            .fold(0u64, |total, v| total.saturating_add(v.total_size));
        if v.wide() {
            out.push(any(theme::row()
                .w_full()
                .items_start()
                .child(stat(s.registry.vaults.len().to_string(), "Vaults", v))
                .child(stat(files.to_string(), "Files", v))
                .child(stat(human_size(bytes), "File contents", v))));
        } else {
            out.push(any(theme::muted(
                format!(
                    "{} vaults · {files} files · {} of file contents",
                    s.registry.vaults.len(),
                    human_size(bytes)
                ),
                c,
            )));
        }
    }

    if s.show_new_vault {
        let ready = !v.text(&v.fields.new_vault_name).trim().is_empty();
        out.push(any(theme::card(c)
            .child(theme::strong("Create a vault", theme::TEXT_BODY, c.text))
            .child(theme::muted(
                "Give this collection a name. You can add files next.",
                c,
            ))
            .child(text_input(&v.fields.new_vault_name))
            .child(
                theme::row()
                    .child(
                        theme::enabled(
                            theme::primary_button("create-vault", "Create vault"),
                            ready,
                        )
                        .on_click(v.on(Action::CreateVault)),
                    )
                    .child(
                        theme::secondary_button("cancel-new-vault", "Cancel")
                            .on_click(v.on(Action::ToggleNewVault(false))),
                    ),
            )));
    }

    if s.registry.vaults.is_empty() {
        if !s.show_new_vault {
            out.push(any(theme::empty_state(
                icon::VAULT,
                "A private place for your files",
                "Create your first vault, then add files or drag them in from your computer.",
                Some(any(theme::primary_button(
                    "first-vault",
                    "Create your first vault",
                )
                .on_click(v.on(Action::ToggleNewVault(true))))),
                c,
            )));
        }
        return out;
    }

    out.push(any(search_field(
        "clear-vault-search",
        &v.fields.vault_search,
        Action::ClearVaultSearch,
        v,
    )));
    let query = v.text(&v.fields.vault_search).trim().to_lowercase();
    let mut vaults: Vec<_> = s
        .registry
        .vaults
        .iter()
        .filter(|vm| vm.name.to_lowercase().contains(&query))
        .collect();
    vaults.sort_by_key(|vm| std::cmp::Reverse(vm.modified_at));
    out.push(any(theme::muted(
        format!(
            "{} vault{} · Recently updated first",
            vaults.len(),
            if vaults.len() == 1 { "" } else { "s" }
        ),
        c,
    )));
    if vaults.is_empty() {
        out.push(any(theme::empty_state(
            icon::VAULT,
            "No matching vaults",
            "Try another name or clear your search.",
            Some(any(theme::secondary_button(
                "clear-search-empty",
                "Clear search",
            )
            .on_click(v.on(Action::ClearVaultSearch)))),
            c,
        )));
    }
    for vault in vaults {
        out.push(any(vault_card(vault, v)));
    }
    out
}

/// The name and the "files · size · updated" line.
fn vault_details(vault: &VaultMeta, v: &View) -> Div {
    let c = v.c;
    let detail = format!(
        "{} file{} · {} · Updated {}",
        vault.file_count,
        if vault.file_count == 1 { "" } else { "s" },
        human_size(vault.total_size),
        fmt_date(vault.modified_at)
    );
    theme::row()
        .flex_1()
        .min_w_0()
        .gap(px(10.0))
        .child(theme::icon_text(icon::VAULT, 24.0, c.accent))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .flex_col()
                .gap(px(2.0))
                .child(
                    div()
                        .id(ElementId::Name(format!("vault-name-{}", vault.id).into()))
                        .w_full()
                        .tooltip(tooltip_text(vault.name.clone()))
                        .child(theme::one_line(theme::strong(
                            vault.name.clone(),
                            px(16.0),
                            c.text,
                        )))
                        .test_support(),
                )
                .child(
                    div()
                        .id(ElementId::Name(format!("vault-detail-{}", vault.id).into()))
                        .w_full()
                        .child(theme::one_line(theme::small(detail, c.text_muted)))
                        .test_support(),
                ),
        )
}

fn vault_actions(vault: &VaultMeta, v: &View) -> Div {
    let id = &vault.id;
    theme::row()
        .flex_none()
        .child(
            theme::primary_button(SharedString::from(format!("open-vault-{id}")), "Open vault")
                .on_click(v.on(Action::OpenVault(id.clone()))),
        )
        .child(
            theme::secondary_button(SharedString::from(format!("send-vault-{id}")), "Send…")
                .on_click(v.on(Action::BeginExport(id.clone()))),
        )
        .child(
            theme::icon_button(
                SharedString::from(format!("delete-vault-{id}")),
                icon::TRASH,
                "Delete vault…",
                v.c,
            )
            .on_click(v.on(Action::RequestDeleteVault(id.clone()))),
        )
}

fn vault_card(vault: &VaultMeta, v: &View) -> Div {
    let c = v.c;
    let card = theme::card(c);
    if v.width >= px(620.0) {
        card.child(
            theme::row()
                .w_full()
                .gap(px(12.0))
                .child(vault_details(vault, v))
                .child(vault_actions(vault, v)),
        )
    } else {
        card.child(vault_details(vault, v))
            .child(vault_actions(vault, v))
    }
}
