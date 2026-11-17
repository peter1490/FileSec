//! "Vaults": the vault list, the new-vault composer, and each vault's row.

use gpui_kit::{div, prelude::*, px, AnyElement, Div, ElementId, SharedString, TestSupportExt};

use crate::store::VaultMeta;
use crate::theme::{self, ico, icon};

use super::{any, page, search_field, text_input, tooltip_text, View};
use crate::app::model::{fmt_date, human_size};
use crate::app::{Action, Session};

pub(in crate::app) fn vaults(s: &Session, v: &View) -> impl IntoElement {
    let actions = theme::row()
        .child(
            theme::secondary_button("import-fsec", "Import .fsec…")
                .icon(ico(icon::IMPORT))
                .on_click(v.on(Action::ImportContainer)),
        )
        .child({
            // One primary action per screen: while the composer is open (its
            // Create is the next step) or the empty state offers its own call
            // to action, the header button steps back to secondary.
            let quiet = s.show_new_vault || s.registry.vaults.is_empty();
            let b = if quiet {
                theme::secondary_button("new-vault", "New vault")
            } else {
                theme::primary_button("new-vault", "New vault")
            };
            b.icon(ico(icon::PLUS))
                .on_click(v.on(Action::ToggleNewVault(!s.show_new_vault)))
        });
    page("vault-list", "Vaults", Some(any(actions)), body(s, v), v)
}

/// One figure of the summary strip.
fn stat(value: String, label: &'static str, first: bool, v: &View) -> Div {
    let c = v.c;
    div()
        .flex_1()
        .min_w_0()
        .px(px(18.0))
        .py(px(14.0))
        .flex()
        .flex_col()
        .gap(px(2.0))
        .when(!first, |d| d.border_l_1().border_color(c.border_subtle))
        .child(theme::muted(label, c))
        .child(theme::one_line(theme::strong(value, px(20.0), c.text)))
}

fn body(s: &Session, v: &View) -> Vec<AnyElement> {
    let c = v.c;
    let mut out = Vec::new();

    if s.show_new_vault {
        out.push(any(new_vault_composer(v)));
    }

    if s.registry.vaults.is_empty() {
        if !s.show_new_vault {
            out.push(any(theme::empty_state(
                icon::VAULT,
                "A private place for your files",
                "Create your first vault, then add files or drag them in from your computer. \
                 Everything inside is encrypted to your identity.",
                Some(any(theme::primary_button(
                    "first-vault",
                    "Create your first vault",
                )
                .icon(ico(icon::PLUS))
                .on_click(v.on(Action::ToggleNewVault(true))))),
                c,
            )));
        }
        return out;
    }

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
        out.push(any(theme::list_container(c)
            .flex_row()
            .child(stat(s.registry.vaults.len().to_string(), "Vaults", true, v))
            .child(stat(files.to_string(), "Files", false, v))
            .child(stat(human_size(bytes), "Stored, encrypted", false, v))));
    }

    let query = v.text(&v.fields.vault_search).trim().to_lowercase();
    let mut vaults: Vec<_> = s
        .registry
        .vaults
        .iter()
        .filter(|vm| vm.name.to_lowercase().contains(&query))
        .collect();
    vaults.sort_by_key(|vm| std::cmp::Reverse(vm.modified_at));

    let count = if v.wide() {
        format!(
            "{} vault{} · recently updated first",
            vaults.len(),
            if vaults.len() == 1 { "" } else { "s" }
        )
    } else {
        format!(
            "{} vaults · {files} files · {}",
            vaults.len(),
            human_size(bytes)
        )
    };
    out.push(any(theme::wrap_row()
        .w_full()
        .justify_between()
        .gap(px(12.0))
        .child(div().w(px(280.0)).max_w_full().child(search_field(
            "clear-vault-search",
            &v.fields.vault_search,
            Action::ClearVaultSearch,
            v,
        )))
        .child(theme::muted(count, c))));

    if vaults.is_empty() {
        out.push(any(theme::empty_state(
            icon::SEARCH,
            "No matching vaults",
            "Try another name, or clear the search to see every vault.",
            Some(any(theme::secondary_button(
                "clear-search-empty",
                "Clear search",
            )
            .on_click(v.on(Action::ClearVaultSearch)))),
            c,
        )));
        return out;
    }

    let mut list = theme::list_container(c);
    for (i, vault) in vaults.into_iter().enumerate() {
        list = list.child(theme::list_row_divider(i, vault_row(vault, v), c));
    }
    out.push(any(list));
    out
}

fn new_vault_composer(v: &View) -> Div {
    let c = v.c;
    let ready = !v.text(&v.fields.new_vault_name).trim().is_empty();
    theme::card(c)
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(2.0))
                .child(theme::strong("New vault", theme::TEXT_H2, c.text))
                .child(theme::muted(
                    "Name the collection. You can add files right after.",
                    c,
                )),
        )
        .child(text_input(&v.fields.new_vault_name))
        .child(
            theme::row()
                .justify_end()
                .child(
                    theme::ghost_button("cancel-new-vault", "Cancel")
                        .on_click(v.on(Action::ToggleNewVault(false))),
                )
                .child(
                    theme::enabled(theme::primary_button("create-vault", "Create vault"), ready)
                        .on_click(v.on(Action::CreateVault)),
                ),
        )
}

/// The icon, name and "files · size · updated" line.
fn vault_details(vault: &VaultMeta, v: &View) -> Div {
    let c = v.c;
    let detail = if vault.file_count == 0 {
        format!("Empty · Updated {}", fmt_date(vault.modified_at))
    } else {
        format!(
            "{} file{} · {} · Updated {}",
            vault.file_count,
            if vault.file_count == 1 { "" } else { "s" },
            human_size(vault.total_size),
            fmt_date(vault.modified_at)
        )
    };
    theme::row()
        .flex_1()
        .min_w_0()
        .gap(px(12.0))
        .child(theme::icon_tile(
            icon::VAULT,
            38.0,
            c.accent,
            theme::accent_soft(c),
        ))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .flex_col()
                .gap(px(1.0))
                .child(
                    div()
                        .id(ElementId::Name(format!("vault-name-{}", vault.id).into()))
                        .w_full()
                        .tooltip(tooltip_text(vault.name.clone()))
                        .child(theme::one_line(theme::strong(
                            vault.name.clone(),
                            theme::TEXT_BODY,
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
        .gap(px(4.0))
        .child(
            theme::icon_button(
                SharedString::from(format!("send-vault-{id}")),
                icon::SEND,
                "Send vault…",
                v.c,
            )
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
        .child(div().w(px(4.0)))
        .child(
            theme::secondary_button(SharedString::from(format!("open-vault-{id}")), "Open")
                .on_click(v.on(Action::OpenVault(id.clone()))),
        )
}

/// A vault row. Double-clicking anywhere on it opens the vault, like a file
/// manager; the explicit "Open" button stays for discoverability.
fn vault_row(vault: &VaultMeta, v: &View) -> impl IntoElement {
    let c = v.c;
    let open = v.on(Action::OpenVault(vault.id.clone()));
    div()
        .id(ElementId::Name(format!("vault-row-{}", vault.id).into()))
        .w_full()
        .px(px(16.0))
        .py(px(12.0))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(12.0))
        .hover(|s| s.bg(c.surface_hi))
        .on_click(move |event, window, cx| {
            if event.click_count() >= 2 {
                open(event, window, cx);
            }
        })
        .child(vault_details(vault, v))
        .child(vault_actions(vault, v))
}
