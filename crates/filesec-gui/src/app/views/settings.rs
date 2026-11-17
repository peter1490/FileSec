//! "Settings": appearance, storage location, on-device protections, and
//! build details.

use gpui_kit::{div, prelude::*, px, AnyElement, Div, SharedString};

use crate::autounlock;
use crate::passkey;
use crate::prefs::ThemeChoice;
use crate::theme::{self, icon, BadgeKind};

use super::{any, chip, disclosure, View};
use crate::app::model::{build_variant, compiled_features};
use crate::app::{Action, Session};

/// A two-column "label: value" line (egui's `Grid`).
fn grid_row(label: &'static str, value: impl IntoElement, v: &View) -> Div {
    theme::row()
        .w_full()
        .gap(px(12.0))
        .child(
            div()
                .w(px(170.0))
                .flex_none()
                .child(theme::text(label, v.c.text_muted)),
        )
        .child(div().flex_1().min_w_0().flex().items_center().child(value))
}

pub(in crate::app) fn settings(s: &Session, v: &View) -> impl IntoElement {
    let c = v.c;
    div()
        .size_full()
        .flex()
        .flex_col()
        .child(theme::section_header("Settings", None, v.wide(), c))
        .child(super::page_scroll("settings-scroll").children(cards(s, v)))
}

fn cards(s: &Session, v: &View) -> Vec<AnyElement> {
    let c = v.c;
    let mut out = Vec::new();

    // ------------------------------------------------------------ Appearance
    // The theme global holds the live preference, so read it back rather than
    // keeping a second copy that could drift from what is on screen.
    let current = theme::current_choice(v.cx);
    let hint = match current {
        ThemeChoice::System => {
            if theme::is_dark(v.cx) {
                "Following the system appearance (currently dark)."
            } else {
                "Following the system appearance (currently light)."
            }
        }
        ThemeChoice::Light => "Always light, whatever the system is set to.",
        ThemeChoice::Dark => "Always dark, whatever the system is set to.",
    };
    out.push(any(theme::card(c)
        .child(theme::strong("Appearance", theme::TEXT_BODY, c.text))
        .child(
            theme::row().children(ThemeChoice::ALL.into_iter().map(|choice| {
                chip(
                    SharedString::from(format!("theme-{}", choice.label().to_lowercase())),
                    choice.label(),
                    current == choice,
                    true,
                    v.on(Action::SetTheme(choice)),
                )
            })),
        )
        .child(theme::muted(hint, c))));

    // ---------------------------------------------------------------- Data
    out.push(any(theme::card(c)
        .child(theme::strong("Data folder", theme::TEXT_BODY, c.text))
        .child(theme::mono(
            s.data_dir.clone(),
            theme::TEXT_SMALL,
            c.text,
            v.cx,
        ))
        .child(
            theme::row()
                .child(
                    theme::icon_button("copy-data-dir", icon::COPY, "Copy path", c)
                        .on_click(v.on(Action::CopyDataDir)),
                )
                .child(
                    theme::secondary_button("reveal-data-dir", "Show in file manager")
                        .on_click(v.on(Action::RevealDataDir)),
                ),
        )
        .child(theme::muted(
            "Vaults, contacts and the vault index are encrypted to your own identity \
                 here. Set FILESEC_DATA_DIR to use a different folder.",
            c,
        ))));

    // ---------------------------------------------------- On-device protection
    let mut protection = theme::card(c)
        .child(theme::strong(
            "Protection on this device",
            theme::TEXT_BODY,
            c.text,
        ))
        .child(grid_row(
            "Rollback protection",
            if s.rollback_warning.is_some() {
                theme::badge("Degraded", BadgeKind::Warn, c)
            } else {
                theme::badge("OS secure storage", BadgeKind::Ok, c)
            },
            v,
        ))
        .child(grid_row(
            "Unlock on this device",
            if autounlock::SUPPORTED {
                theme::badge("Available", BadgeKind::Ok, c)
            } else {
                theme::badge("Not in this build", BadgeKind::Neutral, c)
            },
            v,
        ))
        .child(grid_row(
            "Security keys",
            if passkey::SUPPORTED {
                theme::badge("Supported", BadgeKind::Ok, c)
            } else {
                theme::badge("Not in this build", BadgeKind::Neutral, c)
            },
            v,
        ));
    if let Some(warning) = &s.rollback_warning {
        protection =
            protection.child(theme::banner(c.warn).child(theme::small(warning.clone(), c.text)));
    }
    if autounlock::SUPPORTED {
        if let Some(note) = autounlock::device_binding_warning() {
            protection = protection.child(theme::muted(note, c));
        }
    }
    out.push(any(protection));

    // --------------------------------------------------------------- About
    let features = compiled_features();
    let features = if features.is_empty() {
        "none".to_string()
    } else {
        features.join(", ")
    };
    let mut about = theme::card(c)
        .child(
            theme::row()
                .w_full()
                .child(theme::strong("About", theme::TEXT_BODY, c.text))
                .child(div().flex_1())
                .child(
                    theme::icon_button("copy-build-info", icon::COPY, "Copy build details", c)
                        .on_click(v.on(Action::CopyBuildInfo)),
                ),
        )
        .child(grid_row(
            "Version",
            theme::strong(env!("CARGO_PKG_VERSION"), theme::TEXT_BODY, c.text),
            v,
        ))
        .child(grid_row("Build", theme::text(build_variant(), c.text), v))
        .child(grid_row(
            "Platform",
            theme::mono(env!("FILESEC_TARGET"), theme::TEXT_SMALL, c.text, v.cx),
            v,
        ))
        .child(grid_row(
            "Features",
            theme::mono(features, theme::TEXT_SMALL, c.text, v.cx),
            v,
        ))
        .child(disclosure(
            "notices-toggle",
            "Open-source notices",
            s.show_notices,
            v.on(Action::ToggleNotices),
            c,
        ));
    if s.show_notices {
        about = about
            .child(theme::muted(
                "FileSec is licensed under MIT OR Apache-2.0. It embeds the \
                 typefaces below; the license notices of every library linked \
                 into this app ship next to it as THIRD_PARTY_NOTICES.txt (in the \
                 installation folder, the .app's Resources, the download archive, \
                 or /usr/share/doc on Linux).",
                c,
            ))
            .child(
                div()
                    .id("notices-scroll")
                    .max_h(px(280.0))
                    .overflow_y_scroll()
                    .flex()
                    .flex_col()
                    .gap(px(10.0))
                    .children(theme::EMBEDDED_ASSET_NOTICES.iter().map(|(title, text)| {
                        div()
                            .flex()
                            .flex_col()
                            .gap(px(4.0))
                            .child(theme::strong(*title, theme::TEXT_BODY, c.text))
                            .child(theme::mono(*text, theme::TEXT_SMALL, c.text_muted, v.cx))
                    })),
            );
    }
    out.push(any(about));
    out
}
