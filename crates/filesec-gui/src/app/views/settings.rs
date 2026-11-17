//! "Settings": appearance, storage location, on-device protections, and
//! build details — grouped settings rows, one control per row.

use gpui_kit::component::Sizable;
use gpui_kit::{div, prelude::*, px, AnyElement, SharedString};

use crate::autounlock;
use crate::passkey;
use crate::prefs::ThemeChoice;
use crate::theme::{self, ico, icon, BadgeKind};

use super::{any, disclosure, page, segmented, Segment, View};
use crate::app::model::{build_variant, compiled_features};
use crate::app::{Action, Session};

pub(in crate::app) fn settings(s: &Session, v: &View) -> impl IntoElement {
    page("settings-scroll", "Settings", None, sections(s, v), v)
}

/// A read-only "label … value" row inside a group.
fn info_row(label: &'static str, value: impl IntoElement, v: &View) -> AnyElement {
    let c = v.c;
    any(theme::row()
        .w_full()
        .px(px(16.0))
        .py(px(11.0))
        .gap(px(16.0))
        .child(
            div()
                .w(px(150.0))
                .flex_none()
                .child(theme::text(label, c.text_muted)),
        )
        .child(div().flex_1().min_w_0().flex().justify_end().child(value)))
}

fn sections(s: &Session, v: &View) -> Vec<AnyElement> {
    let c = v.c;
    let wide = v.wide();
    let mut out = Vec::new();

    // ------------------------------------------------------------ Appearance
    // The theme global holds the live preference, so read it back rather than
    // keeping a second copy that could drift from what is on screen.
    let current = theme::current_choice(v.cx);
    let hint = match current {
        ThemeChoice::System => {
            if theme::is_dark(v.cx) {
                "Follows your system setting (dark right now)."
            } else {
                "Follows your system setting (light right now)."
            }
        }
        ThemeChoice::Light => "Always light, whatever the system is set to.",
        ThemeChoice::Dark => "Always dark, whatever the system is set to.",
    };
    let segments = ThemeChoice::ALL
        .into_iter()
        .map(|choice| Segment {
            id: SharedString::from(format!("theme-{}", choice.label().to_lowercase())),
            label: choice.label(),
            glyph: Some(match choice {
                ThemeChoice::System => icon::MONITOR,
                ThemeChoice::Light => icon::SUN,
                ThemeChoice::Dark => icon::MOON,
            }),
            selected: current == choice,
            action: Action::SetTheme(choice),
        })
        .collect();
    out.push(any(theme::group(
        Some("Appearance"),
        None,
        vec![any(theme::group_row(
            "Theme",
            Some(hint.into()),
            Some(any(segmented(segments, v))),
            wide,
            c,
        ))],
        c,
    )));

    // ---------------------------------------------------------------- Data
    out.push(any(theme::group(
        Some("Storage"),
        Some("Set FILESEC_DATA_DIR before launching to use a different folder.".into()),
        vec![any(theme::group_block(c)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(2.0))
                    .child(theme::text("Data folder", c.text))
                    .child(theme::muted(
                        "Vaults, contacts and the vault index, all encrypted to your identity.",
                        c,
                    )),
            )
            .child(
                theme::row()
                    .w_full()
                    .px(px(10.0))
                    .py(px(8.0))
                    .rounded(theme::RADIUS_SM)
                    .bg(c.surface_hi)
                    .border_1()
                    .border_color(c.border_subtle)
                    .child(theme::icon_text(icon::DRIVE, 15.0, c.text_muted))
                    .child(div().flex_1().min_w_0().child(theme::one_line(theme::mono(
                        s.data_dir.clone(),
                        theme::TEXT_SMALL,
                        c.text,
                        v.cx,
                    ))))
                    .child(
                        theme::icon_button("copy-data-dir", icon::COPY, "Copy path", c)
                            .small()
                            .on_click(v.on(Action::CopyDataDir)),
                    ),
            )
            .child(
                theme::row().child(
                    theme::secondary_button("reveal-data-dir", "Show in file manager")
                        .small()
                        .icon(ico(icon::EXTERNAL))
                        .on_click(v.on(Action::RevealDataDir)),
                ),
            ))],
        c,
    )));

    // ---------------------------------------------------- On-device protection
    let mut protection = vec![
        info_row(
            "Rollback protection",
            if s.rollback_warning.is_some() {
                theme::badge("Degraded", BadgeKind::Warn, c)
            } else {
                theme::badge("OS secure storage", BadgeKind::Ok, c)
            },
            v,
        ),
        info_row(
            "Unlock on this device",
            if autounlock::SUPPORTED {
                theme::badge("Available", BadgeKind::Ok, c)
            } else {
                theme::badge("Not in this build", BadgeKind::Neutral, c)
            },
            v,
        ),
        info_row(
            "Security keys",
            if passkey::SUPPORTED {
                theme::badge("Supported", BadgeKind::Ok, c)
            } else {
                theme::badge("Not in this build", BadgeKind::Neutral, c)
            },
            v,
        ),
    ];
    if let Some(warning) = &s.rollback_warning {
        protection.push(any(theme::group_block(c).child(theme::callout(
            icon::WARNING,
            warning.clone(),
            c.warn,
            c,
        ))));
    }
    let binding_note = if autounlock::SUPPORTED {
        autounlock::device_binding_warning().map(SharedString::from)
    } else {
        None
    };
    out.push(any(theme::group(
        Some("Protection on this device"),
        binding_note,
        protection,
        c,
    )));

    // --------------------------------------------------------------- About
    let features = compiled_features();
    let features = if features.is_empty() {
        "none".to_string()
    } else {
        features.join(", ")
    };
    let mut about = vec![
        any(theme::row()
            .w_full()
            .px(px(16.0))
            .py(px(14.0))
            .gap(px(12.0))
            .child(theme::logo_mark(36.0, c))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .child(theme::strong(
                        format!("FileSec {}", env!("CARGO_PKG_VERSION")),
                        theme::TEXT_BODY,
                        c.text,
                    ))
                    .child(theme::muted(build_variant(), c)),
            )
            .child(
                theme::secondary_button("copy-build-info", "Copy details")
                    .small()
                    .icon(ico(icon::COPY))
                    .on_click(v.on(Action::CopyBuildInfo)),
            )),
        info_row(
            "Platform",
            theme::mono(env!("FILESEC_TARGET"), theme::TEXT_SMALL, c.text, v.cx),
            v,
        ),
        info_row(
            "Features",
            theme::mono(features, theme::TEXT_SMALL, c.text, v.cx),
            v,
        ),
    ];
    let mut notices = theme::group_block(c).py(px(8.0)).child(disclosure(
        "notices-toggle",
        "Open-source notices",
        s.show_notices,
        v.on(Action::ToggleNotices),
        c,
    ));
    if s.show_notices {
        notices = notices
            .child(theme::muted(
                "FileSec is licensed under MIT OR Apache-2.0. It embeds the typeface and \
                 icons below; the license notices of every library linked into this app \
                 ship next to it as THIRD_PARTY_NOTICES.txt (in the installation folder, \
                 the .app's Resources, the download archive, or /usr/share/doc on Linux).",
                c,
            ))
            .child(
                div()
                    .id("notices-scroll")
                    .max_h(px(280.0))
                    .overflow_y_scroll()
                    .p(px(12.0))
                    .rounded(theme::RADIUS_SM)
                    .bg(c.surface_hi)
                    .flex()
                    .flex_col()
                    .gap(px(12.0))
                    .children(theme::EMBEDDED_ASSET_NOTICES.iter().map(|(title, text)| {
                        div()
                            .flex()
                            .flex_col()
                            .gap(px(4.0))
                            .child(theme::strong(*title, px(13.0), c.text))
                            .child(theme::mono(*text, px(11.5), c.text_muted, v.cx))
                    })),
            );
    }
    about.push(any(notices));
    out.push(any(theme::group(Some("About"), None, about, c)));
    out
}
