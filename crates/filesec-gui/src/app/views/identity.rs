//! "My identity": the public key and safety number, the post-quantum upgrade,
//! identity backup, security keys, and this-device unlock.

use gpui_kit::component::Sizable;
use gpui_kit::{div, prelude::*, px, AnyElement, SharedString};

use crate::autounlock;
use crate::passkey;
use crate::theme::{self, ico, icon, BadgeKind};

use super::contacts::safety_number;
use super::{any, disclosure, page, View};
use crate::app::model::fmt_date;
use crate::app::{Action, Session, PASSKEY_ALT_UNLOCK_DESC};

pub(in crate::app) fn identity(s: &Session, v: &View) -> impl IntoElement {
    page("identity-scroll", "My identity", None, sections(s, v), v)
}

fn profile_card(s: &Session, v: &View) -> gpui_kit::Div {
    let c = v.c;
    let pubid = s.identity.public();

    #[allow(unused_mut)]
    let mut badges = theme::row().gap(px(6.0));
    #[cfg(feature = "pqc")]
    {
        badges = badges.child(if s.identity.is_hybrid_capable() {
            theme::badge("Post-quantum", BadgeKind::Accent, c)
        } else {
            theme::badge("Classical", BadgeKind::Neutral, c)
        });
    }

    let mut card = theme::card(c)
        .gap(px(16.0))
        .child(
            theme::row()
                .w_full()
                .gap(px(14.0))
                .child(theme::avatar(&s.identity.name, 48.0, c))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .gap(px(4.0))
                        .child(theme::one_line(theme::strong(
                            s.identity.name.clone(),
                            px(18.0),
                            c.text,
                        )))
                        .child(
                            theme::row()
                                .child(theme::muted("Your FileSec identity", c))
                                .child(badges),
                        ),
                ),
        )
        .child(
            div()
                .w_full()
                .flex()
                .flex_col()
                .gap(px(8.0))
                .child(
                    theme::row()
                        .w_full()
                        .child(theme::caption("Safety number", c).flex_1())
                        .child(theme::small(
                            "Compare this with your contacts",
                            c.text_muted,
                        )),
                )
                .child(
                    div()
                        .w_full()
                        .p(px(14.0))
                        .rounded(theme::RADIUS)
                        .bg(c.surface_hi)
                        .border_1()
                        .border_color(c.border_subtle)
                        .child(safety_number(&pubid.safety_number(), v)),
                ),
        )
        .child(
            theme::wrap_row()
                .child(
                    theme::primary_button("copy-pubkey", "Copy public key")
                        .icon(ico(icon::COPY))
                        .on_click(v.on(Action::CopyPubKey)),
                )
                .child(
                    theme::secondary_button("save-pubkey", "Save public key…")
                        .icon(ico(icon::DOWNLOAD))
                        .on_click(v.on(Action::SavePubKey)),
                ),
        )
        .child(theme::muted(
            "Share your public key so others can send you vaults. It contains no secrets.",
            c,
        ))
        .child(theme::separator(c))
        .child(disclosure(
            "fingerprint-toggle",
            "Identity fingerprint",
            s.show_fingerprint,
            v.on(Action::ToggleFingerprint),
            c,
        ));
    if s.show_fingerprint {
        card = card.child(theme::mono(
            pubid.fingerprint_hex(),
            theme::TEXT_SMALL,
            c.text_muted,
            v.cx,
        ));
    }
    card
}

fn sections(s: &Session, v: &View) -> Vec<AnyElement> {
    let c = v.c;
    let wide = v.wide();
    let mut out = vec![any(profile_card(s, v))];

    if let Some(warning) = &s.rollback_warning {
        out.push(any(theme::callout(
            icon::WARNING,
            warning.clone(),
            c.warn,
            c,
        )));
    }

    // Post-quantum status + one-click upgrade (pqc builds only).
    #[cfg(feature = "pqc")]
    {
        let row = if s.identity.is_hybrid_capable() {
            theme::group_row(
                "Hybrid post-quantum keys",
                Some(
                    "X25519 + ML-KEM-768 for encryption, Ed25519 + ML-DSA-65 for signatures."
                        .into(),
                ),
                Some(any(theme::badge("Enabled", BadgeKind::Ok, c))),
                wide,
                c,
            )
        } else {
            theme::group_row(
                "Classical keys",
                Some(
                    "Add post-quantum keys so what you send stays protected against future \
                     quantum computers."
                        .into(),
                ),
                Some(any(theme::secondary_button("begin-migrate", "Upgrade…")
                    .icon(ico(icon::SHIELD))
                    .on_click(v.on(Action::BeginMigrate)))),
                wide,
                c,
            )
        };
        out.push(any(theme::group(
            Some("Post-quantum protection"),
            None,
            vec![any(row)],
            c,
        )));
    }

    // Identity backup: a portable, passphrase-encrypted copy of the private
    // keys, for restoring on another device or after a reinstall.
    out.push(any(theme::group(
        Some("Backup"),
        Some(
            "The backup file holds your private keys. Anyone with the file and its passphrase \
             can act as you — store both somewhere safe."
                .into(),
        ),
        vec![any(theme::group_row(
            "Identity backup",
            Some(
                "Without a backup, a lost device means a lost identity — and everything \
                 encrypted to it."
                    .into(),
            ),
            Some(any(theme::secondary_button(
                "export-identity",
                "Export backup…",
            )
            .icon(ico(icon::SAVE))
            .on_click(v.on(Action::BeginExportIdentity)))),
            wide,
            c,
        ))],
        c,
    )));

    // Security keys (passkeys). Shown when this build supports them, or
    // whenever any are already enrolled.
    if passkey::SUPPORTED || !s.passkeys.is_empty() {
        let mut rows: Vec<AnyElement> = s
            .passkeys
            .iter()
            .enumerate()
            .map(|(i, pk)| {
                any(theme::row()
                    .w_full()
                    .px(px(16.0))
                    .py(px(10.0))
                    .gap(px(12.0))
                    .child(theme::icon_tile(
                        icon::USB,
                        30.0,
                        c.text_muted,
                        c.surface_hi,
                    ))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .child(theme::one_line(theme::text(pk.label.clone(), c.text)))
                            .child(theme::muted(format!("Added {}", fmt_date(pk.added_at)), c)),
                    )
                    .child(
                        theme::ghost_button(
                            SharedString::from(format!("remove-passkey-{i}")),
                            "Remove",
                        )
                        .small()
                        .on_click(v.on(Action::RemovePasskey(i))),
                    ))
            })
            .collect();
        if passkey::SUPPORTED {
            rows.push(any(theme::group_row(
                if s.passkeys.is_empty() {
                    "No security keys yet"
                } else {
                    "Add another key"
                },
                Some(PASSKEY_ALT_UNLOCK_DESC.into()),
                Some(any(theme::secondary_button(
                    "add-passkey",
                    "Add security key…",
                )
                .icon(ico(icon::PLUS))
                .on_click(v.on(Action::BeginAddPasskey)))),
                wide,
                c,
            )));
        }
        out.push(any(theme::group(Some("Security keys"), None, rows, c)));
    }

    // This-device convenience: a device unlock key in the OS keychain so this
    // machine can auto-unlock. Shown when this build supports it, or whenever
    // one is already saved (so it can always be turned off).
    if autounlock::SUPPORTED || s.auto_unlock {
        let control = if s.auto_unlock {
            Some(any(theme::row()
                .child(theme::badge("On", BadgeKind::Ok, c))
                .child(
                    theme::secondary_button("disable-autounlock", "Forget on this device")
                        .on_click(v.on(Action::DisableAutoUnlock)),
                )))
        } else if autounlock::SUPPORTED {
            Some(any(theme::secondary_button(
                "enable-autounlock",
                "Remember on this device…",
            )
            .icon(ico(icon::LAPTOP))
            .on_click(v.on(Action::BeginEnableAutoUnlock))))
        } else {
            None
        };
        let footer = autounlock::device_binding_warning().map(SharedString::from);
        out.push(any(theme::group(
            Some("This device"),
            footer,
            vec![any(theme::group_row(
                "Unlock automatically",
                Some(
                    "Keeps a device unlock key in this computer's keychain. Your passphrase \
                     isn't stored and stays your recovery secret. Anyone using your logged-in \
                     account could open FileSec, so only enable this on a personal device."
                        .into(),
                ),
                control,
                wide,
                c,
            ))],
            c,
        )));
    }

    // The path itself lives on the Settings page, with copy/reveal actions, so
    // it is documented in exactly one place.
    out.push(any(theme::muted(
        "Where your encrypted data is stored is shown in Settings.",
        c,
    )
    .px(px(4.0))));
    out
}
