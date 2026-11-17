//! "My identity": public key and safety number, the post-quantum upgrade,
//! identity backup, security keys, and this-device unlock.

use gpui_kit::{div, prelude::*, px, AnyElement, SharedString};

use crate::autounlock;
use crate::passkey;
use crate::theme::{self, icon};

use super::contacts::safety_number;
use super::{any, disclosure, View};
use crate::app::model::fmt_date;
use crate::app::{Action, Session, PASSKEY_ALT_UNLOCK_DESC};

pub(in crate::app) fn identity(s: &Session, v: &View) -> impl IntoElement {
    let c = v.c;
    div()
        .size_full()
        .flex()
        .flex_col()
        .child(theme::section_header("My identity", None, v.wide(), c))
        .child(theme::page_description(
            "Share your public key to receive vaults. Keep a backup of your private identity \
             somewhere safe.",
            c,
        ))
        .child(super::page_scroll("identity-scroll").children(cards(s, v)))
}

fn cards(s: &Session, v: &View) -> Vec<AnyElement> {
    let c = v.c;
    let pubid = s.identity.public();
    let mut out = Vec::new();

    let mut main = theme::card(c)
        .child(theme::strong(s.identity.name.clone(), px(18.0), c.text))
        .child(theme::muted(
            "Safety number · compare this with your contacts",
            c,
        ))
        .child(safety_number(&pubid.safety_number(), v))
        .child(disclosure(
            "fingerprint-toggle",
            "Identity fingerprint",
            s.show_fingerprint,
            v.on(Action::ToggleFingerprint),
            c,
        ));
    if s.show_fingerprint {
        main = main.child(theme::mono(
            pubid.fingerprint_hex(),
            theme::TEXT_SMALL,
            c.text,
            v.cx,
        ));
    }

    // Post-quantum status + one-click upgrade (pqc builds only).
    #[cfg(feature = "pqc")]
    {
        main = main.child(if s.identity.is_hybrid_capable() {
            theme::wrap_row()
                .child(theme::icon_text(icon::SHIELD, 16.0, c.accent))
                .child(theme::text(
                    "Post-quantum: hybrid X25519+ML-KEM-768 / Ed25519+ML-DSA-65",
                    c.accent,
                ))
        } else {
            theme::wrap_row()
                .child(theme::text(
                    "Post-quantum: not enabled (classical identity)",
                    c.text_muted,
                ))
                .child(
                    theme::secondary_button("begin-migrate", "Upgrade…")
                        .on_click(v.on(Action::BeginMigrate)),
                )
        });
    }
    main = main
        .child(
            theme::wrap_row()
                .child(
                    theme::secondary_button("copy-pubkey", "Copy public key")
                        .on_click(v.on(Action::CopyPubKey)),
                )
                .child(
                    theme::secondary_button("save-pubkey", "Save public key…")
                        .on_click(v.on(Action::SavePubKey)),
                ),
        )
        .child(theme::muted(
            "Share your public key with others so they can send you vaults. It contains no \
             secrets.",
            c,
        ));
    out.push(any(main));

    if let Some(warning) = &s.rollback_warning {
        out.push(any(theme::banner(c.warn).child(
            theme::row()
                .w_full()
                .items_start()
                .child(theme::icon_text(icon::WARNING, 16.0, c.warn))
                .child(theme::text(warning.clone(), c.warn).flex_1().min_w_0()),
        )));
    }

    // Identity backup: a portable, passphrase-encrypted copy of the private
    // keys, for restoring on another device or after a reinstall.
    out.push(any(theme::card(c)
        .child(theme::strong("Identity backup", px(16.0), c.text))
        .child(theme::muted(
            "Save an encrypted backup of your identity so you can restore it on \
                 another device or after a reinstall. Without a backup, a lost device \
                 means a lost identity — and everything encrypted to it.",
            c,
        ))
        .child(
            theme::row().child(
                theme::primary_button("export-identity", "Export identity backup…")
                    .on_click(v.on(Action::BeginExportIdentity)),
            ),
        )
        .child(
            theme::row()
                .items_start()
                .child(theme::icon_text(icon::WARNING, 14.0, c.warn))
                .child(
                    theme::small(
                        "The backup file contains your private keys. Protect it with a \
                             strong passphrase and store it somewhere safe — anyone with the \
                             file and its passphrase becomes you.",
                        c.warn,
                    )
                    .flex_1()
                    .min_w_0(),
                ),
        )));

    // Security keys (passkeys). Shown when this build supports them, or
    // whenever any are already enrolled.
    if passkey::SUPPORTED || !s.passkeys.is_empty() {
        let mut card = theme::card(c)
            .child(theme::strong("Security keys", px(16.0), c.text))
            .child(theme::muted(PASSKEY_ALT_UNLOCK_DESC, c));
        if s.passkeys.is_empty() {
            card = card.child(theme::text("No security keys enrolled.", c.text_muted));
        } else {
            for (i, pk) in s.passkeys.iter().enumerate() {
                card = card.child(
                    theme::row()
                        .w_full()
                        .child(theme::icon_text(icon::KEY, 16.0, c.text_muted))
                        .child(theme::strong(pk.label.clone(), theme::TEXT_BODY, c.text))
                        .child(theme::muted(format!("added {}", fmt_date(pk.added_at)), c))
                        .child(div().flex_1())
                        .child(
                            theme::secondary_button(
                                SharedString::from(format!("remove-passkey-{i}")),
                                "Remove",
                            )
                            .on_click(v.on(Action::RemovePasskey(i))),
                        ),
                );
            }
        }
        if passkey::SUPPORTED {
            card = card.child(
                theme::row().child(
                    theme::primary_button("add-passkey", "+  Add security key…")
                        .on_click(v.on(Action::BeginAddPasskey)),
                ),
            );
        }
        out.push(any(card));
    }

    // This-device convenience: a device unlock key in the OS keychain so this
    // machine can auto-unlock. Shown when this build supports it, or whenever
    // one is already saved (so it can always be turned off).
    if autounlock::SUPPORTED || s.auto_unlock {
        let mut card = theme::card(c)
            .child(theme::strong("This device", px(16.0), c.text))
            .child(theme::muted(
                "Save a device unlock key in this computer's keychain so FileSec unlocks \
                 automatically here. Your passphrase is not stored — it still works and \
                 stays your recovery secret. Anyone with access to your logged-in \
                 account could then open FileSec, so only enable this on a trusted \
                 personal device.",
                c,
            ));
        if let Some(warning) = autounlock::device_binding_warning() {
            card = card.child(theme::small(warning, c.warn));
        }
        if s.auto_unlock {
            card = card.child(
                theme::row()
                    .w_full()
                    .child(theme::icon_text(icon::LOCK_KEY, 15.0, c.ok))
                    .child(theme::text("Auto-unlock is on for this device.", c.ok))
                    .child(div().flex_1())
                    .child(
                        theme::secondary_button("disable-autounlock", "Forget on this device")
                            .on_click(v.on(Action::DisableAutoUnlock)),
                    ),
            );
        } else if autounlock::SUPPORTED {
            card = card.child(
                theme::row().child(
                    theme::secondary_button("enable-autounlock", "Remember on this device…")
                        .on_click(v.on(Action::BeginEnableAutoUnlock)),
                ),
            );
        }
        out.push(any(card));
    }

    // The path itself lives on the Settings page, with copy/reveal actions, so
    // it is documented in exactly one place.
    out.push(any(theme::muted(
        "Where your encrypted data is stored is shown in Settings.",
        c,
    )));
    out
}
