//! The window frame around the screens: the sidebar, page routing, the toast,
//! and the busy overlay.

use gpui_kit::component::button::{Button, ButtonVariants};
use gpui_kit::component::spinner::Spinner;
use gpui_kit::component::Selectable;
use gpui_kit::{
    div, prelude::*, px, AnyElement, Div, ElementId, Pixels, SharedString, TestSupportExt,
};

use crate::prefs::ThemeChoice;
use crate::theme::{self, icon};

use super::{browser, contacts, identity, settings, vaults, View};
use crate::app::{Action, Nav, Session};

/// One sidebar navigation row: icon + label, with selected/hover states.
fn nav_item(
    id: &'static str,
    glyph: &'static str,
    label: &'static str,
    nav: Nav,
    s: &Session,
    v: &View,
) -> Button {
    let c = v.c;
    let selected = if s.open.is_some() {
        nav == Nav::Vaults
    } else {
        s.nav == nav
    };
    let fg = if selected { c.accent } else { c.text };
    Button::new(id)
        .ghost()
        .selected(selected)
        .w_full()
        .h(px(42.0))
        .accessibility_label(label)
        .child(
            div()
                .w_full()
                .flex()
                .flex_row()
                .items_center()
                .gap(px(10.0))
                .pl(px(4.0))
                .child(theme::icon_text(glyph, 18.0, fg))
                .child(
                    div()
                        .text_size(theme::TEXT_BODY)
                        .text_color(fg)
                        .child(label),
                ),
        )
        .on_click(v.on(Action::Nav(nav)))
}

/// The left sidebar (unlocked only).
pub(in crate::app) fn sidebar(s: &Session, v: &View) -> gpui_kit::Stateful<Div> {
    let c = v.c;
    let dark = theme::is_dark(v.cx);
    let (glyph, hover, choice) = if dark {
        (icon::SUN, "Switch to light", ThemeChoice::Light)
    } else {
        (icon::MOON, "Switch to dark", ThemeChoice::Dark)
    };
    let on_settings = s.open.is_none() && s.nav == Nav::Settings;

    let brand = div()
        .flex()
        .flex_col()
        .gap(px(2.0))
        .pt(px(4.0))
        .pb(px(24.0))
        .child(
            theme::row()
                .child(theme::icon_text(icon::LOCK_KEY, 22.0, c.accent))
                .child(theme::strong("FileSec", theme::TEXT_HEADING, c.text)),
        )
        .child(theme::small("Private by design", c.text_muted));

    #[allow(unused_mut)]
    let mut nav = div()
        .flex()
        .flex_col()
        .gap(px(2.0))
        .child(nav_item(
            "nav-vaults",
            icon::VAULT,
            "Vaults",
            Nav::Vaults,
            s,
            v,
        ))
        .child(nav_item(
            "nav-contacts",
            icon::CONTACTS,
            "Contacts",
            Nav::Contacts,
            s,
            v,
        ))
        .child(nav_item(
            "nav-identity",
            icon::IDENTITY,
            "My Identity",
            Nav::Identity,
            s,
            v,
        ));
    #[cfg(feature = "net")]
    {
        nav = nav.child(nav_item(
            "nav-transfer",
            icon::SEND,
            "Transfer",
            Nav::Transfer,
            s,
            v,
        ));
    }

    // Bottom-pinned account context and clearly labelled utilities.
    let bottom = div()
        .flex()
        .flex_col()
        .gap(px(6.0))
        .child(
            theme::row()
                .gap(px(4.0))
                // One-click light/dark flip. The full three-way control,
                // including "follow the system", lives on the Settings page;
                // this shortcut stays usable during a check-out, when
                // navigating away is refused.
                .child(
                    theme::icon_button("theme-toggle", glyph, hover, c)
                        .on_click(v.on(Action::SetTheme(choice))),
                )
                .child(
                    Button::new("nav-settings")
                        .ghost()
                        .selected(on_settings)
                        .label("Settings")
                        .on_click(v.on(Action::Nav(Nav::Settings))),
                ),
        )
        .child(theme::separator(c))
        .child(theme::small("Identity unlocked", c.text_muted))
        .child(theme::one_line(theme::strong(
            s.identity.name.clone(),
            theme::TEXT_BODY,
            c.text,
        )))
        .child(div().h(px(2.0)))
        .child(theme::secondary_button_full("lock", "Lock FileSec").on_click(v.on(Action::Lock)));

    div()
        .id("sidebar")
        .w(theme::SIDEBAR_W)
        .flex_none()
        .h_full()
        .bg(c.sidebar)
        .p(px(12.0))
        .flex()
        .flex_col()
        .child(brand)
        .child(nav)
        .child(div().flex_1())
        .child(bottom)
}

/// The main area for the unlocked session.
pub(in crate::app) fn session(s: &mut Session, v: &View) -> AnyElement {
    if s.open.is_some() {
        return browser::browser(s, v);
    }
    match s.nav {
        Nav::Vaults => vaults::vaults(s, v).into_any_element(),
        Nav::Contacts => contacts::contacts(s, v).into_any_element(),
        Nav::Identity => identity::identity(s, v).into_any_element(),
        #[cfg(feature = "net")]
        Nav::Transfer => crate::app::transfer::transfer(s, v).into_any_element(),
        Nav::Settings => settings::settings(s, v).into_any_element(),
    }
}

/// The floating toast, anchored bottom-right.
pub(in crate::app) fn toast(msg: String, error: bool, bottom_inset: Pixels, v: &View) -> Div {
    let c = v.c;
    let max_w = (v.width - px(64.0)).clamp(px(160.0), px(420.0));
    div()
        .absolute()
        .bottom(bottom_inset)
        .right(px(16.0))
        .max_w(max_w)
        .child(
            theme::toast_card(error, c)
                .id("toast")
                .occlude()
                .child(
                    div()
                        .id(ElementId::Name("toast-text".into()))
                        .flex_1()
                        .min_w_0()
                        .text_size(theme::TEXT_BODY)
                        .text_color(c.text)
                        .child(SharedString::from(msg))
                        .test_support(),
                )
                .child(
                    theme::icon_button("toast-dismiss", icon::CLOSE, "Dismiss notification", c)
                        .on_click(v.on(Action::DismissToast)),
                ),
        )
}

/// The busy overlay: dimmed backdrop + centred spinner and label.
pub(in crate::app) fn busy_overlay(label: String, v: &View) -> AnyElement {
    let c = v.c;
    theme::backdrop("busy", 140)
        .child(
            theme::row()
                .gap(px(10.0))
                .bg(c.surface)
                .border_1()
                .border_color(c.border)
                .rounded(theme::RADIUS)
                .px(px(18.0))
                .py(px(14.0))
                .child(Spinner::new().color(c.accent))
                .child(theme::text(label, c.text)),
        )
        .test_support()
        .into_any_element()
}
