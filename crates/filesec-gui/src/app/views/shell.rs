//! The window frame around the screens: the sidebar, page routing, the toast,
//! the busy overlay, and (macOS) the strip that moves the window.

use std::cell::Cell;
use std::rc::Rc;

use gpui_kit::component::button::{Button, ButtonVariants};
use gpui_kit::component::spinner::Spinner;
use gpui_kit::component::Sizable;
use gpui_kit::{
    div, prelude::*, px, AnyElement, Div, ElementId, MouseButton, Pixels, SharedString,
    TestSupportExt,
};

use crate::prefs::ThemeChoice;
use crate::theme::{self, icon};

use super::{browser, contacts, identity, settings, vaults, View};
use crate::app::{Action, Nav, Session};

/// One sidebar navigation row: icon + label (+ an optional count), with
/// selected/hover states.
fn nav_item(
    id: &'static str,
    glyph: icon::Glyph,
    label: &'static str,
    count: Option<usize>,
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
    let (fg, icon_fg) = if selected {
        (c.text, c.accent)
    } else {
        (c.text_muted, c.text_muted)
    };
    let selected_bg = if c.dark { c.surface_hi } else { c.surface };
    Button::new(id)
        .ghost()
        .w_full()
        .h(px(34.0))
        .accessibility_label(label)
        .when(selected, |b| {
            b.bg(selected_bg).border_1().border_color(c.border_subtle)
        })
        .child(
            div()
                .w_full()
                .flex()
                .flex_row()
                .items_center()
                .gap(px(10.0))
                .child(theme::icon_text(glyph, 16.0, icon_fg))
                .child(
                    div()
                        .flex_1()
                        .text_size(theme::TEXT_BODY)
                        .when(selected, |d| d.font_weight(gpui_kit::FontWeight::SEMIBOLD))
                        .text_color(fg)
                        .child(label),
                )
                .children(count.filter(|n| *n > 0).map(|n| {
                    div()
                        .text_size(theme::TEXT_SMALL)
                        .text_color(c.text_subtle)
                        .child(n.to_string())
                })),
        )
        .on_click(v.on(Action::Nav(nav)))
}

/// The left sidebar (unlocked only).
pub(in crate::app) fn sidebar(s: &Session, v: &View) -> gpui_kit::Stateful<Div> {
    let c = v.c;
    let dark = theme::is_dark(v.cx);
    let (glyph, hover, choice) = if dark {
        (icon::SUN, "Switch to light appearance", ThemeChoice::Light)
    } else {
        (icon::MOON, "Switch to dark appearance", ThemeChoice::Dark)
    };

    // The brand shares the page header's strip; on macOS it sits to the right
    // of the traffic lights.
    let brand = div()
        .flex_none()
        .h(theme::HEADER_H)
        .pl(if crate::UNIFIED_TITLEBAR {
            px(84.0)
        } else {
            px(18.0)
        })
        .pr(px(12.0))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(9.0))
        .child(theme::logo_mark(22.0, c))
        .child(theme::strong("FileSec", px(15.0), c.text));

    let section = |label: &'static str| {
        div()
            .px(px(10.0))
            .pt(px(14.0))
            .pb(px(6.0))
            .text_size(px(11.5))
            .font_weight(gpui_kit::FontWeight::SEMIBOLD)
            .text_color(c.text_subtle)
            .child(label)
    };

    #[allow(unused_mut)]
    let mut nav = div()
        .flex()
        .flex_col()
        .gap(px(2.0))
        .child(section("Library"))
        .child(nav_item(
            "nav-vaults",
            icon::VAULT,
            "Vaults",
            Some(s.registry.vaults.len()),
            Nav::Vaults,
            s,
            v,
        ))
        .child(nav_item(
            "nav-contacts",
            icon::CONTACTS,
            "Contacts",
            Some(s.contacts.contacts.len()),
            Nav::Contacts,
            s,
            v,
        ));
    #[cfg(feature = "net")]
    {
        nav = nav.child(nav_item(
            "nav-transfer",
            icon::SEND,
            "Transfer",
            None,
            Nav::Transfer,
            s,
            v,
        ));
    }
    nav = nav
        .child(section("Account"))
        .child(nav_item(
            "nav-identity",
            icon::IDENTITY,
            "My identity",
            None,
            Nav::Identity,
            s,
            v,
        ))
        .child(nav_item(
            "nav-settings",
            icon::GEAR,
            "Settings",
            None,
            Nav::Settings,
            s,
            v,
        ));

    // Who is unlocked, and the two session-wide controls. The theme flip stays
    // usable during a check-out, when navigating away is refused.
    let account = div()
        .flex_none()
        .m(px(10.0))
        .p(px(8.0))
        .rounded(theme::RADIUS)
        .border_1()
        .border_color(c.border_subtle)
        .bg(if c.dark { c.surface } else { c.surface })
        .flex()
        .flex_row()
        .items_center()
        .gap(px(9.0))
        .child(theme::avatar(&s.identity.name, 30.0, c))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .flex_col()
                .child(theme::one_line(theme::strong(
                    s.identity.name.clone(),
                    px(13.0),
                    c.text,
                )))
                .child(
                    theme::row()
                        .gap(px(5.0))
                        .child(theme::dot(c.ok))
                        .child(theme::small("Unlocked", c.text_muted)),
                ),
        )
        .child(
            theme::icon_button("theme-toggle", glyph, hover, c)
                .small()
                .on_click(v.on(Action::SetTheme(choice))),
        )
        .child(
            theme::icon_button("lock", icon::LOCK, "Lock FileSec", c)
                .small()
                .on_click(v.on(Action::Lock)),
        );

    div()
        .id("sidebar")
        .w(theme::SIDEBAR_W)
        .flex_none()
        .h_full()
        .bg(c.sidebar)
        .border_r_1()
        .border_color(c.border_subtle)
        .flex()
        .flex_col()
        .child(brand)
        .child(
            div()
                .id("sidebar-nav")
                .flex_1()
                .min_h_0()
                .overflow_y_scroll()
                .px(px(10.0))
                .child(nav),
        )
        .child(account)
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

/// The floating toast, anchored bottom-right. Errors stay until dismissed;
/// the close button is always there.
pub(in crate::app) fn toast(msg: String, error: bool, bottom_inset: Pixels, v: &View) -> Div {
    let c = v.c;
    let max_w = (v.window_width - px(48.0)).clamp(px(160.0), px(440.0));
    div()
        .absolute()
        .bottom(bottom_inset)
        .right(px(20.0))
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
                        .py(px(4.0))
                        .text_size(theme::TEXT_BODY)
                        .text_color(c.text)
                        .child(SharedString::from(msg))
                        .test_support(),
                )
                .child(
                    theme::icon_button("toast-dismiss", icon::CLOSE, "Dismiss notification", c)
                        .small()
                        .on_click(v.on(Action::DismissToast)),
                ),
        )
}

/// The busy overlay: dimmed backdrop + a centred card with a spinner and
/// what is happening.
pub(in crate::app) fn busy_overlay(label: String, v: &View) -> AnyElement {
    let c = v.c;
    theme::backdrop("busy", if c.dark { 120 } else { 70 })
        .child(
            theme::float_card(c)
                .flex()
                .flex_row()
                .items_center()
                .gap(px(12.0))
                .px(px(20.0))
                .py(px(16.0))
                .max_w(px(420.0))
                .child(Spinner::new().color(c.accent))
                .child(theme::text(label, c.text)),
        )
        .test_support()
        .into_any_element()
}

/// The invisible strip under the top [`theme::HEADER_H`] of the window that
/// moves it (macOS unified titlebar only). It sits beneath every header, so
/// a press on a button there is the button's (buttons prevent the default);
/// a press on empty header space drags the window, and a double-click zooms
/// it as the system titlebar would.
pub(in crate::app) fn window_drag_strip(flag: Rc<Cell<bool>>) -> Div {
    let down = flag.clone();
    let up = flag.clone();
    let out = flag.clone();
    let moved = flag;
    div()
        .absolute()
        .top_0()
        .left_0()
        .w_full()
        .h(theme::HEADER_H)
        .on_mouse_down(MouseButton::Left, move |event, window, _| {
            if window.default_prevented() {
                down.set(false);
            } else if event.click_count >= 2 {
                down.set(false);
                window.titlebar_double_click();
            } else {
                down.set(true);
            }
        })
        .on_mouse_up(MouseButton::Left, move |_, _, _| up.set(false))
        .on_mouse_down_out(move |_, _, _| out.set(false))
        .on_mouse_move(move |event, window, _| {
            if event.pressed_button != Some(MouseButton::Left) {
                moved.set(false);
            } else if moved.get() {
                moved.set(false);
                window.start_window_move();
            }
        })
}
