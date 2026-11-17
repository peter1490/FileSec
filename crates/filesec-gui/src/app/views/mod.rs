//! The screens. Each function is a pure description of one part of the UI for
//! the current state: it builds GPUI elements and wires their handlers to an
//! [`Action`], which [`FileSecApp::dispatch`] applies.

pub(super) mod auth;
pub(super) mod browser;
pub(super) mod contacts;
pub(super) mod dialogs;
pub(super) mod identity;
pub(super) mod settings;
pub(super) mod shell;
pub(super) mod vaults;

use gpui_kit::component::button::{Button, ButtonVariants};
use gpui_kit::component::checkbox::Checkbox;
use gpui_kit::component::input::{Input, InputState};
use gpui_kit::component::menu::{DropdownMenu, PopupMenuItem};
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::component::Selectable;
use gpui_kit::{
    div, prelude::*, px, AnyElement, App, ClickEvent, Div, ElementId, Entity, FocusHandle, Pixels,
    SharedString, WeakEntity, Window,
};

use crate::theme::{self, Colors};

use super::fields::Fields;
use super::{Action, FileSecApp};

/// Everything a screen needs to describe itself.
pub(super) struct View<'a> {
    pub app: WeakEntity<FileSecApp>,
    pub c: Colors,
    pub cx: &'a App,
    pub fields: &'a Fields,
    /// Width available to the main content area.
    pub width: Pixels,
    /// Window width and height.
    pub window_width: Pixels,
    pub height: Pixels,
    pub browser_focus: FocusHandle,
    pub dialog_focus: FocusHandle,
}

/// A click handler that dispatches `action`.
pub(super) fn handler(
    app: &WeakEntity<FileSecApp>,
    action: Action,
) -> impl Fn(&ClickEvent, &mut Window, &mut App) + 'static {
    let app = app.clone();
    move |_, window, cx| {
        let action = action.clone();
        let _ = app.update(cx, |this, cx| this.dispatch(action, window, cx));
    }
}

impl View<'_> {
    /// A click handler that dispatches `action`.
    pub fn on(&self, action: Action) -> impl Fn(&ClickEvent, &mut Window, &mut App) + 'static {
        handler(&self.app, action)
    }

    /// A checkbox handler mapping the new checked state to an action.
    pub fn on_check(
        &self,
        f: impl Fn(bool) -> Action + 'static,
    ) -> impl Fn(&bool, &mut Window, &mut App) + 'static {
        let app = self.app.clone();
        move |checked, window, cx| {
            let action = f(*checked);
            let _ = app.update(cx, |this, cx| this.dispatch(action, window, cx));
        }
    }

    /// Wide enough for side-by-side layouts (the egui app's 600 px breakpoint).
    pub fn wide(&self) -> bool {
        self.width >= px(600.0)
    }

    /// A plain input's current text.
    pub fn text(&self, entity: &Entity<InputState>) -> SharedString {
        entity.read(self.cx).value()
    }
}

/// A full-width text input.
pub(super) fn text_input(entity: &Entity<InputState>) -> Input {
    Input::new(entity).w_full()
}

/// A labelled field: a small caption above the input.
pub(super) fn labelled(label: &'static str, field: impl IntoElement, c: Colors) -> Div {
    div()
        .w_full()
        .flex()
        .flex_col()
        .gap(px(4.0))
        .child(theme::caption(label, c))
        .child(field)
}

/// A checkbox wired to an action.
pub(super) fn checkbox(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    checked: bool,
    on: impl Fn(&bool, &mut Window, &mut App) + 'static,
) -> Checkbox {
    let label: SharedString = label.into();
    Checkbox::new(id).label(label).checked(checked).on_click(on)
}

/// A button that opens a menu of `(label, action, checked)` items — the
/// GPUI replacement for egui's combo boxes and menu buttons.
pub(super) fn dropdown(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    items: Vec<(SharedString, Action, bool)>,
    v: &View,
) -> impl IntoElement {
    let app = v.app.clone();
    let label: SharedString = label.into();
    Button::new(id)
        .label(label)
        .dropdown_caret(true)
        .dropdown_menu(move |mut menu, _, _| {
            for (label, action, checked) in &items {
                menu = menu.item(
                    PopupMenuItem::new(label.clone())
                        .checked(*checked)
                        .on_click(handler(&app, action.clone())),
                );
            }
            menu
        })
}

/// A selectable chip (egui's `selectable_label`).
pub(super) fn chip(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    selected: bool,
    enabled: bool,
    on: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> Button {
    let b = Button::new(id).label(label).selected(selected);
    let b = if selected { b.primary() } else { b.ghost() };
    theme::enabled(b, enabled).on_click(on)
}

/// A disclosure header (egui's `CollapsingHeader`): a caret, a title, and a
/// toggle action. The caller shows the body when `open`.
pub(super) fn disclosure(
    id: impl Into<ElementId>,
    title: impl Into<SharedString>,
    open: bool,
    on: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    c: Colors,
) -> impl IntoElement {
    div()
        .id(id)
        .flex()
        .flex_row()
        .items_center()
        .gap(px(6.0))
        .cursor_pointer()
        .rounded(theme::RADIUS_SM)
        .px(px(4.0))
        .py(px(4.0))
        .hover(|s| s.bg(c.surface_hi))
        .on_click(on)
        .child(theme::icon_text(
            if open {
                theme::icon::CARET_DOWN
            } else {
                theme::icon::CARET_RIGHT
            },
            14.0,
            c.text_muted,
        ))
        .child(theme::strong(title, theme::TEXT_BODY, c.text))
}

/// A search box with a stable width and an always-reserved clear button.
pub(super) fn search_field(
    id: &'static str,
    entity: &Entity<InputState>,
    clear: Action,
    v: &View,
) -> Div {
    let empty = v.text(entity).is_empty();
    theme::row()
        .w_full()
        .child(div().flex_1().min_w_0().child(Input::new(entity).w_full()))
        .child(
            theme::enabled(
                theme::icon_button(id, theme::icon::CLOSE, "Clear search", v.c),
                !empty,
            )
            .on_click(v.on(clear)),
        )
}

/// Hover text for a truncated label.
pub(super) fn tooltip_text(
    text: impl Into<SharedString>,
) -> impl Fn(&mut Window, &mut App) -> gpui_kit::AnyView + 'static {
    let text: SharedString = text.into();
    move |window, cx| Tooltip::new(text.clone()).build(window, cx)
}

/// A scrolling column for a whole page.
pub(super) fn page_scroll(id: &'static str) -> gpui_kit::Stateful<Div> {
    div()
        .id(id)
        .flex_1()
        .min_h_0()
        .w_full()
        .overflow_y_scroll()
        .flex()
        .flex_col()
        .gap(px(8.0))
}

/// Erase an element's type (for `Option` / `Vec` children).
pub(super) fn any(el: impl IntoElement) -> AnyElement {
    el.into_any_element()
}
