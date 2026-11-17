//! The screens. Each function is a pure description of one part of the UI for
//! the current state: it builds GPUI elements and wires their handlers to an
//! [`Action`], which [`FileSecApp::dispatch`] applies.
//!
//! Every unlocked page shares one frame, built by [`page`]: a fixed-height
//! top bar (title + the page's actions) over a scrolling, width-capped content
//! column. Recurring situations — searching a list, an empty list, a group of
//! settings, a form field — each have one helper here or in [`crate::theme`],
//! so the same situation always looks and reads the same way.

pub(super) mod auth;
pub(super) mod browser;
pub(super) mod contacts;
pub(super) mod dialogs;
pub(super) mod identity;
pub(super) mod settings;
pub(super) mod shell;
pub(super) mod vaults;

use gpui_kit::component::button::{Button, ButtonCustomVariant, ButtonVariants};
use gpui_kit::component::checkbox::Checkbox;
use gpui_kit::component::input::{Input, InputState};
use gpui_kit::component::menu::{DropdownMenu, PopupMenu, PopupMenuItem};
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::component::Sizable;
use gpui_kit::{
    div, prelude::*, px, AnyElement, App, ClickEvent, Div, ElementId, Entity, FocusHandle, Pixels,
    SharedString, WeakEntity, Window,
};

use crate::theme::{self, icon, Colors};

use super::fields::Fields;
use super::{Action, FileSecApp};

/// Everything a screen needs to describe itself.
pub(super) struct View<'a> {
    pub app: WeakEntity<FileSecApp>,
    pub c: Colors,
    pub cx: &'a App,
    pub fields: &'a Fields,
    /// Width available to the main content column (after padding).
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

    /// Wide enough for side-by-side layouts.
    pub fn wide(&self) -> bool {
        self.width >= px(600.0)
    }

    /// A plain input's current text.
    pub fn text(&self, entity: &Entity<InputState>) -> SharedString {
        entity.read(self.cx).value()
    }
}

/// The frame of every unlocked page: the top bar, then a scrolling column of
/// at most [`theme::CONTENT_MAX`], centred, holding `body`.
pub(super) fn page(
    scroll_id: &'static str,
    title: impl Into<SharedString>,
    actions: Option<AnyElement>,
    body: Vec<AnyElement>,
    v: &View,
) -> Div {
    div()
        .size_full()
        .flex()
        .flex_col()
        .child(theme::page_header(title, actions, v.c))
        .child(
            div()
                .id(scroll_id)
                .flex_1()
                .min_h_0()
                .w_full()
                .overflow_y_scroll()
                .flex()
                .flex_col()
                .items_center()
                .child(
                    div()
                        .w_full()
                        .max_w(theme::CONTENT_MAX)
                        .px(theme::PAGE_PAD)
                        .pt(px(20.0))
                        .pb(px(40.0))
                        .flex()
                        .flex_col()
                        .gap(px(16.0))
                        .children(body),
                ),
        )
}

/// A full-width text input.
pub(super) fn text_input(entity: &Entity<InputState>) -> Input {
    Input::new(entity).w_full()
}

/// A labelled field: a label above the input.
pub(super) fn labelled(label: &'static str, field: impl IntoElement, c: Colors) -> Div {
    div()
        .w_full()
        .flex()
        .flex_col()
        .gap(px(6.0))
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

/// Menu entries: `(label, action, checked)`. An empty label is a separator.
pub(super) type MenuItems = Vec<(SharedString, Action, bool)>;

fn fill_menu(mut menu: PopupMenu, items: &MenuItems, app: &WeakEntity<FileSecApp>) -> PopupMenu {
    for (label, action, checked) in items {
        if label.is_empty() {
            menu = menu.separator();
        } else {
            menu = menu.item(
                PopupMenuItem::new(label.clone())
                    .checked(*checked)
                    .on_click(handler(app, action.clone())),
            );
        }
    }
    menu
}

/// A bordered button with a caret, for selects and "New" menus. Configure it
/// (icon, width, disabled) and hand it to [`with_menu`].
pub(super) fn select_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    let label: SharedString = label.into();
    Button::new(id).label(label).dropdown_caret(true)
}

/// Attach a menu of `items` to `button`.
pub(super) fn with_menu(button: Button, items: MenuItems, v: &View) -> impl IntoElement {
    let app = v.app.clone();
    button.dropdown_menu(move |menu, _, _| fill_menu(menu, &items, &app))
}

/// A select-style button that opens a menu.
#[cfg_attr(not(feature = "net"), allow(dead_code))]
pub(super) fn dropdown(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    items: MenuItems,
    v: &View,
) -> impl IntoElement {
    with_menu(select_button(id, label), items, v)
}

/// A quiet icon-only button that opens a menu ("More actions").
pub(super) fn icon_menu(
    id: impl Into<ElementId>,
    glyph: icon::Glyph,
    hover: &'static str,
    items: MenuItems,
    v: &View,
) -> impl IntoElement {
    with_menu(theme::icon_button(id, glyph, hover, v.c), items, v)
}

/// A selectable chip: the accent fill when selected, quiet otherwise.
#[cfg_attr(not(feature = "pqc"), allow(dead_code))]
pub(super) fn chip(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    selected: bool,
    enabled: bool,
    on: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> Button {
    let b = Button::new(id).label(label).small();
    let b = if selected { b.primary() } else { b.ghost() };
    theme::enabled(b, enabled).on_click(on)
}

/// One option of a [`segmented`] control.
pub(super) struct Segment {
    pub id: SharedString,
    pub label: &'static str,
    pub glyph: Option<icon::Glyph>,
    pub selected: bool,
    pub action: Action,
}

/// A segmented control: a recessed track holding mutually exclusive options;
/// the selected one is raised on a surface.
pub(super) fn segmented(segments: Vec<Segment>, v: &View) -> Div {
    let c = v.c;
    let raised = ButtonCustomVariant::new(v.cx)
        .color(c.surface)
        .foreground(c.text)
        .hover(c.surface)
        .active(c.surface)
        .shadow(!c.dark);
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(2.0))
        .p(px(2.0))
        .rounded(px(8.0))
        .bg(c.surface_hi)
        .border_1()
        .border_color(c.border_subtle)
        .children(segments.into_iter().map(|seg| {
            let b = Button::new(seg.id).small().label(seg.label).px(px(10.0));
            let b = match seg.glyph {
                Some(g) => b.icon(theme::ico(g)),
                None => b,
            };
            let b = if seg.selected {
                // Keep the raised fill fully opaque over the track.
                b.custom(raised).bg(c.surface)
            } else {
                b.ghost()
            };
            b.on_click(v.on(seg.action))
        }))
}

/// A disclosure header: a caret, a title, and a toggle action. The caller
/// shows the body when `open`.
pub(super) fn disclosure(
    id: impl Into<ElementId>,
    title: impl Into<SharedString>,
    open: bool,
    on: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    c: Colors,
) -> impl IntoElement {
    let title: SharedString = title.into();
    // In a row so a column parent can't stretch it (a stretched button centres
    // its label, which reads as a heading rather than a toggle).
    div().flex().flex_row().child(
        Button::new(id)
            .ghost()
            .small()
            .icon(theme::ico(if open {
                icon::CARET_DOWN
            } else {
                icon::CARET_RIGHT
            }))
            .label(title)
            .text_color(c.text_muted)
            .on_click(on),
    )
}

/// A search box: a leading search glyph, and a clear button inside the field
/// once there is something to clear. Its width never changes while typing.
pub(super) fn search_field(
    id: &'static str,
    entity: &Entity<InputState>,
    clear: Action,
    v: &View,
) -> Div {
    let c = v.c;
    let empty = v.text(entity).is_empty();
    div().w_full().child(
        Input::new(entity)
            .w_full()
            .prefix(theme::icon_text(icon::SEARCH, 15.0, c.text_subtle))
            .when(!empty, |input| {
                input.suffix(
                    Button::new(id)
                        .ghost()
                        .xsmall()
                        .icon(theme::ico(icon::CLOSE))
                        .tooltip("Clear search")
                        .accessibility_label("Clear search")
                        .on_click(v.on(clear)),
                )
            }),
    )
}

/// Hover text for a truncated label.
pub(super) fn tooltip_text(
    text: impl Into<SharedString>,
) -> impl Fn(&mut Window, &mut App) -> gpui_kit::AnyView + 'static {
    let text: SharedString = text.into();
    move |window, cx| Tooltip::new(text.clone()).build(window, cx)
}

/// Erase an element's type (for `Option` / `Vec` children).
pub(super) fn any(el: impl IntoElement) -> AnyElement {
    el.into_any_element()
}
