//! Visual design system: palette, fonts, appearance, and reusable elements.
//!
//! This module is purely presentational and **feature-agnostic** — it carries no
//! `cfg` gates so every feature permutation (pqc / passkey / keyring / net)
//! compiles against the same helpers. [`install`] is called once from
//! [`crate::run`] before the window opens: it registers the bundled fonts,
//! teaches GPUI Component the FileSec palette for both appearances, and starts
//! out following the OS appearance. [`crate::run`] then applies the user's
//! saved choice via [`apply_choice`] before the first frame, so the unlock
//! screen already paints in the right theme.
//!
//! The element helpers ([`card`], [`primary_button`], [`badge`], …) only
//! *build* elements; behaviour (click handlers, disabled state) is attached by
//! the caller, which keeps every screen a pure function of the app state.

use std::borrow::Cow;
use std::rc::Rc;

use gpui_kit::component::button::{Button, ButtonCustomVariant, ButtonVariants};
use gpui_kit::component::theme::{Theme, ThemeConfig, ThemeMode};
use gpui_kit::component::{Disableable, Sizable};
use gpui_kit::{
    div, px, rgb, AnyElement, App, BoxShadow, Div, ElementId, FontWeight, Global, Hsla,
    InteractiveElement, ParentElement, Pixels, SharedString, Styled, WindowAppearance,
};

use crate::prefs::ThemeChoice;

// ---------------------------------------------------------------------------
// Palette
// ---------------------------------------------------------------------------

/// Raw sRGB palette for one appearance, as `0xRRGGBB`. Kept as integers so the
/// same table feeds both the GPUI colours ([`Colors`]) and the GPUI Component
/// theme config (which takes hex strings).
#[derive(Clone, Copy)]
struct Palette {
    bg: u32,
    surface: u32,
    surface_hi: u32,
    sidebar: u32,
    input: u32,
    border: u32,
    text: u32,
    text_muted: u32,
    accent: u32,
    accent_hi: u32,
    ok: u32,
    warn: u32,
    err: u32,
    on_accent: u32,
}

const DARK: Palette = Palette {
    bg: 0x14161b,
    surface: 0x1b1e25,
    surface_hi: 0x232730,
    sidebar: 0x101217,
    input: 0x0f1116,
    border: 0x2c313c,
    text: 0xe6e8ed,
    text_muted: 0x8a909c,
    accent: 0x6da5ff,
    accent_hi: 0x6aa3f5,
    ok: 0x3fb968,
    warn: 0xd9a33d,
    err: 0xe05d5d,
    on_accent: 0x0c1c34,
};

const LIGHT: Palette = Palette {
    bg: 0xf6f7f9,
    surface: 0xffffff,
    surface_hi: 0xeef0f3,
    sidebar: 0xedeff3,
    input: 0xf3f5f8,
    border: 0xd9dde3,
    text: 0x1b1e25,
    text_muted: 0x5e6573,
    accent: 0x2f6fe0,
    accent_hi: 0x1f5fd6,
    ok: 0x20763e,
    warn: 0x8a5b09,
    err: 0xcf4444,
    on_accent: 0xffffff,
};

/// Semantic colour tokens for one appearance. Helpers resolve the right set
/// from the active appearance via [`colors`], so they recolour automatically
/// when the theme flips.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Colors {
    pub bg: Hsla,
    pub surface: Hsla,
    pub surface_hi: Hsla,
    pub sidebar: Hsla,
    pub input: Hsla,
    pub border: Hsla,
    pub text: Hsla,
    pub text_muted: Hsla,
    pub accent: Hsla,
    pub accent_hi: Hsla,
    pub ok: Hsla,
    pub warn: Hsla,
    pub err: Hsla,
    pub on_accent: Hsla,
}

impl Colors {
    fn from_palette(p: &Palette) -> Self {
        let c = |hex: u32| -> Hsla { rgb(hex).into() };
        Self {
            bg: c(p.bg),
            surface: c(p.surface),
            surface_hi: c(p.surface_hi),
            sidebar: c(p.sidebar),
            input: c(p.input),
            border: c(p.border),
            text: c(p.text),
            text_muted: c(p.text_muted),
            accent: c(p.accent),
            accent_hi: c(p.accent_hi),
            ok: c(p.ok),
            warn: c(p.warn),
            err: c(p.err),
            on_accent: c(p.on_accent),
        }
    }

    #[must_use]
    pub fn dark() -> Self {
        Self::from_palette(&DARK)
    }

    #[must_use]
    pub fn light() -> Self {
        Self::from_palette(&LIGHT)
    }
}

/// `c` at an absolute alpha of `a / 255`.
#[must_use]
pub fn with_alpha(c: Hsla, a: u8) -> Hsla {
    Hsla {
        a: f32::from(a) / 255.0,
        ..c
    }
}

/// Accent colour at a soft translucent alpha — for selected rows and the like.
#[must_use]
pub fn accent_soft(c: Colors) -> Hsla {
    with_alpha(c.accent, 40)
}

/// Black at `a / 255` alpha — modal backdrops and shadows.
#[must_use]
fn black_alpha(a: u8) -> Hsla {
    with_alpha(rgb(0x000000).into(), a)
}

pub const RADIUS: Pixels = px(10.0);
pub const RADIUS_SM: Pixels = px(6.0);
pub const SIDEBAR_W: Pixels = px(216.0);

/// Type scale, matching the app's long-standing sizes.
pub const TEXT_HEADING: Pixels = px(22.0);
pub const TEXT_H2: Pixels = px(16.0);
pub const TEXT_BODY: Pixels = px(14.5);
pub const TEXT_SMALL: Pixels = px(12.0);
pub const TEXT_MONO: Pixels = px(13.0);

/// Family names inside the bundled font files (what GPUI resolves by name).
pub const FONT_UI: &str = "Inter";
pub const FONT_ICONS: &str = "Phosphor";

fn shadow(offset_y: f32, blur: f32, alpha: u8) -> Vec<BoxShadow> {
    vec![BoxShadow {
        color: black_alpha(alpha),
        offset: gpui_kit::point(px(0.0), px(offset_y)),
        blur_radius: px(blur),
        spread_radius: px(0.0),
        inset: false,
    }]
}

// ---------------------------------------------------------------------------
// Appearance state
// ---------------------------------------------------------------------------

/// The live appearance: what the user picked, and what the OS currently is.
/// Lives in a GPUI global so every view (and the Settings page) reads the one
/// value actually on screen rather than a copy that could drift.
struct Appearance {
    choice: ThemeChoice,
    system_dark: bool,
}

impl Global for Appearance {}

fn appearance_is_dark(appearance: WindowAppearance) -> bool {
    matches!(
        appearance,
        WindowAppearance::Dark | WindowAppearance::VibrantDark
    )
}

/// Register bundled fonts and install the light/dark palettes. Call once at
/// startup, before opening a window (fonts must be known before first layout).
pub fn install(cx: &mut App) {
    install_fonts(cx);
    let system_dark = appearance_is_dark(cx.window_appearance());
    cx.set_global(Appearance {
        // Follow the OS appearance until told otherwise. `crate::run` applies
        // the saved choice right after this, before the first frame.
        choice: ThemeChoice::System,
        system_dark,
    });
    Theme::update(cx, |theme| {
        theme.light_theme = Rc::new(component_config(&LIGHT, ThemeMode::Light));
        theme.dark_theme = Rc::new(component_config(&DARK, ThemeMode::Dark));
    });
    sync(cx);
}

/// Apply a saved [`ThemeChoice`].
///
/// The only place [`ThemeChoice`] is mapped onto the toolkit, so the
/// persistence model in [`crate::prefs`] stays UI-free.
pub fn apply_choice(choice: ThemeChoice, cx: &mut App) {
    if !cx.has_global::<Appearance>() {
        install(cx);
    }
    cx.global_mut::<Appearance>().choice = choice;
    sync(cx);
}

/// Record a change in the OS appearance (from a window's appearance
/// observer). Only visible when the user follows the system.
pub fn set_system_appearance(appearance: WindowAppearance, cx: &mut App) {
    if !cx.has_global::<Appearance>() {
        return;
    }
    let dark = appearance_is_dark(appearance);
    if cx.global::<Appearance>().system_dark != dark {
        cx.global_mut::<Appearance>().system_dark = dark;
        sync(cx);
    }
}

/// The choice currently in force.
#[must_use]
pub fn current_choice(cx: &App) -> ThemeChoice {
    cx.try_global::<Appearance>()
        .map_or(ThemeChoice::System, |a| a.choice)
}

/// Whether the dark palette is the one on screen.
#[must_use]
pub fn is_dark(cx: &App) -> bool {
    cx.try_global::<Appearance>()
        .is_some_and(|a| match a.choice {
            ThemeChoice::System => a.system_dark,
            ThemeChoice::Light => false,
            ThemeChoice::Dark => true,
        })
}

/// The token set for the active appearance.
#[must_use]
pub fn colors(cx: &App) -> Colors {
    if is_dark(cx) {
        Colors::dark()
    } else {
        Colors::light()
    }
}

/// Push the resolved appearance into GPUI Component (inputs, menus, buttons,
/// scrollbars) and re-render every window.
fn sync(cx: &mut App) {
    let mode = if is_dark(cx) {
        ThemeMode::Dark
    } else {
        ThemeMode::Light
    };
    Theme::change(mode, None, cx);
}

fn hex(c: u32) -> SharedString {
    format!("#{c:06x}").into()
}

fn hex_alpha(c: u32, a: u8) -> SharedString {
    format!("#{c:06x}{a:02x}").into()
}

/// The FileSec palette expressed as a GPUI Component theme, so its controls
/// (inputs, menus, checkboxes, scrollbars, buttons) match the app's own
/// surfaces in both appearances.
fn component_config(p: &Palette, mode: ThemeMode) -> ThemeConfig {
    let dark = matches!(mode, ThemeMode::Dark);
    let mut cfg = ThemeConfig::default();
    cfg.name = if dark {
        "FileSec Dark"
    } else {
        "FileSec Light"
    }
    .into();
    cfg.mode = mode;
    cfg.font_family = Some(FONT_UI.into());
    cfg.font_size = Some(14.5);
    cfg.radius = Some(6);
    cfg.radius_lg = Some(10);
    cfg.shadow = Some(true);
    let on_danger = if dark { p.on_accent } else { 0xffffff };
    let k = &mut cfg.colors;
    k.background = Some(hex(p.bg));
    k.foreground = Some(hex(p.text));
    k.border = Some(hex(p.border));
    k.input = Some(hex(p.border));
    k.ring = Some(hex(p.accent));
    k.caret = Some(hex(p.accent));
    k.selection = Some(hex_alpha(p.accent, 70));
    k.accent = Some(hex(p.surface_hi));
    k.accent_foreground = Some(hex(p.text));
    k.muted = Some(hex(p.surface_hi));
    k.muted_foreground = Some(hex(p.text_muted));
    k.popover = Some(hex(p.surface));
    k.popover_foreground = Some(hex(p.text));
    k.overlay = Some(hex_alpha(0x000000, 130));
    k.primary = Some(hex(p.accent));
    k.primary_hover = Some(hex(p.accent_hi));
    k.primary_active = Some(hex(p.accent_hi));
    k.primary_foreground = Some(hex(p.on_accent));
    k.secondary = Some(hex(p.surface_hi));
    k.secondary_hover = Some(hex(p.border));
    k.secondary_active = Some(hex(p.border));
    k.secondary_foreground = Some(hex(p.text));
    k.button = Some(hex(p.surface_hi));
    k.button_hover = Some(hex(p.border));
    k.button_active = Some(hex(p.border));
    k.button_foreground = Some(hex(p.text));
    k.danger = Some(hex(p.err));
    k.danger_hover = Some(hex(p.err));
    k.danger_active = Some(hex(p.err));
    k.danger_foreground = Some(hex(on_danger));
    k.success = Some(hex(p.ok));
    k.warning = Some(hex(p.warn));
    k.list = Some(hex(p.surface));
    k.list_hover = Some(hex(p.surface_hi));
    k.list_active = Some(hex_alpha(p.accent, 40));
    k.list_active_border = Some(hex(p.accent));
    k.progress_bar = Some(hex(p.accent));
    k.link = Some(hex(p.accent));
    k.sidebar = Some(hex(p.sidebar));
    k.scrollbar = Some(hex_alpha(p.bg, 0));
    k.scrollbar_thumb = Some(hex_alpha(p.text_muted, 110));
    k.scrollbar_thumb_hover = Some(hex_alpha(p.text_muted, 170));
    k.switch = Some(hex(p.border));
    cfg
}

/// License notices for the assets compiled into the app (the Inter typeface
/// and the Phosphor icon font), shown under *Settings → About* (FS-18). The
/// complete bundle for every linked crate ships next to the binary as
/// `THIRD_PARTY_NOTICES.txt` (scripts/third_party_notices.py).
pub const EMBEDDED_ASSET_NOTICES: &[(&str, &str)] = &[
    (
        "Inter typeface — SIL Open Font License 1.1",
        include_str!("../assets/fonts/Inter-LICENSE.txt"),
    ),
    (
        "Phosphor Icons — MIT License",
        include_str!("../assets/fonts/Phosphor-LICENSE.txt"),
    ),
];

/// Static Inter instances (see scripts/derive_inter_instances.py): GPUI's Linux
/// text stack only renders a variable font's default instance, so real weights
/// need real faces to be consistent on every platform.
const INTER: [&[u8]; 3] = [
    include_bytes!("../assets/fonts/Inter-Regular.ttf"),
    include_bytes!("../assets/fonts/Inter-SemiBold.ttf"),
    include_bytes!("../assets/fonts/Inter-Bold.ttf"),
];
const PHOSPHOR: &[u8] = include_bytes!("../assets/fonts/Phosphor.ttf");

fn install_fonts(cx: &mut App) {
    // Best-effort: if the platform text system refuses a face, GPUI falls back
    // to the system UI font rather than failing to start.
    let mut faces: Vec<Cow<'static, [u8]>> = INTER.iter().map(|f| Cow::Borrowed(*f)).collect();
    faces.push(Cow::Borrowed(PHOSPHOR));
    let _ = cx.text_system().add_fonts(faces);
}

// ---------------------------------------------------------------------------
// Icon glyphs (Phosphor regular). Render with `icon_text`.
// ---------------------------------------------------------------------------

pub mod icon {
    pub const VAULT: &str = "\u{e76e}";
    pub const CONTACTS: &str = "\u{e6f8}"; // address-book
    pub const IDENTITY: &str = "\u{e6f6}"; // identification-badge
    pub const LOCK: &str = "\u{e2fa}";
    pub const LOCK_KEY: &str = "\u{e2fe}";
    pub const PLUS: &str = "\u{e3d4}";
    pub const FILE: &str = "\u{e230}";
    pub const FOLDER: &str = "\u{e24a}";
    pub const EDIT: &str = "\u{e3b4}"; // pencil-simple
    pub const EYE: &str = "\u{e220}";
    pub const TRASH: &str = "\u{e4a6}";
    pub const KEY: &str = "\u{e2d6}";
    pub const SHIELD: &str = "\u{e40c}"; // shield-check
    pub const DOWNLOAD: &str = "\u{e20c}"; // download-simple
    pub const UPLOAD: &str = "\u{e4c0}"; // upload-simple
    pub const SEND: &str = "\u{e398}"; // paper-plane-tilt
    pub const COPY: &str = "\u{e1ca}";
    pub const CHECK: &str = "\u{e182}";
    pub const CHECK_CIRCLE: &str = "\u{e184}";
    pub const WARNING: &str = "\u{e4e0}";
    pub const WARNING_CIRCLE: &str = "\u{e4e2}";
    pub const CLOSE: &str = "\u{e4f6}"; // x
    pub const BACK: &str = "\u{e058}"; // arrow-left
    pub const SUN: &str = "\u{e472}";
    pub const MOON: &str = "\u{e330}";
    pub const SAVE: &str = "\u{e248}"; // floppy-disk
    pub const GEAR: &str = "\u{e270}";
    pub const IMPORT: &str = "\u{e010}"; // tray-arrow-down
    pub const DOTS: &str = "\u{e1fe}"; // dots-three
    pub const CARET_RIGHT: &str = "\u{e13a}";
    pub const CARET_DOWN: &str = "\u{e136}";
}

/// A Phosphor glyph at `size`, in `color`.
pub fn icon_text(glyph: &'static str, size: f32, color: Hsla) -> Div {
    div()
        .flex_none()
        .font_family(FONT_ICONS)
        .text_size(px(size))
        .line_height(px(size))
        .text_color(color)
        .child(glyph)
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

/// Body-size text in `color`.
pub fn text(s: impl Into<SharedString>, color: Hsla) -> Div {
    div().text_size(TEXT_BODY).text_color(color).child(s.into())
}

/// Small supporting text in `color`, wrapping.
pub fn small(s: impl Into<SharedString>, color: Hsla) -> Div {
    div()
        .text_size(TEXT_SMALL)
        .text_color(color)
        .child(s.into())
}

/// Muted small text — the most common supporting-copy style.
pub fn muted(s: impl Into<SharedString>, c: Colors) -> Div {
    small(s, c.text_muted)
}

/// Bold text at `size`.
pub fn strong(s: impl Into<SharedString>, size: Pixels, color: Hsla) -> Div {
    div()
        .text_size(size)
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(color)
        .child(s.into())
}

/// A single line that truncates with an ellipsis instead of wrapping.
pub fn one_line(el: Div) -> Div {
    el.min_w_0().overflow_hidden().truncate()
}

/// Monospace text (fingerprints, addresses, paths).
pub fn mono(s: impl Into<SharedString>, size: Pixels, color: Hsla, cx: &App) -> Div {
    div()
        .font_family(Theme::global(cx).mono_font_family.clone())
        .text_size(size)
        .text_color(color)
        .child(s.into())
}

// ---------------------------------------------------------------------------
// Element helpers
// ---------------------------------------------------------------------------

/// A bordered, rounded, padded surface. Use to group list rows and form
/// sections. Children are stacked vertically with the app's 8 px rhythm.
pub fn card(c: Colors) -> Div {
    div()
        .w_full()
        .flex()
        .flex_col()
        .gap(px(8.0))
        .bg(c.surface)
        .border_1()
        .border_color(c.border)
        .rounded(RADIUS)
        .p(px(16.0))
}

/// A horizontal row with the app's default spacing, vertically centred.
pub fn row() -> Div {
    div().flex().flex_row().items_center().gap(px(8.0))
}

/// A vertical stack with the app's default spacing.
fn col() -> Div {
    div().flex().flex_col().gap(px(8.0))
}

/// A horizontal row whose children wrap onto the next line when narrow.
pub fn wrap_row() -> Div {
    row().flex_wrap()
}

/// Accent-filled primary call-to-action.
pub fn primary_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    Button::new(id).primary().label(label)
}

/// Outlined secondary button.
pub fn secondary_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    Button::new(id).label(label)
}

/// Destructive action button: a solid error-colour fill in both appearances
/// (GPUI Component's own danger variant is only a faint tint in dark mode,
/// which undersells an irreversible action).
pub fn danger_button(id: impl Into<ElementId>, label: impl Into<SharedString>, cx: &App) -> Button {
    let c = colors(cx);
    let fg = if is_dark(cx) {
        c.on_accent
    } else {
        rgb(0xffffff).into()
    };
    let variant = ButtonCustomVariant::new(cx)
        .color(c.err)
        .foreground(fg)
        .hover(c.err.opacity(0.88))
        .active(c.err.opacity(0.76));
    Button::new(id).custom(variant).label(label)
}

/// A borderless text button tinted with the accent colour (links, "Select all").
pub fn link_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    Button::new(id).ghost().small().label(label)
}

/// A compact secondary button ("Copy").
pub fn small_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    Button::new(id).small().label(label)
}

/// Accent-filled primary button that fills the available width.
pub fn primary_button_full(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    primary_button(id, label).w_full().h(px(36.0))
}

/// Secondary button that fills the available width.
pub fn secondary_button_full(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    secondary_button(id, label).w_full().h(px(36.0))
}

/// A borderless icon button tinted with the muted text colour. `hover` is its
/// tooltip and its accessible name.
pub fn icon_button(
    id: impl Into<ElementId>,
    glyph: &'static str,
    hover: &str,
    c: Colors,
) -> Button {
    let hover: SharedString = hover.to_string().into();
    Button::new(id)
        .ghost()
        .w(px(32.0))
        .h(px(32.0))
        .child(icon_text(glyph, 17.0, c.text_muted))
        .tooltip(hover.clone())
        .accessibility_label(hover)
}

/// Set `disabled` on any GPUI Component control in a builder chain.
pub fn enabled<T: Disableable>(el: T, enabled: bool) -> T {
    el.disabled(!enabled)
}

#[derive(Clone, Copy, Debug)]
pub enum BadgeKind {
    Ok,
    Warn,
    Err,
    Neutral,
    Accent,
}

/// A small coloured pill — used for trust state and status flags.
pub fn badge(label: impl Into<SharedString>, kind: BadgeKind, c: Colors) -> Div {
    let col = match kind {
        BadgeKind::Ok => c.ok,
        BadgeKind::Warn => c.warn,
        BadgeKind::Err => c.err,
        BadgeKind::Accent => c.accent,
        BadgeKind::Neutral => c.text_muted,
    };
    div()
        .flex_none()
        .px(px(8.0))
        .py(px(2.0))
        .rounded(px(10.0))
        .bg(with_alpha(col, 38))
        .border_1()
        .border_color(with_alpha(col, 110))
        .text_size(TEXT_SMALL)
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(col)
        .child(label.into())
}

/// A screen heading with a right-aligned action area. Below 600 px the
/// actions wrap underneath the title instead of squeezing it.
pub fn section_header(
    title: impl Into<SharedString>,
    right: Option<AnyElement>,
    wide: bool,
    c: Colors,
) -> Div {
    let heading = strong(title, TEXT_HEADING, c.text);
    let header = if wide {
        div()
            .w_full()
            .flex()
            .flex_row()
            .items_center()
            .justify_between()
            .gap(px(8.0))
            .child(one_line(heading).flex_1())
            .children(right.map(|r| row().flex_none().child(r)))
    } else {
        col()
            .w_full()
            .child(heading)
            .children(right.map(|r| wrap_row().child(r)))
    };
    header.mb(px(8.0))
}

/// Supporting copy below a page heading, with a consistent reading rhythm.
pub fn page_description(s: impl Into<SharedString>, c: Colors) -> Div {
    text(s, c.text_muted).w_full().mb(px(16.0))
}

/// A centred placeholder for empty lists: muted icon, title, subtitle, and an
/// optional call to action.
pub fn empty_state(
    glyph: &'static str,
    title: impl Into<SharedString>,
    subtitle: impl Into<SharedString>,
    cta: Option<AnyElement>,
    c: Colors,
) -> Div {
    div()
        .w_full()
        .pt(px(32.0))
        .pb(px(16.0))
        .flex()
        .flex_col()
        .items_center()
        .child(icon_text(glyph, 44.0, c.text_muted))
        .child(div().h(px(10.0)))
        .child(strong(title, px(16.0), c.text))
        .child(div().h(px(2.0)))
        .child(text(subtitle, c.text_muted).text_center())
        .child(div().h(px(14.0)))
        .children(cta)
}

/// An accent-tinted banner (rounded, soft fill) for transient status messages.
pub fn banner(accent: Hsla) -> Div {
    div()
        .w_full()
        .bg(with_alpha(accent, 28))
        .border_1()
        .border_color(with_alpha(accent, 90))
        .rounded(RADIUS_SM)
        .px(px(12.0))
        .py(px(8.0))
        .mb(px(8.0))
}

/// A subtle centred "OR" divider between alternative actions.
pub fn divider_or(c: Colors) -> Div {
    div()
        .w_full()
        .py(px(4.0))
        .flex()
        .justify_center()
        .child(small("OR", c.text_muted))
}

/// A thin horizontal rule.
pub fn separator(c: Colors) -> Div {
    div().w_full().h(px(1.0)).my(px(4.0)).bg(c.border)
}

/// A field caption (above an input).
pub fn caption(s: impl Into<SharedString>, c: Colors) -> Div {
    small(s, c.text_muted)
}

/// The dimmed full-window backdrop used by modals and the busy overlay. It
/// occludes everything behind it, so the UI underneath cannot be clicked.
pub fn backdrop(id: impl Into<ElementId>, alpha: u8) -> gpui_kit::Stateful<Div> {
    div()
        .id(id)
        .absolute()
        .top_0()
        .left_0()
        .size_full()
        .bg(black_alpha(alpha))
        .occlude()
        .flex()
        .items_center()
        .justify_center()
}

/// The surface of a centred modal dialog (title + scrollable body). The caller
/// places it inside a [`backdrop`] and wires the dismiss behaviour.
pub fn modal_card(
    id: impl Into<ElementId>,
    title: impl Into<SharedString>,
    width: Pixels,
    max_height: Pixels,
    c: Colors,
) -> gpui_kit::Stateful<Div> {
    div()
        .id(id)
        .occlude()
        .w(width)
        .max_h(max_height)
        .flex()
        .flex_col()
        .gap(px(10.0))
        .bg(c.surface)
        .border_1()
        .border_color(c.border)
        .rounded(RADIUS)
        .p(px(18.0))
        .shadow(shadow(8.0, 28.0, 140))
        .child(strong(title, px(18.0), c.text))
}

/// The floating toast surface, anchored bottom-right by the caller.
pub fn toast_card(error: bool, c: Colors) -> Div {
    let accent = if error { c.err } else { c.ok };
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(10.0))
        .bg(c.surface_hi)
        .border_1()
        .border_color(accent)
        .rounded(RADIUS)
        .px(px(14.0))
        .py(px(10.0))
        .shadow(shadow(4.0, 16.0, 120))
        .child(icon_text(
            if error { icon::WARNING } else { icon::CHECK },
            16.0,
            accent,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_palettes_are_distinct_and_opaque() {
        let (d, l) = (Colors::dark(), Colors::light());
        assert_ne!(d.bg, l.bg);
        for c in [d, l] {
            for col in [c.bg, c.surface, c.text, c.accent, c.err] {
                assert!((col.a - 1.0).abs() < f32::EPSILON);
            }
        }
    }

    #[test]
    fn component_config_carries_the_palette() {
        let cfg = component_config(&DARK, ThemeMode::Dark);
        assert_eq!(cfg.colors.background.as_deref(), Some("#14161b"));
        assert_eq!(cfg.colors.primary.as_deref(), Some("#6da5ff"));
        assert_eq!(cfg.font_family.as_deref(), Some(FONT_UI));
        let cfg = component_config(&LIGHT, ThemeMode::Light);
        assert_eq!(cfg.colors.danger_foreground.as_deref(), Some("#ffffff"));
    }

    #[test]
    fn embedded_fonts_are_the_expected_faces() {
        // Sanity: a truncated or swapped asset would silently fall back.
        assert!(INTER.iter().all(|f| f.len() > 100_000));
        assert!(PHOSPHOR.len() > 10_000);
    }
}
