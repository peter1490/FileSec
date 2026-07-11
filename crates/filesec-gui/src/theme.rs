//! Visual design system: palette, fonts, global style, and reusable widgets.
//!
//! This module is purely presentational and **feature-agnostic** — it carries no
//! `cfg` gates so every feature permutation (pqc / passkey / keyring) compiles
//! against the same helpers. [`install`] is called once from
//! [`crate::run`] with the eframe [`egui::Context`]; it registers the bundled
//! fonts and installs a light and a dark [`egui::Style`], then leaves egui to
//! follow the OS theme (overridable with the sidebar toggle).
//!
//! The widget helpers ([`card`], [`primary_button`], [`badge`], …) only *build*
//! UI and return the same [`egui::Response`] the call sites already branch on, so
//! they are drop-in replacements that keep the immediate-mode, action-collection
//! rendering pattern intact.

use std::sync::Arc;

use eframe::egui::{self, Color32};

// ---------------------------------------------------------------------------
// Palette
// ---------------------------------------------------------------------------

/// Semantic colour tokens for one theme. Helpers resolve the right set from the
/// active visuals via [`colors`], so they recolour automatically on theme flip.
#[derive(Clone, Copy)]
pub struct Colors {
    pub bg: Color32,
    pub surface: Color32,
    pub surface_hi: Color32,
    pub sidebar: Color32,
    pub input: Color32,
    pub border: Color32,
    pub text: Color32,
    pub text_muted: Color32,
    pub accent: Color32,
    pub accent_hi: Color32,
    pub ok: Color32,
    pub warn: Color32,
    pub err: Color32,
    pub on_accent: Color32,
}

impl Colors {
    pub const fn dark() -> Self {
        Self {
            bg: Color32::from_rgb(0x14, 0x16, 0x1b),
            surface: Color32::from_rgb(0x1b, 0x1e, 0x25),
            surface_hi: Color32::from_rgb(0x23, 0x27, 0x30),
            sidebar: Color32::from_rgb(0x10, 0x12, 0x17),
            input: Color32::from_rgb(0x0f, 0x11, 0x16),
            border: Color32::from_rgb(0x2c, 0x31, 0x3c),
            text: Color32::from_rgb(0xe6, 0xe8, 0xed),
            text_muted: Color32::from_rgb(0x8a, 0x90, 0x9c),
            accent: Color32::from_rgb(0x4c, 0x8d, 0xf0),
            accent_hi: Color32::from_rgb(0x6a, 0xa3, 0xf5),
            ok: Color32::from_rgb(0x3f, 0xb9, 0x68),
            warn: Color32::from_rgb(0xd9, 0xa3, 0x3d),
            err: Color32::from_rgb(0xe0, 0x5d, 0x5d),
            on_accent: Color32::WHITE,
        }
    }

    pub const fn light() -> Self {
        Self {
            bg: Color32::from_rgb(0xf6, 0xf7, 0xf9),
            surface: Color32::from_rgb(0xff, 0xff, 0xff),
            surface_hi: Color32::from_rgb(0xee, 0xf0, 0xf3),
            sidebar: Color32::from_rgb(0xed, 0xef, 0xf3),
            input: Color32::from_rgb(0xf3, 0xf5, 0xf8),
            border: Color32::from_rgb(0xd9, 0xdd, 0xe3),
            text: Color32::from_rgb(0x1b, 0x1e, 0x25),
            text_muted: Color32::from_rgb(0x5e, 0x65, 0x73),
            accent: Color32::from_rgb(0x2f, 0x6f, 0xe0),
            accent_hi: Color32::from_rgb(0x1f, 0x5f, 0xd6),
            ok: Color32::from_rgb(0x2e, 0x9e, 0x55),
            warn: Color32::from_rgb(0xb5, 0x7e, 0x16),
            err: Color32::from_rgb(0xcf, 0x44, 0x44),
            on_accent: Color32::WHITE,
        }
    }
}

/// The token set for the `ui`'s active theme.
pub fn colors(ui: &egui::Ui) -> Colors {
    if ui.visuals().dark_mode {
        Colors::dark()
    } else {
        Colors::light()
    }
}

/// The token set for the context's active theme (for panel frames built before
/// a `Ui` exists).
pub fn colors_for(ctx: &egui::Context) -> Colors {
    if ctx.theme() == egui::Theme::Dark {
        Colors::dark()
    } else {
        Colors::light()
    }
}

/// Accent colour at a soft translucent alpha — for selected nav rows etc.
pub fn accent_soft(c: Colors) -> Color32 {
    with_alpha(c.accent, 40)
}

// Back-compat shims: the existing `app.rs` colours these status/accent strings
// directly via `colored_label`/`RichText::color`, which override per call and so
// read on both themes. Structural uses migrate to `colors(ui)` over time.
pub const OK_GREEN: Color32 = Color32::from_rgb(0x3f, 0xb9, 0x68);
pub const ERR_RED: Color32 = Color32::from_rgb(0xe0, 0x5d, 0x5d);
pub const WARN_AMBER: Color32 = Color32::from_rgb(0xd9, 0xa3, 0x3d);
pub const MUTED: Color32 = Color32::from_rgb(0x80, 0x87, 0x93);
pub const ACCENT: Color32 = Color32::from_rgb(0x3f, 0x83, 0xe6);

pub const RADIUS: u8 = 8;
pub const RADIUS_SM: u8 = 6;
pub const SIDEBAR_W: f32 = 216.0;

fn with_alpha(c: Color32, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a)
}

fn shadow(offset_y: i8, blur: u8, alpha: u8) -> egui::epaint::Shadow {
    egui::epaint::Shadow {
        offset: [0, offset_y],
        blur,
        spread: 0,
        color: Color32::from_black_alpha(alpha),
    }
}

// ---------------------------------------------------------------------------
// Install: fonts + style for both themes
// ---------------------------------------------------------------------------

/// Register bundled fonts and install the light/dark styles. Call once at startup.
pub fn install(ctx: &egui::Context) {
    install_fonts(ctx);
    // Follow the OS appearance by default; the sidebar toggle overrides this.
    ctx.options_mut(|o| o.theme_preference = egui::ThemePreference::System);
    ctx.set_style_of(egui::Theme::Dark, style_for(egui::Theme::Dark));
    ctx.set_style_of(egui::Theme::Light, style_for(egui::Theme::Light));
}

fn install_fonts(ctx: &egui::Context) {
    use egui::{FontData, FontFamily};
    // Start from the default set so egui's emoji/symbol fallbacks are preserved.
    let mut fonts = egui::FontDefinitions::default();

    fonts.font_data.insert(
        "Inter".to_owned(),
        Arc::new(FontData::from_static(include_bytes!(
            "../assets/fonts/InterVariable.ttf"
        ))),
    );
    fonts.font_data.insert(
        "Phosphor".to_owned(),
        Arc::new(FontData::from_static(include_bytes!(
            "../assets/fonts/Phosphor.ttf"
        ))),
    );

    // Inter becomes the primary proportional face; keep the rest as fallbacks so
    // existing emoji glyphs (🔒 🔑 ⚠ …) still resolve.
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, "Inter".to_owned());
    // Dedicated family for the Phosphor line-icon glyphs.
    fonts.families.insert(
        FontFamily::Name("phosphor".into()),
        vec!["Phosphor".to_owned()],
    );

    ctx.set_fonts(fonts);
}

fn style_for(theme: egui::Theme) -> egui::Style {
    let mut style = theme.default_style();
    let c = match theme {
        egui::Theme::Dark => Colors::dark(),
        egui::Theme::Light => Colors::light(),
    };
    apply(&mut style, &c);
    style
}

fn apply(style: &mut egui::Style, c: &Colors) {
    use egui::{
        CornerRadius, FontFamily::Monospace, FontFamily::Proportional, FontId, Margin, Stroke,
        TextStyle, Vec2,
    };

    // Spacing — roomier than egui defaults.
    let sp = &mut style.spacing;
    sp.item_spacing = Vec2::new(8.0, 8.0);
    sp.button_padding = Vec2::new(12.0, 7.0);
    sp.window_margin = Margin::same(14);
    sp.menu_margin = Margin::same(8);
    sp.interact_size = Vec2::new(0.0, 30.0);
    sp.indent = 18.0;

    // Type scale — larger and cleaner than the tiny egui defaults.
    style.text_styles = [
        (TextStyle::Heading, FontId::new(22.0, Proportional)),
        (
            TextStyle::Name("H2".into()),
            FontId::new(16.0, Proportional),
        ),
        (TextStyle::Body, FontId::new(14.5, Proportional)),
        (TextStyle::Button, FontId::new(14.5, Proportional)),
        (TextStyle::Small, FontId::new(12.0, Proportional)),
        (TextStyle::Monospace, FontId::new(13.0, Monospace)),
    ]
    .into();

    let radius = CornerRadius::same(RADIUS);
    let radius_sm = CornerRadius::same(RADIUS_SM);
    let v = &mut style.visuals;
    v.panel_fill = c.bg;
    v.window_fill = c.surface;
    v.extreme_bg_color = c.input;
    v.text_edit_bg_color = Some(c.input);
    v.faint_bg_color = c.surface_hi;
    v.code_bg_color = c.surface_hi;
    v.override_text_color = Some(c.text);
    v.hyperlink_color = c.accent;
    v.warn_fg_color = c.warn;
    v.error_fg_color = c.err;
    v.window_corner_radius = radius;
    v.menu_corner_radius = radius;
    v.window_stroke = Stroke::new(1.0_f32, c.border);
    v.window_shadow = shadow(8, 24, 120);
    v.popup_shadow = shadow(6, 16, 100);
    v.interact_cursor = Some(egui::CursorIcon::PointingHand);
    v.selection = egui::style::Selection {
        bg_fill: with_alpha(c.accent, 70),
        // Doubles as the focus ring around text inputs (egui draws this stroke
        // when a TextEdit has keyboard focus), so give it a touch more weight.
        stroke: Stroke::new(1.5_f32, c.accent),
    };

    let w = &mut v.widgets;
    // Non-interactive: labels, separators, group frames.
    w.noninteractive.corner_radius = radius_sm;
    w.noninteractive.bg_fill = c.surface;
    w.noninteractive.weak_bg_fill = c.surface;
    w.noninteractive.bg_stroke = Stroke::new(1.0_f32, c.border);
    w.noninteractive.fg_stroke = Stroke::new(1.0_f32, c.text_muted);
    // Inactive: idle buttons / text edits.
    w.inactive.corner_radius = radius_sm;
    w.inactive.bg_fill = c.surface_hi;
    w.inactive.weak_bg_fill = c.surface_hi;
    w.inactive.bg_stroke = Stroke::new(1.0_f32, c.border);
    w.inactive.fg_stroke = Stroke::new(1.0_f32, c.text);
    w.inactive.expansion = 0.0;
    // Hovered.
    w.hovered.corner_radius = radius_sm;
    w.hovered.bg_fill = c.surface_hi;
    w.hovered.weak_bg_fill = c.surface_hi;
    w.hovered.bg_stroke = Stroke::new(1.0_f32, c.accent);
    w.hovered.fg_stroke = Stroke::new(1.0_f32, c.text);
    w.hovered.expansion = 1.0;
    // Active / pressed.
    w.active.corner_radius = radius_sm;
    w.active.bg_fill = with_alpha(c.accent, 64);
    w.active.weak_bg_fill = with_alpha(c.accent, 64);
    w.active.bg_stroke = Stroke::new(1.0_f32, c.accent);
    w.active.fg_stroke = Stroke::new(1.0_f32, c.text);
    w.active.expansion = 1.0;
    // Open (combo boxes / menus).
    w.open.corner_radius = radius_sm;
    w.open.bg_fill = c.surface_hi;
    w.open.weak_bg_fill = c.surface_hi;
    w.open.bg_stroke = Stroke::new(1.0_f32, c.border);
    w.open.fg_stroke = Stroke::new(1.0_f32, c.text);
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
}

/// A [`RichText`] rendered in the Phosphor icon family at `size`.
pub fn icon_text(glyph: &str, size: f32) -> egui::RichText {
    egui::RichText::new(glyph).font(egui::FontId::new(
        size,
        egui::FontFamily::Name("phosphor".into()),
    ))
}

// ---------------------------------------------------------------------------
// Widget helpers
// ---------------------------------------------------------------------------

/// A bordered, rounded, padded surface. Use to group list rows and form sections.
pub fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let c = colors(ui);
    egui::Frame::NONE
        .fill(c.surface)
        .stroke(egui::Stroke::new(1.0_f32, c.border))
        .corner_radius(egui::CornerRadius::same(RADIUS))
        .inner_margin(egui::Margin::same(12))
        .outer_margin(egui::Margin {
            bottom: 8,
            ..Default::default()
        })
        .show(ui, add)
        .inner
}

/// Accent-filled primary call-to-action.
pub fn primary_button(ui: &mut egui::Ui, label: impl Into<String>) -> egui::Response {
    let c = colors(ui);
    ui.add(
        egui::Button::new(
            egui::RichText::new(label.into())
                .color(c.on_accent)
                .strong(),
        )
        .fill(c.accent)
        .corner_radius(egui::CornerRadius::same(RADIUS_SM))
        .min_size(egui::vec2(0.0, 32.0)),
    )
}

/// Outlined secondary button.
pub fn secondary_button(ui: &mut egui::Ui, label: impl Into<String>) -> egui::Response {
    let c = colors(ui);
    ui.add(
        egui::Button::new(egui::RichText::new(label.into()).color(c.text))
            .fill(c.surface_hi)
            .stroke(egui::Stroke::new(1.0_f32, c.border))
            .corner_radius(egui::CornerRadius::same(RADIUS_SM))
            .min_size(egui::vec2(0.0, 32.0)),
    )
}

/// Destructive action button (filled error colour).
pub fn danger_button(ui: &mut egui::Ui, label: impl Into<String>) -> egui::Response {
    let c = colors(ui);
    ui.add(
        egui::Button::new(
            egui::RichText::new(label.into())
                .color(Color32::WHITE)
                .strong(),
        )
        .fill(c.err)
        .corner_radius(egui::CornerRadius::same(RADIUS_SM))
        .min_size(egui::vec2(0.0, 32.0)),
    )
}

/// Accent-filled primary button that fills the available width.
pub fn primary_button_full(ui: &mut egui::Ui, label: impl Into<String>) -> egui::Response {
    let c = colors(ui);
    let w = ui.available_width();
    ui.add_sized(
        egui::vec2(w, 36.0),
        egui::Button::new(
            egui::RichText::new(label.into())
                .color(c.on_accent)
                .strong(),
        )
        .fill(c.accent)
        .corner_radius(egui::CornerRadius::same(RADIUS_SM)),
    )
}

/// Outlined secondary button that fills the available width.
pub fn secondary_button_full(ui: &mut egui::Ui, label: impl Into<String>) -> egui::Response {
    let c = colors(ui);
    let w = ui.available_width();
    ui.add_sized(
        egui::vec2(w, 36.0),
        egui::Button::new(egui::RichText::new(label.into()).color(c.text))
            .fill(c.surface_hi)
            .stroke(egui::Stroke::new(1.0_f32, c.border))
            .corner_radius(egui::CornerRadius::same(RADIUS_SM)),
    )
}

/// A full-width, comfortably-padded single-line input with the inset field look
/// and an accent focus ring.
pub fn text_input(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    password: bool,
) -> egui::Response {
    ui.add(
        egui::TextEdit::singleline(text)
            .password(password)
            .hint_text(hint)
            .desired_width(f32::INFINITY)
            .margin(egui::Margin::symmetric(12, 9))
            .font(egui::TextStyle::Body),
    )
}

/// A full-width multi-line input (e.g. pasting a public key).
///
/// Capped at `rows` lines tall: a `TextEdit::multiline` grows with its content,
/// so pasting a long key would otherwise balloon the field until it pushed the
/// buttons below it off-screen. Wrapping it in a fixed-height scroll area keeps
/// the field compact and scrolls the overflow internally instead.
pub fn text_area(ui: &mut egui::Ui, text: &mut String, hint: &str, rows: usize) -> egui::Response {
    // Match the visible height to `rows` lines plus the field's vertical margin,
    // so an empty field fits exactly and only longer content reveals a scrollbar.
    let row_h = ui.text_style_height(&egui::TextStyle::Body);
    let max_height = row_h * rows as f32 + 16.0;
    egui::ScrollArea::vertical()
        .max_height(max_height)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(text)
                    .hint_text(hint)
                    .desired_width(f32::INFINITY)
                    .desired_rows(rows)
                    .margin(egui::Margin::symmetric(10, 8))
                    .font(egui::TextStyle::Body),
            )
        })
        .inner
}

#[derive(Clone, Copy)]
pub enum BadgeKind {
    Ok,
    Warn,
    Err,
    Neutral,
    Accent,
}

/// A small coloured pill — used for trust state and status flags.
pub fn badge(ui: &mut egui::Ui, text: impl Into<String>, kind: BadgeKind) -> egui::Response {
    let c = colors(ui);
    let col = match kind {
        BadgeKind::Ok => c.ok,
        BadgeKind::Warn => c.warn,
        BadgeKind::Err => c.err,
        BadgeKind::Accent => c.accent,
        BadgeKind::Neutral => c.text_muted,
    };
    egui::Frame::NONE
        .fill(with_alpha(col, 38))
        .stroke(egui::Stroke::new(1.0_f32, with_alpha(col, 110)))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text.into()).color(col).small().strong());
        })
        .response
}

/// A screen heading with a right-aligned action area.
pub fn section_header(ui: &mut egui::Ui, title: &str, right: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.heading(title);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), right);
    });
    ui.add_space(6.0);
}

/// A centered placeholder for empty lists: muted icon, title, subtitle, and a CTA.
pub fn empty_state(
    ui: &mut egui::Ui,
    glyph: &str,
    title: &str,
    subtitle: &str,
    cta: impl FnOnce(&mut egui::Ui),
) {
    let c = colors(ui);
    ui.add_space(48.0);
    ui.vertical_centered(|ui| {
        ui.label(icon_text(glyph, 44.0).color(c.text_muted));
        ui.add_space(10.0);
        ui.label(egui::RichText::new(title).size(16.0).strong());
        ui.add_space(2.0);
        ui.label(egui::RichText::new(subtitle).color(c.text_muted));
        ui.add_space(14.0);
        cta(ui);
    });
}

/// A borderless icon button tinted with the muted text colour. `hover` is its tooltip.
pub fn icon_button(ui: &mut egui::Ui, glyph: &str, hover: &str) -> egui::Response {
    let c = colors(ui);
    ui.add(egui::Button::new(icon_text(glyph, 15.0).color(c.text_muted)).frame(false))
        .on_hover_text(hover)
}

/// An accent-tinted banner (rounded, soft fill) for transient status messages.
pub fn banner<R>(ui: &mut egui::Ui, accent: Color32, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::NONE
        .fill(with_alpha(accent, 28))
        .stroke(egui::Stroke::new(1.0_f32, with_alpha(accent, 90)))
        .corner_radius(egui::CornerRadius::same(RADIUS_SM))
        .inner_margin(egui::Margin::symmetric(12, 8))
        .outer_margin(egui::Margin {
            bottom: 8,
            ..Default::default()
        })
        .show(ui, add)
        .inner
}

/// A subtle centered "OR" divider between alternative actions.
pub fn divider_or(ui: &mut egui::Ui) {
    let c = colors(ui);
    ui.add_space(8.0);
    ui.vertical_centered(|ui| {
        ui.label(egui::RichText::new("OR").color(c.text_muted).small());
    });
    ui.add_space(8.0);
}

/// A centered modal dialog with a dimmed backdrop and a title header. Returns
/// `(should_close, inner)` — `should_close` is `true` when the user clicked the
/// backdrop or pressed Escape, which the caller maps to its cancel action.
pub fn modal<R>(
    ctx: &egui::Context,
    title: &str,
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> (bool, R) {
    let c = colors_for(ctx);
    let resp = egui::Modal::new(egui::Id::new(title))
        .backdrop_color(Color32::from_black_alpha(130))
        .frame(
            egui::Frame::NONE
                .fill(c.surface)
                .stroke(egui::Stroke::new(1.0_f32, c.border))
                .corner_radius(egui::CornerRadius::same(RADIUS))
                .inner_margin(egui::Margin::same(18))
                .shadow(shadow(8, 28, 140)),
        )
        .show(ctx, |ui| {
            ui.set_max_width(460.0);
            ui.label(egui::RichText::new(title).size(18.0).strong());
            ui.add_space(10.0);
            add(ui)
        });
    (resp.should_close(), resp.inner)
}

/// A floating toast anchored bottom-right. Returns `true` if the user dismissed it.
pub fn toast(ctx: &egui::Context, msg: &str, error: bool) -> bool {
    let c = if ctx.theme() == egui::Theme::Dark {
        Colors::dark()
    } else {
        Colors::light()
    };
    let accent = if error { c.err } else { c.ok };
    let mut dismissed = false;
    egui::Area::new(egui::Id::new("filesec_toast"))
        .order(egui::Order::Foreground)
        .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-16.0, -16.0))
        .interactable(true)
        .show(ctx, |ui| {
            egui::Frame::NONE
                .fill(c.surface_hi)
                .stroke(egui::Stroke::new(1.0_f32, accent))
                .corner_radius(egui::CornerRadius::same(RADIUS))
                .inner_margin(egui::Margin::symmetric(14, 10))
                .shadow(shadow(4, 16, 120))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            icon_text(if error { icon::WARNING } else { icon::CHECK }, 16.0)
                                .color(accent),
                        );
                        ui.label(egui::RichText::new(msg).color(c.text));
                        ui.add_space(4.0);
                        if ui
                            .add(
                                egui::Button::new(icon_text(icon::CLOSE, 13.0).color(c.text_muted))
                                    .frame(false),
                            )
                            .clicked()
                        {
                            dismissed = true;
                        }
                    });
                });
        });
    dismissed
}
