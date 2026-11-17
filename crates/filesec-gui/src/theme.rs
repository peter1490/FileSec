//! Visual design system: palette, type scale, icons, appearance, and the
//! reusable building blocks every screen is assembled from.
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
//!
//! Design rules the helpers encode, so screens stay one coherent product:
//!
//! * **One accent.** The accent colour marks the single primary action of a
//!   screen, the current selection, and focus — nothing decorative.
//! * **Neutral surfaces, hairline borders.** Depth comes from a 1 px border and
//!   a whisper of shadow, never from heavy fills.
//! * **One icon family.** Every glyph is a Lucide outline icon (the same set
//!   GPUI Component draws its own controls with), rendered by [`icon_text`] or
//!   a button's `.icon(..)`.
//! * **A fixed type scale** ([`TEXT_TITLE`] … [`TEXT_SMALL`]) and a 4 px
//!   spacing rhythm.

use std::borrow::Cow;
use std::rc::Rc;

use gpui_kit::component::button::{Button, ButtonCustomVariant, ButtonVariants};
use gpui_kit::component::theme::{Theme, ThemeConfig, ThemeMode};
use gpui_kit::component::{Disableable, Icon, Sizable};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    div, px, rgb, AnyElement, App, AssetSource, BoxShadow, Div, ElementId, FontWeight, Global,
    Hsla, InteractiveElement, IntoElement, ParentElement, Pixels, SharedString, Styled,
    WindowAppearance,
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
    /// The main content canvas.
    bg: u32,
    /// The navigation sidebar.
    sidebar: u32,
    /// Cards, lists and grouped sections on the canvas.
    surface: u32,
    /// Hover fills and subtle insets.
    surface_hi: u32,
    /// Dialogs, menus, toasts — anything floating above the canvas.
    raised: u32,
    /// Outer borders of controls and containers.
    border: u32,
    /// Hairlines inside containers (row dividers, header rules).
    border_subtle: u32,
    text: u32,
    text_muted: u32,
    /// Placeholders, disabled text and resting icons. Not for content that
    /// must be read.
    text_subtle: u32,
    accent: u32,
    accent_hi: u32,
    ok: u32,
    warn: u32,
    err: u32,
    on_accent: u32,
}

const DARK: Palette = Palette {
    bg: 0x151517,
    sidebar: 0x0f0f11,
    surface: 0x1a1a1d,
    surface_hi: 0x242428,
    raised: 0x1e1e22,
    border: 0x2e2e34,
    border_subtle: 0x242429,
    text: 0xededf0,
    text_muted: 0xa0a0aa,
    text_subtle: 0x6c6c76,
    accent: 0x7d9cff,
    accent_hi: 0x93adff,
    ok: 0x4fc286,
    warn: 0xe3ad4a,
    err: 0xf26d6d,
    on_accent: 0x0a1330,
};

const LIGHT: Palette = Palette {
    bg: 0xfcfcfd,
    sidebar: 0xf4f4f6,
    surface: 0xffffff,
    surface_hi: 0xf1f1f4,
    raised: 0xffffff,
    border: 0xe0e0e6,
    border_subtle: 0xebebef,
    text: 0x18181d,
    text_muted: 0x5f5f6b,
    text_subtle: 0x9a9aa6,
    accent: 0x3657d6,
    accent_hi: 0x2c4bc0,
    ok: 0x1c7c48,
    warn: 0x965c00,
    err: 0xc93535,
    on_accent: 0xffffff,
};

/// Semantic colour tokens for one appearance. Helpers resolve the right set
/// from the active appearance via [`colors`], so they recolour automatically
/// when the theme flips.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Colors {
    pub bg: Hsla,
    pub sidebar: Hsla,
    pub surface: Hsla,
    pub surface_hi: Hsla,
    pub raised: Hsla,
    /// The fill of a text field. Derived exactly as GPUI Component derives
    /// its `Input` background (the canvas in light mode, the control border
    /// at 30% in dark), so the custom passphrase box matches every other field.
    pub input: Hsla,
    pub border: Hsla,
    pub border_subtle: Hsla,
    pub text: Hsla,
    pub text_muted: Hsla,
    pub text_subtle: Hsla,
    pub accent: Hsla,
    pub accent_hi: Hsla,
    pub ok: Hsla,
    pub warn: Hsla,
    pub err: Hsla,
    pub on_accent: Hsla,
    /// Whether this is the dark set (shadows are dropped in dark mode, where
    /// they only muddy the surfaces).
    pub dark: bool,
}

impl Colors {
    fn from_palette(p: &Palette, dark: bool) -> Self {
        let c = |hex: u32| -> Hsla { rgb(hex).into() };
        Self {
            bg: c(p.bg),
            sidebar: c(p.sidebar),
            surface: c(p.surface),
            surface_hi: c(p.surface_hi),
            raised: c(p.raised),
            input: if dark {
                c(p.border).opacity(0.3)
            } else {
                c(p.bg)
            },
            border: c(p.border),
            border_subtle: c(p.border_subtle),
            text: c(p.text),
            text_muted: c(p.text_muted),
            text_subtle: c(p.text_subtle),
            accent: c(p.accent),
            accent_hi: c(p.accent_hi),
            ok: c(p.ok),
            warn: c(p.warn),
            err: c(p.err),
            on_accent: c(p.on_accent),
            dark,
        }
    }

    #[must_use]
    pub fn dark() -> Self {
        Self::from_palette(&DARK, true)
    }

    #[must_use]
    pub fn light() -> Self {
        Self::from_palette(&LIGHT, false)
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

/// Accent colour at a soft translucent alpha — selected rows, icon tiles.
#[must_use]
pub fn accent_soft(c: Colors) -> Hsla {
    with_alpha(c.accent, if c.dark { 38 } else { 26 })
}

/// Black at `a / 255` alpha — modal backdrops and shadows.
#[must_use]
fn black_alpha(a: u8) -> Hsla {
    with_alpha(rgb(0x000000).into(), a)
}

/// Corner radii: containers, controls, and pills.
pub const RADIUS: Pixels = px(10.0);
pub const RADIUS_SM: Pixels = px(6.0);
pub const RADIUS_LG: Pixels = px(14.0);

/// Fixed chrome sizes.
pub const SIDEBAR_W: Pixels = px(220.0);
/// Height of every page's top bar (and of the macOS window-drag strip).
pub const HEADER_H: Pixels = px(56.0);
/// Horizontal padding of page content and headers.
pub const PAGE_PAD: Pixels = px(24.0);
/// Widest a reading page's content column grows (lists and forms).
pub const CONTENT_MAX: Pixels = px(880.0);

/// Type scale.
pub const TEXT_TITLE: Pixels = px(24.0);
pub const TEXT_HEADING: Pixels = px(20.0);
pub const TEXT_H2: Pixels = px(15.0);
pub const TEXT_BODY: Pixels = px(14.0);
pub const TEXT_LABEL: Pixels = px(13.0);
pub const TEXT_SMALL: Pixels = px(12.5);
pub const TEXT_MONO: Pixels = px(13.0);

/// Family name inside the bundled font files (what GPUI resolves by name).
pub const FONT_UI: &str = "Inter";

fn shadow(offset_y: f32, blur: f32, alpha: u8) -> Vec<BoxShadow> {
    vec![BoxShadow {
        color: black_alpha(alpha),
        offset: gpui_kit::point(px(0.0), px(offset_y)),
        blur_radius: px(blur),
        spread_radius: px(0.0),
        inset: false,
    }]
}

/// The resting elevation of cards and grouped sections (light mode only).
fn shadow_xs(c: Colors) -> Vec<BoxShadow> {
    if c.dark {
        Vec::new()
    } else {
        shadow(1.0, 2.0, 10)
    }
}

/// The elevation of floating surfaces: dialogs, toasts, the busy card.
fn shadow_float(c: Colors) -> Vec<BoxShadow> {
    let mut s = shadow(16.0, 40.0, if c.dark { 150 } else { 46 });
    s.extend(shadow(2.0, 6.0, if c.dark { 90 } else { 18 }));
    s
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
///
/// Button roles: the default button is a bordered surface (secondary actions);
/// `primary` is the accent fill; `ghost` rests in the muted text colour and
/// lifts to full contrast on hover — the quiet toolbar/icon style.
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
    // The rem size: GPUI Component's `text_sm` (buttons, inputs, menus) is
    // 0.875 rem, i.e. 13.1 px — the desktop control size.
    cfg.font_size = Some(15.0);
    cfg.radius = Some(6);
    cfg.radius_lg = Some(10);
    cfg.shadow = Some(!dark);
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
    k.popover = Some(hex(p.raised));
    k.popover_foreground = Some(hex(p.text));
    k.overlay = Some(hex_alpha(0x000000, if dark { 150 } else { 90 }));
    k.primary = Some(hex(p.accent));
    k.primary_hover = Some(hex(p.accent_hi));
    k.primary_active = Some(hex(p.accent_hi));
    k.primary_foreground = Some(hex(p.on_accent));
    k.secondary = Some(hex(p.surface_hi));
    k.secondary_hover = Some(hex(p.surface_hi));
    k.secondary_active = Some(hex(p.border_subtle));
    // Ghost buttons (icon buttons, toolbar actions) rest muted.
    k.secondary_foreground = Some(hex(p.text_muted));
    k.button = Some(hex(p.surface));
    k.button_hover = Some(hex(p.surface_hi));
    k.button_active = Some(hex(p.border_subtle));
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
    k.scrollbar_thumb = Some(hex_alpha(p.text_muted, 90));
    k.scrollbar_thumb_hover = Some(hex_alpha(p.text_muted, 150));
    k.switch = Some(hex(p.border));
    cfg
}

/// License notices for the assets compiled into the app (the Inter typeface
/// and the Lucide icons), shown under *Settings → About* (FS-18). The
/// complete bundle for every linked crate ships next to the binary as
/// `THIRD_PARTY_NOTICES.txt` (scripts/third_party_notices.py).
pub const EMBEDDED_ASSET_NOTICES: &[(&str, &str)] = &[
    (
        "Inter typeface — SIL Open Font License 1.1",
        include_str!("../assets/fonts/Inter-LICENSE.txt"),
    ),
    (
        "Lucide icons — ISC License (Feather-derived icons: MIT License)",
        include_str!("../assets/icons/Lucide-LICENSE.txt"),
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

fn install_fonts(cx: &mut App) {
    // Best-effort: if the platform text system refuses a face, GPUI falls back
    // to the system UI font rather than failing to start.
    let faces: Vec<Cow<'static, [u8]>> = INTER.iter().map(|f| Cow::Borrowed(*f)).collect();
    let _ = cx.text_system().add_fonts(faces);
}

// ---------------------------------------------------------------------------
// Icons (Lucide). Render with `icon_text`, or pass to a button's `.icon(..)`.
// ---------------------------------------------------------------------------

/// The icons the app draws. Each is a Lucide outline glyph; only these SVGs
/// (plus GPUI Component's own defaults) are embedded, via [`AppAssets`].
pub mod icon {
    pub use gpui_kit::assets::IconName as Glyph;

    pub const VAULT: Glyph = Glyph::Vault;
    pub const CONTACTS: Glyph = Glyph::Users;
    pub const IDENTITY: Glyph = Glyph::IdCard;
    pub const LOCK: Glyph = Glyph::Lock;
    pub const LOCK_KEY: Glyph = Glyph::LockKeyhole;
    pub const PLUS: Glyph = Glyph::Plus;
    pub const FILE: Glyph = Glyph::File;
    pub const FILE_TEXT: Glyph = Glyph::FileText;
    pub const FILE_IMAGE: Glyph = Glyph::FileImage;
    pub const FILE_MEDIA: Glyph = Glyph::FilePlay;
    pub const FILE_ARCHIVE: Glyph = Glyph::FileArchive;
    pub const FILE_CODE: Glyph = Glyph::FileCode;
    pub const FILE_PLUS: Glyph = Glyph::FilePlus;
    pub const FOLDER: Glyph = Glyph::Folder;
    pub const FOLDER_PLUS: Glyph = Glyph::FolderPlus;
    pub const FOLDER_INPUT: Glyph = Glyph::FolderInput;
    pub const EDIT: Glyph = Glyph::Pencil;
    pub const EYE: Glyph = Glyph::Eye;
    pub const TRASH: Glyph = Glyph::Trash;
    pub const KEY: Glyph = Glyph::KeyRound;
    pub const SHIELD: Glyph = Glyph::ShieldCheck;
    pub const DOWNLOAD: Glyph = Glyph::Download;
    pub const UPLOAD: Glyph = Glyph::Upload;
    pub const SEND: Glyph = Glyph::Send;
    pub const COPY: Glyph = Glyph::Copy;
    pub const CHECK: Glyph = Glyph::Check;
    pub const CHECK_CIRCLE: Glyph = Glyph::CircleCheck;
    pub const WARNING: Glyph = Glyph::TriangleAlert;
    pub const WARNING_CIRCLE: Glyph = Glyph::CircleAlert;
    pub const ERROR: Glyph = Glyph::CircleX;
    pub const INFO: Glyph = Glyph::Info;
    pub const CLOSE: Glyph = Glyph::X;
    pub const BACK: Glyph = Glyph::ChevronLeft;
    pub const SUN: Glyph = Glyph::Sun;
    pub const MOON: Glyph = Glyph::Moon;
    pub const MONITOR: Glyph = Glyph::Monitor;
    pub const SAVE: Glyph = Glyph::Save;
    pub const GEAR: Glyph = Glyph::Settings;
    pub const IMPORT: Glyph = Glyph::Import;
    pub const DOTS: Glyph = Glyph::Ellipsis;
    pub const CARET_RIGHT: Glyph = Glyph::ChevronRight;
    pub const CARET_DOWN: Glyph = Glyph::ChevronDown;
    pub const SEARCH: Glyph = Glyph::Search;
    pub const SORT: Glyph = Glyph::ArrowUpDown;
    pub const RESTORE: Glyph = Glyph::RotateCcw;
    pub const DRIVE: Glyph = Glyph::HardDrive;
    pub const LAPTOP: Glyph = Glyph::Laptop;
    pub const USB: Glyph = Glyph::Usb;
    pub const EXTERNAL: Glyph = Glyph::ExternalLink;
    pub const FINGERPRINT: Glyph = Glyph::FingerprintPattern;

    /// Every glyph above (the asset test checks each one is embedded).
    pub const ALL: &[Glyph] = &[
        VAULT,
        CONTACTS,
        IDENTITY,
        LOCK,
        LOCK_KEY,
        PLUS,
        FILE,
        FILE_TEXT,
        FILE_IMAGE,
        FILE_MEDIA,
        FILE_ARCHIVE,
        FILE_CODE,
        FILE_PLUS,
        FOLDER,
        FOLDER_PLUS,
        FOLDER_INPUT,
        EDIT,
        EYE,
        TRASH,
        KEY,
        SHIELD,
        DOWNLOAD,
        UPLOAD,
        SEND,
        COPY,
        CHECK,
        CHECK_CIRCLE,
        WARNING,
        WARNING_CIRCLE,
        ERROR,
        INFO,
        CLOSE,
        BACK,
        SUN,
        MOON,
        MONITOR,
        SAVE,
        GEAR,
        IMPORT,
        DOTS,
        CARET_RIGHT,
        CARET_DOWN,
        SEARCH,
        SORT,
        RESTORE,
        DRIVE,
        LAPTOP,
        USB,
        EXTERNAL,
        FINGERPRINT,
    ];
}

gpui_kit::assets::icon_assets!(
    AppIcons,
    [
        Vault,
        Users,
        IdCard,
        Lock,
        LockKeyhole,
        Plus,
        File,
        FileText,
        FileImage,
        FilePlay,
        FileArchive,
        FileCode,
        FilePlus,
        Folder,
        FolderPlus,
        FolderInput,
        Pencil,
        Eye,
        Trash,
        KeyRound,
        ShieldCheck,
        Download,
        Upload,
        Send,
        Copy,
        Check,
        CircleCheck,
        TriangleAlert,
        CircleAlert,
        CircleX,
        Info,
        X,
        ChevronLeft,
        Sun,
        Moon,
        Monitor,
        Save,
        Settings,
        Import,
        Ellipsis,
        ChevronRight,
        ChevronDown,
        Search,
        ArrowUpDown,
        RotateCcw,
        HardDrive,
        Laptop,
        Usb,
        ExternalLink,
        FingerprintPattern,
    ]
);

/// The app's asset source: the icons above, falling back to GPUI Kit's
/// default bundle (the glyphs GPUI Component draws its own controls with).
pub struct AppAssets;

impl AssetSource for AppAssets {
    fn load(&self, path: &str) -> gpui_kit::Result<Option<Cow<'static, [u8]>>> {
        if let Some(bytes) = AppIcons.load(path)? {
            return Ok(Some(bytes));
        }
        gpui_kit::assets::Assets.load(path)
    }

    fn list(&self, path: &str) -> gpui_kit::Result<Vec<SharedString>> {
        let mut paths = gpui_kit::assets::Assets.list(path)?;
        paths.extend(AppIcons.list(path)?);
        paths.sort();
        paths.dedup();
        Ok(paths)
    }
}

/// An icon for a button's `.icon(..)` (it takes the button's text colour, so
/// disabled and hover states tint it correctly).
#[must_use]
pub fn ico(glyph: icon::Glyph) -> Icon {
    Icon::new(glyph)
}

/// A Lucide glyph at `size`, in `color`, in a fixed square box.
pub fn icon_text(glyph: icon::Glyph, size: f32, color: Hsla) -> Div {
    div()
        .flex_none()
        .size(px(size))
        .flex()
        .items_center()
        .justify_center()
        .child(Icon::new(glyph).size(px(size)).text_color(color))
}

/// A glyph centred on a soft rounded tile — list leading icons, empty states,
/// dialog headers.
pub fn icon_tile(glyph: icon::Glyph, tile: f32, fg: Hsla, bg: Hsla) -> Div {
    div()
        .flex_none()
        .size(px(tile))
        .rounded(px((tile * 0.28).round()))
        .bg(bg)
        .flex()
        .items_center()
        .justify_center()
        .child(icon_text(glyph, (tile * 0.5).round(), fg))
}

/// The FileSec mark: a shield on the accent colour.
pub fn logo_mark(size: f32, c: Colors) -> Div {
    div()
        .flex_none()
        .size(px(size))
        .rounded(px((size * 0.3).round()))
        .bg(c.accent)
        .flex()
        .items_center()
        .justify_center()
        .child(icon_text(icon::SHIELD, (size * 0.56).round(), c.on_accent))
}

/// Up to two initials for an avatar.
#[must_use]
pub fn initials(name: &str) -> String {
    let mut out: String = name
        .split_whitespace()
        .filter_map(|w| w.chars().find(|ch| ch.is_alphanumeric()))
        .take(2)
        .flat_map(char::to_uppercase)
        .collect();
    if out.is_empty() {
        out.push('?');
    }
    out
}

/// A round avatar with the name's initials on a soft accent fill.
pub fn avatar(name: &str, size: f32, c: Colors) -> Div {
    div()
        .flex_none()
        .size(px(size))
        .rounded_full()
        .bg(accent_soft(c))
        .flex()
        .items_center()
        .justify_center()
        .text_size(px((size * 0.38).round()))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(c.accent)
        .child(initials(name))
}

/// A small status dot.
pub fn dot(color: Hsla) -> Div {
    div().flex_none().size(px(7.0)).rounded_full().bg(color)
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

/// Semibold text at `size`.
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
// Layout helpers
// ---------------------------------------------------------------------------

/// A bordered, rounded, padded surface. Use to group a form or a panel.
/// Children are stacked vertically on a 12 px rhythm.
pub fn card(c: Colors) -> Div {
    div()
        .w_full()
        .flex()
        .flex_col()
        .gap(px(12.0))
        .bg(c.surface)
        .border_1()
        .border_color(c.border)
        .rounded(RADIUS)
        .shadow(shadow_xs(c))
        .p(px(20.0))
}

/// A bordered list container: rows inside are separated by hairlines (see
/// [`list_row_divider`]). No padding — rows bring their own.
pub fn list_container(c: Colors) -> Div {
    div()
        .w_full()
        .flex()
        .flex_col()
        .bg(c.surface)
        .border_1()
        .border_color(c.border)
        .rounded(RADIUS)
        .shadow(shadow_xs(c))
        .overflow_hidden()
}

/// Wrap a list row so every row after the first gets a top hairline.
pub fn list_row_divider(i: usize, row: impl IntoElement, c: Colors) -> Div {
    div()
        .w_full()
        .when(i > 0, |d| d.border_t_1().border_color(c.border_subtle))
        .child(row)
}

/// A horizontal row with the app's default spacing, vertically centred.
pub fn row() -> Div {
    div().flex().flex_row().items_center().gap(px(8.0))
}

/// A vertical stack with the app's default spacing.
pub fn col() -> Div {
    div().flex().flex_col().gap(px(8.0))
}

/// A horizontal row whose children wrap onto the next line when narrow.
pub fn wrap_row() -> Div {
    row().flex_wrap()
}

/// A page's top bar: title (and optional supporting line) on the left,
/// actions on the right, a hairline below. The same height on every page so
/// navigation never shifts the content.
pub fn page_header(title: impl Into<SharedString>, actions: Option<AnyElement>, c: Colors) -> Div {
    div()
        .flex_none()
        .w_full()
        .h(HEADER_H)
        .px(PAGE_PAD)
        .flex()
        .flex_row()
        .items_center()
        .gap(px(12.0))
        .border_b_1()
        .border_color(c.border_subtle)
        .child(one_line(strong(title, px(16.0), c.text)).flex_1())
        .children(actions.map(|a| row().flex_none().child(a)))
}

/// An in-content heading with a right-aligned action area. Below 600 px the
/// actions wrap underneath the title instead of squeezing it.
pub fn section_header(
    title: impl Into<SharedString>,
    right: Option<AnyElement>,
    wide: bool,
    c: Colors,
) -> Div {
    let heading = strong(title, TEXT_H2, c.text);
    if wide {
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
    }
}

/// Supporting copy at the top of a page body.
pub fn page_description(s: impl Into<SharedString>, c: Colors) -> Div {
    text(s, c.text_muted).w_full()
}

/// A titled group of settings-style rows (macOS System Settings / iOS
/// grouped lists): an optional caption, then a bordered container whose rows
/// are separated by hairlines.
pub fn group(
    title: Option<&'static str>,
    footer: Option<SharedString>,
    rows: Vec<AnyElement>,
    c: Colors,
) -> Div {
    let mut list = list_container(c);
    for (i, r) in rows.into_iter().enumerate() {
        list = list.child(list_row_divider(i, r, c));
    }
    div()
        .w_full()
        .flex()
        .flex_col()
        .gap(px(8.0))
        .children(title.map(|t| {
            div()
                .px(px(4.0))
                .text_size(TEXT_LABEL)
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(c.text_muted)
                .child(t)
        }))
        .child(list)
        .children(footer.map(|f| muted(f, c).px(px(4.0))))
}

/// One row of a [`group`]: a title with optional description on the left and
/// a control on the right. Narrow layouts put the control underneath.
pub fn group_row(
    title: impl Into<SharedString>,
    description: Option<SharedString>,
    control: Option<AnyElement>,
    wide: bool,
    c: Colors,
) -> Div {
    let label = div()
        .flex_1()
        .min_w_0()
        .flex()
        .flex_col()
        .gap(px(2.0))
        .child(text(title, c.text))
        .children(description.map(|d| muted(d, c)));
    let base = div()
        .w_full()
        .px(px(16.0))
        .py(px(12.0))
        .flex()
        .gap(px(12.0));
    if wide {
        base.flex_row()
            .items_center()
            .child(label)
            .children(control.map(|ctl| row().flex_none().child(ctl)))
    } else {
        base.flex_col()
            .child(label)
            .children(control.map(|ctl| wrap_row().child(ctl)))
    }
}

/// A free-form block inside a [`group`] (padding matches [`group_row`]).
pub fn group_block(c: Colors) -> Div {
    let _ = c;
    div()
        .w_full()
        .px(px(16.0))
        .py(px(14.0))
        .flex()
        .flex_col()
        .gap(px(10.0))
}

// ---------------------------------------------------------------------------
// Buttons
// ---------------------------------------------------------------------------

/// Accent-filled primary call-to-action. One per screen.
pub fn primary_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    Button::new(id).primary().label(label)
}

/// Bordered secondary button.
pub fn secondary_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    Button::new(id).label(label)
}

/// A borderless, muted button for tertiary and toolbar actions.
pub fn ghost_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    Button::new(id).ghost().label(label)
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
    // A custom variant rests at a 20% tint of `color` (which reads as
    // disabled); a destructive confirm must be a solid fill.
    Button::new(id).custom(variant).bg(c.err).label(label)
}

/// A borderless small text button (breadcrumbs, "Select all").
pub fn link_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    Button::new(id).ghost().small().label(label)
}

/// A compact secondary button ("Copy").
pub fn small_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    Button::new(id).small().label(label)
}

/// Accent-filled primary button that fills the available width.
pub fn primary_button_full(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    primary_button(id, label).w_full().h(px(38.0))
}

/// Secondary button that fills the available width.
pub fn secondary_button_full(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    secondary_button(id, label).w_full().h(px(38.0))
}

/// A borderless icon button. `hover` is its tooltip and its accessible name.
/// It rests in the muted colour and takes full contrast on hover.
pub fn icon_button(id: impl Into<ElementId>, glyph: icon::Glyph, hover: &str, c: Colors) -> Button {
    let _ = c;
    let hover: SharedString = hover.to_string().into();
    Button::new(id)
        .ghost()
        .icon(ico(glyph))
        .tooltip(hover.clone())
        .accessibility_label(hover)
}

/// Set `disabled` on any GPUI Component control in a builder chain.
pub fn enabled<T: Disableable>(el: T, enabled: bool) -> T {
    el.disabled(!enabled)
}

// ---------------------------------------------------------------------------
// Status and feedback
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum BadgeKind {
    Ok,
    Warn,
    Err,
    Neutral,
    Accent,
}

fn badge_color(kind: BadgeKind, c: Colors) -> Hsla {
    match kind {
        BadgeKind::Ok => c.ok,
        BadgeKind::Warn => c.warn,
        BadgeKind::Err => c.err,
        BadgeKind::Accent => c.accent,
        BadgeKind::Neutral => c.text_muted,
    }
}

/// A small coloured pill — used for trust state and status flags. Colour is
/// never the only signal: the label always says it.
pub fn badge(label: impl Into<SharedString>, kind: BadgeKind, c: Colors) -> Div {
    let col = badge_color(kind, c);
    div()
        .flex_none()
        .h(px(20.0))
        .px(px(8.0))
        .flex()
        .items_center()
        .rounded_full()
        .bg(with_alpha(col, if c.dark { 40 } else { 26 }))
        .text_size(px(11.5))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(col)
        .child(label.into())
}

/// A centred placeholder for empty lists: an icon tile, a title, a subtitle,
/// and an optional call to action.
pub fn empty_state(
    glyph: icon::Glyph,
    title: impl Into<SharedString>,
    subtitle: impl Into<SharedString>,
    cta: Option<AnyElement>,
    c: Colors,
) -> Div {
    div()
        .w_full()
        .pt(px(40.0))
        .pb(px(24.0))
        .flex()
        .flex_col()
        .items_center()
        .child(
            icon_tile(glyph, 52.0, c.text_muted, c.surface_hi)
                .border_1()
                .border_color(c.border_subtle),
        )
        .child(div().h(px(16.0)))
        .child(strong(title, TEXT_H2, c.text).text_center())
        .child(div().h(px(4.0)))
        .child(text(subtitle, c.text_muted).max_w(px(380.0)).text_center())
        .child(div().h(px(18.0)))
        .children(cta)
}

/// A tinted callout for status that must stay on screen (editing, warnings).
pub fn banner(accent: Hsla) -> Div {
    div()
        .w_full()
        .bg(with_alpha(accent, 22))
        .border_1()
        .border_color(with_alpha(accent, 70))
        .rounded(RADIUS)
        .px(px(14.0))
        .py(px(10.0))
}

/// A callout with a leading icon and wrapping text in one colour.
pub fn callout(glyph: icon::Glyph, s: impl Into<SharedString>, color: Hsla, c: Colors) -> Div {
    banner(color).child(
        row()
            .w_full()
            .items_start()
            .gap(px(10.0))
            .child(icon_text(glyph, 16.0, color).mt(px(1.0)))
            .child(text(s, c.text).flex_1().min_w_0()),
    )
}

/// A subtle "or" divider between alternative actions.
pub fn divider_or(c: Colors) -> Div {
    let line = || div().flex_1().h(px(1.0)).bg(c.border_subtle);
    row()
        .w_full()
        .gap(px(12.0))
        .py(px(2.0))
        .child(line())
        .child(small("or", c.text_subtle))
        .child(line())
}

/// A thin horizontal rule.
pub fn separator(c: Colors) -> Div {
    div().w_full().h(px(1.0)).my(px(4.0)).bg(c.border_subtle)
}

/// A form field label (above an input).
pub fn caption(s: impl Into<SharedString>, c: Colors) -> Div {
    div()
        .text_size(TEXT_LABEL)
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(c.text)
        .child(s.into())
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

/// The surface of a floating dialog. The caller fills it (header, scrolling
/// body, footer), places it inside a [`backdrop`], and wires dismissal.
pub fn dialog_surface(
    id: impl Into<ElementId>,
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
        .bg(c.raised)
        .border_1()
        .border_color(c.border)
        .rounded(RADIUS_LG)
        .shadow(shadow_float(c))
        .overflow_hidden()
}

/// A floating card with a title, for simple confirmations built outside the
/// dialog module.
pub fn modal_card(
    id: impl Into<ElementId>,
    title: impl Into<SharedString>,
    width: Pixels,
    max_height: Pixels,
    c: Colors,
) -> gpui_kit::Stateful<Div> {
    dialog_surface(id, width, max_height, c)
        .gap(px(10.0))
        .p(px(22.0))
        .child(strong(title, px(17.0), c.text))
}

/// The floating toast surface, anchored by the caller.
pub fn toast_card(error: bool, c: Colors) -> Div {
    let accent = if error { c.err } else { c.ok };
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap(px(10.0))
        .bg(c.raised)
        .border_1()
        .border_color(c.border)
        .rounded(RADIUS)
        .pl(px(14.0))
        .pr(px(6.0))
        .py(px(6.0))
        .shadow(shadow_float(c))
        .child(icon_text(
            if error {
                icon::ERROR
            } else {
                icon::CHECK_CIRCLE
            },
            18.0,
            accent,
        ))
}

/// The floating surface the busy overlay centres.
pub fn float_card(c: Colors) -> Div {
    div()
        .bg(c.raised)
        .border_1()
        .border_color(c.border)
        .rounded(RADIUS)
        .shadow(shadow_float(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_palettes_are_distinct_and_opaque() {
        let (d, l) = (Colors::dark(), Colors::light());
        assert_ne!(d.bg, l.bg);
        assert!(d.dark && !l.dark);
        for c in [d, l] {
            for col in [c.bg, c.surface, c.raised, c.text, c.accent, c.err] {
                assert!((col.a - 1.0).abs() < f32::EPSILON);
            }
        }
    }

    #[test]
    fn component_config_carries_the_palette() {
        let cfg = component_config(&DARK, ThemeMode::Dark);
        assert_eq!(cfg.colors.background.as_deref(), Some("#151517"));
        assert_eq!(cfg.colors.primary.as_deref(), Some("#7d9cff"));
        assert_eq!(cfg.font_family.as_deref(), Some(FONT_UI));
        let cfg = component_config(&LIGHT, ThemeMode::Light);
        assert_eq!(cfg.colors.danger_foreground.as_deref(), Some("#ffffff"));
    }

    #[test]
    fn embedded_fonts_are_the_expected_faces() {
        // Sanity: a truncated or swapped asset would silently fall back.
        assert!(INTER.iter().all(|f| f.len() > 100_000));
    }

    #[test]
    fn every_icon_the_app_draws_is_embedded() {
        for glyph in icon::ALL {
            let path = glyph.path();
            let bytes = AppAssets.load(&path).expect("load").unwrap_or_default();
            assert!(
                bytes.starts_with(b"<svg"),
                "{path} is not embedded in AppAssets"
            );
        }
    }

    #[test]
    fn initials_take_the_first_letters() {
        assert_eq!(initials("Ada Lovelace"), "AL");
        assert_eq!(initials("bob"), "B");
        assert_eq!(initials("  "), "?");
        assert_eq!(initials("Jean-Luc Picard Third"), "JP");
    }
}
