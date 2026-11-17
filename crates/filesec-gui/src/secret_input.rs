//! A masked, zeroizing single-line input for passphrases and PINs.
//!
//! GPUI Component's `Input` keeps its text in a rope with an undo history,
//! neither of which can be scrubbed. Every secret the app asks for (the
//! passphrase on each auth screen and dialog, security-key PINs, backup
//! passphrases) goes through this element instead:
//!
//! - the text lives in a single [`Zeroizing<String>`]; every edit builds the
//!   new value in a fresh pre-sized zeroizing buffer and the old one is wiped
//!   when it is dropped, so no stale copy is left in freed heap;
//! - there is no undo history and no copy/cut — the plaintext never reaches
//!   the clipboard;
//! - only a run of `•` bullets is shaped and painted, so the plaintext never
//!   enters the text system's layout caches, and IME / accessibility queries
//!   ([`EntityInputHandler::text_for_range`]) see bullets too;
//! - [`SecretInput::take`] moves the value out for a worker (which wipes it
//!   when done) and [`SecretInput::clear`] wipes it in place; dropping the
//!   entity wipes whatever is left.
//!
//! It is the GPUI port of the egui app's `Drop`-zeroized passphrase buffers.

use std::ops::Range;

use gpui_kit::{
    actions, div, fill, point, px, relative, size, App, Bounds, Context, CursorStyle, Element,
    ElementId, ElementInputHandler, Entity, EntityInputHandler, EventEmitter, FocusHandle,
    Focusable, GlobalElementId, InteractiveElement, IntoElement, KeyBinding, LayoutId, MouseButton,
    MouseDownEvent, MouseMoveEvent, MouseUpEvent, PaintQuad, ParentElement, Pixels, Point, Render,
    ShapedLine, SharedString, Style, Styled, TextRun, UTF16Selection, UnderlineStyle, Window,
};
use unicode_segmentation::UnicodeSegmentation;
use zeroize::Zeroizing;

use crate::theme;

actions!(
    secret_input,
    [
        Backspace,
        Delete,
        Left,
        Right,
        SelectLeft,
        SelectRight,
        SelectAll,
        Home,
        End,
        SelectHome,
        SelectEnd,
        Paste,
        Submit,
    ]
);

const CONTEXT: &str = "SecretInput";

/// The glyph every character is drawn as. One UTF-16 unit, three UTF-8 bytes.
const MASK: char = '\u{2022}';

/// `key` with the platform's primary shortcut modifier (⌘ on macOS, Ctrl
/// elsewhere), as a `'static` keystroke for `KeyBinding::new`.
macro_rules! primary {
    ($key:literal) => {
        if cfg!(target_os = "macos") {
            concat!("cmd-", $key)
        } else {
            concat!("ctrl-", $key)
        }
    };
}
pub(crate) use primary;

/// Register the key bindings. Call once at startup.
pub fn init(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("backspace", Backspace, Some(CONTEXT)),
        KeyBinding::new("delete", Delete, Some(CONTEXT)),
        KeyBinding::new("left", Left, Some(CONTEXT)),
        KeyBinding::new("right", Right, Some(CONTEXT)),
        KeyBinding::new("shift-left", SelectLeft, Some(CONTEXT)),
        KeyBinding::new("shift-right", SelectRight, Some(CONTEXT)),
        KeyBinding::new(primary!("a"), SelectAll, Some(CONTEXT)),
        KeyBinding::new("home", Home, Some(CONTEXT)),
        KeyBinding::new("end", End, Some(CONTEXT)),
        KeyBinding::new("shift-home", SelectHome, Some(CONTEXT)),
        KeyBinding::new("shift-end", SelectEnd, Some(CONTEXT)),
        KeyBinding::new(primary!("v"), Paste, Some(CONTEXT)),
        KeyBinding::new("enter", Submit, Some(CONTEXT)),
    ]);
}

/// What the owning view hears about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretInputEvent {
    /// The value changed (typed, deleted, pasted, cleared by the user).
    Changed,
    /// Enter was pressed.
    Submit,
}

pub struct SecretInput {
    focus_handle: FocusHandle,
    content: Zeroizing<String>,
    placeholder: SharedString,
    /// Byte range into `content`.
    selected_range: Range<usize>,
    selection_reversed: bool,
    /// Byte range into `content` of in-progress IME composition.
    marked_range: Option<Range<usize>>,
    /// Shaped masked line from the last paint, for hit testing.
    last_layout: Option<ShapedLine>,
    last_bounds: Option<Bounds<Pixels>>,
    /// Horizontal scroll so the caret of a long secret stays visible.
    scroll_x: Pixels,
    is_selecting: bool,
}

impl EventEmitter<SecretInputEvent> for SecretInput {}

impl SecretInput {
    pub fn new(placeholder: impl Into<SharedString>, cx: &mut Context<Self>) -> Self {
        Self {
            focus_handle: cx.focus_handle().tab_stop(true),
            content: Zeroizing::new(String::new()),
            placeholder: placeholder.into(),
            selected_range: 0..0,
            selection_reversed: false,
            marked_range: None,
            last_layout: None,
            last_bounds: None,
            scroll_x: px(0.0),
            is_selecting: false,
        }
    }

    /// The current secret. Borrow it only for as long as needed; prefer
    /// [`Self::take`] to hand it to a worker.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.content
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    pub fn set_placeholder(&mut self, placeholder: impl Into<SharedString>) {
        self.placeholder = placeholder.into();
    }

    /// Move the secret out, leaving the field empty. The returned buffer wipes
    /// itself when dropped.
    pub fn take(&mut self, cx: &mut Context<Self>) -> Zeroizing<String> {
        let out = std::mem::replace(&mut self.content, Zeroizing::new(String::new()));
        self.reset_cursor();
        cx.notify();
        out
    }

    /// Wipe the secret in place.
    pub fn clear(&mut self, cx: &mut Context<Self>) {
        // Replacing drops (and so zeroizes) the old buffer.
        self.content = Zeroizing::new(String::new());
        self.reset_cursor();
        cx.notify();
    }

    /// Replace the whole value (tests and programmatic fills).
    pub fn set_value(&mut self, value: &str, cx: &mut Context<Self>) {
        let mut next = Zeroizing::new(String::with_capacity(value.len()));
        next.push_str(value);
        self.content = next;
        self.selected_range = self.content.len()..self.content.len();
        self.selection_reversed = false;
        self.marked_range = None;
        cx.emit(SecretInputEvent::Changed);
        cx.notify();
    }

    fn reset_cursor(&mut self) {
        self.selected_range = 0..0;
        self.selection_reversed = false;
        self.marked_range = None;
        self.scroll_x = px(0.0);
    }

    // --- editing actions --------------------------------------------------

    fn left(&mut self, _: &Left, window: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.move_to(self.previous_boundary(self.cursor_offset()), window, cx);
        } else {
            self.move_to(self.selected_range.start, window, cx);
        }
    }

    fn right(&mut self, _: &Right, window: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.move_to(self.next_boundary(self.selected_range.end), window, cx);
        } else {
            self.move_to(self.selected_range.end, window, cx);
        }
    }

    fn select_left(&mut self, _: &SelectLeft, window: &mut Window, cx: &mut Context<Self>) {
        self.select_to(self.previous_boundary(self.cursor_offset()), window, cx);
    }

    fn select_right(&mut self, _: &SelectRight, window: &mut Window, cx: &mut Context<Self>) {
        self.select_to(self.next_boundary(self.cursor_offset()), window, cx);
    }

    fn select_all(&mut self, _: &SelectAll, window: &mut Window, cx: &mut Context<Self>) {
        self.move_to(0, window, cx);
        self.select_to(self.content.len(), window, cx);
    }

    fn home(&mut self, _: &Home, window: &mut Window, cx: &mut Context<Self>) {
        self.move_to(0, window, cx);
    }

    fn end(&mut self, _: &End, window: &mut Window, cx: &mut Context<Self>) {
        self.move_to(self.content.len(), window, cx);
    }

    fn select_home(&mut self, _: &SelectHome, window: &mut Window, cx: &mut Context<Self>) {
        self.select_to(0, window, cx);
    }

    fn select_end(&mut self, _: &SelectEnd, window: &mut Window, cx: &mut Context<Self>) {
        self.select_to(self.content.len(), window, cx);
    }

    fn backspace(&mut self, _: &Backspace, window: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            let prev = self.previous_boundary(self.cursor_offset());
            if self.cursor_offset() == prev {
                return;
            }
            self.select_to(prev, window, cx);
        }
        self.replace_text_in_range(None, "", window, cx);
    }

    fn delete(&mut self, _: &Delete, window: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            let next = self.next_boundary(self.cursor_offset());
            if self.cursor_offset() == next {
                return;
            }
            self.select_to(next, window, cx);
        }
        self.replace_text_in_range(None, "", window, cx);
    }

    fn paste(&mut self, _: &Paste, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
            // A secret is one line; a trailing newline from a password manager
            // must not become part of it.
            let text = Zeroizing::new(text);
            let line = text
                .trim_end_matches(['\r', '\n'])
                .replace(['\r', '\n'], " ");
            let line = Zeroizing::new(line);
            self.replace_text_in_range(None, &line, window, cx);
        }
    }

    fn submit(&mut self, _: &Submit, _: &mut Window, cx: &mut Context<Self>) {
        cx.emit(SecretInputEvent::Submit);
    }

    fn on_mouse_down(
        &mut self,
        event: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.is_selecting = true;
        window.focus(&self.focus_handle, cx);
        let index = self.index_for_mouse_position(event.position);
        if event.modifiers.shift {
            self.select_to(index, window, cx);
        } else {
            self.move_to(index, window, cx);
        }
    }

    fn on_mouse_up(&mut self, _: &MouseUpEvent, _: &mut Window, _: &mut Context<Self>) {
        self.is_selecting = false;
    }

    fn on_mouse_move(
        &mut self,
        event: &MouseMoveEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.is_selecting {
            let index = self.index_for_mouse_position(event.position);
            self.select_to(index, window, cx);
        }
    }

    // --- offsets ----------------------------------------------------------

    fn move_to(&mut self, offset: usize, _: &mut Window, cx: &mut Context<Self>) {
        self.selected_range = offset..offset;
        self.selection_reversed = false;
        cx.notify();
    }

    fn select_to(&mut self, offset: usize, _: &mut Window, cx: &mut Context<Self>) {
        if self.selection_reversed {
            self.selected_range.start = offset;
        } else {
            self.selected_range.end = offset;
        }
        if self.selected_range.end < self.selected_range.start {
            self.selection_reversed = !self.selection_reversed;
            self.selected_range = self.selected_range.end..self.selected_range.start;
        }
        cx.notify();
    }

    fn cursor_offset(&self) -> usize {
        if self.selection_reversed {
            self.selected_range.start
        } else {
            self.selected_range.end
        }
    }

    fn previous_boundary(&self, offset: usize) -> usize {
        self.content
            .grapheme_indices(true)
            .rev()
            .find_map(|(idx, _)| (idx < offset).then_some(idx))
            .unwrap_or(0)
    }

    fn next_boundary(&self, offset: usize) -> usize {
        self.content
            .grapheme_indices(true)
            .find_map(|(idx, _)| (idx > offset).then_some(idx))
            .unwrap_or(self.content.len())
    }

    /// Byte offset in `content` → byte offset in the masked display string.
    fn display_offset(&self, offset: usize) -> usize {
        let offset = offset.min(self.content.len());
        self.content[..offset].chars().count() * MASK.len_utf8()
    }

    /// Byte offset in the masked display string → byte offset in `content`.
    fn content_offset(&self, display: usize) -> usize {
        let nth = display / MASK.len_utf8();
        self.content
            .char_indices()
            .nth(nth)
            .map_or(self.content.len(), |(i, _)| i)
    }

    fn index_for_mouse_position(&self, position: Point<Pixels>) -> usize {
        let (Some(bounds), Some(line)) = (self.last_bounds.as_ref(), self.last_layout.as_ref())
        else {
            return self.content.len();
        };
        if self.content.is_empty() || position.y < bounds.top() {
            return 0;
        }
        if position.y > bounds.bottom() {
            return self.content.len();
        }
        let x = position.x - bounds.left() + self.scroll_x;
        self.content_offset(line.closest_index_for_x(x))
    }

    fn offset_from_utf16(&self, offset: usize) -> usize {
        let mut utf8 = 0;
        let mut utf16 = 0;
        for ch in self.content.chars() {
            if utf16 >= offset {
                break;
            }
            utf16 += ch.len_utf16();
            utf8 += ch.len_utf8();
        }
        utf8
    }

    fn offset_to_utf16(&self, offset: usize) -> usize {
        let mut utf16 = 0;
        let mut utf8 = 0;
        for ch in self.content.chars() {
            if utf8 >= offset {
                break;
            }
            utf8 += ch.len_utf8();
            utf16 += ch.len_utf16();
        }
        utf16
    }

    fn range_to_utf16(&self, range: &Range<usize>) -> Range<usize> {
        self.offset_to_utf16(range.start)..self.offset_to_utf16(range.end)
    }

    fn range_from_utf16(&self, range: &Range<usize>) -> Range<usize> {
        self.offset_from_utf16(range.start)..self.offset_from_utf16(range.end)
    }

    /// Splice `new_text` over `range` into a fresh, pre-sized zeroizing buffer
    /// (no reallocation, so no partial copies left behind). The old buffer is
    /// zeroized when it is replaced.
    fn splice(&mut self, range: &Range<usize>, new_text: &str) {
        let range = range.start.min(self.content.len())..range.end.min(self.content.len());
        let mut next = Zeroizing::new(String::with_capacity(
            self.content.len() - (range.end - range.start) + new_text.len(),
        ));
        next.push_str(&self.content[..range.start]);
        next.push_str(new_text);
        next.push_str(&self.content[range.end..]);
        self.content = next;
    }

    fn masked_text(&self) -> String {
        std::iter::repeat_n(MASK, self.content.chars().count()).collect()
    }
}

impl Drop for SecretInput {
    fn drop(&mut self) {
        // `Zeroizing` wipes on drop; replacing makes the intent explicit and
        // also covers the shaped line, which only ever held bullets.
        self.content = Zeroizing::new(String::new());
    }
}

impl EntityInputHandler for SecretInput {
    fn text_for_range(
        &mut self,
        range_utf16: Range<usize>,
        actual_range: &mut Option<Range<usize>>,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<String> {
        let range = self.range_from_utf16(&range_utf16);
        let range_utf16 = self.range_to_utf16(&range);
        actual_range.replace(range_utf16.clone());
        // Bullets, never the secret: the platform IME and accessibility layers
        // ask for surrounding text through here.
        Some(std::iter::repeat_n(MASK, range_utf16.end - range_utf16.start).collect())
    }

    fn selected_text_range(
        &mut self,
        _ignore_disabled_input: bool,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<UTF16Selection> {
        Some(UTF16Selection {
            range: self.range_to_utf16(&self.selected_range),
            reversed: self.selection_reversed,
        })
    }

    fn set_selected_text_range(
        &mut self,
        range_utf16: Range<usize>,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.selected_range = self.range_from_utf16(&range_utf16);
        self.selection_reversed = false;
        cx.notify();
    }

    fn text_length_utf16(&mut self, _: &mut Window, _: &mut Context<Self>) -> Option<usize> {
        Some(self.content.encode_utf16().count())
    }

    fn marked_text_range(&self, _: &mut Window, _: &mut Context<Self>) -> Option<Range<usize>> {
        self.marked_range
            .as_ref()
            .map(|range| self.range_to_utf16(range))
    }

    fn unmark_text(&mut self, _: &mut Window, cx: &mut Context<Self>) {
        self.marked_range = None;
        cx.notify();
    }

    fn replace_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = range_utf16
            .as_ref()
            .map(|r| self.range_from_utf16(r))
            .or(self.marked_range.clone())
            .unwrap_or(self.selected_range.clone());
        self.splice(&range, new_text);
        let caret = range.start + new_text.len();
        self.selected_range = caret..caret;
        self.selection_reversed = false;
        self.marked_range = None;
        cx.emit(SecretInputEvent::Changed);
        cx.notify();
    }

    fn replace_and_mark_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        new_selected_range_utf16: Option<Range<usize>>,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = range_utf16
            .as_ref()
            .map(|r| self.range_from_utf16(r))
            .or(self.marked_range.clone())
            .unwrap_or(self.selected_range.clone());
        self.splice(&range, new_text);
        self.marked_range =
            (!new_text.is_empty()).then(|| range.start..range.start + new_text.len());
        let start_utf16 = self.offset_to_utf16(range.start);
        let inserted_utf16 = new_text.encode_utf16().count();
        self.selected_range = new_selected_range_utf16
            .map(|sel| {
                self.range_from_utf16(
                    &(start_utf16 + sel.start.min(inserted_utf16)
                        ..start_utf16 + sel.end.min(inserted_utf16)),
                )
            })
            .unwrap_or_else(|| range.start + new_text.len()..range.start + new_text.len());
        self.selection_reversed = false;
        cx.emit(SecretInputEvent::Changed);
        cx.notify();
    }

    fn bounds_for_range(
        &mut self,
        range_utf16: Range<usize>,
        bounds: Bounds<Pixels>,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<Bounds<Pixels>> {
        let line = self.last_layout.as_ref()?;
        let range = self.range_from_utf16(&range_utf16);
        let start = line.x_for_index(self.display_offset(range.start)) - self.scroll_x;
        let end = line.x_for_index(self.display_offset(range.end)) - self.scroll_x;
        Some(Bounds::from_corners(
            point(bounds.left() + start, bounds.top()),
            point(bounds.left() + end, bounds.bottom()),
        ))
    }

    fn character_index_for_point(
        &mut self,
        point: Point<Pixels>,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<usize> {
        let local = self.last_bounds?.localize(&point)?;
        let line = self.last_layout.as_ref()?;
        let display = line.closest_index_for_x(local.x + self.scroll_x);
        Some(self.offset_to_utf16(self.content_offset(display)))
    }
}

impl Focusable for SecretInput {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for SecretInput {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let c = theme::colors(cx);
        let focused = self.focus_handle.is_focused(window);
        div()
            .id(ElementId::Name("secret-input".into()))
            .key_context(CONTEXT)
            .track_focus(&self.focus_handle)
            .cursor(CursorStyle::IBeam)
            .on_action(cx.listener(Self::backspace))
            .on_action(cx.listener(Self::delete))
            .on_action(cx.listener(Self::left))
            .on_action(cx.listener(Self::right))
            .on_action(cx.listener(Self::select_left))
            .on_action(cx.listener(Self::select_right))
            .on_action(cx.listener(Self::select_all))
            .on_action(cx.listener(Self::home))
            .on_action(cx.listener(Self::end))
            .on_action(cx.listener(Self::select_home))
            .on_action(cx.listener(Self::select_end))
            .on_action(cx.listener(Self::paste))
            .on_action(cx.listener(Self::submit))
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_mouse_down))
            .on_mouse_up(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_up_out(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_move(cx.listener(Self::on_mouse_move))
            .w_full()
            .h(px(32.0))
            .px(px(12.0))
            .flex()
            .items_center()
            .overflow_hidden()
            .bg(c.input)
            .border_1()
            .border_color(if focused { c.accent } else { c.border })
            .rounded(theme::RADIUS_SM)
            .text_sm()
            .text_color(c.text)
            .child(MaskedLine {
                input: cx.entity(),
                caret: c.accent,
                selection: theme::with_alpha(c.accent, 70),
                placeholder: c.text_muted,
            })
    }
}

/// The custom element that shapes and paints the masked line, the selection
/// and the caret, and registers the platform input handler.
struct MaskedLine {
    input: Entity<SecretInput>,
    caret: gpui_kit::Hsla,
    selection: gpui_kit::Hsla,
    placeholder: gpui_kit::Hsla,
}

struct MaskedPrepaint {
    line: Option<ShapedLine>,
    cursor: Option<PaintQuad>,
    selection: Option<PaintQuad>,
    scroll_x: Pixels,
}

impl IntoElement for MaskedLine {
    type Element = Self;

    fn into_element(self) -> Self::Element {
        self
    }
}

impl Element for MaskedLine {
    type RequestLayoutState = ();
    type PrepaintState = MaskedPrepaint;

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static core::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui_kit::InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        let mut style = Style::default();
        style.size.width = relative(1.).into();
        style.size.height = window.line_height().into();
        (window.request_layout(style, [], cx), ())
    }

    fn prepaint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui_kit::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        window: &mut Window,
        cx: &mut App,
    ) -> Self::PrepaintState {
        let input = self.input.read(cx);
        let style = window.text_style();
        let (display, color): (SharedString, _) = if input.content.is_empty() {
            (input.placeholder.clone(), self.placeholder)
        } else {
            (input.masked_text().into(), style.color)
        };
        let run = TextRun {
            len: display.len(),
            font: style.font(),
            color,
            background_color: None,
            underline: None,
            strikethrough: None,
        };
        let runs = match input.marked_range.as_ref() {
            Some(marked) if !input.content.is_empty() => {
                let (ms, me) = (
                    input.display_offset(marked.start),
                    input.display_offset(marked.end),
                );
                vec![
                    TextRun {
                        len: ms,
                        ..run.clone()
                    },
                    TextRun {
                        len: me - ms,
                        underline: Some(UnderlineStyle {
                            color: Some(run.color),
                            thickness: px(1.0),
                            wavy: false,
                        }),
                        ..run.clone()
                    },
                    TextRun {
                        len: display.len() - me,
                        ..run
                    },
                ]
                .into_iter()
                .filter(|r| r.len > 0)
                .collect()
            }
            _ => vec![run],
        };
        let font_size = style.font_size.to_pixels(window.rem_size());
        let line = window
            .text_system()
            .shape_line(display, font_size, &runs, None);

        let (cursor_x, sel_start, sel_end) = if input.content.is_empty() {
            (px(0.0), px(0.0), px(0.0))
        } else {
            (
                line.x_for_index(input.display_offset(input.cursor_offset())),
                line.x_for_index(input.display_offset(input.selected_range.start)),
                line.x_for_index(input.display_offset(input.selected_range.end)),
            )
        };
        // Keep the caret inside the field: scroll right when it would run off
        // the end, back left when it moves before the visible start.
        let width = bounds.size.width - px(2.0);
        let mut scroll_x = input.scroll_x;
        if cursor_x - scroll_x > width {
            scroll_x = cursor_x - width;
        } else if cursor_x < scroll_x {
            scroll_x = cursor_x;
        }
        if line.width <= width {
            scroll_x = px(0.0);
        }

        let (selection, cursor) = if input.selected_range.is_empty() {
            (
                None,
                Some(fill(
                    Bounds::new(
                        point(bounds.left() + cursor_x - scroll_x, bounds.top()),
                        size(px(1.5), bounds.bottom() - bounds.top()),
                    ),
                    self.caret,
                )),
            )
        } else {
            (
                Some(fill(
                    Bounds::from_corners(
                        point(bounds.left() + sel_start - scroll_x, bounds.top()),
                        point(bounds.left() + sel_end - scroll_x, bounds.bottom()),
                    ),
                    self.selection,
                )),
                None,
            )
        };
        MaskedPrepaint {
            line: Some(line),
            cursor,
            selection,
            scroll_x,
        }
    }

    fn paint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui_kit::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        prepaint: &mut Self::PrepaintState,
        window: &mut Window,
        cx: &mut App,
    ) {
        let focus_handle = self.input.read(cx).focus_handle.clone();
        window.handle_input(
            &focus_handle,
            ElementInputHandler::new(bounds, self.input.clone()),
            cx,
        );
        let scroll_x = prepaint.scroll_x;
        let Some(line) = prepaint.line.take() else {
            return;
        };
        window.with_content_mask(Some(gpui_kit::ContentMask { bounds }), |window| {
            if let Some(selection) = prepaint.selection.take() {
                window.paint_quad(selection);
            }
            let _ = line.paint(
                point(bounds.origin.x - scroll_x, bounds.origin.y),
                window.line_height(),
                gpui_kit::TextAlign::Left,
                None,
                window,
                cx,
            );
            if focus_handle.is_focused(window) {
                if let Some(cursor) = prepaint.cursor.take() {
                    window.paint_quad(cursor);
                }
            }
        });
        self.input.update(cx, |input, _| {
            input.last_layout = Some(line);
            input.last_bounds = Some(bounds);
            input.scroll_x = scroll_x;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui_kit::TestAppContext;

    #[gpui_kit::test]
    fn edits_keep_a_single_zeroizing_buffer_and_mask_ime_queries(cx: &mut TestAppContext) {
        let window = cx.add_window(|_, cx| SecretInput::new("Passphrase", cx));
        window
            .update(cx, |input, window, cx| {
                input.replace_text_in_range(None, "correct horse", window, cx);
                input.replace_text_in_range(None, " battery", window, cx);
                assert_eq!(input.value(), "correct horse battery");
                // IME / accessibility never see the secret.
                let mut actual = None;
                let shown = input
                    .text_for_range(0..7, &mut actual, window, cx)
                    .expect("text");
                assert_eq!(shown, "•••••••");
                assert!(!shown.contains("correct"));
                // Backspace removes one grapheme.
                input.backspace(&Backspace, window, cx);
                assert_eq!(input.value(), "correct horse batter");
                let taken = input.take(cx);
                assert_eq!(taken.as_str(), "correct horse batter");
                assert!(input.is_empty());
            })
            .unwrap();
    }

    #[gpui_kit::test]
    fn offsets_map_between_secret_and_mask(cx: &mut TestAppContext) {
        let window = cx.add_window(|_, cx| SecretInput::new("", cx));
        window
            .update(cx, |input, _, cx| {
                input.set_value("aé🙂z", cx);
                // 'a' (1 byte), 'é' (2), '🙂' (4), 'z' (1)
                assert_eq!(input.display_offset(0), 0);
                assert_eq!(input.display_offset(1), 3);
                assert_eq!(input.display_offset(3), 6);
                assert_eq!(input.display_offset(7), 9);
                assert_eq!(input.content_offset(9), 7);
                assert_eq!(input.content_offset(12), 8);
                input.clear(cx);
                assert!(input.is_empty());
            })
            .unwrap();
    }
}
