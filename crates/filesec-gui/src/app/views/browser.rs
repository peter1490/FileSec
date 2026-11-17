//! The in-vault file browser: the header (back to vaults, vault name, vault
//! actions), status banners, the toolbar (folder path, search, sort, create),
//! inline composers, the virtualized table of rows, the trash view, and the
//! fixed status/selection bar.

use std::collections::HashSet;
use std::sync::Arc;

use gpui_kit::component::button::{Button, ButtonVariants};
use gpui_kit::component::input::Input;
use gpui_kit::component::menu::{ContextMenuExt, DropdownMenu, PopupMenu, PopupMenuItem};
use gpui_kit::component::Sizable;
use gpui_kit::TestSupportExt;
use gpui_kit::{
    div, prelude::*, px, uniform_list, AnyElement, Div, ElementId, ExternalPaths, FontWeight,
    SharedString, WeakEntity,
};

use filesec_core::manifest::EntryKind;

use crate::theme::{self, ico, icon, Colors};

use super::{any, handler, icon_menu, search_field, select_button, tooltip_text, with_menu, View};
use crate::app::model::{
    breadcrumb_segments, clamp_dir, file_glyph, file_tint, human_size, leaf_name, parent_dir,
    shown, trash_item_detail, view_summary, Row, RowClick, TrashItem,
};
use crate::app::{Action, FileSecApp, RowClickAt, Session, SortMode, BROWSER_CONTEXT};

/// Height of one browser row, and the gap under it (the list's pitch is the
/// sum: every row is the same height, so the list can be virtualized).
const ROW_H: f32 = 40.0;
const ROW_GAP: f32 = 2.0;

/// Height of the fixed status/selection bar.
const FOOTER_H: f32 = 48.0;

/// Width of the "Size" column.
const DETAIL_W: f32 = 168.0;

/// Width of the trailing quick-action column.
const ACTIONS_W: f32 = 60.0;

/// Horizontal inset of the table (rows carry their own inner padding).
const TABLE_PAD: f32 = 14.0;

pub(in crate::app) fn browser(s: &mut Session, v: &View) -> AnyElement {
    let c = v.c;
    let (name, id) = match &s.open {
        Some(o) => (o.reader.name().to_string(), o.id.clone()),
        None => return div().into_any_element(),
    };
    // Cached per committed revision: no per-render clone, index, or trash scan.
    let Some(model) = s.browser_model() else {
        return div().into_any_element();
    };
    // Drop any view whose temp a watcher already wiped (the app was closed), so
    // the banner reflects what is actually still open.
    s.views.retain(|view| view.temp_path.exists());
    // Keep the browse state coherent with the (possibly just-mutated) vault: clamp
    // the current folder to one that still exists, and drop any selection (or
    // anchor) whose entries were removed / renamed / trashed out from under us.
    s.current_dir = clamp_dir(&model.dirs, &s.current_dir);
    s.selected.retain(|p| model.live.contains(p));
    if let Some(a) = &s.select_anchor {
        if !model.live.contains(a) {
            s.select_anchor = None;
        }
    }

    // Leaf of the file currently checked out for editing (if any). While set, all
    // other vault mutations are disabled and the user must check in / discard.
    let editing = s.checkout.as_ref().map(|co| co.leaf.clone());
    let viewing: Vec<String> = s.views.iter().map(|view| view.leaf.clone()).collect();
    let idle = editing.is_none();
    let cur = s.current_dir.clone();
    let in_trash = s.show_trash;
    let trash_len = model.trash.len();

    let mut root = div()
        .id("browser")
        .key_context(BROWSER_CONTEXT)
        .track_focus(&v.browser_focus)
        .size_full()
        .relative()
        .flex()
        .flex_col();

    root = root.child(header(&name, &id, in_trash, trash_len, v));

    // Status that must stay on screen while it is true.
    let mut banners = Vec::new();
    if let Some(leaf) = &editing {
        banners.push(any(theme::banner(c.accent).child(
            theme::wrap_row()
                .w_full()
                .gap(px(10.0))
                .child(theme::icon_text(icon::EDIT, 16.0, c.accent))
                .child(
                    div()
                        .flex_1()
                        .min_w(px(160.0))
                        .flex()
                        .flex_col()
                        .child(theme::strong(
                            format!("Editing “{leaf}”"),
                            theme::TEXT_BODY,
                            c.text,
                        ))
                        .child(theme::muted(
                            "Save your changes in the other app, then check the file back in.",
                            c,
                        )),
                )
                .child(
                    theme::secondary_button("discard", "Discard changes")
                        .on_click(v.on(Action::Discard)),
                )
                .child(
                    theme::primary_button("check-in", "Check in")
                        .icon(ico(icon::CHECK))
                        .on_click(v.on(Action::CheckIn)),
                ),
        )));
    }
    if !viewing.is_empty() {
        let plural = if viewing.len() == 1 { "y" } else { "ies" };
        banners.push(any(theme::banner(c.text_muted).child(
            theme::row()
                .w_full()
                .items_start()
                .gap(px(10.0))
                .child(theme::icon_text(icon::EYE, 16.0, c.text_muted).mt(px(1.0)))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .child(theme::strong(
                            format!("{} read-only cop{plural} open", viewing.len()),
                            theme::TEXT_BODY,
                            c.text,
                        ))
                        .child(theme::muted(
                            format!(
                                "{} — wiped automatically when closed, or when you leave this \
                                 vault.",
                                viewing.join(", ")
                            ),
                            c,
                        )),
                ),
        )));
    }
    if !banners.is_empty() {
        root = root.child(
            div()
                .flex_none()
                .w_full()
                .px(px(24.0))
                .pt(px(14.0))
                .flex()
                .flex_col()
                .gap(px(8.0))
                .children(banners),
        );
    }

    // ---- Trash view: a separate mode that replaces the file list ----
    if in_trash {
        return root
            .child(trash_panel(&model.trash, idle, s.confirm_empty_trash, v))
            .into_any_element();
    }

    root = root.child(toolbar(s, &cur, idle, v));

    // ---- Inline composers (new folder / new file / rename) ----
    if idle {
        if s.show_new_folder {
            root = root.child(composer(
                icon::FOLDER_PLUS,
                "New folder".into(),
                Input::new(&v.fields.new_folder_name),
                ("create-folder", "Create", Action::NewFolder),
                ("cancel-folder", Action::ToggleNewFolder(false)),
                v,
            ));
        }
        if s.show_new_file {
            root = root.child(composer(
                icon::FILE_PLUS,
                "New text file".into(),
                Input::new(&v.fields.new_file_name),
                ("create-file", "Create & edit", Action::NewFile),
                ("cancel-file", Action::ToggleNewFile(false)),
                v,
            ));
        }
        if let Some(target) = s.rename_target.clone() {
            root = root.child(composer(
                icon::EDIT,
                format!("Rename “{}”", shown(leaf_name(&target))).into(),
                Input::new(&v.fields.rename),
                ("confirm-rename", "Save", Action::ConfirmRename),
                ("cancel-rename", Action::CancelRename),
                v,
            ));
        }
    }

    // ---- The file/folder table ----
    let search = v.text(&v.fields.file_search).to_string();
    let searching = !search.trim().is_empty();
    let rows = s.visible_rows(&model, &cur, &search);

    let list: AnyElement = if !model.has_live {
        // A vault holding only trashed files still reads as empty here (the live
        // tree is what the browser shows; the trash has its own view).
        any(theme::empty_state(
            icon::FOLDER,
            "This vault is empty",
            "Add files or folders, or drag them here from your computer. They're encrypted \
             as they're added.",
            idle.then(|| {
                any(theme::row()
                    .child(
                        theme::secondary_button("add-folder-empty", "Add folder…")
                            .icon(ico(icon::FOLDER_PLUS))
                            .on_click(v.on(Action::AddFolder)),
                    )
                    .child(
                        theme::primary_button("add-files-empty", "Add files…")
                            .icon(ico(icon::UPLOAD))
                            .on_click(v.on(Action::AddFiles)),
                    ))
            }),
            c,
        ))
    } else if rows.is_empty() {
        if searching {
            any(theme::empty_state(
                icon::SEARCH,
                format!("No files match “{}”", search.trim()),
                "Search looks in every folder of this vault.",
                Some(any(theme::secondary_button(
                    "clear-search-nomatch",
                    "Clear search",
                )
                .on_click(v.on(Action::ClearFileSearch)))),
                c,
            ))
        } else {
            any(theme::empty_state(
                icon::FOLDER,
                "This folder is empty",
                "Add files here, or drag them in from your computer.",
                idle.then(|| {
                    any(theme::primary_button("add-files-folder", "Add files…")
                        .icon(ico(icon::UPLOAD))
                        .on_click(v.on(Action::AddFiles)))
                }),
                c,
            ))
        }
    } else {
        let selected = Arc::new(s.selected.clone());
        let clear_on_blank = !s.selected.is_empty();
        any(div()
            .id("rows-area")
            .flex_1()
            .min_h_0()
            .w_full()
            .px(px(TABLE_PAD))
            .flex()
            .flex_col()
            // Clicking the blank space below the last row clears the
            // selection, like a file explorer.
            .when(clear_on_blank, |area| {
                area.on_click(v.on(Action::ClearSelection))
            })
            .child(column_header(searching, v))
            .child(div().h(px(4.0)))
            .child(row_list(rows.clone(), selected, idle, searching, v)))
    };

    root = root.child(
        div()
            .flex_1()
            .min_h_0()
            .w_full()
            .flex()
            .flex_col()
            .child(list),
    );
    root = root.child(status_bar(&s.selected, &rows, searching, idle, v));

    // ---- Drag-and-drop from the OS (into the current folder) ----
    let drop_target = if cur.is_empty() {
        name.clone()
    } else {
        shown(leaf_name(&cur))
    };
    let dnd = idle && !s.modal_open();
    root = root.when(dnd, |r| {
        r.drag_over::<ExternalPaths>(move |style, _, _, _| style.bg(theme::accent_soft(c)))
    });
    if dnd && v.cx.has_active_drag() {
        root = root.child(
            div()
                .absolute()
                .top(px(8.0))
                .left(px(8.0))
                .right(px(8.0))
                .bottom(px(8.0))
                .rounded(theme::RADIUS_LG)
                .border_2()
                .border_color(c.accent)
                .bg(theme::with_alpha(c.bg, 200))
                .flex()
                .flex_col()
                .items_center()
                .justify_center()
                .gap(px(12.0))
                .child(theme::icon_tile(
                    icon::UPLOAD,
                    52.0,
                    c.accent,
                    theme::accent_soft(c),
                ))
                .child(theme::strong(
                    format!("Drop to add to “{drop_target}”"),
                    px(16.0),
                    c.text,
                ))
                .child(theme::muted("Files are encrypted as they're added.", c)),
        );
    }
    root.into_any_element()
}

/// The page header: back to the vault list, the vault's name, and the
/// vault-level actions.
fn header(name: &str, id: &str, in_trash: bool, trash_len: usize, v: &View) -> Div {
    let c = v.c;
    let mut right = theme::row().flex_none().gap(px(6.0));
    let trash_label = if in_trash {
        "Back to files".to_string()
    } else if trash_len > 0 {
        format!("Trash ({trash_len})")
    } else {
        "Trash".to_string()
    };
    right = right.child(
        theme::ghost_button("toggle-trash", trash_label)
            .icon(ico(if in_trash { icon::FOLDER } else { icon::TRASH }))
            .on_click(v.on(Action::ShowTrash(!in_trash))),
    );
    if !in_trash {
        right = right
            .child(icon_menu(
                "more",
                icon::DOTS,
                "More actions",
                vec![("Extract all files…".into(), Action::ExtractAll, false)],
                v,
            ))
            .child(
                theme::secondary_button("send-open-vault", "Send vault…")
                    .icon(ico(icon::SEND))
                    .on_click(v.on(Action::BeginExport(id.to_string()))),
            );
    }
    div()
        .flex_none()
        .w_full()
        .h(theme::HEADER_H)
        .pl(px(14.0))
        .pr(px(24.0))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(6.0))
        .border_b_1()
        .border_color(c.border_subtle)
        .child(
            Button::new("all-vaults")
                .ghost()
                .icon(ico(icon::BACK))
                .label("Vaults")
                .tooltip("Back to all vaults")
                .on_click(v.on(Action::CloseVault)),
        )
        .child(theme::text("/", c.text_subtle))
        .child(
            div()
                .id("vault-title")
                .flex_1()
                .min_w_0()
                .tooltip(tooltip_text(name.to_string()))
                .child(theme::one_line(theme::strong(
                    name.to_string(),
                    px(16.0),
                    c.text,
                ))),
        )
        .child(right)
}

/// Folder path on the left; search, sort, and creation on the right. Narrow
/// windows split it over two lines so every control stays reachable.
fn toolbar(s: &Session, cur: &str, idle: bool, v: &View) -> Div {
    let sort_items = SortMode::ALL
        .iter()
        .map(|m| {
            (
                SharedString::from(m.label()),
                Action::SetSort(*m),
                s.sort == *m,
            )
        })
        .collect();
    let sort = with_menu(
        select_button("file-sort", s.sort.label())
            .icon(ico(icon::SORT))
            .w(px(178.0)),
        sort_items,
        v,
    );
    let new_items = vec![
        (
            SharedString::from("New folder"),
            Action::ToggleNewFolder(!s.show_new_folder),
            false,
        ),
        (
            SharedString::from("New text file"),
            Action::ToggleNewFile(!s.show_new_file),
            false,
        ),
        (SharedString::default(), Action::AddFolder, false),
        (
            SharedString::from("Add a folder from disk…"),
            Action::AddFolder,
            false,
        ),
    ];
    let new_menu = with_menu(
        theme::enabled(select_button("new-menu", "New").icon(ico(icon::PLUS)), idle),
        new_items,
        v,
    );
    let add = theme::enabled(
        theme::primary_button("add-files", "Add files…").icon(ico(icon::UPLOAD)),
        idle,
    )
    .on_click(v.on(Action::AddFiles));
    let search = search_field(
        "clear-file-search",
        &v.fields.file_search,
        Action::ClearFileSearch,
        v,
    );
    let frame = div()
        .flex_none()
        .w_full()
        .px(px(24.0))
        .pt(px(14.0))
        .pb(px(10.0))
        .flex()
        .flex_col()
        .gap(px(10.0));
    if v.width >= px(700.0) {
        frame.child(
            theme::row()
                .w_full()
                .child(div().flex_1().min_w_0().child(breadcrumb(cur, v)))
                .child(div().w(px(220.0)).child(search))
                .child(sort)
                .child(new_menu)
                .child(add),
        )
    } else {
        frame
            .child(
                theme::row()
                    .w_full()
                    .child(div().flex_1().min_w_0().child(breadcrumb(cur, v)))
                    .child(add),
            )
            .child(
                theme::row()
                    .w_full()
                    .child(div().flex_1().min_w_0().child(search))
                    .child(sort)
                    .child(new_menu),
            )
    }
}

/// An inline, single-field composer (new folder / new file / rename).
fn composer(
    glyph: icon::Glyph,
    title: SharedString,
    input: Input,
    confirm: (&'static str, &'static str, Action),
    cancel: (&'static str, Action),
    v: &View,
) -> Div {
    let c = v.c;
    div().flex_none().w_full().px(px(24.0)).pb(px(10.0)).child(
        div()
            .w_full()
            .p(px(10.0))
            .pl(px(14.0))
            .rounded(theme::RADIUS)
            .bg(c.surface)
            .border_1()
            .border_color(c.border)
            .child(
                theme::wrap_row()
                    .w_full()
                    .gap(px(10.0))
                    .child(theme::icon_text(glyph, 16.0, c.text_muted))
                    .child(theme::one_line(theme::text(title, c.text)).max_w(px(260.0)))
                    .child(div().flex_1().min_w(px(180.0)).child(input.w_full()))
                    .child(theme::ghost_button(cancel.0, "Cancel").on_click(v.on(cancel.1)))
                    .child(theme::primary_button(confirm.0, confirm.1).on_click(v.on(confirm.2))),
            ),
    )
}

/// The table's column captions.
fn column_header(searching: bool, v: &View) -> Div {
    let c = v.c;
    let caption = |s: &'static str| {
        div()
            .text_size(px(12.0))
            .font_weight(FontWeight::SEMIBOLD)
            .text_color(c.text_muted)
            .child(s)
    };
    div()
        .flex_none()
        .w_full()
        .h(px(32.0))
        .px(px(10.0))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(10.0))
        .border_b_1()
        .border_color(c.border_subtle)
        .child(div().w(px(16.0)))
        .child(caption("Name").flex_1())
        .child(
            caption(if searching { "Size · Folder" } else { "Size" })
                .w(px(DETAIL_W))
                .flex_none(),
        )
        .child(div().w(px(ACTIONS_W)).flex_none())
}

/// The virtualized row list: only rows intersecting the viewport are built.
/// Stable path IDs keep actions attached to the same entry while scrolling,
/// sorting, or searching.
fn row_list(
    rows: Arc<Vec<Row>>,
    selected: Arc<HashSet<String>>,
    idle: bool,
    searching: bool,
    v: &View,
) -> impl IntoElement {
    let c = v.c;
    let app = v.app.clone();
    let count = rows.len();
    uniform_list("rows", count, move |range, _, _| {
        range
            .map(|i| {
                let row = &rows[i];
                entry_row(row, selected.contains(&row.path), idle, searching, c, &app)
            })
            .collect::<Vec<_>>()
    })
    .flex_1()
    .w_full()
}

/// What a click on a row's body means, given the click count and modifiers.
fn row_click(event: &gpui_kit::ClickEvent, cx: &gpui_kit::App) -> RowClick {
    if event.click_count() >= 2 {
        RowClick::Double
    } else {
        let m = event.modifiers();
        RowClick::Single {
            shift: m.shift,
            toggle: m.secondary(cx),
        }
    }
}

/// One row of the table: a full-width, hover/selected-highlighted surface
/// with a type icon, the name, the size column, and trailing quick actions.
/// The body click resolves selection / open on dispatch; trailing buttons and
/// the right-click menu emit their actions directly.
fn entry_row(
    row: &Row,
    selected: bool,
    idle: bool,
    searching: bool,
    c: Colors,
    app: &WeakEntity<FileSecApp>,
) -> AnyElement {
    let is_dir = row.kind == EntryKind::Dir;
    let leaf = leaf_name(&row.path);
    let (glyph, col) = if is_dir {
        (icon::FOLDER, c.accent)
    } else {
        (file_glyph(leaf), file_tint(leaf, c))
    };
    let secondary = if is_dir {
        format!(
            "{} item{}",
            row.children,
            if row.children == 1 { "" } else { "s" }
        )
    } else if searching && !parent_dir(&row.path).is_empty() {
        format!("{} · {}", human_size(row.size), parent_dir(&row.path))
    } else {
        human_size(row.size)
    };
    let path = row.path.clone();
    let click_app = app.clone();
    let click_path = path.clone();
    let menu_row = row.clone();
    let menu_app = app.clone();
    let ctx_row = row.clone();
    let ctx_app = app.clone();

    let body = div()
        .id(ElementId::Name(format!("row-body:{path}").into()))
        .h(px(ROW_H))
        .w_full()
        .px(px(10.0))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(10.0))
        .rounded(theme::RADIUS_SM)
        .when(selected, |r| r.bg(theme::accent_soft(c)))
        .when(!selected, |r| r.hover(|s| s.bg(c.surface_hi)))
        .cursor_pointer()
        .on_click(move |event, window, cx| {
            cx.stop_propagation();
            let action = Action::RowClicked(RowClickAt {
                path: click_path.clone(),
                click: row_click(event, cx),
            });
            let _ = click_app.update(cx, |this, cx| this.dispatch(action, window, cx));
        })
        .child(theme::icon_text(glyph, 16.0, col))
        .child(
            div()
                .id(ElementId::Name(format!("row-name:{path}").into()))
                .flex_1()
                .min_w_0()
                .tooltip(tooltip_text(path.clone()))
                .child(theme::one_line(
                    div()
                        .text_size(theme::TEXT_BODY)
                        .text_color(c.text)
                        .when(selected, |d| d.font_weight(FontWeight::SEMIBOLD))
                        .child(shown(leaf)),
                ))
                .test_support(),
        )
        .child(
            div()
                .id(ElementId::Name(format!("row-detail:{path}").into()))
                .w(px(DETAIL_W))
                .flex_none()
                .child(theme::one_line(
                    div()
                        .text_size(px(13.0))
                        .text_color(c.text_muted)
                        .child(secondary),
                ))
                .test_support(),
        )
        .child(
            theme::row()
                .w(px(ACTIONS_W))
                .flex_none()
                .gap(px(4.0))
                .justify_end()
                .when(!is_dir, |r| {
                    r.child(
                        theme::icon_button(
                            SharedString::from(format!("view:{path}")),
                            icon::EYE,
                            "View read-only",
                            c,
                        )
                        .small()
                        .on_click(handler(app, Action::ViewFile(path.clone()))),
                    )
                })
                .child(
                    theme::icon_button(
                        SharedString::from(format!("row-menu:{path}")),
                        icon::DOTS,
                        &format!("Actions for {}", leaf_name(&path)),
                        c,
                    )
                    .small()
                    .dropdown_menu(move |menu, _, _| entry_menu(menu, &menu_row, idle, &menu_app)),
                ),
        )
        .context_menu(move |menu, _, _| entry_menu(menu, &ctx_row, idle, &ctx_app));

    div()
        .id(ElementId::Name(format!("row:{path}").into()))
        .w_full()
        .h(px(ROW_H + ROW_GAP))
        .pb(px(ROW_GAP))
        .child(body)
        .test_support()
        .into_any_element()
}

/// The entry actions, shared by the "…" menu and the row's context menu.
fn entry_menu(
    mut menu: PopupMenu,
    row: &Row,
    idle: bool,
    app: &WeakEntity<FileSecApp>,
) -> PopupMenu {
    let path = &row.path;
    let item = |label: &'static str, action: Action| {
        PopupMenuItem::new(label).on_click(handler(app, action))
    };
    if row.kind == EntryKind::Dir {
        menu = menu.item(item("Open folder", Action::EnterDir(path.clone())));
    } else {
        menu = menu.item(item("View read-only", Action::ViewFile(path.clone())));
        if idle {
            menu = menu
                .item(item(
                    "Quick edit in FileSec…",
                    Action::QuickEdit(path.clone()),
                ))
                .item(item("Check out & edit…", Action::CheckOut(path.clone())));
        }
        menu = menu.item(item("Save as…", Action::SaveEntryAs(path.clone())));
    }
    if idle {
        menu = menu
            .separator()
            .item(item("Rename…", Action::BeginRename(path.clone())))
            .item(item(
                "Move to folder…",
                Action::BeginMove(vec![path.clone()]),
            ))
            .separator()
            .item(item("Move to Trash", Action::Trash(path.clone())));
    }
    menu
}

/// The folder path ("All files › a › b"); each ancestor navigates.
fn breadcrumb(current: &str, v: &View) -> Div {
    let c = v.c;
    let segs = breadcrumb_segments(current);
    let last = segs.len().saturating_sub(1);
    let mut row = theme::row()
        .w_full()
        .min_w_0()
        .gap(px(2.0))
        .overflow_hidden();
    for (i, (label, target)) in segs.into_iter().enumerate() {
        let label = if i == 0 {
            "All files".to_string()
        } else {
            label
        };
        if i > 0 {
            row = row.child(theme::icon_text(icon::CARET_RIGHT, 14.0, c.text_subtle));
        }
        if i == last {
            row = row
                .child(theme::one_line(theme::strong(label, theme::TEXT_BODY, c.text)).px(px(6.0)));
        } else {
            row = row.child(
                theme::link_button(SharedString::from(format!("crumb:{target}")), label)
                    .on_click(v.on(Action::EnterDir(target))),
            );
        }
    }
    row
}

/// The fixed bar under the table: a summary of the folder, or the actions for
/// the current selection. Its height never changes, so rows never jump.
fn status_bar(
    selected: &HashSet<String>,
    rows: &[Row],
    searching: bool,
    idle: bool,
    v: &View,
) -> Div {
    let c = v.c;
    let frame = div()
        .flex_none()
        .w_full()
        .h(px(FOOTER_H))
        .px(px(24.0))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .border_t_1()
        .border_color(c.border_subtle)
        .bg(if selected.is_empty() {
            c.bg
        } else {
            theme::with_alpha(c.accent, if c.dark { 22 } else { 12 })
        });
    if selected.is_empty() {
        let summary = if rows.is_empty() {
            String::new()
        } else {
            view_summary(rows, searching)
        };
        return frame
            .child(theme::one_line(theme::muted(summary, c)).flex_1())
            .when(v.wide(), |f| {
                f.child(theme::small("Double-click to open", c.text_subtle))
            })
            .when(idle && rows.len() > 1, |f| {
                f.child(
                    theme::link_button("select-all", "Select all")
                        .on_click(v.on(Action::SelectAllVisible)),
                )
            });
    }
    let paths: Vec<String> = selected.iter().cloned().collect();
    frame
        .child(
            theme::enabled(
                theme::icon_button("clear-selection", icon::CLOSE, "Clear selection", c).small(),
                idle,
            )
            .on_click(v.on(Action::ClearSelection)),
        )
        .child(theme::strong(
            format!("{} selected", selected.len()),
            px(13.0),
            c.text,
        ))
        .child(div().flex_1())
        .child(
            theme::enabled(
                theme::secondary_button("trash-selection", "Trash")
                    .small()
                    .icon(ico(icon::TRASH)),
                idle,
            )
            .tooltip("Move selected items to Trash")
            .on_click(v.on(Action::TrashSelected)),
        )
        .child(
            theme::enabled(
                theme::secondary_button("move-selection", "Move…")
                    .small()
                    .icon(ico(icon::FOLDER_INPUT)),
                idle,
            )
            .on_click(v.on(Action::BeginMove(paths))),
        )
        .child(
            theme::enabled(
                theme::primary_button("extract-selection", "Extract…")
                    .small()
                    .icon(ico(icon::DOWNLOAD)),
                idle,
            )
            .on_click(v.on(Action::ExtractSelected)),
        )
}

/// The trash view: soft-deleted entries, each with Restore / Delete forever,
/// plus "Empty Trash". Items stay encrypted at rest until purged, and are never
/// included when a vault is sent or extracted.
fn trash_panel(
    items: &[TrashItem],
    idle: bool,
    confirm_empty: bool,
    v: &View,
) -> gpui_kit::Stateful<Div> {
    let c = v.c;
    // Emptying the trash is the one irreversible bulk action here, so it takes
    // a second, explicit click that names the consequence.
    let mut actions = theme::wrap_row().justify_end();
    if !items.is_empty() && idle {
        if confirm_empty {
            actions = actions
                .child(theme::muted(
                    format!(
                        "Permanently delete {} item{}? This can't be undone.",
                        items.len(),
                        if items.len() == 1 { "" } else { "s" }
                    ),
                    c,
                ))
                .child(
                    theme::ghost_button("cancel-empty-trash", "Cancel")
                        .on_click(v.on(Action::PromptEmptyTrash(false))),
                )
                .child(
                    theme::danger_button("confirm-empty-trash", "Delete all", v.cx)
                        .on_click(v.on(Action::EmptyTrash)),
                );
        } else {
            actions = actions.child(
                theme::secondary_button("empty-trash", "Empty Trash…")
                    .on_click(v.on(Action::PromptEmptyTrash(true))),
            );
        }
    }
    let header = theme::wrap_row()
        .w_full()
        .justify_between()
        .gap(px(12.0))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(2.0))
                .child(theme::strong("Trash", theme::TEXT_H2, c.text))
                .child(theme::muted(
                    "Deleted items stay encrypted here until you empty the Trash. They're \
                     never included when you send or extract this vault.",
                    c,
                )),
        )
        .child(actions);
    let body: AnyElement = if items.is_empty() {
        any(theme::empty_state(
            icon::TRASH,
            "Trash is empty",
            "Files you delete land here first, so you can put them back.",
            None,
            c,
        ))
    } else {
        let mut list = theme::list_container(c);
        for (i, item) in items.iter().enumerate() {
            let leaf = leaf_name(&item.orig_path);
            let (glyph, col) = if item.kind == EntryKind::Dir {
                (icon::FOLDER, c.accent)
            } else {
                (file_glyph(leaf), file_tint(leaf, c))
            };
            let tp = item.trashed_path.clone();
            let row = theme::row()
                .w_full()
                .px(px(16.0))
                .py(px(10.0))
                .gap(px(12.0))
                .child(theme::icon_text(glyph, 16.0, col))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .gap(px(1.0))
                        .child(theme::one_line(theme::text(shown(leaf), c.text)))
                        .child(theme::one_line(theme::muted(trash_item_detail(item), c))),
                )
                .when(idle, |r| {
                    r.child(
                        theme::ghost_button(
                            SharedString::from(format!("purge:{tp}")),
                            "Delete forever",
                        )
                        .small()
                        .on_click(v.on(Action::PurgeTrashed(tp.clone()))),
                    )
                    .child(
                        theme::secondary_button(
                            SharedString::from(format!("restore:{tp}")),
                            "Restore",
                        )
                        .small()
                        .icon(ico(icon::RESTORE))
                        .on_click(v.on(Action::RestoreTrashed(tp.clone()))),
                    )
                });
            list = list.child(theme::list_row_divider(i, row, c));
        }
        any(list)
    };
    div()
        .id("trash-list")
        .flex_1()
        .min_h_0()
        .w_full()
        .overflow_y_scroll()
        .child(
            div()
                .w_full()
                .px(px(24.0))
                .pt(px(18.0))
                .pb(px(32.0))
                .flex()
                .flex_col()
                .gap(px(16.0))
                .child(header)
                .child(body),
        )
}
