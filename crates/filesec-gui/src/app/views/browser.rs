//! The in-vault file browser: header and banners, breadcrumb, search and sort,
//! the file tools and inline composers, the virtualized row list, the trash
//! view, and the fixed selection footer.

use std::collections::HashSet;
use std::sync::Arc;

use gpui_kit::component::button::{Button, ButtonVariants};
use gpui_kit::component::input::Input;
use gpui_kit::component::menu::{ContextMenuExt, DropdownMenu, PopupMenu, PopupMenuItem};
use gpui_kit::TestSupportExt;
use gpui_kit::{
    div, prelude::*, px, uniform_list, AnyElement, Div, ElementId, ExternalPaths, SharedString,
    WeakEntity,
};

use filesec_core::manifest::EntryKind;

use crate::theme::{self, icon, Colors};

use super::{any, dropdown, handler, search_field, tooltip_text, View};
use crate::app::model::{
    breadcrumb_segments, clamp_dir, file_tint, human_size, leaf_name, parent_dir, shown,
    trash_item_detail, view_summary, Row, RowClick, TrashItem,
};
use crate::app::{Action, FileSecApp, RowClickAt, Session, SortMode, BROWSER_CONTEXT};

/// Height of one browser row, and the gap under it (the list's pitch is the
/// sum: every row is the same height, so the list can be virtualized).
const ROW_H: f32 = 44.0;
const ROW_GAP: f32 = 2.0;

/// Height of the fixed selection footer.
const FOOTER_H: f32 = 44.0;

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
        .flex_col()
        .gap(px(8.0));

    // Navigation and vault actions stay separate from the file tools.
    let mut right = theme::row();
    if !in_trash {
        right = right.child(dropdown(
            "more",
            "More",
            vec![("Extract all files…".into(), Action::ExtractAll, false)],
            v,
        ));
    }
    let trash_label = if in_trash {
        "Back to files".to_string()
    } else {
        format!("Trash ({trash_len})")
    };
    right = right.child(
        theme::secondary_button("toggle-trash", trash_label)
            .on_click(v.on(Action::ShowTrash(!in_trash))),
    );
    root = root.child(
        theme::row()
            .w_full()
            .justify_between()
            .child(
                theme::secondary_button("all-vaults", "←  All vaults")
                    .on_click(v.on(Action::CloseVault)),
            )
            .child(right),
    );
    root = root.child(
        theme::row()
            .w_full()
            .child(
                div()
                    .id("vault-title")
                    .flex_1()
                    .min_w_0()
                    .tooltip(tooltip_text(name.clone()))
                    .child(theme::one_line(theme::strong(
                        name.clone(),
                        theme::TEXT_HEADING,
                        c.text,
                    ))),
            )
            .when(!in_trash, |r| {
                r.child(
                    theme::primary_button("send-open-vault", "Send vault…")
                        .on_click(v.on(Action::BeginExport(id.clone()))),
                )
            }),
    );

    if let Some(leaf) = &editing {
        root = root.child(
            theme::banner(c.accent).child(
                theme::row()
                    .w_full()
                    .child(theme::icon_text(icon::EDIT, 16.0, c.accent))
                    .child(theme::strong(
                        format!("Editing {leaf}"),
                        theme::TEXT_BODY,
                        c.accent,
                    ))
                    .child(theme::muted("— edit in your app, then:", c))
                    .child(div().flex_1())
                    .child(
                        theme::primary_button("check-in", "Check in")
                            .on_click(v.on(Action::CheckIn)),
                    )
                    .child(
                        theme::danger_button("discard", "Discard", v.cx)
                            .on_click(v.on(Action::Discard)),
                    ),
            ),
        );
    }

    if !viewing.is_empty() {
        let plural = if viewing.len() == 1 { "y" } else { "ies" };
        root = root.child(
            theme::banner(c.accent).child(
                theme::wrap_row()
                    .child(theme::icon_text(icon::EYE, 16.0, c.accent))
                    .child(theme::strong(
                        format!("Viewing {} read-only cop{plural}", viewing.len()),
                        theme::TEXT_BODY,
                        c.accent,
                    ))
                    .child(theme::muted(format!("({})", viewing.join(", ")), c))
                    .child(theme::muted(
                        "— wiped automatically on close, or when you leave the vault.",
                        c,
                    )),
            ),
        );
    }

    // ---- Trash view: a separate mode that replaces the file list ----
    if in_trash {
        return root
            .child(trash_panel(&model.trash, idle, s.confirm_empty_trash, v))
            .into_any_element();
    }

    // Breadcrumbs get their own wrapping line, including for deep folders.
    root = root.child(breadcrumb(&cur, v));

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
    root = root.child(
        theme::row()
            .w_full()
            .child(div().flex_none().w(px(170.0)).child(dropdown(
                "file-sort",
                s.sort.label(),
                sort_items,
                v,
            )))
            .child(div().flex_1().min_w_0().child(search_field(
                "clear-file-search",
                &v.fields.file_search,
                Action::ClearFileSearch,
                v,
            ))),
    );

    // One primary file action, with less frequent creation tools grouped.
    let new_items = vec![
        (
            SharedString::from("Folder"),
            Action::ToggleNewFolder(!s.show_new_folder),
            false,
        ),
        (
            SharedString::from("Text file"),
            Action::ToggleNewFile(!s.show_new_file),
            false,
        ),
    ];
    root = root.child(
        theme::wrap_row()
            .child(
                theme::enabled(theme::primary_button("add-files", "+  Add files…"), idle)
                    .on_click(v.on(Action::AddFiles)),
            )
            .child(
                theme::enabled(theme::secondary_button("add-folder", "Add folder…"), idle)
                    .on_click(v.on(Action::AddFolder)),
            )
            .when(idle, |r| {
                r.child(dropdown("new-menu", "New…", new_items, v))
            }),
    );

    if s.show_new_folder && idle {
        root = root.child(
            theme::card(c).child(
                theme::wrap_row()
                    .child(
                        div()
                            .w(px(220.0))
                            .child(Input::new(&v.fields.new_folder_name)),
                    )
                    .child(
                        theme::primary_button("create-folder", "Create")
                            .on_click(v.on(Action::NewFolder)),
                    )
                    .child(
                        theme::secondary_button("cancel-folder", "Cancel")
                            .on_click(v.on(Action::ToggleNewFolder(false))),
                    ),
            ),
        );
    }

    if s.show_new_file && idle {
        root = root.child(
            theme::card(c).child(
                theme::wrap_row()
                    .child(
                        div()
                            .w(px(260.0))
                            .child(Input::new(&v.fields.new_file_name)),
                    )
                    .child(
                        theme::primary_button("create-file", "Create & edit")
                            .on_click(v.on(Action::NewFile)),
                    )
                    .child(
                        theme::secondary_button("cancel-file", "Cancel")
                            .on_click(v.on(Action::ToggleNewFile(false))),
                    ),
            ),
        );
    }

    // ---- Inline rename composer ----
    if idle {
        if let Some(target) = s.rename_target.clone() {
            root = root.child(
                theme::card(c).child(
                    theme::wrap_row()
                        .child(theme::text(
                            format!("Rename “{}”", shown(leaf_name(&target))),
                            c.text,
                        ))
                        .child(div().w(px(220.0)).child(Input::new(&v.fields.rename)))
                        .child(
                            theme::primary_button("confirm-rename", "Save")
                                .on_click(v.on(Action::ConfirmRename)),
                        )
                        .child(
                            theme::secondary_button("cancel-rename", "Cancel")
                                .on_click(v.on(Action::CancelRename)),
                        ),
                ),
            );
        }
    }

    // ---- The file/folder list ----
    let search = v.text(&v.fields.file_search).to_string();
    let searching = !search.trim().is_empty();
    let rows = s.visible_rows(&model, &cur, &search);

    let list: AnyElement = if !model.has_live {
        // A vault holding only trashed files still reads as empty here (the live
        // tree is what the browser shows; the trash has its own view).
        any(theme::empty_state(
            icon::FOLDER,
            "This vault is empty",
            "Add files or folders — or just drag them in from your computer.",
            idle.then(|| {
                any(theme::primary_button("add-files-empty", "+  Add files…")
                    .on_click(v.on(Action::AddFiles)))
            }),
            c,
        ))
    } else if rows.is_empty() {
        if searching {
            any(div()
                .w_full()
                .pt(px(40.0))
                .flex()
                .flex_col()
                .items_center()
                .gap(px(8.0))
                .child(theme::icon_text(icon::FILE, 40.0, c.text_muted))
                .child(theme::strong(
                    format!("No files match “{}”", search.trim()),
                    theme::TEXT_BODY,
                    c.text,
                ))
                .child(theme::text(
                    "Search includes every folder in this vault.",
                    c.text_muted,
                ))
                .child(
                    theme::secondary_button("clear-search-nomatch", "Clear search")
                        .on_click(v.on(Action::ClearFileSearch)),
                ))
        } else {
            any(theme::empty_state(
                icon::FOLDER,
                "This folder is empty",
                "Add files here, or drag them in from your computer.",
                idle.then(|| {
                    any(theme::primary_button("add-files-folder", "+  Add files…")
                        .on_click(v.on(Action::AddFiles)))
                }),
                c,
            ))
        }
    } else {
        // An at-a-glance summary of the current view, plus a "select all"
        // affordance on the right when there's more than one item to select.
        let summary = theme::row()
            .w_full()
            .justify_between()
            .child(theme::muted(view_summary(&rows, searching), c))
            .when(idle && rows.len() > 1, |r| {
                r.child(
                    theme::link_button("select-all", "Select all")
                        .on_click(v.on(Action::SelectAllVisible)),
                )
            });
        let selected = Arc::new(s.selected.clone());
        let clear_on_blank = !s.selected.is_empty();
        any(div()
            .id("rows-area")
            .flex_1()
            .min_h_0()
            .w_full()
            .flex()
            .flex_col()
            .gap(px(2.0))
            // Clicking the blank space below the last row clears the
            // selection, like a file explorer.
            .when(clear_on_blank, |area| {
                area.on_click(v.on(Action::ClearSelection))
            })
            .child(summary)
            .child(row_list(rows, selected, idle, searching, v)))
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
    root = root.child(selection_footer(&s.selected, idle, v));

    // ---- Drag-and-drop from the OS (into the current folder) ----
    let drop_target = if cur.is_empty() {
        name.clone()
    } else {
        shown(leaf_name(&cur))
    };
    let dnd = idle && !s.modal_open();
    root = root.when(dnd, |r| {
        r.drag_over::<ExternalPaths>(move |style, _, _, _| {
            style.bg(theme::accent_soft(c)).rounded(theme::RADIUS)
        })
    });
    if dnd && v.cx.has_active_drag() {
        root = root.child(
            div()
                .absolute()
                .top_0()
                .left_0()
                .size_full()
                .rounded(theme::RADIUS)
                .border_2()
                .border_color(c.accent)
                .flex()
                .items_center()
                .justify_center()
                .child(theme::strong(
                    format!("Drop to add to {drop_target}"),
                    px(18.0),
                    c.accent,
                )),
        );
    }
    root.into_any_element()
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

/// One row in the file browser: a full-width, hover/selected-highlighted
/// surface with a type-tinted icon, the name/detail block, and trailing quick
/// actions. The body click resolves selection / open on dispatch; trailing
/// buttons and the right-click menu emit their actions directly.
fn entry_row(
    row: &Row,
    selected: bool,
    idle: bool,
    searching: bool,
    c: Colors,
    app: &WeakEntity<FileSecApp>,
) -> AnyElement {
    let is_dir = row.kind == EntryKind::Dir;
    let (glyph, col) = if is_dir {
        (icon::FOLDER, c.accent)
    } else {
        (icon::FILE, file_tint(leaf_name(&row.path), c))
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
        .gap(px(8.0))
        .rounded(theme::RADIUS_SM)
        .border_1()
        .border_color(if selected {
            c.accent
        } else {
            theme::with_alpha(c.accent, 0)
        })
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
        .child(theme::icon_text(glyph, 18.0, col))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .flex_col()
                .gap(px(2.0))
                .child(
                    div()
                        .id(ElementId::Name(format!("row-name:{path}").into()))
                        .w_full()
                        .tooltip(tooltip_text(path.clone()))
                        .child(theme::one_line(
                            div()
                                .text_size(theme::TEXT_BODY)
                                .text_color(c.text)
                                .child(shown(leaf_name(&path))),
                        ))
                        .test_support(),
                )
                .child(
                    div()
                        .id(ElementId::Name(format!("row-detail:{path}").into()))
                        .w_full()
                        .child(theme::one_line(theme::small(secondary, c.text_muted)))
                        .test_support(),
                ),
        )
        .when(!is_dir, |r| {
            r.child(
                theme::icon_button(
                    SharedString::from(format!("view:{path}")),
                    icon::EYE,
                    "View file read-only",
                    c,
                )
                .on_click(handler(app, Action::ViewFile(path.clone()))),
            )
        })
        .child(
            Button::new(SharedString::from(format!("row-menu:{path}")))
                .ghost()
                .w(px(32.0))
                .h(px(32.0))
                .child(theme::icon_text(icon::DOTS, 17.0, c.text_muted))
                .accessibility_label(SharedString::from(format!(
                    "Actions for {}",
                    leaf_name(&path)
                )))
                .dropdown_menu(move |menu, _, _| entry_menu(menu, &menu_row, idle, &menu_app)),
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

/// The folder breadcrumb ("Home / a / b"); each ancestor crumb navigates.
fn breadcrumb(current: &str, v: &View) -> Div {
    let c = v.c;
    let segs = breadcrumb_segments(current);
    let last = segs.len().saturating_sub(1);
    let mut row = theme::wrap_row().w_full().gap(px(4.0));
    for (i, (label, target)) in segs.into_iter().enumerate() {
        if i > 0 {
            row = row.child(theme::text("/", c.text_muted));
        }
        if i == last {
            row = row.child(theme::one_line(theme::strong(
                label,
                theme::TEXT_BODY,
                c.text,
            )));
        } else {
            row = row.child(
                theme::link_button(SharedString::from(format!("crumb:{target}")), label)
                    .on_click(v.on(Action::EnterDir(target))),
            );
        }
    }
    row
}

/// A fixed footer; its height does not depend on whether anything is selected.
fn selection_footer(selected: &HashSet<String>, idle: bool, v: &View) -> Div {
    let c = v.c;
    let frame = div()
        .flex_none()
        .w_full()
        .h(px(FOOTER_H))
        .px(px(10.0))
        .flex()
        .flex_row()
        .items_center()
        .gap(px(8.0))
        .bg(if selected.is_empty() {
            c.surface
        } else {
            theme::accent_soft(c)
        })
        .border_1()
        .border_color(c.border)
        .rounded(theme::RADIUS_SM);
    if selected.is_empty() {
        return frame.child(theme::one_line(theme::muted(
            "Select items for actions · Double-click to open",
            c,
        )));
    }
    let paths: Vec<String> = selected.iter().cloned().collect();
    frame
        .child(theme::strong(
            format!("{} selected", selected.len()),
            theme::TEXT_SMALL,
            c.accent,
        ))
        .child(div().flex_1())
        .child(
            theme::enabled(theme::primary_button("extract-selection", "Extract…"), idle)
                .on_click(v.on(Action::ExtractSelected)),
        )
        .child(
            theme::enabled(theme::secondary_button("move-selection", "Move…"), idle)
                .on_click(v.on(Action::BeginMove(paths))),
        )
        .child(
            theme::enabled(theme::secondary_button("trash-selection", "Trash"), idle)
                .tooltip("Move selected items to Trash")
                .on_click(v.on(Action::TrashSelected)),
        )
        .child(
            theme::enabled(
                theme::icon_button("clear-selection", icon::CLOSE, "Clear selection", c),
                idle,
            )
            .on_click(v.on(Action::ClearSelection)),
        )
}

/// The trash view: soft-deleted entries, each with Restore / Delete forever, plus
/// an "Empty Trash" action. Items stay encrypted at rest until purged, and are
/// never included when a vault is sent or extracted.
fn trash_panel(items: &[TrashItem], idle: bool, confirm_empty: bool, v: &View) -> Div {
    let c = v.c;
    // Emptying the trash is the one irreversible bulk action here, so it takes
    // a second click to confirm.
    let mut actions = theme::row();
    if !items.is_empty() && idle {
        if confirm_empty {
            actions = actions
                .child(theme::muted(
                    format!("Delete {} item(s) forever?", items.len()),
                    c,
                ))
                .child(
                    theme::secondary_button("cancel-empty-trash", "Cancel")
                        .on_click(v.on(Action::PromptEmptyTrash(false))),
                )
                .child(
                    theme::danger_button("confirm-empty-trash", "Delete all permanently", v.cx)
                        .on_click(v.on(Action::EmptyTrash)),
                );
        } else {
            actions = actions.child(
                theme::danger_button("empty-trash", "Empty Trash", v.cx)
                    .on_click(v.on(Action::PromptEmptyTrash(true))),
            );
        }
    }
    // The title and the actions each stay in one piece; when the window is
    // too narrow for both on one line, the actions wrap below the title.
    let header = theme::wrap_row()
        .w_full()
        .justify_between()
        .child(
            theme::row()
                .child(theme::icon_text(icon::TRASH, 18.0, c.text_muted))
                .child(theme::strong("Trash", theme::TEXT_HEADING, c.text)),
        )
        .child(actions);
    let body: AnyElement = if items.is_empty() {
        any(theme::empty_state(
            icon::TRASH,
            "Trash is empty",
            "Files you delete land here, so you can put them back.",
            None,
            c,
        ))
    } else {
        any(
            super::page_scroll("trash-list").children(items.iter().map(|item| {
                let (glyph, col) = if item.kind == EntryKind::Dir {
                    (icon::FOLDER, c.accent)
                } else {
                    (icon::FILE, file_tint(leaf_name(&item.orig_path), c))
                };
                let tp = item.trashed_path.clone();
                theme::card(c).child(
                    theme::row()
                        .w_full()
                        .gap(px(10.0))
                        .child(theme::icon_text(glyph, 18.0, col))
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .flex()
                                .flex_col()
                                .gap(px(2.0))
                                .child(theme::one_line(theme::text(
                                    shown(leaf_name(&item.orig_path)),
                                    c.text,
                                )))
                                .child(theme::muted(trash_item_detail(item), c)),
                        )
                        .when(idle, |r| {
                            r.child(
                                theme::primary_button(
                                    SharedString::from(format!("restore:{tp}")),
                                    "Restore",
                                )
                                .on_click(v.on(Action::RestoreTrashed(tp.clone()))),
                            )
                            .child(
                                theme::danger_button(
                                    SharedString::from(format!("purge:{tp}")),
                                    "Delete forever",
                                    v.cx,
                                )
                                .on_click(v.on(Action::PurgeTrashed(tp.clone()))),
                            )
                        }),
                )
            })),
        )
    };
    div()
        .flex_1()
        .min_h_0()
        .w_full()
        .flex()
        .flex_col()
        .gap(px(8.0))
        .child(header)
        .child(theme::muted(
            "Deleted items stay encrypted here until you empty the Trash. They're never \
             included when you Send or Extract a vault.",
            c,
        ))
        .child(body)
}
