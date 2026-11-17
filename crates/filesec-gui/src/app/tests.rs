//! Headless UI tests: real GPUI windows (layout, hit testing, focus, keyboard
//! dispatch) driven through the GPUI Kit test harness, plus the pure policy
//! checks that used to live beside the egui smoke tests. A panic anywhere in a
//! render path fails the test.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use gpui_kit::test::{TestEventExt, TestQueryExt, TestWindowExt};
use gpui_kit::{
    point, px, size, AnyWindowHandle, App, AppContext, Bounds, Context, ElementId, Entity,
    MouseButton, Pixels, Point, Role, TestAppContext, Window, WindowBounds, WindowOptions,
};

use filesec_core::contacts::{ContactBook, Trust};
use filesec_core::format;
use filesec_core::identity::Identity;
use filesec_core::util::hex;
use filesec_core::vault::Vault;
use filesec_core::SuiteId;

use super::model::*;
use super::*;
use crate::prefs::ThemeChoice;
use crate::store::{new_vault_id, Registry, Store, VaultMeta};

const MIN: (f32, f32) = (720.0, 520.0);
const DEFAULT: (f32, f32) = (1040.0, 700.0);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn test_session() -> Session {
    let id = Identity::generate("Tester", 0).expect("generate identity");
    Session::new(
        Arc::new(id),
        ContactBook::default(),
        Registry::default(),
        Vec::new(),
        false,
        "/tmp/filesec-ui-test".to_string(),
        None,
    )
}

fn temp_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "filesec-{tag}-{}",
        hex(&filesec_core::secret::random_array::<8>().unwrap())
    ))
}

/// Global setup (fonts, theme, key bindings). Once per test.
fn setup(cx: &mut TestAppContext) {
    cx.update(crate::init);
}

/// Open the app in a headless window of `(w, h)` logical pixels around an
/// explicit store and starting screen.
fn open(
    cx: &mut TestAppContext,
    (w, h): (f32, f32),
    store: Option<Arc<Store>>,
    state: State,
) -> (AnyWindowHandle, Entity<FileSecApp>) {
    cx.update(|cx| {
        let bounds = Bounds {
            origin: Point::default(),
            size: size(px(w), px(h)),
        };
        gpui_kit::open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            cx,
            |window, cx| cx.new(|cx| FileSecApp::with_state(store, state, window, cx)),
        )
        .expect("open test window")
    })
}

/// Render a fresh frame, then inspect / drive the window.
fn ui<R>(
    cx: &mut TestAppContext,
    window: AnyWindowHandle,
    f: impl FnOnce(&mut Window, &mut App) -> R,
) -> R {
    cx.update_window(window, |_, window, cx| {
        window.render_frame(cx);
        f(window, cx)
    })
    .unwrap()
}

/// Run `f` against the app entity with its window.
fn with_app<R>(
    cx: &mut TestAppContext,
    window: AnyWindowHandle,
    app: &Entity<FileSecApp>,
    f: impl FnOnce(&mut FileSecApp, &mut Window, &mut Context<FileSecApp>) -> R,
) -> R {
    cx.update_window(window, |_, window, cx| {
        app.update(cx, |a, cx| f(a, window, cx))
    })
    .unwrap()
}

fn dispatch(cx: &mut TestAppContext, window: AnyWindowHandle, app: &Entity<FileSecApp>, a: Action) {
    with_app(cx, window, app, |this, window, cx| {
        this.dispatch(a, window, cx)
    });
}

/// Wait for the running background job and apply its report, as the repaint
/// pump would.
fn finish_job(cx: &mut TestAppContext, window: AnyWindowHandle, app: &Entity<FileSecApp>) -> bool {
    let job = with_app(cx, window, app, |this, _, _| this.job.take());
    let Some(job) = job else {
        return false;
    };
    let report = job
        .rx
        .recv_timeout(Duration::from_secs(30))
        .expect("job finished");
    with_app(cx, window, app, |this, window, cx| {
        this.apply(report, window, cx)
    });
    true
}

fn read<R>(
    cx: &mut TestAppContext,
    app: &Entity<FileSecApp>,
    f: impl FnOnce(&FileSecApp) -> R,
) -> R {
    cx.update(|cx| f(app.read(cx)))
}

fn session<R>(
    cx: &mut TestAppContext,
    app: &Entity<FileSecApp>,
    f: impl FnOnce(&Session) -> R,
) -> R {
    read(cx, app, |a| match &a.state {
        State::Unlocked(s) => f(s),
        _ => panic!("not unlocked"),
    })
}

fn session_mut<R>(
    cx: &mut TestAppContext,
    window: AnyWindowHandle,
    app: &Entity<FileSecApp>,
    f: impl FnOnce(&mut Session) -> R,
) -> R {
    with_app(cx, window, app, |a, _, cx| {
        cx.notify();
        match &mut a.state {
            State::Unlocked(s) => f(s),
            _ => panic!("not unlocked"),
        }
    })
}

fn center_y(b: Bounds<Pixels>) -> f32 {
    f32::from(b.top() + b.bottom()) / 2.0
}

/// Every visible button lies inside the window horizontally.
fn assert_buttons_fit(window: &Window, width: f32) {
    for button in window.find_all_by_role(Role::Button) {
        if !button.visible() {
            continue;
        }
        let b = button.bounds();
        assert!(
            f32::from(b.left()) >= -0.5 && f32::from(b.right()) <= width + 0.5,
            "Button {:?} ({:?}) falls outside the window: {b:?}",
            button.label(),
            button.path().last()
        );
    }
}

/// A store with one vault holding `Documents/notes.txt` and `report.txt`,
/// opened in the browser.
fn vault_app(
    cx: &mut TestAppContext,
    dims: (f32, f32),
) -> (AnyWindowHandle, Entity<FileSecApp>, PathBuf, String) {
    let dir = temp_dir("ui-vault");
    let store = Arc::new(Store::at_with_secure_storage(&dir, None).unwrap());
    let mut s = test_session();
    let vault_id = new_vault_id().unwrap();
    let mut vault = Vault::new("Centering example", 0);
    vault
        .add_file("Documents/notes.txt", b"hello".to_vec(), None, None)
        .unwrap();
    vault
        .add_file("report.txt", b"report".to_vec(), None, None)
        .unwrap();
    store.save_vault(&s.identity, &vault_id, &vault).unwrap();
    let reader = store.open_vault(&s.identity, &vault_id).unwrap();
    s.registry.upsert(VaultMeta {
        id: vault_id.clone(),
        name: reader.name().into(),
        created_at: 0,
        modified_at: 0,
        file_count: reader.file_count() as u64,
        total_size: reader.total_size(),
    });
    store.save_registry(&s.identity, &s.registry).unwrap();
    s.open = Some(OpenVault {
        id: vault_id.clone(),
        reader,
    });
    let (window, app) = open(cx, dims, Some(store), State::Unlocked(Box::new(s)));
    (window, app, dir, vault_id)
}

fn plaintext_temp() -> PathBuf {
    let path = temp_dir("exit");
    std::fs::write(&path, vec![0xa5u8; 256 * 1024]).expect("write temp");
    path
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

#[gpui_kit::test]
fn screens_render_without_panic(cx: &mut TestAppContext) {
    setup(cx);
    let restore = FirstRun {
        error: None,
        restore: Some(RestoreForm {
            path: "/tmp/alice.fsecid".into(),
            error: Some("The backup passphrase is incorrect.".into()),
        }),
    };
    let unlock_all = Unlock {
        has_passkeys: true,
        has_saved: true,
        legacy_recovery: false,
        error: Some("That passphrase is incorrect.".into()),
    };
    let legacy = Unlock {
        legacy_recovery: true,
        ..Unlock::default()
    };
    let anchor = AnchorRecovery {
        reason: "anchor-recovery-required: test".into(),
        confirmed: true,
        error: Some("Enter your passphrase.".into()),
    };
    for state in [
        State::FirstRun(FirstRun::default()),
        State::FirstRun(restore),
        State::Unlock(Unlock::default()),
        State::Unlock(unlock_all),
        State::Unlock(legacy),
        State::Fatal("boom".into()),
        State::AnchorRecovery(anchor),
    ] {
        let (window, _) = open(cx, MIN, None, state);
        ui(cx, window, |window, _| assert_buttons_fit(window, MIN.0));
    }

    // Every session page, then every dialog over it.
    let (window, app) = open(cx, DEFAULT, None, State::Unlocked(Box::new(test_session())));
    #[allow(unused_mut)]
    let mut pages = vec![Nav::Vaults, Nav::Contacts, Nav::Identity, Nav::Settings];
    #[cfg(feature = "net")]
    pages.push(Nav::Transfer);
    for nav in pages {
        dispatch(cx, window, &app, Action::Nav(nav));
        ui(cx, window, |_, _| {});
    }
    // Settings again with the degraded-rollback banner and both disclosures.
    session_mut(cx, window, &app, |s| {
        s.rollback_warning = Some("Rollback protection is in degraded mode.".into());
        s.show_notices = true;
        s.show_fingerprint = true;
    });
    ui(cx, window, |_, _| {});
    dispatch(cx, window, &app, Action::Nav(Nav::Identity));
    ui(cx, window, |_, _| {});

    let bob = Identity::generate("Bob", 0).unwrap();
    session_mut(cx, window, &app, |s| {
        s.contacts.upsert(bob.public(), 0);
        s.registry.upsert(VaultMeta {
            id: "v".into(),
            name: "Vault".into(),
            created_at: 0,
            modified_at: 0,
            file_count: 1,
            total_size: 1,
        });
    });
    let bob_hex = hex(&bob.fingerprint());
    for action in [
        Action::BeginExportIdentity,
        Action::BeginAddPasskey,
        Action::BeginEnableAutoUnlock,
        Action::BeginVerify(bob_hex.clone()),
        Action::BeginExport("v".into()),
        Action::RequestDeleteVault("v".into()),
    ] {
        dispatch(cx, window, &app, action);
        ui(cx, window, |window, _| {
            assert_buttons_fit(window, DEFAULT.0)
        });
        session_mut(cx, window, &app, |s| {
            s.export_identity = None;
            s.add_passkey = None;
            s.auto_unlock_form = None;
            s.verify = None;
            s.export = None;
            s.delete_vault = None;
        });
    }
    // The export dialog with an unverified recipient ticked.
    dispatch(cx, window, &app, Action::BeginExport("v".into()));
    dispatch(cx, window, &app, Action::ToggleRecipient(bob_hex.clone()));
    #[cfg(feature = "pqc")]
    dispatch(cx, window, &app, Action::SetExportSuite(SuiteId::Hybrid));
    ui(cx, window, |_, _| {});
    dispatch(cx, window, &app, Action::CancelExport);
    // Import result and contact preview.
    session_mut(cx, window, &app, |s| {
        s.last_import = Some(ImportInfo {
            sender: bob.public(),
            sender_fpr_hex: bob_hex.clone(),
            sender_name: None,
            verified: false,
            vault_name: "Shared".into(),
            file_count: 2,
        });
    });
    ui(cx, window, |_, _| {});
    dispatch(cx, window, &app, Action::AddSenderToContacts);
    ui(cx, window, |_, _| {});
    dispatch(cx, window, &app, Action::CancelPreview);
    #[cfg(feature = "pqc")]
    {
        dispatch(cx, window, &app, Action::BeginMigrate);
        ui(cx, window, |_, _| {});
        dispatch(cx, window, &app, Action::CancelMigrate);
    }
}

#[gpui_kit::test]
fn browser_renders_populated_vault_without_panic(cx: &mut TestAppContext) {
    setup(cx);
    // A real on-disk vault so the browser's reader / row / breadcrumb /
    // selection paths run through real frames.
    let dir = temp_dir("browser-smoke");
    let store = Arc::new(Store::at(&dir).expect("store"));
    let id = Identity::generate("Tester", 0).expect("identity");
    let vid = new_vault_id().unwrap();
    store
        .save_vault(&id, &vid, &Vault::new("Demo", 0))
        .expect("save vault");
    let src = dir.join("src");
    std::fs::create_dir_all(&src).expect("src dir");
    std::fs::write(src.join("a.txt"), b"hello").expect("write a");
    std::fs::write(src.join("pic.png"), b"img").expect("write pic");
    let reader = store.open_vault(&id, &vid).expect("open");
    let added = vec![
        format::AddedFile {
            vault_path: "folder/a.txt".into(),
            source: src.join("a.txt"),
            mtime: None,
            mode: None,
        },
        format::AddedFile {
            vault_path: "pic.png".into(),
            source: src.join("pic.png"),
            mtime: None,
            mode: None,
        },
    ];
    store
        .append_files_to_vault(&id, &vid, &reader, &added, &["folder".to_string()])
        .expect("append");
    let reader = store.open_vault(&id, &vid).expect("reopen");
    let mut s = Session::new(
        Arc::new(id),
        ContactBook::default(),
        Registry::default(),
        Vec::new(),
        false,
        dir.display().to_string(),
        None,
    );
    s.open = Some(OpenVault {
        id: vid.clone(),
        reader,
    });
    let (window, app) = open(cx, MIN, Some(store.clone()), State::Unlocked(Box::new(s)));

    // Root view: a folder row + a (type-tinted) file row, breadcrumb, sort.
    ui(cx, window, |window, _| {
        assert!(window.find("row:folder").visible());
        assert!(window.find("row:pic.png").visible());
        assert_buttons_fit(window, MIN.0);
    });
    // Inside the folder: scoped view + deeper breadcrumb.
    dispatch(cx, window, &app, Action::EnterDir("folder".into()));
    ui(cx, window, |window, _| {
        assert!(window.find("row:folder/a.txt").visible());
        assert!(window.try_find("row:pic.png").is_none());
    });
    // A multi-selection including a folder, with every sort order.
    dispatch(cx, window, &app, Action::EnterDir(String::new()));
    session_mut(cx, window, &app, |s| {
        s.selected.insert("folder".into());
        s.selected.insert("pic.png".into());
        s.select_anchor = Some("folder".into());
    });
    for mode in SortMode::ALL {
        dispatch(cx, window, &app, Action::SetSort(mode));
        ui(cx, window, |window, _| assert_buttons_fit(window, MIN.0));
    }
    // The new-folder and new-file composers.
    dispatch(cx, window, &app, Action::ToggleNewFolder(true));
    ui(cx, window, |_, _| {});
    dispatch(cx, window, &app, Action::ToggleNewFile(true));
    ui(cx, window, |_, _| {});
    dispatch(cx, window, &app, Action::ToggleNewFile(false));
    // The quick editor modal (with unsaved changes).
    session_mut(cx, window, &app, |s| {
        s.text_editor = Some(TextEditor {
            path: "pic.png".into(),
            leaf: "pic.png".into(),
            original: Zeroizing::new("hello".into()),
            dirty: true,
        });
    });
    ui(cx, window, |window, _| {
        assert!(window.find("editor-save").visible());
    });
    dispatch(cx, window, &app, Action::CloseTextEditor);

    // Soft-delete a file, then drive the trash view, the rename composer, and
    // the move dialog through real frames.
    let identity = session(cx, &app, |s| Arc::clone(&s.identity));
    let r = store.open_vault(&identity, &vid).expect("reopen2");
    let dest = trash_dest(123, "abcd", "pic.png");
    store
        .rename_in_vault(&identity, &vid, &r, &[("pic.png".to_string(), dest)])
        .expect("trash a file");
    let reader = store.open_vault(&identity, &vid).expect("reopen3");
    session_mut(cx, window, &app, |s| {
        s.open = Some(OpenVault {
            id: vid.clone(),
            reader,
        });
    });
    dispatch(cx, window, &app, Action::ShowTrash(true));
    ui(cx, window, |window, _| {
        assert!(window.find("empty-trash").visible());
        assert_buttons_fit(window, MIN.0);
    });
    dispatch(cx, window, &app, Action::PromptEmptyTrash(true));
    ui(cx, window, |window, _| {
        assert!(window.find("confirm-empty-trash").visible());
        assert_buttons_fit(window, MIN.0);
    });
    dispatch(cx, window, &app, Action::ShowTrash(false));
    dispatch(cx, window, &app, Action::BeginRename("folder/a.txt".into()));
    ui(cx, window, |window, cx| {
        assert!(window.find("confirm-rename").visible());
        let _ = cx;
    });
    assert_eq!(
        text_of(cx, &app, |f| f.rename.clone()),
        "a.txt",
        "the rename composer is pre-filled with the current name"
    );
    dispatch(cx, window, &app, Action::CancelRename);
    dispatch(
        cx,
        window,
        &app,
        Action::BeginMove(vec!["folder/a.txt".into()]),
    );
    ui(cx, window, |window, _| {
        assert!(window.find("move-here").visible());
    });
    dispatch(cx, window, &app, Action::CancelMove);

    // Empty-vault state.
    let empty_vid = new_vault_id().unwrap();
    store
        .save_vault(&identity, &empty_vid, &Vault::new("Empty", 0))
        .expect("save empty");
    let empty_reader = store.open_vault(&identity, &empty_vid).expect("open empty");
    session_mut(cx, window, &app, |s| {
        s.open = Some(OpenVault {
            id: empty_vid,
            reader: empty_reader,
        });
    });
    ui(cx, window, |window, _| {
        assert!(window.find("add-files-empty").visible());
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// A plain field's text.
fn text_of(
    cx: &mut TestAppContext,
    app: &Entity<FileSecApp>,
    field: impl FnOnce(&Fields) -> Entity<gpui_kit::component::input::InputState>,
) -> String {
    cx.update(|cx| {
        let entity = field(&app.read(cx).fields);
        entity.read(cx).value().to_string()
    })
}

/// A secret field's text.
fn secret_of(
    cx: &mut TestAppContext,
    app: &Entity<FileSecApp>,
    field: impl FnOnce(&Fields) -> Entity<crate::secret_input::SecretInput>,
) -> String {
    cx.update(|cx| {
        let entity = field(&app.read(cx).fields);
        entity.read(cx).value().to_string()
    })
}

/// Fill a secret field programmatically (as typing would).
fn set_secret(
    cx: &mut TestAppContext,
    app: &Entity<FileSecApp>,
    value: &str,
    field: impl FnOnce(&Fields) -> Entity<crate::secret_input::SecretInput>,
) {
    cx.update(|cx| {
        let entity = field(&app.read(cx).fields);
        entity.update(cx, |s, cx| s.set_value(value, cx));
    });
}

// ---------------------------------------------------------------------------
// Behaviour through real pointer and keyboard input
// ---------------------------------------------------------------------------

#[gpui_kit::test]
fn selection_keeps_rows_stationary_and_double_click_opens_the_same_folder(cx: &mut TestAppContext) {
    setup(cx);
    let (window, app, dir, _) = vault_app(cx, MIN);
    let (before, file_before) = ui(cx, window, |window, _| {
        let row = window.find("row:Documents").bounds();
        let name = window.find("row-name:Documents").bounds();
        let detail = window.find("row-detail:Documents").bounds();
        // The row element includes the 2 px gap below it.
        let row_center = (f32::from(row.top()) + f32::from(row.bottom()) - 2.0) / 2.0;
        let text_center = (f32::from(name.top()) + f32::from(detail.bottom())) / 2.0;
        assert!(
            (text_center - row_center).abs() <= 1.0,
            "File names and details must be centered within their row: {text_center} vs {row_center}"
        );
        (row, window.find("row:report.txt").bounds())
    });

    ui(cx, window, |window, cx| window.click("row:Documents", cx));
    assert!(session(cx, &app, |s| s.selected.contains("Documents")));
    ui(cx, window, |window, _| {
        assert_eq!(before, window.find("row:Documents").bounds());
        assert_eq!(file_before, window.find("row:report.txt").bounds());
        assert_buttons_fit(window, MIN.0);
    });

    with_app(cx, window, &app, |a, _, _| {
        a.set_toast("Saved successfully.", false)
    });
    ui(cx, window, |window, _| {
        let notification = window.find("toast-dismiss").bounds();
        let extract = window.find("extract-selection").bounds();
        assert!(
            f32::from(notification.bottom()) + 10.0 <= f32::from(extract.top()),
            "Notifications must not cover selection actions: {notification:?} vs {extract:?}"
        );
    });
    with_app(cx, window, &app, |a, _, _| a.toast = None);

    dispatch(cx, window, &app, Action::ClearSelection);
    ui(cx, window, |window, cx| {
        assert_eq!(before, window.find("row:Documents").bounds());
        window.double_click("row:Documents", cx);
    });
    assert_eq!(
        session(cx, &app, |s| s.current_dir.clone()),
        "Documents",
        "The second click must still hit the original folder"
    );
    drop(app);
    let _ = std::fs::remove_dir_all(dir);
}

#[gpui_kit::test]
fn modifier_clicks_toggle_and_extend_the_selection(cx: &mut TestAppContext) {
    setup(cx);
    let (window, app, dir, _) = vault_app(cx, DEFAULT);
    let toggle = if cfg!(target_os = "macos") {
        gpui_kit::Modifiers::command()
    } else {
        gpui_kit::Modifiers::control()
    };
    ui(cx, window, |window, cx| {
        window.click("row:Documents", cx);
        window.click_with_modifiers("row:report.txt", toggle, cx);
    });
    assert_eq!(session(cx, &app, |s| s.selected.len()), 2);
    ui(cx, window, |window, cx| {
        window.click_with_modifiers("row:Documents", toggle, cx);
    });
    assert_eq!(
        session(cx, &app, |s| s.selected.iter().cloned().collect::<Vec<_>>()),
        vec!["report.txt".to_string()]
    );
    // The ⌘/Ctrl-click above moved the anchor to Documents: shift-clicking
    // report.txt selects the range between them.
    ui(cx, window, |window, cx| {
        window.click_with_modifiers("row:report.txt", gpui_kit::Modifiers::shift(), cx);
    });
    assert_eq!(
        session(cx, &app, |s| s.selected.len()),
        2,
        "shift selects the range"
    );
    // Clicking the blank space below the rows clears the selection.
    let blank = ui(cx, window, |window, _| {
        let area = window.find("row:report.txt").bounds();
        point(area.center().x, area.bottom() + px(60.0))
    });
    ui(cx, window, |window, cx| {
        window.pointer_move(blank, None, cx);
        window.pointer_down(blank, MouseButton::Left, cx);
        window.pointer_up(blank, MouseButton::Left, cx);
    });
    assert!(session(cx, &app, |s| s.selected.is_empty()));
    let _ = std::fs::remove_dir_all(dir);
}

#[gpui_kit::test]
fn browser_keyboard_shortcuts_and_search(cx: &mut TestAppContext) {
    setup(cx);
    let (window, app, dir, _) = vault_app(cx, MIN);
    ui(cx, window, |window, cx| window.click("row:report.txt", cx));
    // ⌘/Ctrl-A selects every item in the view.
    let select_all = if cfg!(target_os = "macos") {
        "cmd-a"
    } else {
        "ctrl-a"
    };
    ui(cx, window, |window, cx| window.press(select_all, cx));
    assert_eq!(session(cx, &app, |s| s.selected.len()), 2);
    // Escape clears the selection first...
    ui(cx, window, |window, cx| window.press("escape", cx));
    assert!(session(cx, &app, |s| s.selected.is_empty()));
    // ...and ⌘/Ctrl-F jumps to the search field, where typing searches the
    // whole vault and starts from a clean selection.
    ui(cx, window, |window, cx| window.click("row:report.txt", cx));
    let find = if cfg!(target_os = "macos") {
        "cmd-f"
    } else {
        "ctrl-f"
    };
    ui(cx, window, |window, cx| {
        window.press(find, cx);
        window.input("notes", cx);
    });
    assert_eq!(text_of(cx, &app, |f| f.file_search.clone()), "notes");
    assert!(
        session(cx, &app, |s| s.selected.is_empty()),
        "A new search must clear the previous selection"
    );
    ui(cx, window, |window, _| {
        assert!(window.find("row:Documents/notes.txt").visible());
        assert!(window.try_find("row:report.txt").is_none());
    });
    // Escape with an empty selection clears the search.
    dispatch(cx, window, &app, Action::ClearFileSearch);
    assert!(text_of(cx, &app, |f| f.file_search.clone()).is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[gpui_kit::test]
fn large_browser_only_renders_the_visible_rows(cx: &mut TestAppContext) {
    setup(cx);
    let dir = temp_dir("ui-large");
    let store = Arc::new(Store::at_with_secure_storage(&dir, None).unwrap());
    let mut s = test_session();
    let vault_id = new_vault_id().unwrap();
    let mut vault = Vault::new("Large", 0);
    for i in 0..1_500 {
        vault
            .add_file(&format!("file-{i:05}.txt"), Vec::new(), None, None)
            .unwrap();
    }
    store.save_vault(&s.identity, &vault_id, &vault).unwrap();
    let reader = store.open_vault(&s.identity, &vault_id).unwrap();
    s.open = Some(OpenVault {
        id: vault_id,
        reader,
    });
    let (window, _app) = open(cx, MIN, Some(store), State::Unlocked(Box::new(s)));
    ui(cx, window, |window, _| {
        let rows = window
            .elements()
            .into_iter()
            .filter(
                |e| matches!(e.path().last(), Some(ElementId::Name(n)) if n.starts_with("row:")),
            )
            .count();
        assert!(rows > 0, "the first rows are rendered");
        assert!(rows < 60, "offscreen rows were rendered: {rows}");
    });
    let _ = std::fs::remove_dir_all(dir);
}

#[gpui_kit::test]
fn vault_deletion_requires_the_dialogs_explicit_confirmation(cx: &mut TestAppContext) {
    setup(cx);
    let (window, app, dir, vault_id) = vault_app(cx, MIN);
    session_mut(cx, window, &app, |s| s.open = None);
    dispatch(cx, window, &app, Action::ConfirmDeleteVault);
    assert!(
        read(cx, &app, |a| a.job.is_none()),
        "A confirmation without a pending dialog must do nothing"
    );
    dispatch(
        cx,
        window,
        &app,
        Action::RequestDeleteVault(vault_id.clone()),
    );
    assert!(
        read(cx, &app, |a| a.job.is_none()),
        "Requesting deletion must not start disk work"
    );
    // The safe choice has the keyboard.
    ui(cx, window, |window, _| {
        assert_eq!(window.find("delete-vault-cancel").focused(), Some(true));
    });
    ui(cx, window, |window, cx| window.press("escape", cx));
    assert!(session(cx, &app, |s| s.delete_vault.is_none()
        && s.registry.vaults.len() == 1));
    assert!(read(cx, &app, |a| a.job.is_none()));

    // Clicking outside the dialog cancels.
    dispatch(
        cx,
        window,
        &app,
        Action::RequestDeleteVault(vault_id.clone()),
    );
    let outside = point(px(710.0), px(510.0));
    ui(cx, window, |window, cx| {
        window.pointer_move(outside, None, cx);
        window.pointer_down(outside, MouseButton::Left, cx);
        window.pointer_up(outside, MouseButton::Left, cx);
    });
    assert!(session(cx, &app, |s| s.delete_vault.is_none()
        && s.registry.vaults.len() == 1));
    assert!(
        read(cx, &app, |a| a.job.is_none()),
        "Clicking outside the dialog must cancel deletion"
    );

    // Only the explicit confirmation deletes.
    dispatch(
        cx,
        window,
        &app,
        Action::RequestDeleteVault(vault_id.clone()),
    );
    ui(cx, window, |window, cx| {
        window.click("delete-vault-confirm", cx)
    });
    assert!(
        finish_job(cx, window, &app),
        "Explicit confirmation starts deletion"
    );
    assert!(session(cx, &app, |s| s.registry.vaults.is_empty()
        && s.delete_vault.is_none()));
    let (store, identity) = read(cx, &app, |a| {
        (a.store.clone().unwrap(), a.ident_arc().unwrap())
    });
    assert!(store.open_vault(&identity, &vault_id).is_err());
    let _ = std::fs::remove_dir_all(dir);
}

#[gpui_kit::test]
fn vault_text_and_notifications_are_vertically_centered_with_their_controls(
    cx: &mut TestAppContext,
) {
    setup(cx);
    let (window, app, dir, vault_id) = vault_app(cx, DEFAULT);
    session_mut(cx, window, &app, |s| s.open = None);
    ui(cx, window, |window, _| {
        let id = |name: &str| ElementId::Name(format!("{name}-{vault_id}").into());
        let title = window.find(id("vault-name")).bounds();
        let details = window.find(id("vault-detail")).bounds();
        let open = window.find(id("open-vault")).bounds();
        let text_center = (f32::from(title.top()) + f32::from(details.bottom())) / 2.0;
        assert!(
            (text_center - center_y(open)).abs() <= 1.0,
            "Text block and buttons must share a center: text={text_center}, button={open:?}"
        );
    });
    let msg = "A notification with enough text to wrap onto more than one line and keep both \
               icons centered.";
    with_app(cx, window, &app, |a, _, _| a.set_toast(msg, false));
    ui(cx, window, |window, _| {
        let text = window.find("toast-text").bounds();
        let close = window.find("toast-dismiss").bounds();
        assert!(
            (center_y(text) - center_y(close)).abs() <= 1.0,
            "Notification text and close button must share a center: {text:?}, {close:?}"
        );
    });
    let _ = std::fs::remove_dir_all(dir);
}

#[gpui_kit::test]
fn long_names_keep_page_actions_inside_the_minimum_window(cx: &mut TestAppContext) {
    setup(cx);
    let mut s = test_session();
    s.registry.vaults.push(VaultMeta {
        id: "sample".into(),
        name: "A very long vault name ".repeat(10),
        created_at: 0,
        modified_at: 0,
        file_count: 12,
        total_size: 1024,
    });
    s.contacts.upsert(
        Identity::generate("Long contact name ".repeat(10), 0)
            .unwrap()
            .public(),
        0,
    );
    let (window, app) = open(cx, MIN, None, State::Unlocked(Box::new(s)));
    for nav in [Nav::Vaults, Nav::Contacts, Nav::Identity, Nav::Settings] {
        dispatch(cx, window, &app, Action::Nav(nav));
        ui(cx, window, |window, _| assert_buttons_fit(window, MIN.0));
    }
    dispatch(cx, window, &app, Action::Nav(Nav::Vaults));
    dispatch(cx, window, &app, Action::ToggleNewVault(true));
    ui(cx, window, |window, _| assert_buttons_fit(window, MIN.0));
}

#[gpui_kit::test]
fn an_expiring_toast_does_not_swallow_navigation_and_errors_stay_visible(cx: &mut TestAppContext) {
    setup(cx);
    let (window, app) = open(cx, MIN, None, State::Unlocked(Box::new(test_session())));
    with_app(cx, window, &app, |a, _, cx| {
        a.set_toast("Saved", false);
        a.arm_toast_timer(cx);
    });
    cx.executor().advance_clock(Duration::from_millis(5_800));
    ui(cx, window, |window, cx| window.click("nav-contacts", cx));
    cx.executor().advance_clock(Duration::from_millis(400));
    cx.run_until_parked();
    assert!(session(cx, &app, |s| s.nav == Nav::Contacts));
    assert!(
        read(cx, &app, |a| a.toast.is_none()),
        "success toasts expire"
    );

    with_app(cx, window, &app, |a, _, cx| {
        a.set_toast("Action failed. Please try again.", true);
        a.arm_toast_timer(cx);
    });
    cx.executor().advance_clock(Duration::from_secs(60));
    cx.run_until_parked();
    assert!(
        read(cx, &app, |a| a.toast.is_some()),
        "Errors need to remain available to read and dismiss"
    );
    ui(cx, window, |window, cx| window.click("toast-dismiss", cx));
    assert!(read(cx, &app, |a| a.toast.is_none()));
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

#[gpui_kit::test]
fn secrets_are_wiped_when_their_form_closes(cx: &mut TestAppContext) {
    setup(cx);
    let (window, app) = open(cx, DEFAULT, None, State::Unlocked(Box::new(test_session())));
    dispatch(cx, window, &app, Action::BeginAddPasskey);
    set_secret(cx, &app, "a passphrase to wipe", |f| f.passkey_pass.clone());
    set_secret(cx, &app, "123456", |f| f.passkey_pin.clone());
    dispatch(cx, window, &app, Action::CancelAddPasskey);
    assert!(secret_of(cx, &app, |f| f.passkey_pass.clone()).is_empty());
    assert!(secret_of(cx, &app, |f| f.passkey_pin.clone()).is_empty());

    dispatch(cx, window, &app, Action::BeginExportIdentity);
    set_secret(cx, &app, "backup passphrase one", |f| {
        f.export_id_pass.clone()
    });
    set_secret(cx, &app, "backup passphrase two", |f| {
        f.export_id_pass2.clone()
    });
    ui(cx, window, |window, cx| window.press("escape", cx));
    assert!(secret_of(cx, &app, |f| f.export_id_pass.clone()).is_empty());
    assert!(secret_of(cx, &app, |f| f.export_id_pass2.clone()).is_empty());

    // Locking wipes everything typed before unlock too.
    set_secret(cx, &app, "typed early", |f| f.unlock_pass.clone());
    dispatch(cx, window, &app, Action::Lock);
    // On the unlock screen the passphrase field stays usable...
    set_secret(cx, &app, "unlock me", |f| f.unlock_pass.clone());
    with_app(cx, window, &app, |a, window, cx| a.scrub_fields(window, cx));
    assert_eq!(secret_of(cx, &app, |f| f.unlock_pass.clone()), "unlock me");
    // ...and is wiped the moment the session opens.
    let report = JobReport::ok(
        Outcome::Unlocked(Box::new(SessionInit {
            identity: Identity::generate("Tester", 0).unwrap(),
            contacts: ContactBook::default(),
            registry: Registry::default(),
            passkeys: Vec::new(),
            auto_unlock: false,
            data_dir: String::new(),
            rollback_warning: None,
        })),
        "",
    );
    with_app(cx, window, &app, |a, window, cx| {
        a.apply(report, window, cx)
    });
    assert!(secret_of(cx, &app, |f| f.unlock_pass.clone()).is_empty());
}

#[gpui_kit::test]
fn unlock_takes_the_passphrase_out_of_the_field(cx: &mut TestAppContext) {
    setup(cx);
    let dir = temp_dir("ui-unlock");
    let store = Arc::new(Store::at_with_secure_storage(&dir, None).unwrap());
    let (window, app) = open(cx, MIN, Some(store), State::Unlock(Unlock::default()));
    ui(cx, window, |window, _| {
        assert_eq!(
            window.find("unlock").disabled(),
            Some(true),
            "empty passphrase"
        );
    });
    set_secret(cx, &app, "not the passphrase", |f| f.unlock_pass.clone());
    ui(cx, window, |window, cx| window.click("unlock", cx));
    // The field is emptied as soon as the worker takes the passphrase.
    assert!(secret_of(cx, &app, |f| f.unlock_pass.clone()).is_empty());
    assert!(finish_job(cx, window, &app));
    assert!(read(
        cx,
        &app,
        |a| matches!(&a.state, State::Unlock(u) if u.error.is_some())
    ));
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------
// Appearance
// ---------------------------------------------------------------------------

/// Every [`ThemeChoice`] must survive the round trip through the theme state.
///
/// The regression guard for the sidebar gear change: "follow the system" now
/// exists solely as a `ThemeChoice` variant. If the mapping ever drops
/// `System`, this fails rather than silently stranding the user on light or
/// dark forever.
#[gpui_kit::test]
fn every_theme_choice_round_trips_through_the_context(cx: &mut TestAppContext) {
    setup(cx);
    for choice in ThemeChoice::ALL {
        cx.update(|cx| theme::apply_choice(choice, cx));
        assert_eq!(
            cx.update(|cx| theme::current_choice(cx)),
            choice,
            "{choice:?} did not round-trip"
        );
    }
    cx.update(|cx| {
        theme::apply_choice(ThemeChoice::Dark, cx);
        assert!(theme::is_dark(cx));
        assert!(gpui_kit::component::theme::Theme::global(cx).is_dark());
        theme::apply_choice(ThemeChoice::Light, cx);
        assert!(!theme::is_dark(cx));
        assert!(!gpui_kit::component::theme::Theme::global(cx).is_dark());
    });
}

/// A saved theme must reach the *pre-unlock* screens: `.prefs` is unencrypted
/// precisely because the unlock screen is painted before any identity exists.
#[gpui_kit::test]
fn a_saved_theme_reaches_the_unlock_screen(cx: &mut TestAppContext) {
    setup(cx);
    let dir = temp_dir("theme");
    let store = Store::at(&dir).expect("store");
    store
        .save_prefs(&crate::prefs::Prefs {
            theme: ThemeChoice::Light,
            ..crate::prefs::Prefs::default()
        })
        .expect("save prefs");
    cx.update(|cx| theme::apply_choice(ThemeChoice::Dark, cx));
    let store = Arc::new(Store::at(&dir).expect("store"));
    let (window, app) = open(cx, MIN, Some(store), State::Unlock(Unlock::default()));
    with_app(cx, window, &app, |a, _, cx| a.apply_saved_theme(cx));
    assert_eq!(
        cx.update(|cx| theme::current_choice(cx)),
        ThemeChoice::Light
    );
    ui(cx, window, |_, cx| assert!(!theme::is_dark(cx)));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The whole user-visible loop: picking a theme changes the appearance *and*
/// writes it to disk, so the next launch honours it.
#[gpui_kit::test]
fn choosing_a_theme_applies_it_and_persists_it(cx: &mut TestAppContext) {
    setup(cx);
    let dir = temp_dir("settheme");
    let store = Arc::new(Store::at(&dir).expect("store"));
    let (window, app) = open(
        cx,
        MIN,
        Some(store),
        State::Unlocked(Box::new(test_session())),
    );
    dispatch(cx, window, &app, Action::Nav(Nav::Settings));
    for (id, choice) in [
        ("theme-light", ThemeChoice::Light),
        ("theme-dark", ThemeChoice::Dark),
        ("theme-system", ThemeChoice::System),
    ] {
        // Through the real Settings chip, not just the action.
        ui(cx, window, |window, cx| window.click(id, cx));
        assert_eq!(
            cx.update(|cx| theme::current_choice(cx)),
            choice,
            "not applied: {choice:?}"
        );
        assert_eq!(
            Store::at(&dir).expect("store").load_prefs().theme,
            choice,
            "not persisted: {choice:?}"
        );
    }
    // No store (the fatal screen): the appearance still changes, and nothing
    // panics trying to save.
    with_app(cx, window, &app, |a, _, _| a.store = None);
    dispatch(cx, window, &app, Action::SetTheme(ThemeChoice::Dark));
    assert_eq!(cx.update(|cx| theme::current_choice(cx)), ThemeChoice::Dark);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Shutdown and plaintext temps
// ---------------------------------------------------------------------------

/// Quitting must not shred plaintext on the UI thread — that is what made the
/// app look frozen. The first close request hands every temp to the background
/// wiper and *refuses* the close, so the UI keeps painting; once the queue
/// drains the close may go through.
#[gpui_kit::test]
fn close_request_is_held_while_temps_are_shredded(cx: &mut TestAppContext) {
    setup(cx);
    let (window, app) = open(cx, MIN, None, State::Unlocked(Box::new(test_session())));
    let temp = plaintext_temp();
    session_mut(cx, window, &app, |s| {
        s.views.push(ActiveView {
            leaf: "Q4 salary report.pdf".to_string(),
            temp_path: temp.clone(),
        });
    });
    let allowed = with_app(cx, window, &app, |a, window, cx| {
        a.request_close(window, cx)
    });
    // The 256 KiB temp is normally still queued at this point, so the close is
    // refused and the shutdown overlay covers the window. (If the wiper won
    // the race, the close correctly goes straight through.)
    if !allowed {
        assert!(read(cx, &app, |a| a.exit_wipe.is_some()));
        ui(cx, window, |window, _| {
            assert!(window.find("busy").visible(), "the shutdown overlay is up");
        });
    }
    // The banner clears at once even though the shred may still be running.
    assert!(session(cx, &app, |s| s.views.is_empty()));
    // Once the queue drains, the close is allowed.
    with_app(cx, window, &app, |a, _, _| {
        a.wiper.finish(Duration::from_secs(20))
    });
    assert!(!temp.exists(), "temp survived the wipe");
    assert!(read(cx, &app, |a| a.exit_wipe_finished()));
}

/// With nothing left to shred — the common case — quitting is not delayed.
#[gpui_kit::test]
fn close_request_passes_straight_through_when_nothing_is_queued(cx: &mut TestAppContext) {
    setup(cx);
    let (window, app) = open(cx, MIN, None, State::Unlocked(Box::new(test_session())));
    let held = with_app(cx, window, &app, |a, window, cx| {
        a.request_close(window, cx)
    });
    assert!(held, "close must go through when there is nothing to wipe");
    assert!(read(cx, &app, |a| a.exit_wipe.is_none()));
}

/// A check-in streams the check-out temp back into the vault. Quitting mid
/// check-in must not hand that file to the shredder, or the worker would read
/// random bytes over the user's edit. Views are still queued; the check-out
/// temp is left for the next unlock's sweep.
#[gpui_kit::test]
fn quitting_mid_job_does_not_shred_the_file_the_job_is_reading(cx: &mut TestAppContext) {
    setup(cx);
    let (window, app) = open(cx, MIN, None, State::Unlocked(Box::new(test_session())));
    let checkout_temp = plaintext_temp();
    let view_temp = plaintext_temp();
    let (_tx, rx) = mpsc::channel();
    with_app(cx, window, &app, |a, _, _| {
        a.job = Some(Job {
            rx,
            label: "Checking in…".to_string(),
        });
        if let State::Unlocked(s) = &mut a.state {
            s.checkout = Some(Checkout {
                vault_id: "v".to_string(),
                entry_path: "notes.txt".to_string(),
                leaf: "notes.txt".to_string(),
                temp_path: checkout_temp.clone(),
                orig_blake3: [0u8; 32],
                mode: None,
            });
            s.views.push(ActiveView {
                leaf: "secret.pdf".to_string(),
                temp_path: view_temp.clone(),
            });
        }
        a.wipe_all_temps(true);
        a.wiper.finish(Duration::from_secs(20));
    });
    assert!(
        checkout_temp.exists(),
        "the running job's file must not be shredded under it"
    );
    assert!(
        session(cx, &app, |s| s.checkout.is_some()),
        "the check-out must stay registered so the job can finish"
    );
    assert!(!view_temp.exists(), "view temps are still wiped");
    let _ = std::fs::remove_file(&checkout_temp);
}

/// Leaving the vault must return immediately and clear the banner, handing the
/// shred to the background wiper rather than blocking the UI on it.
#[gpui_kit::test]
fn leaving_the_vault_queues_view_temps_instead_of_blocking(cx: &mut TestAppContext) {
    setup(cx);
    let (window, app) = open(cx, MIN, None, State::Unlocked(Box::new(test_session())));
    let temps: Vec<PathBuf> = (0..3).map(|_| plaintext_temp()).collect();
    session_mut(cx, window, &app, |s| {
        for t in &temps {
            s.views.push(ActiveView {
                leaf: "secret.pdf".to_string(),
                temp_path: t.clone(),
            });
        }
    });
    dispatch(cx, window, &app, Action::CloseVault);
    assert!(session(cx, &app, |s| s.views.is_empty()));
    with_app(cx, window, &app, |a, _, _| {
        a.wiper.finish(Duration::from_secs(20))
    });
    for t in &temps {
        assert!(!t.exists(), "{} survived the wipe", t.display());
    }
}

// ---------------------------------------------------------------------------
// Pure policy checks (no window)
// ---------------------------------------------------------------------------

#[test]
fn passphrase_policy_rejects_short_and_weak_inputs() {
    assert_eq!(
        passphrase_policy_error("short").unwrap(),
        format!("Passphrase must be at least {MIN_PASSPHRASE_CHARS} characters.")
    );
    assert_eq!(
        passphrase_policy_error("password1234").unwrap(),
        PASSPHRASE_STRENGTH_MESSAGE
    );
    assert_eq!(
        passphrase_policy_error("aaaaaaaaaaaaaaaa").unwrap(),
        PASSPHRASE_STRENGTH_MESSAGE
    );
    assert_eq!(
        passphrase_policy_error("verylongbutonlylowercase").unwrap(),
        PASSPHRASE_STRENGTH_MESSAGE
    );
}

#[test]
fn passphrase_policy_accepts_strong_local_passphrases() {
    assert!(passphrase_policy_error("correct horse battery staple").is_none());
    assert!(passphrase_policy_error("LongEnough123!").is_none());
}

/// The security-key card must describe an *alternative* unlock method, not a
/// second factor. (F04)
#[test]
fn security_key_wording_says_alternative_not_two_factor() {
    let d = PASSKEY_ALT_UNLOCK_DESC.to_lowercase();
    assert!(
        d.contains("alternative"),
        "must call it an alternative unlock"
    );
    assert!(
        d.contains("not a second factor"),
        "must explicitly disclaim two-factor framing"
    );
    assert!(
        !d.contains("in addition to"),
        "must not imply layering on the passphrase"
    );
    assert!(
        !d.contains("two-factor") && !d.contains("two factor"),
        "must not call itself two-factor authentication"
    );
}

/// FS-18: the embedded assets' license texts are compiled in and shown.
#[test]
fn embedded_asset_notices_carry_the_license_texts() {
    let all: String = theme::EMBEDDED_ASSET_NOTICES
        .iter()
        .map(|(_, text)| *text)
        .collect();
    assert!(all.contains("SIL OPEN FONT LICENSE Version 1.1"));
    assert!(all.contains("Lucide Icons"));
    assert!(all.contains("ISC License"));
    assert!(all.contains("Permission is hereby granted"));
}

/// Audit item: an unverified recipient needs an explicit per-export
/// confirmation of that exact key; a warning alone is not consent.
#[test]
fn unverified_recipients_need_explicit_per_export_confirmation() {
    let bob = Identity::generate("Bob", 0).unwrap();
    let carol = Identity::generate("Carol", 0).unwrap();
    let mut contacts = ContactBook::default();
    contacts.upsert(bob.public(), 0);
    contacts.upsert(carol.public(), 0);
    contacts.set_trust(&carol.fingerprint(), Trust::Verified, 0);
    let mut form = ExportForm {
        vault_id: "v".into(),
        selected: [hex(&bob.fingerprint()), hex(&carol.fingerprint())]
            .into_iter()
            .collect(),
        confirmed_unverified: HashSet::new(),
        include_self: false,
        suite: SuiteId::default(),
    };
    assert_eq!(
        unconfirmed_unverified(&form, &contacts),
        vec!["Bob".to_string()]
    );
    form.confirmed_unverified.insert(hex(&bob.fingerprint()));
    assert!(unconfirmed_unverified(&form, &contacts).is_empty());
    // Confirming never changes trust.
    assert_eq!(
        contacts.find(&bob.fingerprint()).unwrap().trust,
        Trust::Unverified
    );
}

/// Auto-unlock's device-binding advisory is shown exactly when storage is
/// available but not device-bound. (F09)
#[test]
fn device_binding_warning_matches_platform_support() {
    let warning = crate::autounlock::device_binding_warning();
    if crate::autounlock::SUPPORTED && !crate::autounlock::DEVICE_BOUND {
        assert!(warning.is_some(), "non-device-bound storage must warn");
    } else {
        assert!(warning.is_none(), "device-bound/unsupported must not warn");
    }
}

#[test]
fn bounded_identity_import_reads_reject_oversized_files() {
    let dir = temp_dir("gui-bounds");
    std::fs::create_dir_all(&dir).unwrap();
    let pubkey = dir.join("oversized.fsecpub");
    std::fs::File::create(&pubkey)
        .unwrap()
        .set_len(MAX_PUBLIC_IDENTITY_FILE_LEN + 1)
        .unwrap();
    assert!(read_bounded_file(
        &pubkey,
        MAX_PUBLIC_IDENTITY_FILE_LEN,
        "FileSec public key file"
    )
    .is_err());
    let backup = dir.join("oversized.fsecid");
    std::fs::File::create(&backup)
        .unwrap()
        .set_len(MAX_IDENTITY_BACKUP_FILE_LEN + 1)
        .unwrap();
    assert!(read_bounded_text_file(
        &backup,
        MAX_IDENTITY_BACKUP_FILE_LEN,
        "FileSec identity backup"
    )
    .is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The About card must not claim a feature that is not compiled in.
#[test]
fn compiled_features_match_the_cfg_flags() {
    let f = compiled_features();
    assert_eq!(f.contains(&"pqc"), cfg!(feature = "pqc"));
    assert_eq!(f.contains(&"net"), cfg!(feature = "net"));
    assert_eq!(f.contains(&"keyring"), cfg!(feature = "keyring"));
    assert_eq!(f.contains(&"passkey"), cfg!(feature = "passkey"));
    let line = build_info_line();
    assert!(line.contains(env!("CARGO_PKG_VERSION")), "{line}");
    assert!(line.contains(env!("FILESEC_TARGET")), "{line}");
}

/// O-02: the browser model and rows are built once per committed vault
/// revision and reused across renders; a commit (or switching folder, search,
/// or sort) invalidates exactly what depends on it.
#[test]
fn browser_model_is_cached_per_revision() {
    let dir = temp_dir("model-cache");
    let store = Store::at_with_secure_storage(&dir, None).expect("store");
    let mut s = test_session();
    let vid = new_vault_id().unwrap();
    let mut vault = Vault::new("Docs", 0);
    vault.add_file("a.txt", b"a".to_vec(), None, None).unwrap();
    store
        .save_vault(s.identity.as_ref(), &vid, &vault)
        .expect("save");
    let reader = store.open_vault(s.identity.as_ref(), &vid).expect("open");
    s.open = Some(OpenVault {
        id: vid.clone(),
        reader,
    });
    let first = s.browser_model().unwrap();
    let again = s.browser_model().unwrap();
    assert!(
        Arc::ptr_eq(&first, &again),
        "same revision reuses the model"
    );
    let rows = s.visible_rows(&first, "", "");
    assert!(Arc::ptr_eq(&rows, &s.visible_rows(&first, "", "")));
    assert!(!Arc::ptr_eq(&rows, &s.visible_rows(&first, "", "a")));
    let reader = s.open.as_ref().unwrap().reader.clone();
    store
        .put_bytes_in_vault(s.identity.as_ref(), &vid, &reader, "b.txt", b"b", None)
        .expect("mutate");
    s.open = Some(OpenVault {
        id: vid.clone(),
        reader: store.open_vault(s.identity.as_ref(), &vid).expect("reopen"),
    });
    let rebuilt = s.browser_model().unwrap();
    assert!(
        !Arc::ptr_eq(&first, &rebuilt),
        "a commit rebuilds the model"
    );
    assert_eq!(rebuilt.entries.len(), 2);
    assert_eq!(s.visible_rows(&rebuilt, "", "").len(), 2);
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}
