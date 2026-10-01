// Structured fuzzing of v2 vault mutations and their failure paths.
//
// The input is decoded into a sequence of puts, mkdirs, removes, renames, and
// small batches over a tiny name space (including nested, trashed, aliasing,
// and deceptive names). After every operation — whether it succeeded or was
// refused — the vault reopened from disk must list exactly the files of a
// model updated only on success, with their exact content: a refused
// operation changes nothing, and a committed one persists completely.
#![no_main]

use std::collections::BTreeMap;
use std::sync::OnceLock;

use filesec_core::format_v2::VaultReaderV2;
use filesec_core::identity::Identity;
use filesec_core::manifest::EntryKind;
use filesec_core::SuiteId;
use libfuzzer_sys::fuzz_target;

const NAMES: &[&str] = &[
    "a", "b", "a/b", "a/c", "d", "d/e", "A", "a/b/c", ".trash/x", "a\u{202e}txt.exe",
];

fn identity() -> &'static Identity {
    static ID: OnceLock<Identity> = OnceLock::new();
    ID.get_or_init(|| Identity::generate("Fuzz", 0).expect("identity"))
}

type Model = BTreeMap<String, Vec<u8>>;

fn subtree(model: &Model, root: &str) -> Vec<String> {
    let prefix = format!("{root}/");
    model
        .keys()
        .filter(|k| *k == root || k.starts_with(&prefix))
        .cloned()
        .collect()
}

fn check(reader: &VaultReaderV2, dir: &std::path::Path, model: &Model) {
    let reopened = VaultReaderV2::open(dir, identity()).expect("vault must reopen");
    for r in [reader, &reopened] {
        let files: Vec<&str> = r
            .entries()
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .map(|e| e.path.as_str())
            .collect();
        let expected: Vec<&str> = model.keys().map(String::as_str).collect();
        let mut sorted = files.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, expected, "listing diverged from the model");
        for (path, content) in model {
            assert_eq!(&*r.read_entry(path).expect("file reads"), &content[..]);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let dir = std::env::temp_dir().join(format!("filesec-fuzz-ops-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let Ok(mut reader) = VaultReaderV2::create(&dir, identity(), SuiteId::Classic, "V", 0) else {
        return;
    };
    let mut model = Model::new();
    for op in data.chunks(3).take(24) {
        let [kind, x, y] = match *op {
            [k, x, y] => [k, x, y],
            _ => break,
        };
        let a = NAMES[usize::from(x) % NAMES.len()];
        let b = NAMES[usize::from(y) % NAMES.len()];
        match kind % 5 {
            0 => {
                let content = vec![y; usize::from(x % 7)];
                if reader.put_file_bytes(a, &content, None, None).is_ok() {
                    model.insert(a.to_string(), content);
                }
            }
            1 => {
                let _ = reader.mkdir(a);
            }
            2 => {
                if reader.remove_path(a).is_ok() {
                    for key in subtree(&model, a) {
                        model.remove(&key);
                    }
                }
            }
            3 => {
                if reader.rename(a, b).is_ok() {
                    for key in subtree(&model, a) {
                        let moved = format!("{b}{}", &key[a.len()..]);
                        if let Some(content) = model.remove(&key) {
                            model.insert(moved, content);
                        }
                    }
                }
            }
            _ => {
                // A small batch: all three succeed together or none apply.
                let nested = format!("{b}/x");
                let result = reader.commit_batch(|batch| {
                    batch.put_bytes(a, &[x], None, None)?;
                    batch.mkdir(b)?;
                    batch.put_bytes(&nested, &[y], None, None)
                });
                if result.is_ok() {
                    model.insert(a.to_string(), vec![x]);
                    model.insert(nested, vec![y]);
                }
            }
        }
        check(&reader, &dir, &model);
    }
    let _ = std::fs::remove_dir_all(&dir);
});
