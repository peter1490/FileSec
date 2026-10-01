// Fuzz the complete v1 container reader, not just the manifest schema:
//
// 1. Arbitrary bytes go through the in-memory importer (preamble, header,
//    signature-before-decrypt, manifest, data stream) and the streaming
//    verify-and-open path. Both must reject cleanly.
// 2. A valid container built from fuzz-chosen contents is tampered at a
//    fuzz-chosen byte. Opening it must then fail — never yield different
//    plaintext — and the untampered container must round-trip exactly.
#![no_main]

use std::sync::OnceLock;

use filesec_core::format::{self, ExportOptions};
use filesec_core::identity::Identity;
use filesec_core::vault::Vault;
use libfuzzer_sys::fuzz_target;

fn identity() -> &'static Identity {
    static ID: OnceLock<Identity> = OnceLock::new();
    ID.get_or_init(|| Identity::generate("Fuzz", 0).expect("identity"))
}

fn scratch(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("filesec-fuzz-{}-{tag}", std::process::id()))
}

fuzz_target!(|data: &[u8]| {
    let id = identity();
    let _ = format::import_vault(data, id);
    let raw = scratch("raw.fsec");
    if std::fs::write(&raw, data).is_ok() {
        let _ = format::verify_and_open(&raw, id);
    }

    if data.len() < 4 {
        return;
    }
    let (control, body) = data.split_at(4);
    let mut vault = Vault::new("fuzz", 0);
    for (i, chunk) in body.chunks(23).take(6).enumerate() {
        let _ = vault.add_file(&format!("d{}/f{i}", i % 2), chunk.to_vec(), None, None);
    }
    let mut container = Vec::new();
    if format::export_vault(&vault, id, &[id.public()], &ExportOptions::default(), &mut container)
        .is_err()
    {
        return;
    }
    let original = format::import_vault(&container, id).expect("valid container opens");
    for entry in vault.entries() {
        let got = original.vault.get(&entry.path).expect("entry present");
        assert_eq!(&got.content[..], &entry.content[..]);
    }
    let at = usize::from(u16::from_le_bytes([control[0], control[1]])) % container.len();
    container[at] ^= control[2] | 1;
    if let Ok(opened) = format::import_vault(&container, id) {
        panic!(
            "tampered container (byte {at}) opened with {} entries",
            opened.vault.entries().len()
        );
    }
});
