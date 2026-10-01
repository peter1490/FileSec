//! Allocation budgets under malformed and concurrent input (audit O-04).
//!
//! A counting global allocator records the peak number of live heap bytes, so
//! these checks are deterministic and portable (unlike sampling process RSS).
//! Everything runs inside ONE test function: the allocator is process-wide, and
//! parallel tests would pollute each other's peaks.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use filesec_core::format::{self, ExportOptions};
use filesec_core::format_v2::VaultReaderV2;
use filesec_core::identity::Identity;
use filesec_core::vault::Vault;
use filesec_core::SuiteId;

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to the system allocator with the caller's
// layout unchanged; the counters are bookkeeping only.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = System.realloc(ptr, layout, new_size);
        if !new.is_null() {
            if new_size >= layout.size() {
                let now = CURRENT.fetch_add(new_size - layout.size(), Ordering::SeqCst)
                    + (new_size - layout.size());
                PEAK.fetch_max(now, Ordering::SeqCst);
            } else {
                CURRENT.fetch_sub(layout.size() - new_size, Ordering::SeqCst);
            }
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const MIB: usize = 1024 * 1024;

/// Peak extra heap (above what was live before) while running `f`.
fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = CURRENT.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let out = f();
    (out, PEAK.load(Ordering::SeqCst).saturating_sub(base))
}

fn tmp(name: &str) -> PathBuf {
    let suffix = filesec_core::util::hex(&filesec_core::secret::random_vec(6).unwrap());
    std::env::temp_dir().join(format!("filesec-mem-{suffix}-{name}"))
}

#[test]
fn metadata_and_streaming_paths_stay_within_their_budgets() {
    let identity = Identity::generate("Owner", 0).unwrap();

    // 1. A tiny file whose preamble claims the largest header: refused before
    //    allocating for it (it used to allocate the full claimed header first).
    let liar = tmp("liar.fsec");
    let mut bytes = b"FSEC\x1a".to_vec();
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&(filesec_core::limits::MAX_CONTAINER_HEADER_LEN as u32).to_be_bytes());
    bytes.extend_from_slice(&[0u8; 64]);
    std::fs::write(&liar, &bytes).unwrap();
    let (result, peak) = peak_during(|| format::open_vault_from_path(&liar, &identity));
    assert!(result.is_err());
    assert!(peak < MIB, "malformed header allocated {peak} bytes");
    let _ = std::fs::remove_file(&liar);

    // 2. A v2 vault whose manifest file is huge garbage: rejected by size
    //    before it is read into memory.
    let dir = tmp("v2-oversized");
    VaultReaderV2::create(&dir, &identity, SuiteId::Classic, "V", 1).unwrap();
    std::fs::File::create(dir.join("manifest"))
        .unwrap()
        .set_len(filesec_core::limits::MAX_MANIFEST_LEN + 1)
        .unwrap();
    let (result, peak) = peak_during(|| VaultReaderV2::open(&dir, &identity));
    assert!(result.is_err());
    assert!(peak < MIB, "oversized manifest allocated {peak} bytes");
    let _ = std::fs::remove_dir_all(&dir);

    // 3. Concurrent opens of a realistic vault (1,000 files in 50 folders)
    //    stay a small multiple of its manifest size each.
    let dir = tmp("v2-concurrent");
    let mut vault = Vault::new("Many", 1);
    for i in 0..1_000 {
        vault
            .add_file(
                &format!("dir-{}/file-{i}.txt", i % 50),
                vec![b'x'; 16],
                None,
                None,
            )
            .unwrap();
    }
    VaultReaderV2::from_vault(&dir, &identity, SuiteId::Classic, &vault).unwrap();
    drop(vault);
    let manifest_len = std::fs::metadata(dir.join("manifest")).unwrap().len() as usize;
    let (_, peak) = peak_during(|| {
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| scope.spawn(|| VaultReaderV2::open(&dir, &identity).unwrap()))
                .collect();
            for handle in handles {
                assert_eq!(handle.join().unwrap().entries().len(), 1_050);
            }
        });
    });
    assert!(
        peak < 4 * (8 * manifest_len) + 4 * MIB,
        "4 concurrent opens peaked at {peak} bytes for a {manifest_len}-byte manifest"
    );
    let _ = std::fs::remove_dir_all(&dir);

    // 4. Streaming extraction of a 16 MiB file holds about one chunk, not
    //    the file (metadata excluded).
    let dir = tmp("v2-stream");
    let mut reader = VaultReaderV2::create(&dir, &identity, SuiteId::Classic, "V", 1).unwrap();
    let source = tmp("big.bin");
    std::fs::write(&source, vec![7u8; 16 * MIB]).unwrap();
    reader.put_file("big.bin", &source, None, None).unwrap();
    let dest = tmp("v2-stream-out");
    std::fs::create_dir_all(&dest).unwrap();
    let (result, peak) = peak_during(|| reader.extract_to(&dest));
    result.unwrap();
    assert!(
        peak < 4 * MIB,
        "streaming extraction peaked at {peak} bytes"
    );
    assert_eq!(
        std::fs::metadata(dest.join("big.bin")).unwrap().len(),
        (16 * MIB) as u64
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dest);
    let _ = std::fs::remove_file(&source);

    // 5. Encrypting a container streams too: exporting that 16 MiB vault
    //    to a file never holds the plaintext whole.
    let dir = tmp("v2-export");
    let mut reader = VaultReaderV2::create(&dir, &identity, SuiteId::Classic, "V", 1).unwrap();
    let source = tmp("big2.bin");
    std::fs::write(&source, vec![9u8; 16 * MIB]).unwrap();
    reader.put_file("big.bin", &source, None, None).unwrap();
    let out = tmp("export.fsec");
    let (result, peak) = peak_during(|| {
        filesec_core::format_v2::export_v2_to_path(
            &reader,
            &identity,
            &[identity.public()],
            &ExportOptions::default(),
            &out,
        )
    });
    result.unwrap();
    assert!(peak < 4 * MIB, "streaming export peaked at {peak} bytes");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&source);
    let _ = std::fs::remove_file(&out);
}
