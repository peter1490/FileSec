//! Independent storage for rollback-protection high-water anchors.
//!
//! The anchors that make local state rollback-resistant must live **outside**
//! the data directory they protect, or restoring an old copy of the directory
//! would restore old anchors with it. Where the platform has one, they live in
//! the OS secure store (macOS Keychain, Windows Credential Manager, Linux Secret
//! Service) via [`crate::autounlock`]; otherwise the store falls back to an
//! explicitly degraded file inside the data directory.
//!
//! [`SecureAnchorStorage`] abstracts the secure half so the persistence layer's
//! backend-selection and recovery rules can be tested deterministically with
//! [`MemoryAnchorStorage`] — including an unavailable keychain and a
//! capacity-limited one — without touching the developer's real keychain.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// A secure key/value store for anchor records, keyed by an opaque account
/// string. Implementations must be safe to share between threads.
///
/// `Err` means the storage is **unreachable or failed** — distinct from
/// `Ok(None)`, which means it answered and holds nothing under that key. The
/// backend-selection rules depend on that distinction: only a storage that
/// answers can prove a store was never secure-anchored.
pub trait SecureAnchorStorage: Send + Sync {
    /// Read the record stored under `account`.
    fn load(&self, account: &str) -> Result<Option<Vec<u8>>, String>;
    /// Create or replace the record stored under `account`.
    fn save(&self, account: &str, bytes: &[u8]) -> Result<(), String>;
    /// Remove the record stored under `account` (idempotent).
    fn delete(&self, account: &str) -> Result<(), String>;
}

/// The platform keychain, through [`crate::autounlock`]'s anchor service.
pub struct KeychainAnchorStorage;

impl SecureAnchorStorage for KeychainAnchorStorage {
    fn load(&self, account: &str) -> Result<Option<Vec<u8>>, String> {
        crate::autounlock::load_state_anchors(account).map_err(|e| e.to_string())
    }

    fn save(&self, account: &str, bytes: &[u8]) -> Result<(), String> {
        crate::autounlock::save_state_anchors(account, bytes).map_err(|e| e.to_string())
    }

    fn delete(&self, account: &str) -> Result<(), String> {
        crate::autounlock::delete_state_anchors(account).map_err(|e| e.to_string())
    }
}

/// The secure anchor storage this build uses by default: the OS keychain when
/// compiled with the `keyring` feature, otherwise none (degraded file anchors).
#[must_use]
pub fn platform_storage() -> Option<Arc<dyn SecureAnchorStorage>> {
    if crate::autounlock::SUPPORTED {
        Some(Arc::new(KeychainAnchorStorage))
    } else {
        None
    }
}

/// An in-memory [`SecureAnchorStorage`] for tests and embedding.
///
/// It can be switched unavailable (every call errors, like a locked or missing
/// keychain), limited to a per-record byte capacity (like Windows Credential
/// Manager's 2,560-byte `CredentialBlob`), and counts lookups so a test can
/// assert that secure storage was actually consulted.
#[derive(Default)]
pub struct MemoryAnchorStorage {
    records: Mutex<HashMap<String, Vec<u8>>>,
    unavailable: AtomicBool,
    capacity: Option<usize>,
    lookups: AtomicUsize,
}

impl MemoryAnchorStorage {
    /// An empty, available storage with no capacity limit.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty storage that rejects any record larger than `bytes`.
    #[must_use]
    pub fn with_record_capacity(bytes: usize) -> Self {
        Self {
            capacity: Some(bytes),
            ..Self::default()
        }
    }

    /// Make every subsequent call fail (`true`) or succeed again (`false`).
    pub fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.store(unavailable, Ordering::SeqCst);
    }

    /// How many `load` calls have been made so far.
    #[must_use]
    pub fn lookups(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }

    /// Number of records currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.lock().map(|r| r.len()).unwrap_or(0)
    }

    /// Whether no records are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every record, sorted by account — for asserting that nothing changed.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(String, Vec<u8>)> {
        let mut records: Vec<_> = self
            .records
            .lock()
            .map(|r| r.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        records.sort();
        records
    }

    /// Size of the largest record currently held.
    #[must_use]
    pub fn largest_record(&self) -> usize {
        self.records
            .lock()
            .map(|r| r.values().map(Vec::len).max().unwrap_or(0))
            .unwrap_or(0)
    }

    fn check_available(&self) -> Result<(), String> {
        if self.unavailable.load(Ordering::SeqCst) {
            Err("secure storage is unavailable".into())
        } else {
            Ok(())
        }
    }

    fn records(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, Vec<u8>>>, String> {
        self.records
            .lock()
            .map_err(|_| "secure storage lock poisoned".to_string())
    }
}

impl SecureAnchorStorage for MemoryAnchorStorage {
    fn load(&self, account: &str) -> Result<Option<Vec<u8>>, String> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        self.check_available()?;
        Ok(self.records()?.get(account).cloned())
    }

    fn save(&self, account: &str, bytes: &[u8]) -> Result<(), String> {
        self.check_available()?;
        if let Some(capacity) = self.capacity {
            if bytes.len() > capacity {
                return Err(format!(
                    "secure storage record too large ({} > {capacity} bytes)",
                    bytes.len()
                ));
            }
        }
        self.records()?.insert(account.to_string(), bytes.to_vec());
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<(), String> {
        self.check_available()?;
        self.records()?.remove(account);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn memory_storage_distinguishes_absent_from_unavailable() {
        let storage = MemoryAnchorStorage::new();
        assert_eq!(storage.load("a").unwrap(), None);
        storage.save("a", b"one").unwrap();
        assert_eq!(storage.load("a").unwrap().as_deref(), Some(&b"one"[..]));
        storage.set_unavailable(true);
        assert!(storage.load("a").is_err());
        assert!(storage.save("a", b"two").is_err());
        storage.set_unavailable(false);
        storage.delete("a").unwrap();
        assert_eq!(storage.load("a").unwrap(), None);
        assert_eq!(storage.lookups(), 4);
    }

    #[test]
    fn memory_storage_enforces_record_capacity() {
        let storage = MemoryAnchorStorage::with_record_capacity(4);
        storage.save("a", b"1234").unwrap();
        assert!(storage.save("a", b"12345").is_err());
        assert_eq!(storage.largest_record(), 4);
    }
}
