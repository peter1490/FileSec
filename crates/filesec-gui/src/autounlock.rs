//! Optional "remember on this device" auto-unlock, backed by the OS keychain.
//!
//! When the user opts in, their passphrase is stored in the platform secret
//! store — macOS Keychain, Windows Credential Manager, or the Linux Secret
//! Service (GNOME Keyring / KWallet) — so FileSec can unlock without prompting on
//! this machine. It is strictly **opt-in**, scoped to the current data
//! directory, and never replaces the passphrase: the passphrase remains the
//! recovery secret and keeps working everywhere. Removing the saved secret (or
//! running a build without the `keyring` feature) simply falls back to the
//! passphrase prompt.
//!
//! The whole module is **inert without the `keyring` feature**: the calls below
//! become stubs (`load` reports "nothing saved", `save`/`clear` error) and the
//! default build pulls in no secret-store dependency at all — mirroring
//! [`crate::passkey`].
//!
//! Trust model: the OS keychain is the protection boundary here — it gates the
//! stored secret behind the logged-in OS user. This deliberately trades a little
//! of FileSec's "passphrase only in your head" stance for convenience on a
//! trusted personal device, which is exactly why it is off by default and
//! per-device. The secret stored is the passphrase bytes; a passphrase change or
//! a post-quantum migration keeps the same passphrase, so the saved secret stays
//! valid (unlike passkeys, which a migration invalidates).

use zeroize::Zeroizing;

/// Service name FileSec registers under in the OS keychain. Stable, so a saved
/// secret is found again on the next launch.
pub const SERVICE: &str = "dev.FileSec.FileSec";

/// Whether this build was compiled with OS-keychain support (`keyring` feature).
/// The UI uses this to show/enable the "remember on this device" controls.
pub const SUPPORTED: bool = cfg!(feature = "keyring");

/// A user-facing keychain error (already a human-readable message).
#[derive(Debug)]
pub struct AutoUnlockError(pub String);

impl AutoUnlockError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl std::fmt::Display for AutoUnlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AutoUnlockError {}

/// Whether a secret is currently saved for `account` (the data directory). Any
/// keychain error is treated as "nothing saved" so the UI degrades gracefully.
#[must_use]
pub fn is_saved(account: &str) -> bool {
    matches!(load(account), Ok(Some(_)))
}

// ---------------------------------------------------------------------------
// Real implementation — feature-gated. Platform backends are selected by
// target in Cargo.toml (security-framework on macOS, windows-sys on Windows,
// the D-Bus Secret Service on Linux), so each OS pulls only its own backend.
// ---------------------------------------------------------------------------

#[cfg(feature = "keyring")]
fn entry(account: &str) -> Result<keyring::Entry, AutoUnlockError> {
    keyring::Entry::new(SERVICE, account)
        .map_err(|e| AutoUnlockError::new(format!("the OS keychain is unavailable: {e}")))
}

/// Save `secret` (the passphrase bytes) for `account` (the data directory),
/// replacing any existing entry.
#[cfg(feature = "keyring")]
pub fn save(account: &str, secret: &[u8]) -> Result<(), AutoUnlockError> {
    entry(account)?
        .set_secret(secret)
        .map_err(|e| AutoUnlockError::new(format!("could not save to the OS keychain: {e}")))
}

/// Load the saved secret for `account`, or `None` if nothing is stored. The
/// secret is returned in a zeroizing buffer so it is wiped after use.
#[cfg(feature = "keyring")]
pub fn load(account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, AutoUnlockError> {
    match entry(account)?.get_secret() {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(AutoUnlockError::new(format!(
            "could not read the OS keychain: {e}"
        ))),
    }
}

/// Remove the saved secret for `account`. Succeeds (idempotently) if there was
/// nothing stored.
#[cfg(feature = "keyring")]
pub fn clear(account: &str) -> Result<(), AutoUnlockError> {
    match entry(account)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(AutoUnlockError::new(format!(
            "could not update the OS keychain: {e}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Inert stubs when the `keyring` feature is off (the default build).
// ---------------------------------------------------------------------------

#[cfg(not(feature = "keyring"))]
const NO_SUPPORT: &str =
    "this build has no OS-keychain support — rebuild FileSec with `--features keyring`";

#[cfg(not(feature = "keyring"))]
pub fn save(_account: &str, _secret: &[u8]) -> Result<(), AutoUnlockError> {
    Err(AutoUnlockError::new(NO_SUPPORT))
}

#[cfg(not(feature = "keyring"))]
pub fn load(_account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, AutoUnlockError> {
    Ok(None)
}

#[cfg(not(feature = "keyring"))]
pub fn clear(_account: &str) -> Result<(), AutoUnlockError> {
    Err(AutoUnlockError::new(NO_SUPPORT))
}
