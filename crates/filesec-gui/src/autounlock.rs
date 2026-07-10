//! Optional "remember on this device" auto-unlock, backed by the OS keychain.
//!
//! When the user opts in, FileSec stores a **random 32-byte device token** in the
//! platform secret store — macOS Keychain, Windows Credential Manager, or the
//! Linux Secret Service (GNOME Keyring / KWallet) — so it can unlock without
//! prompting on this machine. It is strictly **opt-in**, scoped to the current
//! data directory, and never replaces the passphrase: the passphrase remains the
//! recovery secret and keeps working everywhere.
//!
//! ## Why a token, not the passphrase
//!
//! The stored secret is **never the passphrase**. The token wraps the keystore's
//! data key in a dedicated device keyslot (see
//! [`filesec_core::keystore::KeystoreFile::set_device_token`]); the token alone is
//! useless without this machine's keystore file, and it is a full-entropy secret
//! that cannot be guessed or reused as a passphrase. Forgetting auto-unlock
//! clears the token *and* removes the device keyslot (advancing the keystore's
//! rollback-protected epoch), so a restored older keystore cannot silently
//! re-enable a device that was turned off. This is the F09 hardening: convenience
//! no longer leaks the passphrase into generic keychain storage.
//!
//! ## Device binding
//!
//! Where the platform supports it the token is device-local and non-syncing:
//!
//! * **macOS** — stored in the login keychain as a generic password; the keyring
//!   backend does not mark it synchronizable, so it stays on this device and is
//!   not pushed to iCloud Keychain. (See [`DEVICE_BOUND`].)
//! * **Windows** — a per-user Credential Manager entry, local to this account on
//!   this machine.
//! * **Linux** — the Secret Service gives **no device-binding or user-presence
//!   guarantee**; [`DEVICE_BOUND`] is `false` and [`device_binding_warning`]
//!   returns a caveat the UI surfaces so the user only enables it on a trusted
//!   machine.
//!
//! The whole module is **inert without the `keyring` feature**: the calls below
//! become stubs (`load_device_token` reports "nothing saved", `save`/`clear`
//! error) and the default build pulls in no secret-store dependency at all —
//! mirroring [`crate::passkey`].
//!
//! Trust model: the OS keychain gates the stored token behind the logged-in OS
//! user. This deliberately trades a little of FileSec's "passphrase only in your
//! head" stance for convenience on a trusted personal device, which is exactly
//! why it is off by default, per-device, and stores only a revocable token.

use zeroize::Zeroizing;

/// Service name FileSec registers under in the OS keychain. Stable, so a saved
/// token is found again on the next launch.
pub const SERVICE: &str = "dev.FileSec.FileSec";
/// Separate keychain service for rollback high-water anchors. Anchors are
/// non-secret but must be protected from local filesystem rollback/deletion.
pub const ANCHOR_SERVICE: &str = "dev.FileSec.FileSec.StateAnchors";

/// Whether this build was compiled with OS-keychain support (`keyring` feature).
/// The UI uses this to show/enable the "remember on this device" controls.
pub const SUPPORTED: bool = cfg!(feature = "keyring");

/// Whether this platform's keychain binds the stored device token to this
/// device/user — i.e. it does not sync or export to other machines. True on
/// macOS (login keychain, non-syncing) and Windows (per-user Credential
/// Manager); false on Linux, whose Secret Service offers no such guarantee.
pub const DEVICE_BOUND: bool =
    cfg!(all(feature = "keyring", any(target_os = "macos", target_os = "windows")));

/// A device-binding caveat to surface in the UI when auto-unlock is available but
/// the platform keychain gives no device-binding/user-presence guarantee (the
/// Linux Secret Service). `None` when storage is device-bound or auto-unlock is
/// unsupported.
#[must_use]
pub fn device_binding_warning() -> Option<&'static str> {
    (SUPPORTED && !DEVICE_BOUND).then_some(
        "On this system the device token is kept in the Secret Service (GNOME Keyring / KWallet), \
         which gives no guarantee it stays on this device and may be readable whenever you are \
         logged in. Only enable auto-unlock on a trusted personal machine.",
    )
}

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

/// Whether a device token is currently saved for `account` (the data directory).
/// Any keychain error is treated as "nothing saved" so the UI degrades
/// gracefully.
#[must_use]
pub fn is_saved(account: &str) -> bool {
    matches!(load_device_token(account), Ok(Some(_)))
}

// ---------------------------------------------------------------------------
// Real implementation — feature-gated. Platform backends are selected by
// target in Cargo.toml (security-framework on macOS, windows-sys on Windows,
// the D-Bus Secret Service on Linux), so each OS pulls only its own backend.
// ---------------------------------------------------------------------------

#[cfg(feature = "keyring")]
fn entry(account: &str) -> Result<keyring::Entry, AutoUnlockError> {
    entry_for(SERVICE, account)
}

#[cfg(feature = "keyring")]
fn entry_for(service: &str, account: &str) -> Result<keyring::Entry, AutoUnlockError> {
    keyring::Entry::new(service, account)
        .map_err(|e| AutoUnlockError::new(format!("the OS keychain is unavailable: {e}")))
}

/// Save the random device `token` for `account` (the data directory), replacing
/// any existing entry. The token — never the passphrase — is the only secret
/// this module persists.
#[cfg(feature = "keyring")]
pub fn save_device_token(account: &str, token: &[u8]) -> Result<(), AutoUnlockError> {
    entry(account)?
        .set_secret(token)
        .map_err(|e| AutoUnlockError::new(format!("could not save to the OS keychain: {e}")))
}

/// Load the saved device token for `account`, or `None` if nothing is stored. The
/// token is returned in a zeroizing buffer so it is wiped after use.
#[cfg(feature = "keyring")]
pub fn load_device_token(account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, AutoUnlockError> {
    match entry(account)?.get_secret() {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(AutoUnlockError::new(format!(
            "could not read the OS keychain: {e}"
        ))),
    }
}

/// Remove the saved device token for `account`. Succeeds (idempotently) if there
/// was nothing stored.
#[cfg(feature = "keyring")]
pub fn clear_device_token(account: &str) -> Result<(), AutoUnlockError> {
    match entry(account)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(AutoUnlockError::new(format!(
            "could not update the OS keychain: {e}"
        ))),
    }
}

/// Load the serialized high-water anchor set from OS secure storage. `None`
/// means this data directory has not established its first anchor yet.
#[cfg(feature = "keyring")]
pub fn load_state_anchors(account: &str) -> Result<Option<Vec<u8>>, AutoUnlockError> {
    match entry_for(ANCHOR_SERVICE, account)?.get_secret() {
        Ok(bytes) => Ok(Some(bytes)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(AutoUnlockError::new(format!(
            "could not read rollback anchors from the OS keychain: {e}"
        ))),
    }
}

/// Persist the serialized high-water anchor set in OS secure storage.
#[cfg(feature = "keyring")]
pub fn save_state_anchors(account: &str, bytes: &[u8]) -> Result<(), AutoUnlockError> {
    entry_for(ANCHOR_SERVICE, account)?
        .set_secret(bytes)
        .map_err(|e| {
            AutoUnlockError::new(format!(
                "could not save rollback anchors to the OS keychain: {e}"
            ))
        })
}

// ---------------------------------------------------------------------------
// Inert stubs when the `keyring` feature is off (the default build).
// ---------------------------------------------------------------------------

#[cfg(not(feature = "keyring"))]
const NO_SUPPORT: &str =
    "this build has no OS-keychain support — rebuild FileSec with `--features keyring`";

#[cfg(not(feature = "keyring"))]
pub fn save_device_token(_account: &str, _token: &[u8]) -> Result<(), AutoUnlockError> {
    Err(AutoUnlockError::new(NO_SUPPORT))
}

#[cfg(not(feature = "keyring"))]
pub fn load_device_token(_account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, AutoUnlockError> {
    Ok(None)
}

#[cfg(not(feature = "keyring"))]
pub fn clear_device_token(_account: &str) -> Result<(), AutoUnlockError> {
    Err(AutoUnlockError::new(NO_SUPPORT))
}

#[cfg(not(feature = "keyring"))]
pub fn load_state_anchors(_account: &str) -> Result<Option<Vec<u8>>, AutoUnlockError> {
    Err(AutoUnlockError::new(NO_SUPPORT))
}

#[cfg(not(feature = "keyring"))]
pub fn save_state_anchors(_account: &str, _bytes: &[u8]) -> Result<(), AutoUnlockError> {
    Err(AutoUnlockError::new(NO_SUPPORT))
}
