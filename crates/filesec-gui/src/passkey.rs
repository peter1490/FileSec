//! Passkey (FIDO2 `hmac-secret`) authenticator backends.
//!
//! FileSec is fully offline, so a passkey can't "log you in" — there is no
//! server to verify a WebAuthn assertion. Instead we use the FIDO2
//! **`hmac-secret`** extension (a.k.a. the WebAuthn PRF): the authenticator
//! deterministically returns a stable 32-byte secret for a given credential +
//! salt, gated by physical possession of the device and user verification
//! (touch / PIN / biometric). That secret wraps the keystore's data key — see
//! [`filesec_core::keystore`], which performs all the wrapping crypto and takes
//! the 32-byte output as a plain input.
//!
//! This module is the **hardware bridge** that produces that secret. The
//! [`Authenticator`] trait keeps backends swappable: the hardware security-key
//! backend ([`HardwareKey`], behind the `passkey` cargo feature) is implemented
//! first; a platform backend (Touch ID / Windows Hello) can be added later
//! behind the same trait. The whole module is **inert without the `passkey`
//! feature** — [`enroll`]/[`assert`] then return [`PasskeyError`] and the
//! default build pulls in no FIDO2 dependency at all.

use filesec_core::keystore::{PasskeyEnrollment, HMAC_SECRET_LEN};
use zeroize::Zeroizing;

/// Relying-party id under which FileSec creates its local credentials. Fixed,
/// since the credentials are only ever used by this app on this device.
pub const RP_ID: &str = "filesec.local";

/// Whether this build was compiled with hardware-passkey support (the `passkey`
/// feature). The UI uses this to enable/disable passkey controls.
pub const SUPPORTED: bool = cfg!(feature = "passkey");

#[cfg(not(feature = "passkey"))]
const NO_SUPPORT: &str =
    "this build has no passkey support — rebuild FileSec with `--features passkey`";

/// A user-facing passkey error (already a human-readable message).
#[derive(Debug)]
pub struct PasskeyError(pub String);

impl PasskeyError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl std::fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PasskeyError {}

/// A swappable passkey backend.
///
/// The hardware (FIDO2/CTAP2-over-USB) backend is the first implementation; a
/// platform backend (Touch ID / Windows Hello via the OS WebAuthn API) can be
/// added behind the same trait without touching the keystore or the UI flow.
pub trait Authenticator {
    /// Create a new credential with the `hmac-secret` extension enabled, then
    /// immediately derive its secret for a fresh random salt — yielding a
    /// ready-to-store [`PasskeyEnrollment`]. `now` is stamped as the enroll time.
    fn enroll(
        &self,
        rp_id: &str,
        label: &str,
        pin: Option<&str>,
        now: i64,
    ) -> Result<PasskeyEnrollment, PasskeyError>;

    /// Re-derive the 32-byte `hmac-secret` for an already-enrolled credential and
    /// its stored salt. Used at unlock time.
    fn assert(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        hmac_salt: &[u8; HMAC_SECRET_LEN],
        pin: Option<&str>,
    ) -> Result<Zeroizing<[u8; HMAC_SECRET_LEN]>, PasskeyError>;
}

/// Enroll a new hardware passkey with the default backend. The UI calls this on
/// a worker thread (the FIDO2 ceremony blocks on a device touch).
#[cfg(feature = "passkey")]
pub fn enroll(label: &str, pin: Option<&str>, now: i64) -> Result<PasskeyEnrollment, PasskeyError> {
    HardwareKey.enroll(RP_ID, label, pin, now)
}

/// Stub used when the `passkey` feature is off: always errors.
#[cfg(not(feature = "passkey"))]
pub fn enroll(
    _label: &str,
    _pin: Option<&str>,
    _now: i64,
) -> Result<PasskeyEnrollment, PasskeyError> {
    Err(PasskeyError::new(NO_SUPPORT))
}

/// Re-derive the `hmac-secret` for an enrolled passkey with the default backend.
#[cfg(feature = "passkey")]
pub fn assert(
    credential_id: &[u8],
    hmac_salt: &[u8; HMAC_SECRET_LEN],
    pin: Option<&str>,
) -> Result<Zeroizing<[u8; HMAC_SECRET_LEN]>, PasskeyError> {
    HardwareKey.assert(RP_ID, credential_id, hmac_salt, pin)
}

/// Stub used when the `passkey` feature is off: always errors.
#[cfg(not(feature = "passkey"))]
pub fn assert(
    _credential_id: &[u8],
    _hmac_salt: &[u8; HMAC_SECRET_LEN],
    _pin: Option<&str>,
) -> Result<Zeroizing<[u8; HMAC_SECRET_LEN]>, PasskeyError> {
    Err(PasskeyError::new(NO_SUPPORT))
}

// ---------------------------------------------------------------------------
// Hardware (FIDO2/CTAP2) backend — feature-gated.
//
// NOTE: this backend talks to a physical security key over USB HID (via
// `ctap-hid-fido2`, which vendors and compiles the C `hidapi` library). It
// therefore cannot be exercised in CI / a headless sandbox and is verified
// on-device. It is compiled only with `--features passkey`; the default build
// and all default tests never touch it.
// ---------------------------------------------------------------------------

#[cfg(feature = "passkey")]
pub use hardware::HardwareKey;

#[cfg(feature = "passkey")]
mod hardware {
    use super::{Authenticator, PasskeyError, HMAC_SECRET_LEN};
    use ctap_hid_fido2::fidokey::{
        get_assertion::get_assertion_params::{Extension as GaExt, GetAssertionArgs},
        make_credential::make_credential_params::{Extension as McExt, MakeCredentialArgs},
        GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
    };
    use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
    use filesec_core::keystore::PasskeyEnrollment;
    use zeroize::Zeroizing;

    /// The default backend: a roaming FIDO2 hardware key (YubiKey, SoloKey, …).
    pub struct HardwareKey;

    fn random32() -> Result<[u8; 32], PasskeyError> {
        filesec_core::secret::random_array::<32>()
            .map_err(|_| PasskeyError::new("secure random number generation failed"))
    }

    /// Open the first connected authenticator.
    fn open_device() -> Result<ctap_hid_fido2::FidoKeyHid, PasskeyError> {
        FidoKeyHidFactory::create(&Cfg::init())
            .map_err(|e| PasskeyError::new(format!("no security key found: {e}")))
    }

    /// High-security verification policy for a get-assertion: when a PIN is
    /// supplied we authenticate with it (which performs user verification);
    /// otherwise we keep the builder's default `uv = Some(true)` so the
    /// authenticator still enforces built-in UV (biometric / its own PIN). We
    /// deliberately never call `without_pin_and_uv()` — no-verification unlock is
    /// not offered for the keystore (F10).
    fn get_assertion_args<'a>(
        rp_id: &str,
        challenge: &[u8],
        credential_id: &[u8],
        hmac_salt: &[u8; HMAC_SECRET_LEN],
        pin: Option<&'a str>,
    ) -> GetAssertionArgs<'a> {
        let mut builder = GetAssertionArgsBuilder::new(rp_id, challenge)
            .credential_id(credential_id)
            .extensions(&[GaExt::HmacSecret(Some(*hmac_salt))]);
        if let Some(p) = pin {
            builder = builder.pin(p);
        }
        builder.build()
    }

    /// The make-credential counterpart of [`get_assertion_args`]: enrollment
    /// requires user verification by default and never falls back to a
    /// no-verification ceremony (F10).
    fn make_credential_args<'a>(
        rp_id: &str,
        challenge: &[u8],
        pin: Option<&'a str>,
    ) -> MakeCredentialArgs<'a> {
        let mut builder = MakeCredentialArgsBuilder::new(rp_id, challenge)
            .extensions(&[McExt::HmacSecret(Some(true))]);
        if let Some(p) = pin {
            builder = builder.pin(p);
        }
        builder.build()
    }

    /// Run a get-assertion with the `hmac-secret` extension and return the
    /// 32-byte output the key derived for `hmac_salt`.
    fn derive_hmac_secret(
        device: &ctap_hid_fido2::FidoKeyHid,
        rp_id: &str,
        credential_id: &[u8],
        hmac_salt: &[u8; HMAC_SECRET_LEN],
        pin: Option<&str>,
    ) -> Result<Zeroizing<[u8; HMAC_SECRET_LEN]>, PasskeyError> {
        let challenge = random32()?;
        let args = get_assertion_args(rp_id, &challenge, credential_id, hmac_salt, pin);
        let assertions = device
            .get_assertion_with_args(&args)
            .map_err(|e| PasskeyError::new(format!("authentication failed: {e}")))?;
        let first = assertions
            .into_iter()
            .next()
            .ok_or_else(|| PasskeyError::new("the security key returned no assertion"))?;
        for ext in first.extensions {
            if let GaExt::HmacSecret(Some(output)) = ext {
                return Ok(Zeroizing::new(output));
            }
        }
        Err(PasskeyError::new(
            "the security key did not return an hmac-secret — it may not support that extension",
        ))
    }

    impl Authenticator for HardwareKey {
        fn enroll(
            &self,
            rp_id: &str,
            label: &str,
            pin: Option<&str>,
            now: i64,
        ) -> Result<PasskeyEnrollment, PasskeyError> {
            let device = open_device()?;
            let challenge = random32()?;
            let args = make_credential_args(rp_id, &challenge, pin);
            let attestation = device
                .make_credential_with_args(&args)
                .map_err(|e| PasskeyError::new(format!("could not create a passkey: {e}")))?;
            let credential_id = attestation.credential_descriptor.id.clone();
            if credential_id.is_empty() {
                return Err(PasskeyError::new(
                    "the security key returned an empty credential id",
                ));
            }
            // Derive the secret for a fresh salt; both the salt and credential id
            // are public handles stored in the keystore.
            let hmac_salt = random32()?;
            let hmac_output = derive_hmac_secret(&device, rp_id, &credential_id, &hmac_salt, pin)?;
            Ok(PasskeyEnrollment {
                credential_id,
                rp_id: rp_id.to_string(),
                hmac_salt,
                label: label.to_string(),
                added_at: now,
                hmac_output,
            })
        }

        fn assert(
            &self,
            rp_id: &str,
            credential_id: &[u8],
            hmac_salt: &[u8; HMAC_SECRET_LEN],
            pin: Option<&str>,
        ) -> Result<Zeroizing<[u8; HMAC_SECRET_LEN]>, PasskeyError> {
            let device = open_device()?;
            derive_hmac_secret(&device, rp_id, credential_id, hmac_salt, pin)
        }
    }

    // These tests only assemble the CTAP2 request arguments and inspect them —
    // no authenticator is touched — so they run in the (feature-gated) CI build
    // without any physical key. They pin the F10 policy: no ceremony is ever
    // configured to skip user verification.
    #[cfg(test)]
    mod tests {
        use super::*;

        const RP: &str = "filesec.local";

        #[test]
        fn no_pin_ceremonies_request_user_verification_by_default() {
            // Enrollment with no PIN must still request UV (uv = Some(true)),
            // never the old no-PIN/no-UV path.
            let mc = make_credential_args(RP, &[0u8; 32], None);
            assert_eq!(mc.uv, Some(true), "enroll must require user verification");
            assert!(mc.pin.is_none());

            // Unlock (get-assertion) with no PIN must likewise request UV.
            let salt = [0x11u8; HMAC_SECRET_LEN];
            let ga = get_assertion_args(RP, &[0u8; 32], b"cred", &salt, None);
            assert_eq!(ga.uv, Some(true), "unlock must require user verification");
            assert!(ga.pin.is_none());
        }

        #[test]
        fn pin_ceremonies_authenticate_with_the_pin() {
            // A supplied PIN is used to verify; the builder clears the separate
            // uv hint because the PIN itself performs verification.
            let mc = make_credential_args(RP, &[0u8; 32], Some("1234"));
            assert_eq!(mc.pin, Some("1234"));
            assert_eq!(mc.uv, None);

            let salt = [0x22u8; HMAC_SECRET_LEN];
            let ga = get_assertion_args(RP, &[0u8; 32], b"cred", &salt, Some("1234"));
            assert_eq!(ga.pin, Some("1234"));
            assert_eq!(ga.uv, None);
        }
    }
}
