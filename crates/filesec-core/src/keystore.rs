//! Passphrase- (and optionally passkey-) protected keystore for the user's
//! private identity.
//!
//! The private keys are serialized to CBOR and sealed with XChaCha20-Poly1305.
//! Two on-disk formats coexist, distinguished by a magic preamble:
//!
//! * **v1** (legacy) — the secret bundle is sealed *directly* under a master key
//!   derived from the passphrase via Argon2id. Bare CBOR, no framing. Every
//!   keystore created without a passkey uses this format, byte-for-byte
//!   unchanged, so older builds keep opening it.
//! * **v2** — a key-wrapping layer ("keyslots", à la LUKS/age). The bundle is
//!   encrypted **once** under a random 32-byte data-encryption key (the DEK); the
//!   DEK is then wrapped once per unlock method: always exactly one **passphrase**
//!   slot, plus zero or more **passkey** slots (a FIDO2 `hmac-secret` output wraps
//!   the DEK). A keystore is promoted v1→v2 the first time a passkey is enrolled.
//!
//! The passphrase slot is a single field, not a list — so no operation can ever
//! remove it. The passphrase is always a valid way in (your recovery path), even
//! if every enrolled passkey is lost.
//!
//! This module is deliberately **hardware-free**: it consumes the 32-byte
//! `hmac-secret` output as a plain input ([`PasskeyEnrollment::hmac_output`] and
//! the argument to [`KeystoreFile::unlock_with_passkey`]). Talking to a physical
//! authenticator lives in the GUI layer; the wrapping crypto here is fully
//! unit-testable with a synthetic secret.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::kdf::{self, KdfParams};
use crate::secret::{SymKey, SYM_KEY_LEN};
use crate::{aead, codec, kem, secret, sign};

/// Legacy (v1) keystore format version.
const VERSION_V1: u16 = 1;
/// Keyslot (v2) keystore format version.
const VERSION_V2: u16 = 2;
/// Magic preamble identifying a framed v2 keystore. A v1 keystore is bare CBOR
/// (a map, whose first byte is in the CBOR major-type-5 range, never `0x46`/`F`),
/// so it can never begin with these bytes — the magic is an unambiguous
/// discriminator between the two formats.
const MAGIC_V2: &[u8; 4] = b"FSK\x1a";

/// Magic preamble identifying a portable identity backup (see
/// [`export_identity_armored`]). Distinct from [`MAGIC_V2`] so a backup blob and
/// a live keystore can never be mistaken for one another.
const MAGIC_BACKUP: &[u8; 4] = b"FSB\x1a";
/// Backup format version, framed after [`MAGIC_BACKUP`].
const VERSION_BACKUP_V1: u16 = 1;
/// ASCII-armor delimiters for an exported identity backup, matching the
/// `.fsecpub` armor style so the file is human-identifiable and email-safe.
const BACKUP_ARMOR_BEGIN: &str = "-----BEGIN FILESEC IDENTITY BACKUP-----";
const BACKUP_ARMOR_END: &str = "-----END FILESEC IDENTITY BACKUP-----";

/// Salt length for Argon2id.
const SALT_LEN: usize = 16;
/// Length of the `hmac-secret` salt fed to the authenticator and of the 32-byte
/// secret it returns.
pub const HMAC_SECRET_LEN: usize = 32;

/// AEAD associated data binding the v1 keystore purpose/version.
const AAD_V1: &[u8] = b"FileSec keystore v1";
/// AEAD associated data binding the v2 secret-bundle encryption — distinct from
/// [`AAD_V1`] so a v1 ciphertext can never be reinterpreted as a v2 bundle.
const AAD_BUNDLE_V2: &[u8] = b"FileSec keystore v2 bundle";
/// Base AEAD associated data for a v2 DEK wrap. Each slot extends it with
/// slot-identifying material (see [`passphrase_wrap_aad`]/[`passkey_wrap_aad`]).
const WRAP_AAD_V2: &[u8] = b"FileSec keystore v2 dek-wrap";
/// AEAD associated data binding a portable identity backup — distinct from every
/// keystore AAD so a backup ciphertext can never be reinterpreted as a keystore.
const AAD_BACKUP_V1: &[u8] = b"FileSec identity backup v1";
/// Domain-separation context deriving a passkey slot's key-encryption key from
/// the authenticator's `hmac-secret` output.
const PASSKEY_KEK_CONTEXT: &str = "FileSec passkey keyslot v1";

/// The decrypted private identity bundle. Zeroized on drop.
///
/// The post-quantum fields are present only for a hybrid identity and are
/// serialized only when set (`skip_serializing_if`), so a classical keystore is
/// byte-for-byte unchanged and older keystores still unlock. Each PQC keypair is
/// stored as its compact seed (re-expanded on use) plus the cached public key.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SecretBundle {
    name: String,
    created_at: i64,
    sign_secret: [u8; sign::SECRET_LEN],
    kem_secret: [u8; kem::SECRET_LEN],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mldsa_seed: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mldsa_public: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mlkem_seed: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mlkem_public: Option<Vec<u8>>,
}

/// Serialize `identity`'s secret material into a [`SecretBundle`].
fn build_bundle(identity: &Identity) -> SecretBundle {
    SecretBundle {
        name: identity.name.clone(),
        created_at: identity.created_at,
        sign_secret: *identity.sign_secret(),
        kem_secret: *identity.kem_secret(),
        mldsa_seed: identity.mldsa_secret().map(<[u8]>::to_vec),
        mldsa_public: identity.mldsa_public().map(<[u8]>::to_vec),
        mlkem_seed: identity.mlkem_secret().map(<[u8]>::to_vec),
        mlkem_public: identity.mlkem_public().map(<[u8]>::to_vec),
    }
}

/// Reconstruct an [`Identity`] from a decrypted bundle, then wipe the bundle.
fn bundle_into_identity(mut bundle: SecretBundle) -> Identity {
    // Re-pair each PQC public with its seed; a half-present pair (which a
    // well-formed keystore never produces) degrades to a classical identity.
    let pair = |public: &Option<Vec<u8>>, seed: &Option<Vec<u8>>| match (public, seed) {
        (Some(p), Some(s)) => Some((p.clone(), s.clone())),
        _ => None,
    };
    let mldsa = pair(&bundle.mldsa_public, &bundle.mldsa_seed);
    let mlkem = pair(&bundle.mlkem_public, &bundle.mlkem_seed);
    let identity = Identity::from_parts(
        bundle.name.clone(),
        bundle.created_at,
        bundle.sign_secret,
        bundle.kem_secret,
        mldsa,
        mlkem,
    );
    bundle.zeroize();
    identity
}

// ---------------------------------------------------------------------------
// Public input/output types
// ---------------------------------------------------------------------------

/// Everything needed to enroll one passkey as a keyslot. Produced by an
/// authenticator backend (GUI layer) and consumed by
/// [`KeystoreFile::add_passkey`]. Every field except `hmac_output` is a public,
/// non-secret handle stored verbatim in the keystore; `hmac_output` is the
/// 32-byte `hmac-secret` value and is zeroized on drop.
pub struct PasskeyEnrollment {
    /// Opaque FIDO2 credential id used to target this credential at unlock time.
    pub credential_id: Vec<u8>,
    /// Relying-party id the credential was created under (a fixed app value).
    pub rp_id: String,
    /// The 32-byte salt fed to the `hmac-secret` extension (public, stored).
    pub hmac_salt: [u8; HMAC_SECRET_LEN],
    /// Human label shown in the UI (e.g. "YubiKey 5C").
    pub label: String,
    /// Unix time the passkey was enrolled.
    pub added_at: i64,
    /// The 32-byte `hmac-secret` output the authenticator returned for
    /// `hmac_salt`. Secret; wraps the DEK and is never persisted.
    pub hmac_output: Zeroizing<[u8; HMAC_SECRET_LEN]>,
}

/// Public, non-secret description of one enrolled passkey, for the UI and for
/// driving the authenticator at unlock time.
#[derive(Clone, Debug)]
pub struct PasskeyInfo {
    /// Opaque FIDO2 credential id (the allow-list entry to assert against).
    pub credential_id: Vec<u8>,
    /// Relying-party id the credential was created under.
    pub rp_id: String,
    /// The salt to feed back to the `hmac-secret` extension at unlock.
    pub hmac_salt: Vec<u8>,
    /// Human label shown in the UI.
    pub label: String,
    /// Unix time the passkey was enrolled.
    pub added_at: i64,
}

// ---------------------------------------------------------------------------
// Shared wrap helpers
// ---------------------------------------------------------------------------

/// Append a length-prefixed field to a hasher so concatenated fields can't be
/// confused with one another.
fn update_lp(h: &mut blake3::Hasher, field: &[u8]) {
    h.update(&(field.len() as u64).to_le_bytes());
    h.update(field);
}

/// AEAD associated data for the passphrase slot's DEK wrap, binding the slot's
/// salt and KDF parameters so they cannot be tampered with or downgraded.
fn passphrase_wrap_aad(salt: &[u8], params: &KdfParams) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    update_lp(&mut h, b"passphrase");
    update_lp(&mut h, salt);
    update_lp(&mut h, &params.m_cost.to_le_bytes());
    update_lp(&mut h, &params.t_cost.to_le_bytes());
    update_lp(&mut h, &params.p_cost.to_le_bytes());
    let mut aad = WRAP_AAD_V2.to_vec();
    aad.extend_from_slice(h.finalize().as_bytes());
    aad
}

/// AEAD associated data for a passkey slot's DEK wrap, binding the credential
/// id, relying-party id, and hmac salt so a slot cannot be silently repointed at
/// a different credential or salt.
fn passkey_wrap_aad(credential_id: &[u8], rp_id: &str, hmac_salt: &[u8]) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    update_lp(&mut h, b"passkey");
    update_lp(&mut h, credential_id);
    update_lp(&mut h, rp_id.as_bytes());
    update_lp(&mut h, hmac_salt);
    let mut aad = WRAP_AAD_V2.to_vec();
    aad.extend_from_slice(h.finalize().as_bytes());
    aad
}

/// Wrap the DEK under `kek` with a fresh nonce, returning `(nonce, ciphertext)`.
fn wrap_dek(kek: &SymKey, dek: &SymKey, aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let nonce = secret::random_vec(aead::NONCE_LEN)?;
    let ciphertext = aead::seal(kek, &nonce, aad, dek.as_bytes())?;
    Ok((nonce, ciphertext))
}

/// Unwrap a DEK previously wrapped with [`wrap_dek`]. Returns [`Error::Auth`] if
/// `kek`/`aad` are wrong (the caller may map this to a friendlier error).
fn unwrap_dek(kek: &SymKey, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<SymKey> {
    let pt = Zeroizing::new(aead::open(kek, nonce, aad, ciphertext)?);
    if pt.len() != SYM_KEY_LEN {
        return Err(Error::BadKey("wrapped DEK length"));
    }
    let mut arr = [0u8; SYM_KEY_LEN];
    arr.copy_from_slice(&pt);
    let key = SymKey::from_bytes(arr);
    arr.zeroize();
    Ok(key)
}

/// Encrypt `identity`'s secret bundle under the DEK, returning `(nonce, ct)`.
fn encrypt_bundle(dek: &SymKey, identity: &Identity) -> Result<(Vec<u8>, Vec<u8>)> {
    let bundle = build_bundle(identity);
    let plaintext = Zeroizing::new(codec::to_vec(&bundle)?);
    let nonce = secret::random_vec(aead::NONCE_LEN)?;
    let ciphertext = aead::seal(dek, &nonce, AAD_BUNDLE_V2, &plaintext)?;
    Ok((nonce, ciphertext))
}

/// Decrypt a DEK-encrypted bundle and reconstruct the identity.
fn decrypt_bundle(dek: &SymKey, nonce: &[u8], ciphertext: &[u8]) -> Result<Identity> {
    let plaintext = Zeroizing::new(aead::open(dek, nonce, AAD_BUNDLE_V2, ciphertext)?);
    let bundle: SecretBundle = codec::from_slice(&plaintext)?;
    Ok(bundle_into_identity(bundle))
}

// ---------------------------------------------------------------------------
// v1 (legacy) keystore
// ---------------------------------------------------------------------------

/// On-disk v1 keystore: the secret bundle sealed directly under the passphrase
/// master key. Kept verbatim so existing files round-trip unchanged.
#[derive(Serialize, Deserialize)]
struct KeystoreV1 {
    version: u16,
    kdf: KdfParams,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl KeystoreV1 {
    fn create(identity: &Identity, passphrase: &[u8], params: KdfParams) -> Result<Self> {
        let salt = secret::random_vec(SALT_LEN)?;
        let master = kdf::derive_master_key(passphrase, &salt, params)?;
        let nonce = secret::random_vec(aead::NONCE_LEN)?;
        let bundle = build_bundle(identity);
        let plaintext = Zeroizing::new(codec::to_vec(&bundle)?);
        let ciphertext = aead::seal(&master, &nonce, AAD_V1, &plaintext)?;
        Ok(Self {
            version: VERSION_V1,
            kdf: params,
            salt,
            nonce,
            ciphertext,
        })
    }

    fn unlock(&self, passphrase: &[u8]) -> Result<Identity> {
        let master = kdf::derive_master_key(passphrase, &self.salt, self.kdf)?;
        let plaintext = Zeroizing::new(
            aead::open(&master, &self.nonce, AAD_V1, &self.ciphertext)
                .map_err(|_| Error::BadPassphrase)?,
        );
        let bundle: SecretBundle = codec::from_slice(&plaintext)?;
        Ok(bundle_into_identity(bundle))
    }
}

// ---------------------------------------------------------------------------
// Portable identity backup
// ---------------------------------------------------------------------------

/// A portable, passphrase-encrypted backup of a private identity. Structurally a
/// v1-style sealing (Argon2id key + XChaCha20-Poly1305 over the [`SecretBundle`]),
/// but bound under [`AAD_BACKUP_V1`] and framed behind [`MAGIC_BACKUP`] so it is
/// unambiguously a backup, never a live keystore. It carries **no passkey slots**
/// — a backup restores anywhere with just its passphrase.
#[derive(Serialize, Deserialize)]
struct IdentityBackupV1 {
    version: u16,
    kdf: KdfParams,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Produce a portable, passphrase-encrypted, ASCII-armored backup of `identity`.
///
/// The private keys (including the ML-DSA/ML-KEM seeds of a hybrid identity) are
/// serialized and sealed under a key derived from `passphrase` via Argon2id — the
/// plaintext never touches disk. The result is base64 wrapped in
/// `-----BEGIN FILESEC IDENTITY BACKUP-----` armor, suitable for saving to a
/// `.fsecid` file, printing, or pasting. Restore it later with
/// [`import_identity_armored`].
///
/// The backup is only as safe as `passphrase`: anyone with the file and the
/// passphrase recovers the full identity.
pub fn export_identity_armored(
    identity: &Identity,
    passphrase: &[u8],
    params: KdfParams,
) -> Result<String> {
    let salt = secret::random_vec(SALT_LEN)?;
    let master = kdf::derive_master_key(passphrase, &salt, params)?;
    let nonce = secret::random_vec(aead::NONCE_LEN)?;
    let bundle = build_bundle(identity);
    let plaintext = Zeroizing::new(codec::to_vec(&bundle)?);
    let ciphertext = aead::seal(&master, &nonce, AAD_BACKUP_V1, &plaintext)?;
    let backup = IdentityBackupV1 {
        version: VERSION_BACKUP_V1,
        kdf: params,
        salt,
        nonce,
        ciphertext,
    };

    let body = codec::to_vec(&backup)?;
    let mut framed = Vec::with_capacity(MAGIC_BACKUP.len() + 2 + body.len());
    framed.extend_from_slice(MAGIC_BACKUP);
    framed.extend_from_slice(&VERSION_BACKUP_V1.to_be_bytes());
    framed.extend_from_slice(&body);

    let b64 = data_encoding::BASE64.encode(&framed);
    let mut out = String::new();
    out.push_str(BACKUP_ARMOR_BEGIN);
    out.push('\n');
    for line in b64.as_bytes().chunks(64) {
        // chunks of base64 are valid ASCII by construction.
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str(BACKUP_ARMOR_END);
    out.push('\n');
    Ok(out)
}

/// Parse an armored identity backup (as produced by [`export_identity_armored`])
/// and decrypt it with `passphrase`, reconstructing the [`Identity`].
///
/// Tolerant of surrounding whitespace and the armor lines being present or not. A
/// wrong passphrase (or any tampering) surfaces as [`Error::BadPassphrase`]; input
/// that isn't a FileSec identity backup surfaces as [`Error::Format`].
pub fn import_identity_armored(text: &str, passphrase: &[u8]) -> Result<Identity> {
    // De-armor: collect the base64 body between the delimiters, ignoring the
    // armor lines and surrounding whitespace.
    let mut body = String::new();
    let mut in_block = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == BACKUP_ARMOR_BEGIN {
            in_block = true;
            continue;
        }
        if trimmed == BACKUP_ARMOR_END {
            break;
        }
        if in_block {
            body.push_str(trimmed);
        }
    }
    // Be forgiving if the armor delimiters were stripped (e.g. by a chat client):
    // fall back to treating all non-delimiter lines as the base64 body.
    if body.is_empty() {
        body = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("-----"))
            .collect();
    }
    if body.is_empty() {
        return Err(Error::Format("no identity backup found"));
    }
    let framed = data_encoding::BASE64
        .decode(body.as_bytes())
        .or_else(|_| data_encoding::BASE64_NOPAD.decode(body.as_bytes()))
        .map_err(|_| Error::Format("invalid base64 in identity backup"))?;

    if framed.len() < MAGIC_BACKUP.len() + 2 || &framed[..MAGIC_BACKUP.len()] != MAGIC_BACKUP {
        return Err(Error::Format("not a FileSec identity backup"));
    }
    let version = u16::from_be_bytes([framed[MAGIC_BACKUP.len()], framed[MAGIC_BACKUP.len() + 1]]);
    if version != VERSION_BACKUP_V1 {
        return Err(Error::Format("unsupported identity backup version"));
    }
    let backup: IdentityBackupV1 = codec::from_slice(&framed[MAGIC_BACKUP.len() + 2..])?;
    if backup.version != VERSION_BACKUP_V1 {
        return Err(Error::Format("identity backup version mismatch"));
    }
    backup.kdf.validate_for_open()?;

    let master = kdf::derive_master_key(passphrase, &backup.salt, backup.kdf)?;
    let plaintext = Zeroizing::new(
        aead::open(&master, &backup.nonce, AAD_BACKUP_V1, &backup.ciphertext)
            .map_err(|_| Error::BadPassphrase)?,
    );
    let bundle: SecretBundle = codec::from_slice(&plaintext)?;
    Ok(bundle_into_identity(bundle))
}

// ---------------------------------------------------------------------------
// v2 (keyslot) keystore
// ---------------------------------------------------------------------------

/// The single passphrase keyslot: the DEK wrapped under an Argon2id key.
#[derive(Serialize, Deserialize)]
struct PassphraseSlot {
    kdf: KdfParams,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    wrapped_dek: Vec<u8>,
}

/// One passkey keyslot: the DEK wrapped under a key derived from a FIDO2
/// `hmac-secret` output, plus the public handles needed to re-derive it.
#[derive(Clone, Serialize, Deserialize)]
struct PasskeySlot {
    credential_id: Vec<u8>,
    rp_id: String,
    hmac_salt: Vec<u8>,
    label: String,
    added_at: i64,
    nonce: Vec<u8>,
    wrapped_dek: Vec<u8>,
}

/// On-disk v2 keystore body (serialized after the magic preamble).
#[derive(Serialize, Deserialize)]
struct KeystoreV2 {
    version: u16,
    bundle_nonce: Vec<u8>,
    bundle_ct: Vec<u8>,
    passphrase: PassphraseSlot,
    #[serde(default)]
    passkeys: Vec<PasskeySlot>,
}

/// Build the single passphrase slot wrapping `dek`.
fn build_passphrase_slot(
    dek: &SymKey,
    passphrase: &[u8],
    params: KdfParams,
) -> Result<PassphraseSlot> {
    let salt = secret::random_vec(SALT_LEN)?;
    let kek = kdf::derive_master_key(passphrase, &salt, params)?;
    let aad = passphrase_wrap_aad(&salt, &params);
    let (nonce, wrapped_dek) = wrap_dek(&kek, dek, &aad)?;
    Ok(PassphraseSlot {
        kdf: params,
        salt,
        nonce,
        wrapped_dek,
    })
}

impl KeystoreV2 {
    /// Build a fresh v2 keystore for `identity` and also hand back its DEK (so a
    /// just-built keystore can immediately enroll a passkey without re-deriving).
    fn create_with_dek(
        identity: &Identity,
        passphrase: &[u8],
        params: KdfParams,
    ) -> Result<(Self, SymKey)> {
        let dek = SymKey::random()?;
        let (bundle_nonce, bundle_ct) = encrypt_bundle(&dek, identity)?;
        let passphrase = build_passphrase_slot(&dek, passphrase, params)?;
        Ok((
            Self {
                version: VERSION_V2,
                bundle_nonce,
                bundle_ct,
                passphrase,
                passkeys: Vec::new(),
            },
            dek,
        ))
    }

    /// Recover the DEK via the passphrase slot. Maps an authentication failure
    /// (wrong passphrase) to [`Error::BadPassphrase`].
    fn unlock_dek_with_passphrase(&self, passphrase: &[u8]) -> Result<SymKey> {
        let kek = kdf::derive_master_key(passphrase, &self.passphrase.salt, self.passphrase.kdf)?;
        let aad = passphrase_wrap_aad(&self.passphrase.salt, &self.passphrase.kdf);
        unwrap_dek(
            &kek,
            &self.passphrase.nonce,
            &self.passphrase.wrapped_dek,
            &aad,
        )
        .map_err(|_| Error::BadPassphrase)
    }

    fn unlock(&self, passphrase: &[u8]) -> Result<Identity> {
        let dek = self.unlock_dek_with_passphrase(passphrase)?;
        decrypt_bundle(&dek, &self.bundle_nonce, &self.bundle_ct)
    }

    fn unlock_with_passkey(&self, index: usize, hmac_output: &[u8]) -> Result<Identity> {
        let slot = self
            .passkeys
            .get(index)
            .ok_or(Error::Format("passkey slot index out of range"))?;
        let kek = kdf::derive_subkey(PASSKEY_KEK_CONTEXT, hmac_output);
        let aad = passkey_wrap_aad(&slot.credential_id, &slot.rp_id, &slot.hmac_salt);
        let dek = unwrap_dek(&kek, &slot.nonce, &slot.wrapped_dek, &aad)?;
        decrypt_bundle(&dek, &self.bundle_nonce, &self.bundle_ct)
    }

    /// Wrap the (already recovered) `dek` under a new passkey slot.
    fn add_passkey(&mut self, dek: &SymKey, enrollment: PasskeyEnrollment) -> Result<()> {
        let kek = kdf::derive_subkey(PASSKEY_KEK_CONTEXT, enrollment.hmac_output.as_slice());
        let aad = passkey_wrap_aad(
            &enrollment.credential_id,
            &enrollment.rp_id,
            &enrollment.hmac_salt,
        );
        let (nonce, wrapped_dek) = wrap_dek(&kek, dek, &aad)?;
        self.passkeys.push(PasskeySlot {
            credential_id: enrollment.credential_id,
            rp_id: enrollment.rp_id,
            hmac_salt: enrollment.hmac_salt.to_vec(),
            label: enrollment.label,
            added_at: enrollment.added_at,
            nonce,
            wrapped_dek,
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public façade
// ---------------------------------------------------------------------------

/// The active on-disk representation behind [`KeystoreFile`].
enum Inner {
    V1(KeystoreV1),
    V2(KeystoreV2),
}

/// A FileSec keystore: the encrypted private identity, openable by passphrase
/// and (once enrolled) by passkey.
pub struct KeystoreFile(Inner);

impl KeystoreFile {
    /// Create a new (v1) keystore wrapping `identity` under `passphrase`. The
    /// on-disk format is unchanged from before passkeys existed; enrolling a
    /// passkey later promotes it to v2.
    pub fn create(identity: &Identity, passphrase: &[u8], params: KdfParams) -> Result<Self> {
        Ok(Self(Inner::V1(KeystoreV1::create(
            identity, passphrase, params,
        )?)))
    }

    /// Serialize to bytes for storage on disk. A v1 keystore is bare CBOR; a v2
    /// keystore is the magic preamble (`MAGIC` + version) followed by CBOR.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match &self.0 {
            Inner::V1(v1) => codec::to_vec(v1),
            Inner::V2(v2) => {
                let body = codec::to_vec(v2)?;
                let mut out = Vec::with_capacity(MAGIC_V2.len() + 2 + body.len());
                out.extend_from_slice(MAGIC_V2);
                out.extend_from_slice(&VERSION_V2.to_be_bytes());
                out.extend_from_slice(&body);
                Ok(out)
            }
        }
    }

    /// Parse keystore bytes (does not decrypt — call [`Self::unlock`] or
    /// [`Self::unlock_with_passkey`]). Dispatches on the magic preamble: present
    /// ⇒ framed v2; absent ⇒ legacy v1 bare CBOR.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() >= MAGIC_V2.len() + 2 && &bytes[..MAGIC_V2.len()] == MAGIC_V2 {
            let version = u16::from_be_bytes([bytes[MAGIC_V2.len()], bytes[MAGIC_V2.len() + 1]]);
            if version != VERSION_V2 {
                return Err(Error::Format("unsupported keystore version"));
            }
            let v2: KeystoreV2 = codec::from_slice(&bytes[MAGIC_V2.len() + 2..])?;
            if v2.version != VERSION_V2 {
                return Err(Error::Format("keystore version mismatch"));
            }
            v2.passphrase.kdf.validate_for_open()?;
            Ok(Self(Inner::V2(v2)))
        } else {
            let v1: KeystoreV1 = codec::from_slice(bytes)?;
            if v1.version != VERSION_V1 {
                return Err(Error::Format("unsupported keystore version"));
            }
            v1.kdf.validate_for_open()?;
            Ok(Self(Inner::V1(v1)))
        }
    }

    /// Decrypt and reconstruct the [`Identity`] with the supplied passphrase.
    /// A wrong passphrase surfaces as [`Error::BadPassphrase`].
    pub fn unlock(&self, passphrase: &[u8]) -> Result<Identity> {
        match &self.0 {
            Inner::V1(v1) => v1.unlock(passphrase),
            Inner::V2(v2) => v2.unlock(passphrase),
        }
    }

    /// Whether any passkeys are enrolled (always false for a v1 keystore).
    #[must_use]
    pub fn has_passkeys(&self) -> bool {
        matches!(&self.0, Inner::V2(v2) if !v2.passkeys.is_empty())
    }

    /// The enrolled passkeys' public handles, in slot order. The index of each
    /// entry is the `slot_index` to pass to [`Self::unlock_with_passkey`].
    #[must_use]
    pub fn passkey_slots(&self) -> Vec<PasskeyInfo> {
        match &self.0 {
            Inner::V2(v2) => v2
                .passkeys
                .iter()
                .map(|s| PasskeyInfo {
                    credential_id: s.credential_id.clone(),
                    rp_id: s.rp_id.clone(),
                    hmac_salt: s.hmac_salt.clone(),
                    label: s.label.clone(),
                    added_at: s.added_at,
                })
                .collect(),
            Inner::V1(_) => Vec::new(),
        }
    }

    /// Enroll a passkey as an additional unlock method. Authorized by the
    /// passphrase (which also recovers the DEK); the first enrollment promotes a
    /// v1 keystore to v2. The passphrase slot is always retained.
    ///
    /// This only mutates the in-memory keystore — the caller must persist the
    /// result (atomically) for it to take effect.
    pub fn add_passkey(&mut self, passphrase: &[u8], enrollment: PasskeyEnrollment) -> Result<()> {
        let dek = match &self.0 {
            Inner::V1(v1) => {
                // Verifies the passphrase and yields the identity to re-wrap.
                let identity = v1.unlock(passphrase)?;
                let (v2, dek) = KeystoreV2::create_with_dek(&identity, passphrase, v1.kdf)?;
                self.0 = Inner::V2(v2);
                dek
            }
            Inner::V2(v2) => v2.unlock_dek_with_passphrase(passphrase)?,
        };
        match &mut self.0 {
            Inner::V2(v2) => v2.add_passkey(&dek, enrollment),
            // `add_passkey` always leaves `self` in the V2 state above.
            Inner::V1(_) => Err(Error::Format("keystore promotion failed")),
        }
    }

    /// Remove the passkey slot at `index`. Out of range ⇒ [`Error::Format`].
    /// There is deliberately no way to remove the passphrase slot.
    ///
    /// Mutates only the in-memory keystore — the caller must persist the result.
    pub fn remove_passkey(&mut self, index: usize) -> Result<()> {
        match &mut self.0 {
            Inner::V2(v2) if index < v2.passkeys.len() => {
                v2.passkeys.remove(index);
                Ok(())
            }
            Inner::V2(_) => Err(Error::Format("passkey slot index out of range")),
            Inner::V1(_) => Err(Error::Format("no passkeys are enrolled")),
        }
    }

    /// Decrypt and reconstruct the [`Identity`] using the `hmac-secret` output
    /// from the passkey enrolled at `slot_index`. A wrong secret surfaces as
    /// [`Error::Auth`].
    pub fn unlock_with_passkey(
        &self,
        slot_index: usize,
        hmac_output: &[u8; HMAC_SECRET_LEN],
    ) -> Result<Identity> {
        match &self.0 {
            Inner::V2(v2) => v2.unlock_with_passkey(slot_index, hmac_output.as_slice()),
            Inner::V1(_) => Err(Error::Format("no passkeys are enrolled")),
        }
    }
}

#[cfg(test)]
mod tests {
    // Inline test needs private-field access (the bundle ciphertext is not part
    // of the public API). The crate-level denies on unwrap/panic are relaxed
    // here, as they are for the integration tests under `tests/`.
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn enroll(secret: u8, cred: &[u8]) -> PasskeyEnrollment {
        PasskeyEnrollment {
            credential_id: cred.to_vec(),
            rp_id: "filesec.local".into(),
            hmac_salt: [secret ^ 0xa5; HMAC_SECRET_LEN],
            label: "k".into(),
            added_at: 0,
            hmac_output: Zeroizing::new([secret; HMAC_SECRET_LEN]),
        }
    }

    /// Enrolling more passkeys must never re-encrypt the secret bundle: the DEK
    /// and its ciphertext are fixed at creation, and only the `passkeys` list
    /// grows. (Re-sealing under the same DEK with a reused nonce would be a
    /// nonce-reuse bug.)
    #[test]
    fn adding_passkeys_never_reencrypts_the_bundle() {
        let id = Identity::generate("Z", 0).unwrap();
        let params = KdfParams {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let mut ks = KeystoreFile::create(&id, b"pw", params).unwrap();
        ks.add_passkey(b"pw", enroll(1, b"c0")).unwrap();
        let (n0, c0) = match &ks.0 {
            Inner::V2(v2) => (v2.bundle_nonce.clone(), v2.bundle_ct.clone()),
            Inner::V1(_) => panic!("expected v2 after enrollment"),
        };
        ks.add_passkey(b"pw", enroll(2, b"c1")).unwrap();
        match &ks.0 {
            Inner::V2(v2) => {
                assert_eq!(v2.bundle_nonce, n0, "bundle nonce must not change");
                assert_eq!(v2.bundle_ct, c0, "bundle ciphertext must not change");
                assert_eq!(v2.passkeys.len(), 2);
            }
            Inner::V1(_) => panic!("expected v2"),
        }
    }

    /// A passkey slot's public handles (credential id, rp id, hmac salt) are
    /// bound into the DEK-wrap AAD, so tampering with any of them makes the
    /// genuine `hmac-secret` unable to unwrap the DEK. Mutating the private slot
    /// field directly is the precise way to prove this.
    #[test]
    fn passkey_slot_metadata_is_aead_bound() {
        let id = Identity::generate("Eve", 5).unwrap();
        let params = KdfParams {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let mut ks = KeystoreFile::create(&id, b"pw", params).unwrap();
        let secret = [0x55u8; HMAC_SECRET_LEN];
        ks.add_passkey(b"pw", enroll(0x55, b"cred-xyz")).unwrap();
        // The genuine secret unlocks before tampering.
        assert!(ks.unlock_with_passkey(0, &secret).is_ok());

        // Flip one byte of the stored credential id; the recomputed wrap AAD no
        // longer matches what wrapped the DEK.
        match &mut ks.0 {
            Inner::V2(v2) => v2.passkeys[0].credential_id[0] ^= 0x01,
            Inner::V1(_) => panic!("expected v2"),
        }
        assert!(ks.unlock_with_passkey(0, &secret).is_err());
        // The independent passphrase slot still opens it.
        assert_eq!(ks.unlock(b"pw").unwrap().fingerprint(), id.fingerprint());
    }

    fn fast_params() -> KdfParams {
        KdfParams {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn excessive_params() -> KdfParams {
        KdfParams {
            m_cost: kdf::KdfPolicy::open().max_m_cost + 1,
            t_cost: 1,
            p_cost: 1,
        }
    }

    /// An exported backup decrypts back to the same identity (same fingerprint,
    /// name, and creation time) under the export passphrase.
    #[test]
    fn identity_backup_round_trips() {
        let id = Identity::generate("Alice", 1234).unwrap();
        let armored = export_identity_armored(&id, b"backup-pass", fast_params()).unwrap();
        assert!(armored.contains(BACKUP_ARMOR_BEGIN));
        let restored = import_identity_armored(&armored, b"backup-pass").unwrap();
        assert_eq!(restored.fingerprint(), id.fingerprint());
        assert_eq!(restored.name, "Alice");
        assert_eq!(restored.created_at, 1234);
    }

    /// A hybrid identity's post-quantum seeds survive the backup round-trip, so
    /// the restored identity keeps the same (PQC-folded) fingerprint.
    #[cfg(feature = "pqc")]
    #[test]
    fn hybrid_identity_backup_round_trips() {
        let id = Identity::generate_hybrid("Bob", 99).unwrap();
        assert!(id.is_hybrid_capable());
        let armored = export_identity_armored(&id, b"backup-pass", fast_params()).unwrap();
        let restored = import_identity_armored(&armored, b"backup-pass").unwrap();
        assert!(restored.is_hybrid_capable());
        assert_eq!(restored.fingerprint(), id.fingerprint());
    }

    /// The wrong export passphrase is rejected as [`Error::BadPassphrase`].
    #[test]
    fn identity_backup_rejects_wrong_passphrase() {
        let id = Identity::generate("Alice", 0).unwrap();
        let armored = export_identity_armored(&id, b"right-pass", fast_params()).unwrap();
        assert!(matches!(
            import_identity_armored(&armored, b"wrong-pass"),
            Err(Error::BadPassphrase)
        ));
    }

    /// Flipping a byte of the ciphertext makes the AEAD reject it (tamper-evident).
    #[test]
    fn identity_backup_detects_tampering() {
        let id = Identity::generate("Alice", 0).unwrap();
        let armored = export_identity_armored(&id, b"backup-pass", fast_params()).unwrap();
        // Decode, flip a ciphertext byte, re-encode, and confirm it no longer opens.
        let body: String = armored
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let mut framed = data_encoding::BASE64.decode(body.as_bytes()).unwrap();
        let last = framed.len() - 1;
        framed[last] ^= 0x01;
        let tampered = format!(
            "{BACKUP_ARMOR_BEGIN}\n{}\n{BACKUP_ARMOR_END}\n",
            data_encoding::BASE64.encode(&framed)
        );
        assert!(import_identity_armored(&tampered, b"backup-pass").is_err());
    }

    #[test]
    fn keystore_parser_rejects_excessive_v1_kdf_params() {
        let v1 = KeystoreV1 {
            version: VERSION_V1,
            kdf: excessive_params(),
            salt: vec![0u8; SALT_LEN],
            nonce: vec![0u8; aead::NONCE_LEN],
            ciphertext: vec![0u8; aead::TAG_LEN],
        };
        let bytes = codec::to_vec(&v1).unwrap();
        assert!(matches!(
            KeystoreFile::from_bytes(&bytes),
            Err(Error::KdfParams(_))
        ));
    }

    #[test]
    fn identity_backup_import_rejects_excessive_kdf_params() {
        let backup = IdentityBackupV1 {
            version: VERSION_BACKUP_V1,
            kdf: excessive_params(),
            salt: vec![0u8; SALT_LEN],
            nonce: vec![0u8; aead::NONCE_LEN],
            ciphertext: vec![0u8; aead::TAG_LEN],
        };
        let body = codec::to_vec(&backup).unwrap();
        let mut framed = Vec::with_capacity(MAGIC_BACKUP.len() + 2 + body.len());
        framed.extend_from_slice(MAGIC_BACKUP);
        framed.extend_from_slice(&VERSION_BACKUP_V1.to_be_bytes());
        framed.extend_from_slice(&body);
        let armored = format!(
            "{BACKUP_ARMOR_BEGIN}\n{}\n{BACKUP_ARMOR_END}\n",
            data_encoding::BASE64.encode(&framed)
        );
        assert!(matches!(
            import_identity_armored(&armored, b"backup-pass"),
            Err(Error::KdfParams(_))
        ));
    }

    /// A backup and a live keystore are distinct artifacts: neither parser accepts
    /// the other's bytes (distinct magic / AAD domain separation).
    #[test]
    fn backup_and_keystore_are_not_interchangeable() {
        let id = Identity::generate("Alice", 0).unwrap();
        let armored = export_identity_armored(&id, b"pw", fast_params()).unwrap();

        // A backup blob is not a keystore.
        let body: String = armored
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let backup_bytes = data_encoding::BASE64.decode(body.as_bytes()).unwrap();
        assert!(KeystoreFile::from_bytes(&backup_bytes).is_err());

        // A keystore is not a backup (feed its base64 to the backup parser).
        let ks = KeystoreFile::create(&id, b"pw", fast_params()).unwrap();
        let ks_armored = format!(
            "{BACKUP_ARMOR_BEGIN}\n{}\n{BACKUP_ARMOR_END}\n",
            data_encoding::BASE64.encode(&ks.to_bytes().unwrap())
        );
        assert!(matches!(
            import_identity_armored(&ks_armored, b"pw"),
            Err(Error::Format(_))
        ));
    }
}
