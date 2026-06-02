//! User identities: long-term keypairs, public identity, and fingerprints.
//!
//! An [`Identity`] holds the user's private signing (Ed25519) and agreement
//! (X25519) keys. Its [`PublicIdentity`] is the shareable half, identified by a
//! BLAKE3 [`PublicIdentity::fingerprint`] rendered as a human-comparable
//! [`PublicIdentity::safety_number`].

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::kem::{self, KemKeyPair};
use crate::sign::{self, SignKeyPair};
use crate::{codec, util};

const FPR_CONTEXT: &[u8] = b"FileSec identity fingerprint v1";
const ARMOR_BEGIN: &str = "-----BEGIN FILESEC PUBLIC KEY-----";
const ARMOR_END: &str = "-----END FILESEC PUBLIC KEY-----";

/// The public, shareable half of an identity.
///
/// A classical identity carries only the Ed25519 (`sign_public`) and X25519
/// (`kem_public`) keys. A **hybrid** identity additionally carries an
/// ML-DSA-65 verifying key and an ML-KEM-768 encapsulation key. The post-quantum
/// fields are serialized only when present (`skip_serializing_if`), so a
/// classical `.fsecpub` is byte-for-byte unchanged and old keys still parse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIdentity {
    /// Advisory display name (not bound into the fingerprint).
    pub name: String,
    /// Unix creation time (advisory).
    pub created_at: i64,
    /// Ed25519 verifying key.
    pub sign_public: [u8; sign::PUBLIC_LEN],
    /// X25519 agreement public key.
    pub kem_public: [u8; kem::PUBLIC_LEN],
    /// ML-DSA-65 verifying key (hybrid identities only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mldsa_public: Option<Vec<u8>>,
    /// ML-KEM-768 encapsulation key (hybrid identities only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mlkem_public: Option<Vec<u8>>,
}

impl PublicIdentity {
    /// 32-byte BLAKE3 fingerprint over the public keys. The name is deliberately
    /// excluded — it is advisory and mutable, while the fingerprint is the
    /// stable cryptographic identity.
    ///
    /// The post-quantum keys are folded in **only when present**, each behind a
    /// distinct domain tag. A classical identity therefore hashes exactly the
    /// same bytes as before (the fingerprint, and thus the safety number, is
    /// unchanged), while a hybrid identity's fingerprint commits to all four
    /// public keys — so verifying a hybrid contact's safety number out-of-band
    /// authenticates its ML-DSA and ML-KEM keys too.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(FPR_CONTEXT);
        h.update(&self.sign_public);
        h.update(&self.kem_public);
        if let Some(m) = &self.mldsa_public {
            h.update(b"ml-dsa-65");
            h.update(m);
        }
        if let Some(m) = &self.mlkem_public {
            h.update(b"ml-kem-768");
            h.update(m);
        }
        *h.finalize().as_bytes()
    }

    /// Whether this identity carries the post-quantum keys needed to take part
    /// in a hybrid (`0x0101`) container — both an ML-DSA and an ML-KEM key.
    #[must_use]
    pub fn is_hybrid_capable(&self) -> bool {
        self.mldsa_public.is_some() && self.mlkem_public.is_some()
    }

    /// Full fingerprint as lowercase hex.
    #[must_use]
    pub fn fingerprint_hex(&self) -> String {
        util::hex(&self.fingerprint())
    }

    /// Fingerprint rendered as a grouped base32 safety number for out-of-band
    /// verification.
    #[must_use]
    pub fn safety_number(&self) -> String {
        util::safety_number(&self.fingerprint())
    }

    /// Whether `candidate` — as a human typed or pasted it while comparing
    /// out-of-band, with arbitrary spacing, dashes, or letter case — equals this
    /// identity's safety number. Empty/whitespace-only input never matches, so a
    /// blank field can't be mistaken for a confirmed comparison. Both values are
    /// public, so a plain (non-constant-time) comparison is fine here.
    #[must_use]
    pub fn safety_number_matches(&self, candidate: &str) -> bool {
        let got = util::normalize_safety_number(candidate);
        !got.is_empty() && got == util::normalize_safety_number(&self.safety_number())
    }

    /// Encode as compact CBOR bytes (the `.fsecpub` file body).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        codec::to_vec(self)
    }

    /// Decode from CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        codec::from_slice(bytes)
    }

    /// Encode as an ASCII-armored block for pasting into chat/email.
    pub fn to_armored(&self) -> Result<String> {
        let b64 = data_encoding::BASE64.encode(&self.to_bytes()?);
        let mut out = String::new();
        out.push_str(ARMOR_BEGIN);
        out.push('\n');
        for line in b64.as_bytes().chunks(64) {
            // chunks of base64 are valid ASCII by construction.
            out.push_str(&String::from_utf8_lossy(line));
            out.push('\n');
        }
        out.push_str(ARMOR_END);
        out.push('\n');
        Ok(out)
    }

    /// Decode an ASCII-armored block (tolerant of surrounding whitespace).
    pub fn from_armored(text: &str) -> Result<Self> {
        let mut body = String::new();
        let mut in_block = false;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed == ARMOR_BEGIN {
                in_block = true;
                continue;
            }
            if trimmed == ARMOR_END {
                break;
            }
            if in_block {
                body.push_str(trimmed);
            }
        }
        if body.is_empty() {
            return Err(Error::Format("no armored public key found"));
        }
        let bytes = data_encoding::BASE64
            .decode(body.as_bytes())
            .map_err(|_| Error::Format("invalid base64 in armored key"))?;
        Self::from_bytes(&bytes)
    }

    /// Parse a public key from text a human pasted, being forgiving about what
    /// exactly they copied. Accepts a full armored block, or a bare base64 body
    /// with the armor lines and/or surrounding whitespace missing (people often
    /// copy just the middle, or lose the `-----` lines to a chat client). Tries
    /// the strict armored form first, then falls back to decoding the remaining
    /// text as base64 (padded or not).
    pub fn from_pasted(text: &str) -> Result<Self> {
        if let Ok(id) = Self::from_armored(text) {
            return Ok(id);
        }
        // Strip any armor delimiter lines and whitespace, then treat the rest as
        // a bare base64 body.
        let body: String = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("-----"))
            .collect();
        if body.is_empty() {
            return Err(Error::Format("no public key found"));
        }
        let bytes = data_encoding::BASE64
            .decode(body.as_bytes())
            .or_else(|_| data_encoding::BASE64_NOPAD.decode(body.as_bytes()))
            .map_err(|_| Error::Format("not a recognizable public key"))?;
        Self::from_bytes(&bytes)
    }
}

/// Post-quantum key material attached to an identity (an ML-DSA signing key or
/// an ML-KEM agreement key).
///
/// Held as raw bytes — the keypair `seed` (zeroized on drop) plus the cached
/// `public` — so the keystore can persist it and any build can load/forward it;
/// the actual lattice operations live in [`crate::mldsa`]/[`crate::mlkem`]
/// behind the `pqc` feature.
#[derive(Clone)]
pub(crate) struct PqcMaterial {
    pub(crate) public: Vec<u8>,
    pub(crate) seed: Zeroizing<Vec<u8>>,
}

/// A full identity, including secret keys. Secret material lives inside the
/// underlying keypair types (and [`PqcMaterial`]), which zeroize on drop.
pub struct Identity {
    /// Advisory display name.
    pub name: String,
    /// Unix creation time.
    pub created_at: i64,
    sign: SignKeyPair,
    kem: KemKeyPair,
    /// ML-DSA-65 signing material (hybrid identities only).
    mldsa: Option<PqcMaterial>,
    /// ML-KEM-768 agreement material (hybrid identities only).
    mlkem: Option<PqcMaterial>,
}

impl Identity {
    /// Generate a brand-new classical identity with fresh keypairs.
    pub fn generate(name: impl Into<String>, created_at: i64) -> Result<Self> {
        Ok(Self {
            name: name.into(),
            created_at,
            sign: SignKeyPair::generate()?,
            kem: KemKeyPair::generate()?,
            mldsa: None,
            mlkem: None,
        })
    }

    /// Generate a brand-new **hybrid** identity: the classical Ed25519/X25519
    /// keys plus fresh ML-DSA-65 and ML-KEM-768 keypairs. Such an identity can
    /// take part in classical *and* hybrid (`0x0101`) containers.
    #[cfg(feature = "pqc")]
    pub fn generate_hybrid(name: impl Into<String>, created_at: i64) -> Result<Self> {
        let (mldsa_public, mldsa_seed) = crate::mldsa::generate()?;
        let (mlkem_public, mlkem_seed) = crate::mlkem::generate()?;
        Ok(Self {
            name: name.into(),
            created_at,
            sign: SignKeyPair::generate()?,
            kem: KemKeyPair::generate()?,
            mldsa: Some(PqcMaterial {
                public: mldsa_public,
                seed: Zeroizing::new(mldsa_seed.to_vec()),
            }),
            mlkem: Some(PqcMaterial {
                public: mlkem_public,
                seed: Zeroizing::new(mlkem_seed.to_vec()),
            }),
        })
    }

    /// Upgrade a classical identity to **hybrid** in place: keep the existing
    /// Ed25519 and X25519 keys exactly, and add fresh ML-DSA-65 + ML-KEM-768
    /// keypairs. This is the basis of the "migrate to post-quantum" flow.
    ///
    /// Because the post-quantum keys are folded into the fingerprint, the result
    /// has a **new fingerprint** (and safety number) even though the classical
    /// keys are unchanged — so the caller must re-encrypt anything addressed to
    /// the old fingerprint and have contacts re-verify. Errors if the identity is
    /// already hybrid.
    #[cfg(feature = "pqc")]
    pub fn upgraded_to_hybrid(&self) -> Result<Self> {
        if self.mldsa.is_some() || self.mlkem.is_some() {
            return Err(Error::Vault("identity is already post-quantum".into()));
        }
        let (mldsa_public, mldsa_seed) = crate::mldsa::generate()?;
        let (mlkem_public, mlkem_seed) = crate::mlkem::generate()?;
        Ok(Self {
            name: self.name.clone(),
            created_at: self.created_at,
            // Rebuild the classical keypairs from their own secret bytes so the
            // Ed25519/X25519 keys (and thus the classical half of the identity)
            // are preserved byte-for-byte.
            sign: SignKeyPair::from_secret_bytes(*self.sign.secret_bytes()),
            kem: KemKeyPair::from_secret_bytes(*self.kem.secret_bytes()),
            mldsa: Some(PqcMaterial {
                public: mldsa_public,
                seed: Zeroizing::new(mldsa_seed.to_vec()),
            }),
            mlkem: Some(PqcMaterial {
                public: mlkem_public,
                seed: Zeroizing::new(mlkem_seed.to_vec()),
            }),
        })
    }

    /// Reconstruct a classical identity from stored secret seeds (used by the
    /// keystore on unlock).
    pub fn from_secrets(
        name: String,
        created_at: i64,
        sign_secret: [u8; sign::SECRET_LEN],
        kem_secret: [u8; kem::SECRET_LEN],
    ) -> Self {
        Self::from_parts(name, created_at, sign_secret, kem_secret, None, None)
    }

    /// Reconstruct an identity (classical or hybrid) from stored secrets. Each
    /// post-quantum part is `(public_bytes, seed_bytes)`; pass `None` for a
    /// classical identity. Used by the keystore on unlock.
    pub(crate) fn from_parts(
        name: String,
        created_at: i64,
        sign_secret: [u8; sign::SECRET_LEN],
        kem_secret: [u8; kem::SECRET_LEN],
        mldsa: Option<(Vec<u8>, Vec<u8>)>,
        mlkem: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Self {
        let into_material = |m: Option<(Vec<u8>, Vec<u8>)>| {
            m.map(|(public, seed)| PqcMaterial {
                public,
                seed: Zeroizing::new(seed),
            })
        };
        Self {
            name,
            created_at,
            sign: SignKeyPair::from_secret_bytes(sign_secret),
            kem: KemKeyPair::from_secret_bytes(kem_secret),
            mldsa: into_material(mldsa),
            mlkem: into_material(mlkem),
        }
    }

    /// The shareable public identity (includes the post-quantum keys for a
    /// hybrid identity).
    #[must_use]
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            name: self.name.clone(),
            created_at: self.created_at,
            sign_public: self.sign.public_bytes(),
            kem_public: self.kem.public_bytes(),
            mldsa_public: self.mldsa.as_ref().map(|m| m.public.clone()),
            mlkem_public: self.mlkem.as_ref().map(|m| m.public.clone()),
        }
    }

    /// This identity's fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.public().fingerprint()
    }

    /// Sign a message with the Ed25519 key.
    pub fn sign(&self, message: &[u8]) -> [u8; sign::SIGNATURE_LEN] {
        self.sign.sign(message)
    }

    /// Recipient-side X25519 agreement against a sender ephemeral public key.
    pub fn agree(&self, ephemeral_public: &[u8; kem::PUBLIC_LEN]) -> Result<Zeroizing<[u8; 32]>> {
        self.kem.agree(ephemeral_public)
    }

    /// X25519 agreement public key.
    #[must_use]
    pub fn kem_public(&self) -> [u8; kem::PUBLIC_LEN] {
        self.kem.public_bytes()
    }

    /// Ed25519 verifying key.
    #[must_use]
    pub fn sign_public(&self) -> [u8; sign::PUBLIC_LEN] {
        self.sign.public_bytes()
    }

    pub(crate) fn sign_secret(&self) -> Zeroizing<[u8; sign::SECRET_LEN]> {
        self.sign.secret_bytes()
    }

    pub(crate) fn kem_secret(&self) -> Zeroizing<[u8; kem::SECRET_LEN]> {
        self.kem.secret_bytes()
    }

    /// ML-DSA-65 verifying key, if this is a hybrid identity.
    #[must_use]
    pub fn mldsa_public(&self) -> Option<&[u8]> {
        self.mldsa.as_ref().map(|m| m.public.as_slice())
    }

    /// ML-KEM-768 encapsulation key, if this is a hybrid identity.
    #[must_use]
    pub fn mlkem_public(&self) -> Option<&[u8]> {
        self.mlkem.as_ref().map(|m| m.public.as_slice())
    }

    /// Whether this identity carries the post-quantum keys needed for a hybrid
    /// (`0x0101`) container.
    #[must_use]
    pub fn is_hybrid_capable(&self) -> bool {
        self.mldsa.is_some() && self.mlkem.is_some()
    }

    /// Stored ML-DSA seed (for keystore persistence).
    pub(crate) fn mldsa_secret(&self) -> Option<&[u8]> {
        self.mldsa.as_ref().map(|m| m.seed.as_slice())
    }

    /// Stored ML-KEM seed (for keystore persistence).
    pub(crate) fn mlkem_secret(&self) -> Option<&[u8]> {
        self.mlkem.as_ref().map(|m| m.seed.as_slice())
    }

    /// Sign `message` with the ML-DSA-65 key. Errors with
    /// [`Error::MissingPqcKey`] if this is a classical identity.
    #[cfg(feature = "pqc")]
    pub fn sign_pqc(&self, message: &[u8]) -> Result<Vec<u8>> {
        let m = self
            .mldsa
            .as_ref()
            .ok_or(Error::MissingPqcKey("identity has no ML-DSA key"))?;
        crate::mldsa::sign(&m.seed, message)
    }

    /// Recipient-side ML-KEM-768 decapsulation of `ciphertext`. Errors with
    /// [`Error::MissingPqcKey`] if this is a classical identity.
    #[cfg(feature = "pqc")]
    pub fn mlkem_decapsulate(
        &self,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; crate::mlkem::SHARED_LEN]>> {
        let m = self
            .mlkem
            .as_ref()
            .ok_or(Error::MissingPqcKey("identity has no ML-KEM key"))?;
        crate::mlkem::decapsulate(&m.seed, ciphertext)
    }
}
