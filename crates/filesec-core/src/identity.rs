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
}

impl PublicIdentity {
    /// 32-byte BLAKE3 fingerprint over the public keys. The name is deliberately
    /// excluded — it is advisory and mutable, while the fingerprint is the
    /// stable cryptographic identity.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(FPR_CONTEXT);
        h.update(&self.sign_public);
        h.update(&self.kem_public);
        *h.finalize().as_bytes()
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

/// A full identity, including secret keys. Secret material lives inside the
/// underlying keypair types, which zeroize on drop.
pub struct Identity {
    /// Advisory display name.
    pub name: String,
    /// Unix creation time.
    pub created_at: i64,
    sign: SignKeyPair,
    kem: KemKeyPair,
}

impl Identity {
    /// Generate a brand-new identity with fresh keypairs.
    pub fn generate(name: impl Into<String>, created_at: i64) -> Result<Self> {
        Ok(Self {
            name: name.into(),
            created_at,
            sign: SignKeyPair::generate()?,
            kem: KemKeyPair::generate()?,
        })
    }

    /// Reconstruct from stored secret seeds (used by the keystore on unlock).
    pub fn from_secrets(
        name: String,
        created_at: i64,
        sign_secret: [u8; sign::SECRET_LEN],
        kem_secret: [u8; kem::SECRET_LEN],
    ) -> Self {
        Self {
            name,
            created_at,
            sign: SignKeyPair::from_secret_bytes(sign_secret),
            kem: KemKeyPair::from_secret_bytes(kem_secret),
        }
    }

    /// The shareable public identity.
    #[must_use]
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            name: self.name.clone(),
            created_at: self.created_at,
            sign_public: self.sign.public_bytes(),
            kem_public: self.kem.public_bytes(),
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
}
