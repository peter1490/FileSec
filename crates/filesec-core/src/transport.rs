//! Direct (server-less) transfer channel: an authenticated, forward-secret
//! handshake plus an AEAD record layer, built only from FileSec's own
//! primitives (X25519 / Ed25519 / BLAKE3 / XChaCha20-Poly1305).
//!
//! This module is **transport-agnostic**: it consumes and produces opaque byte
//! buffers and never touches a socket. The TCP plumbing, NAT mapping, and UI live
//! in `filesec-gui` behind its own `net` feature. Keeping the cryptography here
//! means it stays under the crate's `#![forbid(unsafe_code)]` /
//! `deny(unwrap/expect/panic)` discipline and is unit-tested offline.
//!
//! # Roles
//!
//! The **initiator** is the party that dials out — the *file sender*. The
//! **responder** is the one that listens — the *file receiver*. After the
//! handshake the initiator sends an [`RecordType::Offer`], the responder replies
//! with an [`RecordType::OfferDecision`], then the initiator streams
//! [`RecordType::Data`] records and a final [`RecordType::Done`].
//!
//! # Handshake (SIGMA-I, 1.5 round trips)
//!
//! ```text
//! initiator I ── Hello   ─────────────▶ responder R   (I's ephemeral + nonce; no identity yet)
//! initiator I ◀─ Auth    ────────────── responder R   (R's ephemeral + nonce + identity + signature)
//! initiator I ── Confirm ─────────────▶ responder R   (I's identity + signature, AEAD-sealed)
//!                  … channel open, records flow …
//! ```
//!
//! Both sides contribute a fresh ephemeral X25519 key (forward secrecy) and a
//! 32-byte nonce. An *ephemeral transcript hash* `th0` commits to the protocol
//! version, suite, both ephemerals, both nonces, and a commitment to the optional
//! pairing code. Authentication is by Ed25519 **signature over `th0` and the
//! signer's identity keys** (SIGMA's "sign the key exchange, bind the identity"),
//! never by a static DH — so compromising a party's long-term *agreement* key
//! cannot impersonate a peer (KCI resistance). Identities are revealed under the
//! session key, so the initiator stays anonymous until it has verified the
//! responder.
//!
//! Session keys are derived from the ephemeral↔ephemeral DH bound to `th0`:
//! `k = BLAKE3-derive_key(label, ee_dh ‖ th0)`, one key per direction. The
//! `Confirm` message is sealed under the initiator→responder key, so it opens
//! only if both sides derived the same `th0` and DH — that is the key
//! confirmation that closes the SIGMA loop.
//!
//! # What each side checks
//!
//! * The **initiator** verifies the responder's signature, then checks the
//!   responder's fingerprint equals the expected contact's (constant-time);
//!   "right address, wrong identity" aborts with [`Error::PeerIdentityMismatch`].
//! * The **responder** decrypts `Confirm`, verifies the initiator's signature, and
//!   hands the caller the authenticated peer fingerprint via [`PeerAuth`]; the GUI
//!   then enforces that this peer is a `Trust::Verified` contact.
//!
//! # Pairing code (per-transfer second factor)
//!
//! An optional one-time code is folded into `th0` via
//! `BLAKE3("FileSec p2p pairing v1" ‖ code)`. Because it is inside the signed
//! transcript *and* the key schedule, a mismatch makes the responder's signature
//! fail to verify on the initiator (and `Confirm` fail to open on the responder):
//! the session simply cannot form. When the peer identity otherwise matches, such
//! a failure is reported as [`Error::PairingCodeMismatch`] as a best-effort hint.
//! A short numeric code is low entropy and, against an attacker who *already*
//! controls a valid verified identity, offline-guessable; it is a layered second
//! factor on top of the public-key identity gate, not a standalone authenticator.
//!
//! # Record layer
//!
//! After the handshake, each application record is an independent AEAD frame:
//! nonce = `direction_byte ‖ 0…0 ‖ counter_be64`, AAD = `th0 ‖ type ‖ counter`,
//! with a strictly increasing per-direction counter that is *not* transmitted.
//! A dropped, reordered, duplicated, or tampered frame therefore fails to open
//! (surfaced as [`Error::Auth`]). The payload carried in `Data` records is the
//! existing signed + recipient-encrypted `.fsec` container, so the file is sealed
//! end-to-end independent of this channel (defense in depth).
//!
//! # Threat-model boundaries (not protected)
//!
//! Traffic analysis (record sizes and timing — hence the file-size class — are
//! visible); the responder's address being learned by anyone who completes
//! `Hello`; denial-of-service from unauthenticated dialers (mitigated only by the
//! caller's handshake timeouts and single-listener policy); endpoint compromise;
//! and the correctness of the user's out-of-band safety-number verification, which
//! is the trust root. There is no post-compromise security / ratcheting — one
//! ephemeral DH per transfer, which suffices for a one-shot transfer.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::identity::{Identity, PublicIdentity};
use crate::kem::EphemeralKeyPair;
use crate::secret::{ct_eq, random_array, SymKey};
use crate::{aead, codec, kdf, sign};

/// Wire magic: ASCII `FSECP2P` plus a one-byte format tag.
const MAGIC: [u8; 8] = *b"FSECP2P\x01";
/// Handshake protocol version (bumped on any breaking change to the messages).
const PROTO_VERSION: u16 = 1;
/// The single classical cipher-suite this version offers (XChaCha20-Poly1305 /
/// X25519 / Ed25519 / BLAKE3). Named atomically and bound into `th0` so it cannot
/// be downgraded in-band.
const SUITE_CLASSIC: u16 = 0x0001;

/// Domain labels (versioned, in the crate's `"FileSec … v1"` family).
const TRANSCRIPT_LABEL: &[u8] = b"FileSec p2p transcript v1";
const PAIRING_LABEL: &[u8] = b"FileSec p2p pairing v1";
const RESPONDER_AUTH_LABEL: &[u8] = b"FileSec p2p responder auth v1";
const INITIATOR_AUTH_LABEL: &[u8] = b"FileSec p2p initiator auth v1";
const SESSION_KEY_I2R: &str = "FileSec p2p session key i2r v1";
const SESSION_KEY_R2I: &str = "FileSec p2p session key r2i v1";

/// Direction byte mixed into every record nonce so a frame can never be reflected
/// back to its sender under the same key/counter.
const DIR_I2R: u8 = 0x01;
const DIR_R2I: u8 = 0x02;
/// The `Confirm` message occupies the initiator→responder record at counter 0
/// (type 0); application records therefore start at counter 1.
const CONFIRM_CTR: u64 = 0;
const CONFIRM_TYPE: u8 = 0;
const FIRST_RECORD_CTR: u64 = 1;

// ---------------------------------------------------------------------------
// Wire messages (CBOR). Fixed-size keys are arrays; the 64-byte Ed25519
// signatures travel as `Vec<u8>` (ciborium has no 64-array impl) and are length-
// checked on read, mirroring how the container stores variable-length fields.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct HelloMsg {
    magic: [u8; 8],
    version: u16,
    suite: u16,
    i_ephemeral: [u8; 32],
    i_nonce: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct AuthMsg {
    r_ephemeral: [u8; 32],
    r_nonce: [u8; 32],
    r_identity: PublicIdentity,
    r_sig: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct ConfirmMsg {
    sealed: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct ConfirmInner {
    i_identity: PublicIdentity,
    i_sig: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Commit to the optional pairing code (a fixed "absent" marker when `None`).
fn pairing_commit(code: Option<&[u8]>) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(PAIRING_LABEL);
    match code {
        Some(c) => {
            h.update(&[1u8]);
            h.update(c);
        }
        None => {
            h.update(&[0u8]);
        }
    }
    *h.finalize().as_bytes()
}

/// The ephemeral transcript hash: everything both sides know before identities
/// are exchanged. Signatures and session keys are bound to this value.
#[allow(clippy::too_many_arguments)]
fn transcript0(
    version: u16,
    suite: u16,
    i_ephemeral: &[u8; 32],
    i_nonce: &[u8; 32],
    r_ephemeral: &[u8; 32],
    r_nonce: &[u8; 32],
    pairing_commit: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(TRANSCRIPT_LABEL);
    h.update(&version.to_be_bytes());
    h.update(&suite.to_be_bytes());
    h.update(i_ephemeral);
    h.update(i_nonce);
    h.update(r_ephemeral);
    h.update(r_nonce);
    h.update(pairing_commit);
    *h.finalize().as_bytes()
}

/// The message the responder signs: `th0` plus the responder's own identity keys.
fn responder_sig_msg(th0: &[u8; 32], r_sign_pub: &[u8; 32], r_kem_pub: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(RESPONDER_AUTH_LABEL);
    h.update(th0);
    h.update(r_sign_pub);
    h.update(r_kem_pub);
    *h.finalize().as_bytes()
}

/// The message the initiator signs: `th0` plus **both** parties' identity keys, so
/// the initiator explicitly commits to talking to this responder (unknown-key-share
/// resistance).
fn initiator_sig_msg(
    th0: &[u8; 32],
    r_sign_pub: &[u8; 32],
    r_kem_pub: &[u8; 32],
    i_sign_pub: &[u8; 32],
    i_kem_pub: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(INITIATOR_AUTH_LABEL);
    h.update(th0);
    h.update(r_sign_pub);
    h.update(r_kem_pub);
    h.update(i_sign_pub);
    h.update(i_kem_pub);
    *h.finalize().as_bytes()
}

/// Derive the two directional session keys from the ephemeral DH bound to `th0`.
fn derive_session_keys(ee_dh: &[u8; 32], th0: &[u8; 32]) -> (SymKey, SymKey) {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(ee_dh);
    ikm.extend_from_slice(th0);
    let k_i2r = kdf::derive_subkey(SESSION_KEY_I2R, &ikm);
    let k_r2i = kdf::derive_subkey(SESSION_KEY_R2I, &ikm);
    (k_i2r, k_r2i)
}

/// Build a record nonce: `direction ‖ 0…0 ‖ counter_be64` (24 bytes for XChaCha).
fn record_nonce(direction: u8, counter: u64) -> [u8; aead::NONCE_LEN] {
    let mut nonce = [0u8; aead::NONCE_LEN];
    nonce[0] = direction;
    nonce[aead::NONCE_LEN - 8..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Build a record's associated data: `th0 ‖ type ‖ counter_be64`.
fn record_aad(th0: &[u8; 32], record_type: u8, counter: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 1 + 8);
    aad.extend_from_slice(th0);
    aad.push(record_type);
    aad.extend_from_slice(&counter.to_be_bytes());
    aad
}

/// Parse a fixed-size array from a slice, mapping a wrong length to a protocol error.
fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    <[u8; N]>::try_from(bytes).map_err(|_| Error::HandshakeProtocol("wrong field length"))
}

// ---------------------------------------------------------------------------
// Record types
// ---------------------------------------------------------------------------

/// The kind of application record carried over an open [`Session`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordType {
    /// The sender's transfer offer (filename, size, …) — initiator → responder.
    Offer,
    /// The receiver's accept/reject decision — responder → initiator.
    OfferDecision,
    /// A chunk of the encrypted `.fsec` payload — initiator → responder.
    Data,
    /// End-of-transfer marker — initiator → responder.
    Done,
}

impl RecordType {
    fn to_byte(self) -> u8 {
        match self {
            RecordType::Offer => 1,
            RecordType::OfferDecision => 2,
            RecordType::Data => 3,
            RecordType::Done => 4,
        }
    }

    fn from_byte(b: u8) -> Result<Self> {
        match b {
            1 => Ok(RecordType::Offer),
            2 => Ok(RecordType::OfferDecision),
            3 => Ok(RecordType::Data),
            4 => Ok(RecordType::Done),
            _ => Err(Error::HandshakeProtocol("unknown record type")),
        }
    }
}

// ---------------------------------------------------------------------------
// Open session (record layer)
// ---------------------------------------------------------------------------

/// An authenticated, forward-secret channel established by the handshake. Records
/// are sealed/opened with strictly increasing per-direction counters, so any
/// drop, reorder, duplication, or tampering is detected ([`Error::Auth`]).
pub struct Session {
    send_key: SymKey,
    recv_key: SymKey,
    send_dir: u8,
    recv_dir: u8,
    send_ctr: u64,
    recv_ctr: u64,
    th0: [u8; 32],
}

impl Session {
    fn for_initiator(k_i2r: SymKey, k_r2i: SymKey, th0: [u8; 32]) -> Self {
        Self {
            send_key: k_i2r,
            recv_key: k_r2i,
            send_dir: DIR_I2R,
            recv_dir: DIR_R2I,
            send_ctr: FIRST_RECORD_CTR,
            recv_ctr: FIRST_RECORD_CTR,
            th0,
        }
    }

    fn for_responder(k_i2r: SymKey, k_r2i: SymKey, th0: [u8; 32]) -> Self {
        Self {
            send_key: k_r2i,
            recv_key: k_i2r,
            send_dir: DIR_R2I,
            recv_dir: DIR_I2R,
            send_ctr: FIRST_RECORD_CTR,
            recv_ctr: FIRST_RECORD_CTR,
            th0,
        }
    }

    /// Seal one application record, advancing the send counter. The returned frame
    /// is `type_byte ‖ ciphertext`; the type is also bound into the AAD, so a
    /// tampered type byte fails to open.
    pub fn seal_record(&mut self, record_type: RecordType, plaintext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.send_ctr;
        let nonce = record_nonce(self.send_dir, counter);
        let aad = record_aad(&self.th0, record_type.to_byte(), counter);
        let ciphertext = aead::seal(&self.send_key, &nonce, &aad, plaintext)?;
        self.send_ctr = self
            .send_ctr
            .checked_add(1)
            .ok_or(Error::HandshakeProtocol("record counter overflow"))?;
        let mut frame = Vec::with_capacity(1 + ciphertext.len());
        frame.push(record_type.to_byte());
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    /// Open one application record, advancing the receive counter. Returns the
    /// record type (read from the leading byte, but authenticated via the AAD) and
    /// the plaintext. Fails with [`Error::Auth`] on any drop / reorder / tamper.
    pub fn open_record(&mut self, frame: &[u8]) -> Result<(RecordType, Zeroizing<Vec<u8>>)> {
        let (type_byte, ciphertext) = frame
            .split_first()
            .ok_or(Error::HandshakeProtocol("empty record"))?;
        let record_type = RecordType::from_byte(*type_byte)?;
        let counter = self.recv_ctr;
        let nonce = record_nonce(self.recv_dir, counter);
        let aad = record_aad(&self.th0, record_type.to_byte(), counter);
        let plaintext = aead::open(&self.recv_key, &nonce, &aad, ciphertext)?;
        self.recv_ctr = self
            .recv_ctr
            .checked_add(1)
            .ok_or(Error::HandshakeProtocol("record counter overflow"))?;
        Ok((record_type, Zeroizing::new(plaintext)))
    }
}

// ---------------------------------------------------------------------------
// Authenticated peer (responder's view of the initiator)
// ---------------------------------------------------------------------------

/// The cryptographically authenticated initiator, returned to the responder so it
/// can enforce its contact-book / `Trust::Verified` policy.
pub struct PeerAuth {
    /// The initiator's long-term identity fingerprint (the safety number).
    pub fingerprint: [u8; 32],
    /// The initiator's full public identity (as presented over the channel).
    pub identity: PublicIdentity,
}

// ---------------------------------------------------------------------------
// Initiator (file sender)
// ---------------------------------------------------------------------------

/// The dialing side of the handshake (the file sender).
pub struct Initiator<'a> {
    identity: &'a Identity,
    ephemeral: EphemeralKeyPair,
    nonce: [u8; 32],
    expected_peer_fpr: [u8; 32],
    pairing_commit: [u8; 32],
    code_set: bool,
}

impl<'a> Initiator<'a> {
    /// Begin a handshake toward the contact identified by `expected_peer_fpr`,
    /// optionally gated by a normalized one-time `pairing_code`.
    pub fn new(
        identity: &'a Identity,
        expected_peer_fpr: [u8; 32],
        pairing_code: Option<&[u8]>,
    ) -> Result<Self> {
        Ok(Self {
            identity,
            ephemeral: EphemeralKeyPair::generate()?,
            nonce: random_array::<32>()?,
            expected_peer_fpr,
            pairing_commit: pairing_commit(pairing_code),
            code_set: pairing_code.is_some(),
        })
    }

    /// Produce the `Hello` message bytes (the first thing on the wire).
    pub fn write_hello(&self) -> Result<Vec<u8>> {
        let hello = HelloMsg {
            magic: MAGIC,
            version: PROTO_VERSION,
            suite: SUITE_CLASSIC,
            i_ephemeral: self.ephemeral.public(),
            i_nonce: self.nonce,
        };
        codec::to_vec(&hello)
    }

    /// Consume the responder's `Auth`; verify it is the expected contact and that
    /// its signature is valid; then return the `Confirm` bytes to send and the
    /// open [`Session`]. Aborts with [`Error::PeerIdentityMismatch`] on a wrong
    /// identity and [`Error::PairingCodeMismatch`]/[`Error::BadSignature`] on a
    /// failed authentication.
    pub fn read_auth_write_confirm(self, auth_bytes: &[u8]) -> Result<(Vec<u8>, Session)> {
        let auth: AuthMsg = codec::from_slice(auth_bytes)?;
        let r_sig = fixed::<{ sign::SIGNATURE_LEN }>(&auth.r_sig)?;
        let r_sign_pub = auth.r_identity.sign_public;
        let r_kem_pub = auth.r_identity.kem_public;

        let th0 = transcript0(
            PROTO_VERSION,
            SUITE_CLASSIC,
            &self.ephemeral.public(),
            &self.nonce,
            &auth.r_ephemeral,
            &auth.r_nonce,
            &self.pairing_commit,
        );

        // Check the identity FIRST so a plain "wrong contact" is distinguishable
        // from an authentication failure (the fingerprint is sent in the clear and
        // is independently confirmed by the signature below).
        if !ct_eq(&auth.r_identity.fingerprint(), &self.expected_peer_fpr) {
            return Err(Error::PeerIdentityMismatch);
        }

        let sig_msg = responder_sig_msg(&th0, &r_sign_pub, &r_kem_pub);
        if sign::verify(&r_sign_pub, &sig_msg, &r_sig).is_err() {
            // Identity matched but the signature did not: most likely a wrong
            // pairing code (it changes th0) or active tampering. Either way we
            // abort; the variant is only a hint for the user.
            return Err(if self.code_set {
                Error::PairingCodeMismatch
            } else {
                Error::BadSignature
            });
        }

        let ee_dh = self.ephemeral.agree(&auth.r_ephemeral)?;
        let (k_i2r, k_r2i) = derive_session_keys(&ee_dh, &th0);

        // Build and seal the initiator's identity proof.
        let i_pub = self.identity.public();
        let i_sig_msg = initiator_sig_msg(
            &th0,
            &r_sign_pub,
            &r_kem_pub,
            &i_pub.sign_public,
            &i_pub.kem_public,
        );
        let i_sig = self.identity.sign(&i_sig_msg);
        let inner = ConfirmInner {
            i_identity: i_pub,
            i_sig: i_sig.to_vec(),
        };
        let inner_bytes = codec::to_vec(&inner)?;
        let nonce = record_nonce(DIR_I2R, CONFIRM_CTR);
        let aad = record_aad(&th0, CONFIRM_TYPE, CONFIRM_CTR);
        let sealed = aead::seal(&k_i2r, &nonce, &aad, &inner_bytes)?;
        let confirm_bytes = codec::to_vec(&ConfirmMsg { sealed })?;

        Ok((confirm_bytes, Session::for_initiator(k_i2r, k_r2i, th0)))
    }
}

// ---------------------------------------------------------------------------
// Responder (file receiver)
// ---------------------------------------------------------------------------

/// State carried by the responder between `Auth` and `Confirm`.
struct ResponderPending {
    th0: [u8; 32],
    k_i2r: SymKey,
    k_r2i: SymKey,
}

/// The listening side of the handshake (the file receiver).
pub struct Responder<'a> {
    identity: &'a Identity,
    ephemeral: EphemeralKeyPair,
    nonce: [u8; 32],
    pairing_commit: [u8; 32],
    code_set: bool,
    expected_peer_fpr: Option<[u8; 32]>,
    pending: Option<ResponderPending>,
}

impl<'a> Responder<'a> {
    /// Prepare to answer a handshake, optionally gated by a normalized one-time
    /// `pairing_code` the user is reading out of band.
    ///
    /// When `expected_peer_fpr` is `Some`, the receiver has **designated** which
    /// contact it is expecting: any peer that authenticates as a different
    /// identity is rejected ([`Error::PeerIdentityMismatch`]) — symmetric with the
    /// initiator's own expected-peer check. The responder still answers `Hello`
    /// with its (public) `Auth` before it learns who connected, but it never
    /// proceeds past the handshake — no offer, no data — unless the live peer is
    /// the designated, authenticated contact. Pass `None` to accept any
    /// authenticated peer (the caller then applies its own policy).
    pub fn new(
        identity: &'a Identity,
        pairing_code: Option<&[u8]>,
        expected_peer_fpr: Option<[u8; 32]>,
    ) -> Result<Self> {
        Ok(Self {
            identity,
            ephemeral: EphemeralKeyPair::generate()?,
            nonce: random_array::<32>()?,
            pairing_commit: pairing_commit(pairing_code),
            code_set: pairing_code.is_some(),
            expected_peer_fpr,
            pending: None,
        })
    }

    /// Consume the initiator's `Hello`; derive the session keys; return the `Auth`
    /// bytes to send back (carrying the responder's identity and signature).
    pub fn read_hello_write_auth(&mut self, hello_bytes: &[u8]) -> Result<Vec<u8>> {
        let hello: HelloMsg = codec::from_slice(hello_bytes)?;
        if hello.magic != MAGIC {
            return Err(Error::HandshakeProtocol("not a FileSec transfer handshake"));
        }
        if hello.version != PROTO_VERSION {
            return Err(Error::HandshakeProtocol("unsupported handshake version"));
        }
        if hello.suite != SUITE_CLASSIC {
            return Err(Error::HandshakeProtocol("unsupported handshake suite"));
        }

        let th0 = transcript0(
            PROTO_VERSION,
            SUITE_CLASSIC,
            &hello.i_ephemeral,
            &hello.i_nonce,
            &self.ephemeral.public(),
            &self.nonce,
            &self.pairing_commit,
        );
        let ee_dh = self.ephemeral.agree(&hello.i_ephemeral)?;
        let (k_i2r, k_r2i) = derive_session_keys(&ee_dh, &th0);

        let r_pub = self.identity.public();
        let sig_msg = responder_sig_msg(&th0, &r_pub.sign_public, &r_pub.kem_public);
        let r_sig = self.identity.sign(&sig_msg);
        let auth = AuthMsg {
            r_ephemeral: self.ephemeral.public(),
            r_nonce: self.nonce,
            r_identity: r_pub,
            r_sig: r_sig.to_vec(),
        };
        let auth_bytes = codec::to_vec(&auth)?;
        self.pending = Some(ResponderPending { th0, k_i2r, k_r2i });
        Ok(auth_bytes)
    }

    /// Consume the initiator's `Confirm`; decrypt and verify the initiator's
    /// identity proof; return the authenticated peer and the open [`Session`].
    pub fn read_confirm(self, confirm_bytes: &[u8]) -> Result<(PeerAuth, Session)> {
        let pending = self
            .pending
            .ok_or(Error::HandshakeProtocol("handshake out of order"))?;
        let confirm: ConfirmMsg = codec::from_slice(confirm_bytes)?;

        let nonce = record_nonce(DIR_I2R, CONFIRM_CTR);
        let aad = record_aad(&pending.th0, CONFIRM_TYPE, CONFIRM_CTR);
        // A wrong pairing code makes k_i2r differ, so this open fails; map that to
        // the pairing-code hint when a code was in use.
        let inner_bytes =
            aead::open(&pending.k_i2r, &nonce, &aad, &confirm.sealed).map_err(|e| {
                if self.code_set {
                    Error::PairingCodeMismatch
                } else {
                    e
                }
            })?;
        let inner: ConfirmInner = codec::from_slice(&inner_bytes)?;
        let i_sig = fixed::<{ sign::SIGNATURE_LEN }>(&inner.i_sig)?;

        let r_pub = self.identity.public();
        let i_sig_msg = initiator_sig_msg(
            &pending.th0,
            &r_pub.sign_public,
            &r_pub.kem_public,
            &inner.i_identity.sign_public,
            &inner.i_identity.kem_public,
        );
        sign::verify(&inner.i_identity.sign_public, &i_sig_msg, &i_sig)?;

        let peer = PeerAuth {
            fingerprint: inner.i_identity.fingerprint(),
            identity: inner.i_identity,
        };
        // If the receiver designated an expected sender, reject anyone else — even
        // a different, validly-authenticated contact.
        if let Some(expected) = self.expected_peer_fpr {
            if !ct_eq(&peer.fingerprint, &expected) {
                return Err(Error::PeerIdentityMismatch);
            }
        }
        Ok((
            peer,
            Session::for_responder(pending.k_i2r, pending.k_r2i, pending.th0),
        ))
    }
}

#[cfg(test)]
mod tests {
    // White-box tests: they craft / mutate the private wire structs, which the
    // black-box integration tests in `tests/transport.rs` cannot reach. The
    // crate-level denies on unwrap/panic are relaxed here, as for all tests.
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::identity::Identity;

    fn ids() -> (Identity, Identity) {
        (
            Identity::generate("I", 1).unwrap(),
            Identity::generate("R", 2).unwrap(),
        )
    }

    fn hello_with(version: u16, suite: u16, magic: [u8; 8]) -> Vec<u8> {
        codec::to_vec(&HelloMsg {
            magic,
            version,
            suite,
            i_ephemeral: [7u8; 32],
            i_nonce: [9u8; 32],
        })
        .unwrap()
    }

    #[test]
    fn bad_magic_rejected() {
        let (_i, r) = ids();
        let mut resp = Responder::new(&r, None, None).unwrap();
        let bytes = hello_with(PROTO_VERSION, SUITE_CLASSIC, *b"NOTFSEC!");
        assert!(matches!(
            resp.read_hello_write_auth(&bytes),
            Err(Error::HandshakeProtocol(_))
        ));
    }

    #[test]
    fn downgrade_version_rejected() {
        let (_i, r) = ids();
        let mut resp = Responder::new(&r, None, None).unwrap();
        let bytes = hello_with(PROTO_VERSION + 1, SUITE_CLASSIC, MAGIC);
        assert!(matches!(
            resp.read_hello_write_auth(&bytes),
            Err(Error::HandshakeProtocol(_))
        ));
    }

    #[test]
    fn downgrade_suite_rejected() {
        let (_i, r) = ids();
        let mut resp = Responder::new(&r, None, None).unwrap();
        let bytes = hello_with(PROTO_VERSION, 0x0099, MAGIC);
        assert!(matches!(
            resp.read_hello_write_auth(&bytes),
            Err(Error::HandshakeProtocol(_))
        ));
    }

    #[test]
    fn tampered_auth_signature_rejected() {
        let (i, r) = ids();
        let initiator = Initiator::new(&i, r.fingerprint(), None).unwrap();
        let mut resp = Responder::new(&r, None, None).unwrap();
        let hello = initiator.write_hello().unwrap();
        let auth = resp.read_hello_write_auth(&hello).unwrap();
        let mut parsed: AuthMsg = codec::from_slice(&auth).unwrap();
        parsed.r_sig[0] ^= 0xff;
        let tampered = codec::to_vec(&parsed).unwrap();
        assert!(matches!(
            initiator.read_auth_write_confirm(&tampered),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn tampered_responder_ephemeral_rejected() {
        // Mutating the responder's ephemeral changes th0, so the signature the
        // initiator recomputes no longer matches what the responder signed.
        let (i, r) = ids();
        let initiator = Initiator::new(&i, r.fingerprint(), None).unwrap();
        let mut resp = Responder::new(&r, None, None).unwrap();
        let hello = initiator.write_hello().unwrap();
        let auth = resp.read_hello_write_auth(&hello).unwrap();
        let mut parsed: AuthMsg = codec::from_slice(&auth).unwrap();
        parsed.r_ephemeral[0] ^= 0xff;
        let tampered = codec::to_vec(&parsed).unwrap();
        assert!(matches!(
            initiator.read_auth_write_confirm(&tampered),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn replayed_auth_rejected() {
        // An Auth captured for one initiator cannot be replayed to another: the
        // fresh ephemeral/nonce make a different th0, so the signature fails.
        let (i, r) = ids();
        let init_a = Initiator::new(&i, r.fingerprint(), None).unwrap();
        let mut resp = Responder::new(&r, None, None).unwrap();
        let hello_a = init_a.write_hello().unwrap();
        let auth = resp.read_hello_write_auth(&hello_a).unwrap();

        let init_b = Initiator::new(&i, r.fingerprint(), None).unwrap();
        let _ = init_b.write_hello().unwrap();
        assert!(matches!(
            init_b.read_auth_write_confirm(&auth),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn tampered_confirm_rejected() {
        let (i, r) = ids();
        let initiator = Initiator::new(&i, r.fingerprint(), None).unwrap();
        let mut resp = Responder::new(&r, None, None).unwrap();
        let hello = initiator.write_hello().unwrap();
        let auth = resp.read_hello_write_auth(&hello).unwrap();
        let (mut confirm, _isess) = initiator.read_auth_write_confirm(&auth).unwrap();
        let last = confirm.len() - 1;
        confirm[last] ^= 0xff;
        assert!(resp.read_confirm(&confirm).is_err());
    }
}
