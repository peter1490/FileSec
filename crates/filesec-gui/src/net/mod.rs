//! Direct (server-less) peer-to-peer file transfer.
//!
//! A receiver enters *listen mode* (LAN-only by default, or internet via NAT-PMP
//! port mapping); a sender dials a chosen **verified contact** at an IP/port. The
//! authenticated, forward-secret handshake lives in `filesec_core::transport`;
//! this module owns the sockets, NAT mapping, threading, and the bridge to the
//! egui UI. It is compiled only with the `net` feature.
//!
//! Each transfer runs on its own dedicated `std::thread` (no async runtime),
//! talking to the UI thread over two channels: [`NetEvent`]s flow up, [`NetCommand`]s
//! flow down. The UI drains events non-blocking each frame; the net thread wakes
//! the UI via `egui::Context::request_repaint` on every event.

mod concurrency;
mod listener;
mod nat;
mod sender;
mod wire;

use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use filesec_core::contacts::ContactBook;
use filesec_core::{Identity, PublicIdentity};

use crate::store::{Store, VaultMeta};

/// Receiver-side configuration for listen mode.
pub struct ListenConfig {
    /// TCP port to listen on (0 lets the OS choose; the chosen port is reported).
    pub port: u16,
    /// Whether to also try to open the port on the router and surface the public IP.
    pub internet: bool,
    /// The verified contact the receiver designates as the expected sender. Any
    /// peer that authenticates as a different identity is refused. `None` accepts
    /// any verified contact (the GUI always sets this).
    pub expected_sender_fpr: Option<[u8; 32]>,
}

/// Sender-side configuration for a single outbound transfer.
pub struct SendConfig {
    /// Host (IP literal or name) the receiver gave out.
    pub host: String,
    /// TCP port the receiver is listening on.
    pub port: u16,
    /// The verified contact to send to (the `.fsec` is encrypted to this identity).
    pub recipient: PublicIdentity,
    /// The contact's fingerprint, checked against the live peer ("right IP, wrong
    /// identity" aborts).
    pub recipient_fpr: [u8; 32],
    /// The transfer code the user typed (the receiver's per-transfer 128-bit
    /// secret, in grouped/base32 display form; decoded before use). Mandatory — a
    /// transfer cannot proceed without it. `None` is rejected by the sender.
    pub transfer_code: Option<String>,
    /// The local vault to send.
    pub vault_id: String,
}

/// Status of the router port-mapping attempt (internet mode only).
#[derive(Clone, Debug)]
pub enum NatStatus {
    /// LAN-only: no mapping was attempted.
    Disabled,
    /// The router mapped the port; the public address is in `Listening`.
    Mapped,
    /// Mapping was attempted but failed; the reason is shown and the listener
    /// stays reachable on the LAN.
    Unavailable(String),
}

/// Events the net thread sends up to the UI.
#[derive(Debug)]
pub enum NetEvent {
    /// The listener is up. `lan_addr` is always shown; `public_addr` is present
    /// when the router mapping succeeded. `transfer_code` is the per-transfer
    /// 128-bit secret (grouped display form) the user passes to the sender out of
    /// band.
    Listening {
        lan_addr: String,
        public_addr: Option<String>,
        nat: NatStatus,
        transfer_code: String,
    },
    /// The sender is dialing the receiver.
    Connecting,
    /// A free-form status line describing the current phase, shown verbatim to the
    /// user (e.g. "Waiting for Bob to accept…", "Encrypting & sending…",
    /// "Verifying & saving…"). Lets the worker describe exactly what is happening
    /// at moments that aren't captured by the structured events.
    Status(String),
    /// The peer completed the mutual-auth handshake.
    PeerConnected {
        fpr_hex: String,
        name: Option<String>,
        verified: bool,
    },
    /// An incoming transfer is offered; the receiver must accept or reject.
    Offer {
        filename: String,
        size: u64,
        sender_name: Option<String>,
        verified: bool,
    },
    /// Byte progress during the streamed transfer.
    Progress { done: u64, total: u64 },
    /// A receive completed: the verified vault landed in the local store.
    Received {
        meta: VaultMeta,
        file_count: usize,
        sender_name: Option<String>,
    },
    /// A send completed.
    Sent { vault_name: String },
    /// The peer (receiver) declined the offer.
    Declined,
    /// A recoverable error ended this transfer; the message is user-facing.
    Error(String),
    /// The net thread has stopped and released its resources.
    Stopped,
}

/// Commands the UI sends down to the net thread.
#[derive(Clone, Copy, Debug)]
pub enum NetCommand {
    /// Accept the pending incoming offer.
    AcceptOffer,
    /// Reject the pending incoming offer.
    RejectOffer,
    /// Cancel the in-progress transfer.
    Cancel,
    /// Stop listening / sending and release resources.
    Stop,
}

/// Sends [`NetEvent`]s up and wakes the UI. Cloned into each worker thread.
#[derive(Clone)]
struct Emitter {
    tx: mpsc::Sender<NetEvent>,
    ctx: egui::Context,
}

impl Emitter {
    /// Emit an event and request a repaint. Returns `false` if the UI side is gone
    /// (the worker should then stop).
    fn emit(&self, event: NetEvent) -> bool {
        let ok = self.tx.send(event).is_ok();
        self.ctx.request_repaint();
        ok
    }
}

/// The UI-side handle to a running transfer: drain events, send commands, stop.
pub struct NetHandle {
    commands: mpsc::Sender<NetCommand>,
    events: mpsc::Receiver<NetEvent>,
    join: Option<thread::JoinHandle<()>>,
}

impl NetHandle {
    /// Non-blocking poll for the next event.
    pub fn try_recv(&self) -> Option<NetEvent> {
        self.events.try_recv().ok()
    }

    /// Send a command to the net thread (best-effort).
    pub fn send(&self, command: NetCommand) {
        let _ = self.commands.send(command);
    }

    /// Signal the thread to stop. Does not join (so the UI never blocks); the
    /// thread cleans up its socket, NAT mapping, and temp files on its own. The
    /// finite NAT lease backstops cleanup even if the process exits first.
    pub fn stop(&mut self) {
        let _ = self.commands.send(NetCommand::Stop);
        // Detach: dropping the channels also signals the worker (its sends/recvs
        // start failing), so we never wait on a possibly-blocked socket here.
        self.join.take();
    }
}

impl Drop for NetHandle {
    fn drop(&mut self) {
        let _ = self.commands.send(NetCommand::Stop);
    }
}

/// Spawn the receiver (listen mode).
pub fn start_listener(
    config: ListenConfig,
    identity: Arc<Identity>,
    store: Arc<Store>,
    contacts: ContactBook,
    ctx: egui::Context,
) -> NetHandle {
    let (event_tx, event_rx) = mpsc::channel();
    let (cmd_tx, cmd_rx) = mpsc::channel();
    let emitter = Emitter { tx: event_tx, ctx };
    let contacts = Arc::new(contacts);
    let join = thread::spawn(move || {
        if let Err(msg) = listener::run(config, identity, store, contacts, &emitter, &cmd_rx) {
            emitter.emit(NetEvent::Error(msg));
        }
        emitter.emit(NetEvent::Stopped);
    });
    NetHandle {
        commands: cmd_tx,
        events: event_rx,
        join: Some(join),
    }
}

/// Spawn the sender (one outbound transfer).
pub fn start_sender(
    config: SendConfig,
    identity: Arc<Identity>,
    store: Arc<Store>,
    ctx: egui::Context,
) -> NetHandle {
    let (event_tx, event_rx) = mpsc::channel();
    let (cmd_tx, cmd_rx) = mpsc::channel();
    let emitter = Emitter { tx: event_tx, ctx };
    let join = thread::spawn(move || {
        if let Err(msg) = sender::run(config, &identity, &store, &emitter, &cmd_rx) {
            emitter.emit(NetEvent::Error(msg));
        }
        emitter.emit(NetEvent::Stopped);
    });
    NetHandle {
        commands: cmd_tx,
        events: event_rx,
        join: Some(join),
    }
}

// ---------------------------------------------------------------------------
// Shared wire payloads carried inside Offer / OfferDecision records (CBOR via the
// core codec, which the GUI already links).
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct OfferMsg {
    filename: String,
    size: u64,
    sender_fpr: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct DecisionMsg {
    accept: bool,
}

// ---------------------------------------------------------------------------
// Transfer-secret codec
//
// The per-transfer second factor is a fresh 128-bit secret (16 bytes). It is
// shown to the user as Crockford base32 — a 26-symbol alphabet that omits the
// ambiguous `I L O U` and folds look-alikes on input — grouped for readability.
// The raw 16 bytes are what the transport actually keys on; the display string
// only has to round-trip back to those bytes. (A QR presentation is deferred: a
// correct in-tree QR encoder is substantial, and adding a QR crate would break
// this build's deliberately dependency-light, MSRV-pinned posture — the copyable
// grouped code covers the same out-of-band channel.)
// ---------------------------------------------------------------------------

/// Length of the raw transfer secret in bytes (128 bits).
pub(crate) const TRANSFER_SECRET_LEN: usize = 16;
/// Number of base32 symbols a 16-byte secret encodes to (`⌈128 / 5⌉`).
const SECRET_SYMBOLS: usize = 26;
/// Crockford base32 alphabet (no `I`, `L`, `O`, `U`).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Display grouping size.
const GROUP: usize = 4;

/// Generate a fresh 128-bit transfer secret.
fn generate_transfer_secret() -> Result<[u8; TRANSFER_SECRET_LEN], String> {
    filesec_core::secret::random_array::<TRANSFER_SECRET_LEN>().map_err(|e| e.to_string())
}

/// Encode the raw secret to its canonical (ungrouped, upper-case) base32 form.
fn encode_transfer_secret(bytes: &[u8; TRANSFER_SECRET_LEN]) -> String {
    let mut out = String::with_capacity(SECRET_SYMBOLS);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(CROCKFORD[((buffer >> bits) & 0x1f) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(
            CROCKFORD[((buffer << (5 - bits)) & 0x1f) as usize],
        ));
    }
    out
}

/// Insert group separators into a canonical code for display, e.g.
/// `ABCD-EFGH-…`.
fn group_transfer_code(code: &str) -> String {
    let mut out = String::with_capacity(code.len() + code.len() / GROUP);
    for (i, c) in code.chars().enumerate() {
        if i > 0 && i % GROUP == 0 {
            out.push('-');
        }
        out.push(c);
    }
    out
}

/// The full display string for a freshly generated secret: grouped base32.
fn display_transfer_code(bytes: &[u8; TRANSFER_SECRET_LEN]) -> String {
    group_transfer_code(&encode_transfer_secret(bytes))
}

/// Fold one input character to its base32 value, tolerating case and the usual
/// look-alikes (`O`→`0`, `I`/`L`→`1`). Returns `None` for a non-symbol.
fn decode_symbol(c: char) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    CROCKFORD
        .iter()
        .position(|&a| char::from(a) == c)
        .map(|p| p as u8)
}

/// Decode a user-entered transfer code back to the raw 16-byte secret. Separators
/// and whitespace are ignored; the payload must be exactly [`SECRET_SYMBOLS`]
/// valid symbols or this returns `None`.
fn decode_transfer_code(input: &str) -> Option<[u8; TRANSFER_SECRET_LEN]> {
    let symbols: Vec<u8> = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(decode_symbol)
        .collect::<Option<Vec<u8>>>()?;
    if symbols.len() != SECRET_SYMBOLS {
        return None;
    }
    let mut out = [0u8; TRANSFER_SECRET_LEN];
    let mut idx = 0;
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for sym in symbols {
        buffer = (buffer << 5) | u32::from(sym);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if idx < TRANSFER_SECRET_LEN {
                out[idx] = ((buffer >> bits) & 0xff) as u8;
                idx += 1;
            }
        }
    }
    (idx == TRANSFER_SECRET_LEN).then_some(out)
}

/// Current Unix time in seconds (best-effort; 0 if the clock is before the epoch).
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_round_trips_through_display() {
        let secret = generate_transfer_secret().unwrap();
        let display = display_transfer_code(&secret);
        // Grouped, uses only the Crockford alphabet + separators.
        assert!(display.contains('-'));
        assert_eq!(decode_transfer_code(&display), Some(secret));
    }

    #[test]
    fn decode_is_tolerant_of_case_spacing_and_lookalikes() {
        let secret = [0x9au8; TRANSFER_SECRET_LEN];
        let canon = encode_transfer_secret(&secret);
        // Same code re-typed lower-case, spaced, and with look-alike glyphs.
        let messy: String = canon
            .chars()
            .map(|c| match c {
                '0' => 'O',
                '1' => 'l',
                other => other.to_ascii_lowercase(),
            })
            .collect();
        let spaced = format!("  {}  ", group_transfer_code(&messy).replace('-', " "));
        assert_eq!(decode_transfer_code(&spaced), Some(secret));
    }

    #[test]
    fn decode_rejects_wrong_length_and_bad_symbols() {
        assert_eq!(decode_transfer_code(""), None);
        assert_eq!(decode_transfer_code("ABCD-EFGH"), None); // too short
        let secret = [0x11u8; TRANSFER_SECRET_LEN];
        let canon = encode_transfer_secret(&secret);
        assert_eq!(decode_transfer_code(&format!("{canon}Z")), None); // too long
                                                                      // `U` is not in the Crockford alphabet and is not a folded look-alike.
        let with_bad = format!("U{}", &canon[1..]);
        assert_eq!(decode_transfer_code(&with_bad), None);
    }

    #[test]
    fn canonical_form_has_expected_shape() {
        let secret = generate_transfer_secret().unwrap();
        let canon = encode_transfer_secret(&secret);
        assert_eq!(canon.len(), SECRET_SYMBOLS);
        assert!(canon.bytes().all(|b| CROCKFORD.contains(&b)));
    }
}
