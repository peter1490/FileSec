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
    /// The pairing code the user typed (raw; normalized before use). `None` = none.
    pub pairing_code: Option<String>,
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
    /// when the router mapping succeeded. `pairing_code` is the one-time code the
    /// user reads out to the sender.
    Listening {
        lan_addr: String,
        public_addr: Option<String>,
        nat: NatStatus,
        pairing_code: String,
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

/// Sends [`NetEvent`]s up and wakes the UI. Cloned into the worker thread.
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
    let join = thread::spawn(move || {
        if let Err(msg) = listener::run(config, &identity, &store, &contacts, &emitter, &cmd_rx) {
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
// Pairing-code helpers
// ---------------------------------------------------------------------------

/// Generate a fresh 8-digit one-time pairing code (the normalized form).
fn generate_pairing_code() -> Result<String, String> {
    let bytes = filesec_core::secret::random_array::<8>().map_err(|e| e.to_string())?;
    Ok(bytes.iter().map(|b| char::from(b'0' + (b % 10))).collect())
}

/// Group an 8-digit code for display, e.g. `1234-5678`.
fn group_code(code: &str) -> String {
    if code.len() == 8 {
        format!("{}-{}", &code[..4], &code[4..])
    } else {
        code.to_string()
    }
}

/// Normalize a user-entered code: keep only alphanumerics, lowercased — so spacing,
/// dashes, and case don't matter when the two sides compare.
fn normalize_code(input: &str) -> String {
    input
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Current Unix time in seconds (best-effort; 0 if the clock is before the epoch).
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
