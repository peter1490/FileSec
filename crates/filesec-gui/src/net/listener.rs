//! Receiver side: bind a port (LAN, or internet via NAT-PMP), then service dialers
//! from a **bounded pool of worker threads** so no single slow or hostile client
//! can stall the listener. Each worker runs the mutual-auth handshake behind a
//! hard deadline (slowloris defense), gates on the transfer secret and the contact
//! book, and — for at most one authenticated peer at a time — prompts the user and
//! streams the incoming `.fsec` to a private temp for the existing verify+import
//! path. Repeatedly-failing source IPs are backed off.

use std::io::Write;
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use filesec_core::contacts::{ContactBook, Trust};
use filesec_core::transport::{RecordType, Responder};
use filesec_core::{codec, format, Identity};

use super::concurrency::{RateLimiter, Semaphore};
use super::nat::PortMapping;
use super::wire::{
    read_frame_until, read_handshake_frame_deadline, write_frame, MAX_FRAME, MAX_HANDSHAKE_FRAME,
};
use super::{
    display_transfer_code, generate_transfer_secret, now_unix, DecisionMsg, Emitter, ListenConfig,
    NatStatus, NetCommand, NetEvent, OfferMsg, TRANSFER_SECRET_LEN,
};
use crate::store::{new_vault_id, secure_wipe, Store, VaultMeta};

/// Per-operation socket timeout for the data phase (post-handshake).
const SOCKET_TIMEOUT: Duration = Duration::from_secs(30);
/// Absolute wall-clock budget for one connection's whole mutual-auth handshake.
/// A dialer that has not finished authenticating within this window is dropped,
/// freeing its worker slot — the core of the slowloris defense.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
/// Per-read socket timeout used *during* the handshake so the deadline-aware
/// reader wakes periodically to re-check [`HANDSHAKE_DEADLINE`] even if the peer
/// dribbles or stalls bytes.
const HANDSHAKE_READ_POLL: Duration = Duration::from_secs(2);
/// How long the accept loop sleeps between non-blocking accept attempts.
const ACCEPT_POLL: Duration = Duration::from_millis(150);
/// How long to wait for the user to accept/reject an incoming offer.
const OFFER_DECISION_TIMEOUT: Duration = Duration::from_secs(300);
/// Ceiling on connections handshaking concurrently. A flood beyond this is
/// refused immediately (the socket is closed) rather than spawning unbounded
/// threads; legitimate concurrent attempts stay bounded and observable.
const MAX_CONCURRENT_HANDSHAKES: usize = 8;
/// How often to prune the rate-limiter's per-IP table.
const RATE_PRUNE_INTERVAL: Duration = Duration::from_secs(60);
/// Hard ceiling on a declared inbound transfer size. The receiver streams the
/// offered `.fsec` to a temp file and stops only once `received` exceeds the
/// *declared* size, so an unbounded declared size would let a verified-but-hostile
/// sender fill the disk. This caps the declared size (and therefore the bytes
/// ever written) before a single byte is accepted. Well above any realistic vault
/// yet a firm bound against disk exhaustion. (Querying actual free space portably
/// would need a platform dependency this dependency-light build avoids; the cap is
/// the enforced defense.)
const MAX_TRANSFER_SIZE: u64 = 64 * 1024 * 1024 * 1024;

/// Everything a worker thread needs, cloned per connection.
#[derive(Clone)]
struct Shared {
    identity: Arc<Identity>,
    store: Arc<Store>,
    contacts: Arc<ContactBook>,
    emitter: Emitter,
    secret: Arc<[u8; TRANSFER_SECRET_LEN]>,
    /// The verified contact the receiver designated as the expected sender.
    expected: Option<[u8; 32]>,
    /// Set when the UI asks to stop; workers observe it as a backstop to cancel.
    stop: Arc<AtomicBool>,
    /// `true` while one authenticated transfer owns the UI. Serializes the
    /// offer/receive/import phase to a single peer at a time.
    transfer_active: Arc<AtomicBool>,
    /// The active transfer's private decision channel; the accept loop forwards
    /// Accept/Reject/Cancel here.
    active_cmd: Arc<Mutex<Option<mpsc::Sender<NetCommand>>>>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

/// The outcome of servicing one connection, telling the worker how to react.
struct ConnError {
    /// User-facing message; emitted as [`NetEvent::Error`] only when
    /// `user_facing` is set (pre-auth probes stay silent to avoid UI spam).
    message: String,
    /// The failure happened at or before the transfer-secret proof — treat the
    /// peer as a probe and back its IP off.
    rate_limit: bool,
    /// Surface this to the UI (an authenticated peer's problem the user should
    /// see).
    user_facing: bool,
}

impl ConnError {
    /// A pre-auth failure: silent, and the source IP is backed off.
    fn probe(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            rate_limit: true,
            user_facing: false,
        }
    }

    /// An authenticated peer's failure the user should see.
    fn shown(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            rate_limit: false,
            user_facing: true,
        }
    }

    /// A benign refusal (e.g. the receiver is busy) — silent, no backoff.
    fn quiet(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            rate_limit: false,
            user_facing: false,
        }
    }
}

pub fn run(
    config: ListenConfig,
    identity: Arc<Identity>,
    store: Arc<Store>,
    contacts: Arc<ContactBook>,
    emitter: &Emitter,
    cmd_rx: &Receiver<NetCommand>,
) -> Result<(), String> {
    let listener = TcpListener::bind(("0.0.0.0", config.port))
        .map_err(|e| format!("could not open the port: {e}"))?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let local_port = listener
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(config.port);
    let lan_addr = match local_lan_ip() {
        Some(ip) => format!("{ip}:{local_port}"),
        None => format!("this machine:{local_port}"),
    };

    // Router port mapping (internet mode only). Kept alive for the session; unmaps
    // on drop. A finite lease (refreshed below) backstops a crash.
    let mut mapping: Option<PortMapping> = None;
    let (public_addr, nat) = if config.internet {
        match PortMapping::create(local_port) {
            Ok(m) => {
                let public = m.public_addr().to_string();
                mapping = Some(m);
                (Some(public), NatStatus::Mapped)
            }
            Err(e) => (None, NatStatus::Unavailable(e)),
        }
    } else {
        (None, NatStatus::Disabled)
    };

    let secret = generate_transfer_secret()?;
    if !emitter.emit(NetEvent::Listening {
        lan_addr,
        public_addr,
        nat,
        transfer_code: display_transfer_code(&secret),
    }) {
        return Ok(());
    }

    let shared = Shared {
        identity,
        store,
        contacts,
        emitter: emitter.clone(),
        secret: Arc::new(secret),
        expected: config.expected_sender_fpr,
        stop: Arc::new(AtomicBool::new(false)),
        transfer_active: Arc::new(AtomicBool::new(false)),
        active_cmd: Arc::new(Mutex::new(None)),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new())),
    };
    let permits = Semaphore::new(MAX_CONCURRENT_HANDSHAKES);

    let mut last_refresh = Instant::now();
    let mut last_prune = Instant::now();
    loop {
        // Lifecycle + command routing. Stop tears down; the decision commands are
        // forwarded to whichever worker currently owns the transfer.
        match cmd_rx.try_recv() {
            Ok(NetCommand::Stop) | Err(TryRecvError::Disconnected) => {
                shared.stop.store(true, Ordering::Release);
                forward_command(&shared.active_cmd, NetCommand::Cancel);
                return Ok(());
            }
            Ok(cmd) => forward_command(&shared.active_cmd, cmd),
            Err(TryRecvError::Empty) => {}
        }

        if let Some(m) = &mapping {
            if last_refresh.elapsed().as_secs() >= PortMapping::refresh_interval_secs() {
                let _ = m.refresh();
                last_refresh = Instant::now();
            }
        }
        if last_prune.elapsed() >= RATE_PRUNE_INTERVAL {
            if let Ok(mut rl) = shared.rate_limiter.lock() {
                rl.prune(Instant::now());
            }
            last_prune = Instant::now();
        }

        match listener.accept() {
            Ok((stream, peer)) => {
                let ip = peer.ip();
                // Per-IP backoff: a source that keeps failing the handshake is
                // refused for a growing window before it costs us a worker slot.
                if let Ok(mut rl) = shared.rate_limiter.lock() {
                    if !rl.allow(ip, Instant::now()) {
                        drop(stream);
                        continue;
                    }
                }
                // Bounded pool: refuse (close) immediately when saturated.
                let Some(permit) = permits.try_acquire() else {
                    drop(stream);
                    continue;
                };
                let _ = stream.set_nonblocking(false);
                let shared = shared.clone();
                let _ = std::thread::Builder::new()
                    .name("filesec-net-conn".into())
                    .spawn(move || {
                        let _permit = permit; // released when the worker exits
                        service(&shared, stream, ip);
                    });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            Err(e) => {
                shared.stop.store(true, Ordering::Release);
                return Err(format!("could not accept a connection: {e}"));
            }
        }
    }
}

/// Forward a decision/cancel command to the active transfer, if any.
fn forward_command(active_cmd: &Mutex<Option<mpsc::Sender<NetCommand>>>, cmd: NetCommand) {
    let tx = active_cmd.lock().ok().and_then(|g| g.clone());
    if let Some(tx) = tx {
        let _ = tx.send(cmd);
    }
}

/// Worker-thread entry: run one connection to completion, then apply rate-limit
/// bookkeeping and surface any user-facing error.
fn service(shared: &Shared, stream: TcpStream, ip: IpAddr) {
    match handle_conn(shared, stream, ip) {
        Ok(()) => {}
        Err(err) => {
            if err.rate_limit {
                if let Ok(mut rl) = shared.rate_limiter.lock() {
                    rl.record_failure(ip, Instant::now());
                }
            }
            if err.user_facing {
                shared.emitter.emit(NetEvent::Error(err.message));
            }
        }
    }
}

/// Handle one accepted connection through to import (or a clean rejection/error).
fn handle_conn(shared: &Shared, mut stream: TcpStream, ip: IpAddr) -> Result<(), ConnError> {
    // Handshake phase: short per-read timeout so the deadline reader can enforce
    // the absolute HANDSHAKE_DEADLINE against a slow/dribbling peer.
    stream
        .set_read_timeout(Some(HANDSHAKE_READ_POLL))
        .map_err(|e| ConnError::probe(e.to_string()))?;
    stream
        .set_write_timeout(Some(HANDSHAKE_READ_POLL))
        .map_err(|e| ConnError::probe(e.to_string()))?;
    let deadline = Instant::now() + HANDSHAKE_DEADLINE;

    let mut responder = Responder::new(&shared.identity, shared.secret.as_ref(), shared.expected)
        .map_err(|e| ConnError::probe(e.to_string()))?;

    let hello = read_handshake_frame_deadline(&mut stream, deadline)
        .map_err(|e| ConnError::probe(e.to_string()))?;
    // The transfer-secret proof is verified inside `read_hello_write_auth`; a
    // failure here means the dialer could not prove the secret, so no Auth (no
    // identity, no signature) is produced. Treat it as a probe and back it off.
    let auth = responder
        .read_hello_write_auth(&hello)
        .map_err(|e| ConnError::probe(e.to_string()))?;

    // Secret proven: this peer holds the code, so clear its rate-limit record and
    // stop backing it off for any later, benign hiccup.
    if let Ok(mut rl) = shared.rate_limiter.lock() {
        rl.record_success(ip);
    }

    write_frame(&mut stream, &auth).map_err(|e| ConnError::quiet(e.to_string()))?;
    let confirm = read_handshake_frame_deadline(&mut stream, deadline)
        .map_err(|e| ConnError::quiet(e.to_string()))?;
    let (peer, session) = match responder.read_confirm(&confirm) {
        Ok(pair) => pair,
        Err(filesec_core::Error::PeerIdentityMismatch) => {
            return Err(ConnError::shown(
                "Refused: a different contact connected than the one you're expecting.",
            ))
        }
        Err(e) => return Err(ConnError::shown(e.to_string())),
    };

    // Only one authenticated transfer may drive the UI at a time. A second
    // concurrent (verified) sender is closed silently rather than clobbering the
    // active transfer's UI.
    if shared
        .transfer_active
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(ConnError::quiet("receiver is busy with another transfer"));
    }
    let _active = ActiveGuard {
        flag: &shared.transfer_active,
        active_cmd: &shared.active_cmd,
    };
    // Register a private decision channel; the accept loop forwards the user's
    // Accept/Reject/Cancel here. Done *before* the offer is emitted, so the UI's
    // reply can never race ahead of registration.
    let (dec_tx, dec_rx) = mpsc::channel();
    if let Ok(mut g) = shared.active_cmd.lock() {
        *g = Some(dec_tx);
    }

    // Transfer phase: switch to the longer per-operation timeout.
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|e| ConnError::quiet(e.to_string()))?;
    stream
        .set_write_timeout(Some(SOCKET_TIMEOUT))
        .map_err(|e| ConnError::quiet(e.to_string()))?;

    run_transfer(shared, &mut stream, session, &peer, &dec_rx)
}

/// The authenticated offer → decision → receive → import flow for one peer.
fn run_transfer(
    shared: &Shared,
    stream: &mut TcpStream,
    mut session: filesec_core::transport::Session,
    peer: &filesec_core::transport::PeerAuth,
    dec_rx: &Receiver<NetCommand>,
) -> Result<(), ConnError> {
    // Contact-book gate: only a verified contact may send.
    let contact = shared.contacts.find(&peer.fingerprint);
    let verified = matches!(contact.map(|c| c.trust), Some(Trust::Verified));
    let name = contact.map(|c| c.identity.name.clone());
    let fpr_hex = peer.identity.fingerprint_hex();
    shared.emitter.emit(NetEvent::PeerConnected {
        fpr_hex: fpr_hex.clone(),
        name: name.clone(),
        verified,
    });
    if !verified {
        return Err(ConnError::shown(format!(
            "Refused a transfer from an unverified sender ({}…). Add and verify them in Contacts first.",
            fpr_hex.get(..16).unwrap_or(&fpr_hex)
        )));
    }

    // Read the offer.
    let offer_frame = read_frame_until(
        stream,
        MAX_HANDSHAKE_FRAME,
        Instant::now() + SOCKET_TIMEOUT,
        || transfer_cancelled(shared, dec_rx),
    )
    .map_err(|e| ConnError::shown(e.to_string()))?;
    let (rtype, plaintext) = session
        .open_record(&offer_frame)
        .map_err(|e| ConnError::shown(e.to_string()))?;
    if rtype != RecordType::Offer {
        return Err(ConnError::shown(
            "protocol error: expected a transfer offer",
        ));
    }
    let offer: OfferMsg =
        codec::from_slice(&plaintext).map_err(|e| ConnError::shown(e.to_string()))?;
    if offer.sender_fpr != peer.fingerprint {
        return Err(ConnError::shown(
            "the offer's sender does not match the connected identity",
        ));
    }
    // Reject an absurdly large declared size before prompting the user or writing
    // a byte — the received-size check below only bounds bytes to this declared
    // size, so an uncapped size is a disk-exhaustion lever.
    if !transfer_size_acceptable(offer.size) {
        return Err(ConnError::shown(
            "the offered transfer is too large to accept",
        ));
    }
    shared.emitter.emit(NetEvent::Offer {
        filename: filesec_core::sanitize_display_name(&offer.filename),
        size: offer.size,
        sender_name: name.clone(),
        verified,
    });

    // Wait for the user to accept or reject, then tell the sender.
    let accept = wait_decision(dec_rx, &shared.stop)?;
    let decision =
        codec::to_vec(&DecisionMsg { accept }).map_err(|e| ConnError::shown(e.to_string()))?;
    let frame = session
        .seal_record(RecordType::OfferDecision, &decision)
        .map_err(|e| ConnError::shown(e.to_string()))?;
    write_frame(stream, &frame).map_err(|e| ConnError::shown(e.to_string()))?;
    if !accept {
        return Ok(());
    }

    // Stream the encrypted container to a private temp, then verify + import.
    let incoming_id = new_vault_id().map_err(|e| ConnError::shown(e.to_string()))?;
    let temp = shared
        .store
        .create_private_checkout_file(&format!("incoming-{incoming_id}.fsec"))
        .map_err(|e| ConnError::shown(e.to_string()))?;
    let result = match receive_into(stream, &mut session, &temp, offer.size, shared, dec_rx) {
        Ok(()) => {
            // The bytes are in; verifying the signature and re-encrypting into the
            // local store can take a moment for a large vault, so say so.
            shared
                .emitter
                .emit(NetEvent::Status("Verifying & saving…".into()));
            import_received(&shared.store, &shared.identity, &temp, &peer.fingerprint)
        }
        Err(e) => Err(e),
    };
    let _ = secure_wipe(&temp);
    let (meta, file_count) = result.map_err(ConnError::shown)?;
    shared.emitter.emit(NetEvent::Received {
        meta,
        file_count,
        sender_name: name,
    });
    Ok(())
}

/// Clears the single-transfer flag and the forwarding channel on scope exit, so a
/// dropped/errored transfer always frees the slot for the next dialer.
struct ActiveGuard<'a> {
    flag: &'a AtomicBool,
    active_cmd: &'a Mutex<Option<mpsc::Sender<NetCommand>>>,
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut g) = self.active_cmd.lock() {
            *g = None;
        }
        self.flag.store(false, Ordering::Release);
    }
}

/// Wait (up to [`OFFER_DECISION_TIMEOUT`]) for the accept/reject command.
fn wait_decision(dec_rx: &Receiver<NetCommand>, stop: &AtomicBool) -> Result<bool, ConnError> {
    let deadline = Instant::now() + OFFER_DECISION_TIMEOUT;
    loop {
        if stop.load(Ordering::Acquire) {
            return Err(ConnError::quiet("Transfer cancelled."));
        }
        match dec_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(NetCommand::AcceptOffer) => return Ok(true),
            Ok(NetCommand::RejectOffer) => return Ok(false),
            Ok(_) => return Err(ConnError::quiet("Transfer cancelled.")),
            Err(RecvTimeoutError::Timeout) if Instant::now() >= deadline => {
                return Err(ConnError::shown(
                    "No response to the transfer offer (timed out).",
                ))
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err(ConnError::quiet("Transfer cancelled."))
            }
        }
    }
}

fn transfer_cancelled(shared: &Shared, commands: &Receiver<NetCommand>) -> bool {
    shared.stop.load(Ordering::Acquire)
        || matches!(
            commands.try_recv(),
            Ok(NetCommand::Cancel | NetCommand::Stop) | Err(TryRecvError::Disconnected)
        )
}

/// Read `Data` records into `temp` until `Done`, enforcing the declared size.
fn receive_into(
    stream: &mut TcpStream,
    session: &mut filesec_core::transport::Session,
    temp: &Path,
    size: u64,
    shared: &Shared,
    dec_rx: &Receiver<NetCommand>,
) -> Result<(), String> {
    // `temp` was just created private (0600) by `create_private_checkout_file`
    // in the app-owned checkout dir. Open *that* file for writing rather than
    // re-`create`-ing it, so a vanished temp is an error instead of a silently
    // re-created, loosely-permissioned one.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(temp)
        .map_err(|e| e.to_string())?;
    let mut received: u64 = 0;
    let mut last_progress = Instant::now();
    loop {
        if shared.stop.load(Ordering::Acquire) {
            return Err("Transfer cancelled.".into());
        }
        match dec_rx.try_recv() {
            Ok(NetCommand::Cancel) | Ok(NetCommand::Stop) => {
                return Err("Transfer cancelled.".into())
            }
            Err(TryRecvError::Disconnected) => return Err("Transfer cancelled.".into()),
            _ => {}
        }
        let frame = read_frame_until(stream, MAX_FRAME, Instant::now() + SOCKET_TIMEOUT, || {
            transfer_cancelled(shared, dec_rx)
        })
        .map_err(|e| e.to_string())?;
        let (rtype, plaintext) = session.open_record(&frame).map_err(|e| e.to_string())?;
        match rtype {
            RecordType::Data => {
                if plaintext.is_empty() {
                    return Err("protocol error: empty data record".into());
                }
                received = received.saturating_add(plaintext.len() as u64);
                if received > size {
                    return Err("the sender exceeded the declared size".into());
                }
                file.write_all(&plaintext).map_err(|e| e.to_string())?;
                if received == size || last_progress.elapsed() >= Duration::from_millis(100) {
                    shared.emitter.emit(NetEvent::Progress {
                        done: received,
                        total: size,
                    });
                    last_progress = Instant::now();
                }
            }
            RecordType::Done if plaintext.is_empty() => break,
            _ => return Err("protocol error during the transfer".into()),
        }
    }
    file.flush().map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    if received != size {
        return Err("the transfer ended early (size mismatch)".into());
    }
    Ok(())
}

/// Verify the container's signature, confirm the signer is the connected peer,
/// and import it into the local store. Returns its metadata for the registry.
fn import_received(
    store: &Store,
    identity: &Identity,
    temp: &Path,
    peer_fpr: &[u8; 32],
) -> Result<(VaultMeta, usize), String> {
    let (reader, sender) = format::verify_and_open(temp, identity).map_err(|e| e.to_string())?;
    if &sender.fingerprint != peer_fpr {
        return Err("the file's signature does not match the connected sender".into());
    }
    let id = new_vault_id().map_err(|e| e.to_string())?;
    store.import_reader_to_vault(identity, &id, &reader)?;
    let file_count = reader.file_count();
    let meta = VaultMeta {
        id,
        name: reader.name().to_string(),
        created_at: reader.created_at(),
        modified_at: now_unix(),
        file_count: file_count as u64,
        total_size: reader.total_size(),
    };
    Ok((meta, file_count))
}

/// Best-effort LAN IP for display (the source address the OS routes outward).
/// No packet is sent — a UDP "connect" only selects the local interface.
fn local_lan_ip() -> Option<String> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    // 203.0.113.0/24 is TEST-NET-3 (RFC 5737): nothing is contacted; it only
    // makes the OS pick the default-route source address.
    socket.connect(("203.0.113.1", 9)).ok()?;
    socket.local_addr().ok().map(|a| a.ip().to_string())
}

/// Whether a sender's declared inbound transfer size is within the acceptance
/// ceiling. The received-byte check only bounds writes to the *declared* size, so
/// this is the guard that keeps a hostile declared size from filling the disk.
fn transfer_size_acceptable(size: u64) -> bool {
    size <= MAX_TRANSFER_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_size_cap_rejects_above_ceiling() {
        assert!(transfer_size_acceptable(0));
        assert!(transfer_size_acceptable(MAX_TRANSFER_SIZE));
        assert!(!transfer_size_acceptable(MAX_TRANSFER_SIZE + 1));
        assert!(!transfer_size_acceptable(u64::MAX));
    }
}
