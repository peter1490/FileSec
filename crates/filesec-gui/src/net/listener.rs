//! Receiver side: bind a port (LAN, or internet via NAT-PMP), authenticate the
//! dialing peer, gate on the contact book, prompt the user, then stream the
//! incoming `.fsec` to a temp and import it through the existing verify path.

use std::io::Write;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::time::{Duration, Instant};

use filesec_core::contacts::{ContactBook, Trust};
use filesec_core::transport::{RecordType, Responder};
use filesec_core::{codec, format, Identity};

use super::nat::PortMapping;
use super::wire::{read_frame, read_handshake_frame, write_frame};
use super::{
    generate_pairing_code, group_code, now_unix, DecisionMsg, Emitter, ListenConfig, NatStatus,
    NetCommand, NetEvent, OfferMsg,
};
use crate::store::{new_vault_id, secure_wipe, Store, VaultMeta};

/// Per-operation socket timeout for the handshake and data phases.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the accept loop sleeps between non-blocking accept attempts.
const ACCEPT_POLL: Duration = Duration::from_millis(150);
/// How long to wait for the user to accept/reject an incoming offer.
const OFFER_DECISION_TIMEOUT: Duration = Duration::from_secs(300);
/// Hard ceiling on a declared inbound transfer size. The receiver streams the
/// offered `.fsec` to a temp file and stops only once `received` exceeds the
/// *declared* size, so an unbounded declared size would let a verified-but-hostile
/// sender fill the disk. This caps the declared size (and therefore the bytes
/// ever written) before a single byte is accepted. Well above any realistic vault
/// yet a firm bound against disk exhaustion. (Querying actual free space portably
/// would need a platform dependency this dependency-light build avoids; the cap is
/// the enforced defense.)
const MAX_TRANSFER_SIZE: u64 = 64 * 1024 * 1024 * 1024;

pub fn run(
    config: ListenConfig,
    identity: &Identity,
    store: &Store,
    contacts: &ContactBook,
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

    let code = generate_pairing_code()?;
    if !emitter.emit(NetEvent::Listening {
        lan_addr,
        public_addr,
        nat,
        pairing_code: group_code(&code),
    }) {
        return Ok(());
    }

    let mut last_refresh = Instant::now();
    loop {
        match cmd_rx.try_recv() {
            Ok(NetCommand::Stop) => return Ok(()),
            Err(TryRecvError::Disconnected) => return Ok(()),
            _ => {}
        }
        if let Some(m) = &mapping {
            if last_refresh.elapsed().as_secs() >= PortMapping::refresh_interval_secs() {
                let _ = m.refresh();
                last_refresh = Instant::now();
            }
        }
        match listener.accept() {
            Ok((stream, _peer)) => {
                let _ = stream.set_nonblocking(false);
                if let Err(msg) = handle_conn(
                    stream,
                    identity,
                    store,
                    contacts,
                    &code,
                    config.expected_sender_fpr,
                    emitter,
                    cmd_rx,
                ) {
                    if !emitter.emit(NetEvent::Error(msg)) {
                        return Ok(());
                    }
                }
                // Keep listening for the next transfer (same session + code).
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            Err(e) => return Err(format!("could not accept a connection: {e}")),
        }
    }
}

/// Handle one accepted connection through to import (or a clean rejection/error).
#[allow(clippy::too_many_arguments)]
fn handle_conn(
    mut stream: TcpStream,
    identity: &Identity,
    store: &Store,
    contacts: &ContactBook,
    code: &str,
    expected: Option<[u8; 32]>,
    emitter: &Emitter,
    cmd_rx: &Receiver<NetCommand>,
) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));

    // Mutual-auth handshake. `expected` designates which contact the receiver is
    // waiting for; the core rejects anyone else even if they authenticate validly.
    let mut responder =
        Responder::new(identity, Some(code.as_bytes()), expected).map_err(|e| e.to_string())?;
    let hello = read_handshake_frame(&mut stream).map_err(|e| e.to_string())?;
    let auth = responder
        .read_hello_write_auth(&hello)
        .map_err(|e| e.to_string())?;
    write_frame(&mut stream, &auth).map_err(|e| e.to_string())?;
    let confirm = read_handshake_frame(&mut stream).map_err(|e| e.to_string())?;
    let (peer, mut session) = match responder.read_confirm(&confirm) {
        Ok(pair) => pair,
        Err(filesec_core::Error::PeerIdentityMismatch) => {
            return Err(
                "Refused: a different contact connected than the one you're expecting.".into(),
            )
        }
        Err(e) => return Err(e.to_string()),
    };

    // Contact-book gate: only a verified contact may send.
    let contact = contacts.find(&peer.fingerprint);
    let verified = matches!(contact.map(|c| c.trust), Some(Trust::Verified));
    let name = contact.map(|c| c.identity.name.clone());
    let fpr_hex = peer.identity.fingerprint_hex();
    emitter.emit(NetEvent::PeerConnected {
        fpr_hex: fpr_hex.clone(),
        name: name.clone(),
        verified,
    });
    if !verified {
        return Err(format!(
            "Refused a transfer from an unverified sender ({}…). Add and verify them in Contacts first.",
            fpr_hex.get(..16).unwrap_or(&fpr_hex)
        ));
    }

    // Read the offer.
    let offer_frame = read_handshake_frame(&mut stream).map_err(|e| e.to_string())?;
    let (rtype, plaintext) = session
        .open_record(&offer_frame)
        .map_err(|e| e.to_string())?;
    if rtype != RecordType::Offer {
        return Err("protocol error: expected a transfer offer".into());
    }
    let offer: OfferMsg = codec::from_slice(&plaintext).map_err(|e| e.to_string())?;
    if offer.sender_fpr != peer.fingerprint {
        return Err("the offer's sender does not match the connected identity".into());
    }
    // Reject an absurdly large declared size before prompting the user or writing
    // a byte — the received-size check below only bounds bytes to this declared
    // size, so an uncapped size is a disk-exhaustion lever.
    if !transfer_size_acceptable(offer.size) {
        return Err("the offered transfer is too large to accept".into());
    }
    emitter.emit(NetEvent::Offer {
        filename: offer.filename.clone(),
        size: offer.size,
        sender_name: name.clone(),
        verified,
    });

    // Wait for the user to accept or reject, then tell the sender.
    let accept = wait_decision(cmd_rx)?;
    let decision = codec::to_vec(&DecisionMsg { accept }).map_err(|e| e.to_string())?;
    let frame = session
        .seal_record(RecordType::OfferDecision, &decision)
        .map_err(|e| e.to_string())?;
    write_frame(&mut stream, &frame).map_err(|e| e.to_string())?;
    if !accept {
        return Ok(());
    }

    // Stream the encrypted container to a private temp, then verify + import.
    let incoming_id = new_vault_id()?;
    let temp = store.create_private_checkout_file(&format!("incoming-{incoming_id}.fsec"))?;
    let result = match receive_into(
        &mut stream,
        &mut session,
        &temp,
        offer.size,
        emitter,
        cmd_rx,
    ) {
        Ok(()) => {
            // The bytes are in; verifying the signature and re-encrypting into the
            // local store can take a moment for a large vault, so say so.
            emitter.emit(NetEvent::Status("Verifying & saving…".into()));
            import_received(store, identity, &temp, &peer.fingerprint)
        }
        Err(e) => Err(e),
    };
    let _ = secure_wipe(&temp);
    let (meta, file_count) = result?;
    emitter.emit(NetEvent::Received {
        meta,
        file_count,
        sender_name: name,
    });
    Ok(())
}

/// Wait (up to [`OFFER_DECISION_TIMEOUT`]) for the accept/reject command.
fn wait_decision(cmd_rx: &Receiver<NetCommand>) -> Result<bool, String> {
    match cmd_rx.recv_timeout(OFFER_DECISION_TIMEOUT) {
        Ok(NetCommand::AcceptOffer) => Ok(true),
        Ok(NetCommand::RejectOffer) => Ok(false),
        Ok(_) => Err("Transfer cancelled.".into()),
        Err(RecvTimeoutError::Timeout) => {
            Err("No response to the transfer offer (timed out).".into())
        }
        Err(RecvTimeoutError::Disconnected) => Err("Transfer cancelled.".into()),
    }
}

/// Read `Data` records into `temp` until `Done`, enforcing the declared size.
fn receive_into(
    stream: &mut TcpStream,
    session: &mut filesec_core::transport::Session,
    temp: &Path,
    size: u64,
    emitter: &Emitter,
    cmd_rx: &Receiver<NetCommand>,
) -> Result<(), String> {
    let mut file = std::fs::File::create(temp).map_err(|e| e.to_string())?;
    let mut received: u64 = 0;
    loop {
        match cmd_rx.try_recv() {
            Ok(NetCommand::Cancel) | Ok(NetCommand::Stop) => {
                return Err("Transfer cancelled.".into())
            }
            Err(TryRecvError::Disconnected) => return Err("Transfer cancelled.".into()),
            _ => {}
        }
        let frame = read_frame(stream).map_err(|e| e.to_string())?;
        let (rtype, plaintext) = session.open_record(&frame).map_err(|e| e.to_string())?;
        match rtype {
            RecordType::Data => {
                received = received.saturating_add(plaintext.len() as u64);
                if received > size {
                    return Err("the sender exceeded the declared size".into());
                }
                file.write_all(&plaintext).map_err(|e| e.to_string())?;
                emitter.emit(NetEvent::Progress {
                    done: received,
                    total: size,
                });
            }
            RecordType::Done => break,
            _ => return Err("protocol error during the transfer".into()),
        }
    }
    file.flush().map_err(|e| e.to_string())?;
    let _ = file.sync_all();
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
    let id = new_vault_id()?;
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
