//! Sender side: export the chosen vault to a temp `.fsec` encrypted to the
//! recipient, dial the receiver, authenticate it as the chosen contact, offer the
//! transfer, and stream it.

use std::io::Read;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Duration;

use filesec_core::transport::{Initiator, RecordType};
use filesec_core::{codec, ExportOptions, Identity};

use super::wire::{read_frame, write_frame};
use super::{normalize_code, DecisionMsg, Emitter, NetCommand, NetEvent, OfferMsg, SendConfig};
use crate::store::{new_vault_id, secure_wipe, Store};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(30);
/// While waiting for the receiver's accept/reject, allow for the human at the
/// other end (slightly longer than the receiver's own offer timeout).
const DECISION_TIMEOUT: Duration = Duration::from_secs(310);
/// Plaintext-equivalent chunk size streamed per `Data` record.
const CHUNK: usize = 64 * 1024;

pub fn run(
    config: SendConfig,
    identity: &Identity,
    store: &Store,
    emitter: &Emitter,
    cmd_rx: &Receiver<NetCommand>,
) -> Result<(), String> {
    // Produce the signed, recipient-encrypted container to a private temp.
    let reader = store.open_vault(identity, &config.vault_id)?;
    let vault_name = reader.name().to_string();
    let temp = store.create_private_checkout_file(&format!("outgoing-{}.fsec", new_vault_id()))?;
    let recipients = [config.recipient.clone()];
    let options = ExportOptions::default();
    if let Err(e) =
        filesec_core::format_v2::export_v2_to_path(&reader, identity, &recipients, &options, &temp)
    {
        let _ = secure_wipe(&temp);
        return Err(e.to_string());
    }

    let result = send_file(&config, identity, &temp, &vault_name, emitter, cmd_rx);
    let _ = secure_wipe(&temp);
    result
}

fn send_file(
    config: &SendConfig,
    identity: &Identity,
    temp: &Path,
    vault_name: &str,
    emitter: &Emitter,
    cmd_rx: &Receiver<NetCommand>,
) -> Result<(), String> {
    let size = std::fs::metadata(temp).map_err(|e| e.to_string())?.len();

    emitter.emit(NetEvent::Connecting);
    let addr = resolve(&config.host, config.port)?;
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| format!("could not connect to {}:{}: {e}", config.host, config.port))?;
    let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));

    // Mutual-auth handshake; aborts in core on a fingerprint or pairing-code mismatch.
    let code = config
        .pairing_code
        .as_deref()
        .map(normalize_code)
        .filter(|c| !c.is_empty());
    let initiator = Initiator::new(
        identity,
        config.recipient_fpr,
        code.as_deref().map(str::as_bytes),
    )
    .map_err(|e| e.to_string())?;
    let hello = initiator.write_hello().map_err(|e| e.to_string())?;
    write_frame(&mut stream, &hello).map_err(|e| e.to_string())?;
    let auth = read_frame(&mut stream).map_err(|e| e.to_string())?;
    let (confirm, mut session) = initiator
        .read_auth_write_confirm(&auth)
        .map_err(|e| e.to_string())?;
    write_frame(&mut stream, &confirm).map_err(|e| e.to_string())?;

    let name = (!config.recipient.name.is_empty()).then(|| config.recipient.name.clone());
    emitter.emit(NetEvent::PeerConnected {
        fpr_hex: config.recipient.fingerprint_hex(),
        name,
        verified: true,
    });

    // Offer the transfer.
    let offer = OfferMsg {
        filename: format!("{vault_name}.fsec"),
        size,
        sender_fpr: identity.fingerprint(),
    };
    let offer_bytes = codec::to_vec(&offer).map_err(|e| e.to_string())?;
    let offer_frame = session
        .seal_record(RecordType::Offer, &offer_bytes)
        .map_err(|e| e.to_string())?;
    write_frame(&mut stream, &offer_frame).map_err(|e| e.to_string())?;

    // Await the receiver's decision (the human may take a while).
    let _ = stream.set_read_timeout(Some(DECISION_TIMEOUT));
    let decision_frame = read_frame(&mut stream).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
    let (rtype, plaintext) = session
        .open_record(&decision_frame)
        .map_err(|e| e.to_string())?;
    if rtype != RecordType::OfferDecision {
        return Err("protocol error: expected a decision".into());
    }
    let decision: DecisionMsg = codec::from_slice(&plaintext).map_err(|e| e.to_string())?;
    if !decision.accept {
        emitter.emit(NetEvent::Declined);
        return Ok(());
    }

    // Stream the container as Data records, then Done.
    let mut file = std::fs::File::open(temp).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; CHUNK];
    let mut sent: u64 = 0;
    loop {
        match cmd_rx.try_recv() {
            Ok(NetCommand::Cancel) | Ok(NetCommand::Stop) => {
                return Err("Transfer cancelled.".into())
            }
            Err(TryRecvError::Disconnected) => return Err("Transfer cancelled.".into()),
            _ => {}
        }
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        let chunk = buf.get(..n).ok_or("internal read overflow")?;
        let frame = session
            .seal_record(RecordType::Data, chunk)
            .map_err(|e| e.to_string())?;
        write_frame(&mut stream, &frame).map_err(|e| e.to_string())?;
        sent = sent.saturating_add(n as u64);
        emitter.emit(NetEvent::Progress {
            done: sent,
            total: size,
        });
    }
    let done = session
        .seal_record(RecordType::Done, b"")
        .map_err(|e| e.to_string())?;
    write_frame(&mut stream, &done).map_err(|e| e.to_string())?;

    emitter.emit(NetEvent::Sent {
        vault_name: vault_name.to_string(),
    });
    Ok(())
}

/// Resolve `host:port` to a single socket address.
fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("could not resolve {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("no address found for {host}"))
}
