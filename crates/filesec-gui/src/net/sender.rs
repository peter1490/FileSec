//! Sender side: dial the receiver and authenticate it as the chosen contact
//! **first** — so an unreachable peer, a wrong address, or the wrong identity
//! fails in seconds — and only then stream the chosen vault, encrypted to the
//! recipient on the fly, straight over the wire.
//!
//! Nothing is written to a temp `.fsec` and the whole vault is never held in
//! memory: the container is produced by [`filesec_core::format_v2::V2ExportPlan`]
//! chunk-by-chunk and each ~64 KiB of ciphertext is framed into one `Data` record
//! as it is produced, so encryption and network send happen together. Peak memory
//! is a couple of chunks regardless of vault size.

use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

use filesec_core::transport::{Initiator, RecordType, Session};
use filesec_core::{codec, ExportOptions, Identity};

use super::wire::{read_frame_until, write_frame, MAX_HANDSHAKE_FRAME};
use super::{
    decode_transfer_code, DecisionMsg, Emitter, NetCommand, NetEvent, OfferMsg, SendConfig,
};
use crate::store::Store;

/// How long to wait for the TCP connection itself. Kept short: this is the
/// "is the receiver even up?" probe, and it now runs *before* any encryption, so a
/// down or wrong-address peer is reported quickly rather than after a long,
/// pointless encrypt of the whole vault.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-operation socket timeout for the handshake and data phases.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(30);
/// While waiting for the receiver's accept/reject, allow for the human at the
/// other end (slightly longer than the receiver's own offer timeout).
const DECISION_TIMEOUT: Duration = Duration::from_secs(310);
/// Plaintext-equivalent chunk size carried per `Data` record.
const CHUNK: usize = 64 * 1024;

pub fn run(
    config: SendConfig,
    identity: &Identity,
    store: &Store,
    emitter: &Emitter,
    cmd_rx: &Receiver<NetCommand>,
) -> Result<(), String> {
    // Open the vault for metadata only — no file content is read here (or until
    // we actually start streaming, below).
    let reader = store.open_vault(identity, &config.vault_id)?;
    let vault_name = reader.name().to_string();

    // 1. Connect first, so an unreachable receiver fails fast.
    emitter.emit(NetEvent::Connecting);
    let addr = resolve(&config.host, config.port)?;
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(|e| {
        format!(
            "Couldn't reach the receiver at {}:{}. Make sure they've started listening and the address and port are right. ({e})",
            config.host, config.port
        )
    })?;
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(SOCKET_TIMEOUT))
        .map_err(|e| e.to_string())?;

    // 2. Mutual-auth handshake; aborts in core on a fingerprint or transfer-secret
    //    mismatch. Completing it proves the receiver is up *and* is the contact we
    //    meant to reach — all before we encrypt a single byte. The transfer secret
    //    is mandatory: without it the receiver will not disclose its identity.
    let secret = config
        .transfer_code
        .as_deref()
        .and_then(decode_transfer_code)
        .ok_or_else(|| {
            "Enter the transfer code the receiver is showing (letters and numbers).".to_string()
        })?;
    let initiator =
        Initiator::new(identity, config.recipient_fpr, &secret).map_err(|e| e.to_string())?;
    let hello = initiator.write_hello().map_err(|e| e.to_string())?;
    write_frame(&mut stream, &hello).map_err(|e| e.to_string())?;
    let auth = read_frame_until(
        &mut stream,
        MAX_HANDSHAKE_FRAME,
        Instant::now() + SOCKET_TIMEOUT,
        || cancelled(cmd_rx),
    )
    .map_err(|e| e.to_string())?;
    let (confirm, mut session) = initiator
        .read_auth_write_confirm(&auth)
        .map_err(|e| e.to_string())?;
    write_frame(&mut stream, &confirm).map_err(|e| e.to_string())?;

    let peer_name = (!config.recipient.name.is_empty()).then(|| config.recipient.name.clone());
    emitter.emit(NetEvent::PeerConnected {
        fpr_hex: config.recipient.fingerprint_hex(),
        name: peer_name.clone(),
        verified: true,
    });

    // 3. Prepare the export — manifest + content-key wrap only, still no file data
    //    read — which gives us the exact container size to declare in the offer.
    let recipients = [config.recipient.clone()];
    let options = ExportOptions::default();
    let plan = reader
        .export_plan(identity, &recipients, &options)
        .map_err(|e| e.to_string())?;
    let size = plan.container_size();

    // 4. Offer the transfer, then await the receiver's decision.
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

    let who = peer_name.clone().unwrap_or_else(|| "the receiver".into());
    emitter.emit(NetEvent::Status(format!("Waiting for {who} to accept…")));

    let decision_frame = read_frame_until(
        &mut stream,
        MAX_HANDSHAKE_FRAME,
        Instant::now() + DECISION_TIMEOUT,
        || cancelled(cmd_rx),
    )
    .map_err(|e| e.to_string())?;
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

    // 5. Stream the container straight over the wire: each ~64 KiB of ciphertext is
    //    encrypted on the fly from the blobs and sent as one `Data` record. No temp
    //    file, no whole-vault buffer — encrypting and sending are interleaved.
    emitter.emit(NetEvent::Status("Encrypting & sending…".into()));
    let mut rw = RecordWriter::new(&mut session, &mut stream, emitter, cmd_rx, size);
    let result = plan.write_to(&mut rw);
    if rw.cancelled {
        return Err("Transfer cancelled.".into());
    }
    result.map_err(|e| e.to_string())?;
    rw.finish().map_err(|e| e.to_string())?;

    emitter.emit(NetEvent::Sent { vault_name });
    Ok(())
}

/// A [`Write`] that frames the bytes of the streamed container into encrypted
/// `Data` records on the open session, reporting byte progress and honoring a
/// cancel/stop command between records.
///
/// [`filesec_core::format_v2::V2ExportPlan::write_to`] writes the whole container
/// straight through here, so encryption and the network send are interleaved.
struct RecordWriter<'a, W: Write> {
    session: &'a mut Session,
    stream: &'a mut W,
    emitter: &'a Emitter,
    cmd_rx: &'a Receiver<NetCommand>,
    /// Total container bytes — equal to the size declared in the offer.
    total: u64,
    /// Container bytes handed to the socket so far.
    sent: u64,
    last_progress: Instant,
    /// Bytes buffered toward the next `Data` record (at most `CHUNK`).
    buf: Vec<u8>,
    /// Set if a Cancel/Stop arrived (or the UI dropped the command channel) so the
    /// caller can report a clean cancellation instead of a raw socket error.
    cancelled: bool,
}

impl<'a, W: Write> RecordWriter<'a, W> {
    fn new(
        session: &'a mut Session,
        stream: &'a mut W,
        emitter: &'a Emitter,
        cmd_rx: &'a Receiver<NetCommand>,
        total: u64,
    ) -> Self {
        Self {
            session,
            stream,
            emitter,
            cmd_rx,
            total,
            sent: 0,
            last_progress: Instant::now(),
            buf: Vec::with_capacity(CHUNK),
            cancelled: false,
        }
    }

    /// Whether a Cancel/Stop is pending; records it so the caller can map the
    /// resulting write error to a clean "cancelled" message.
    fn cancel_requested(&mut self) -> bool {
        match self.cmd_rx.try_recv() {
            Ok(NetCommand::Cancel) | Ok(NetCommand::Stop) | Err(TryRecvError::Disconnected) => {
                self.cancelled = true;
                true
            }
            _ => false,
        }
    }

    /// Seal `chunk` as a `Data` record, send it, and advance progress.
    fn send_data(&mut self, chunk: &[u8]) -> io::Result<()> {
        if self.cancel_requested() {
            return Err(io::Error::other("transfer cancelled"));
        }
        let frame = self
            .session
            .seal_record(RecordType::Data, chunk)
            .map_err(|e| io::Error::other(e.to_string()))?;
        write_frame(self.stream, &frame)?;
        self.sent = self.sent.saturating_add(chunk.len() as u64);
        if self.sent == self.total || self.last_progress.elapsed() >= Duration::from_millis(100) {
            self.emitter.emit(NetEvent::Progress {
                done: self.sent,
                total: self.total,
            });
            self.last_progress = Instant::now();
        }
        Ok(())
    }

    /// Flush any buffered tail as a final `Data` record, then send `Done`.
    fn finish(mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let chunk = std::mem::take(&mut self.buf);
            self.send_data(&chunk)?;
        }
        let done = self
            .session
            .seal_record(RecordType::Done, b"")
            .map_err(|e| io::Error::other(e.to_string()))?;
        write_frame(self.stream, &done)
    }
}

impl<W: Write> Write for RecordWriter<'_, W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut remaining = data;
        while !remaining.is_empty() {
            if self.buf.is_empty() && remaining.len() >= CHUNK {
                // Send complete chunks directly from the caller's slice. This
                // avoids copying a large header and repeatedly shifting its tail.
                self.send_data(&remaining[..CHUNK])?;
                remaining = &remaining[CHUNK..];
            } else {
                let n = remaining.len().min(CHUNK - self.buf.len());
                self.buf.extend_from_slice(&remaining[..n]);
                remaining = &remaining[n..];
                if self.buf.len() == CHUNK {
                    let chunk = std::mem::take(&mut self.buf);
                    let result = self.send_data(&chunk);
                    self.buf = chunk;
                    self.buf.clear();
                    result?;
                }
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Records are emitted at CHUNK boundaries and the tail in `finish`. A
        // mid-stream flush from the container writer must not emit a short record
        // (that would just fragment the stream), so this is intentionally a no-op.
        Ok(())
    }
}

/// Resolve `host:port` to a single socket address.
fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("could not resolve {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("no address found for {host}"))
}

fn cancelled(commands: &Receiver<NetCommand>) -> bool {
    matches!(
        commands.try_recv(),
        Ok(NetCommand::Cancel | NetCommand::Stop) | Err(TryRecvError::Disconnected)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use filesec_core::transport::Responder;
    use std::io::Cursor;
    use std::sync::mpsc;

    #[test]
    fn record_writer_bounds_buffer_and_preserves_fragmented_content() {
        let alice = Identity::generate("Alice", 0).unwrap();
        let bob = Identity::generate("Bob", 0).unwrap();
        let secret = b"record writer test transfer secret";
        let initiator = Initiator::new(&alice, bob.fingerprint(), secret).unwrap();
        let mut responder = Responder::new(&bob, secret, None).unwrap();
        let auth = responder
            .read_hello_write_auth(&initiator.write_hello().unwrap())
            .unwrap();
        let (confirm, mut sending) = initiator.read_auth_write_confirm(&auth).unwrap();
        let (_, mut receiving) = responder.read_confirm(&confirm).unwrap();
        let (event_tx, _events) = mpsc::channel();
        let (_commands, command_rx) = mpsc::channel();
        let emitter = Emitter {
            tx: event_tx,
            ctx: egui::Context::default(),
        };
        let data: Vec<u8> = (0..CHUNK * 20 + 123).map(|i| (i % 251) as u8).collect();
        let mut wire = Vec::new();
        let mut writer = RecordWriter::new(
            &mut sending,
            &mut wire,
            &emitter,
            &command_rx,
            data.len() as u64,
        );
        writer.write_all(&data[..17]).unwrap();
        writer.write_all(&data[17..]).unwrap();
        assert!(writer.buf.capacity() <= CHUNK);
        writer.finish().unwrap();
        let mut wire = Cursor::new(wire);
        let mut restored = Vec::new();
        loop {
            let frame = super::super::wire::read_frame(&mut wire).unwrap();
            let (kind, body) = receiving.open_record(&frame).unwrap();
            if kind == RecordType::Done {
                assert!(body.is_empty());
                break;
            }
            assert_eq!(kind, RecordType::Data);
            assert!(body.len() <= CHUNK);
            restored.extend_from_slice(&body);
        }
        assert_eq!(restored, data);
        assert_eq!(wire.position(), wire.get_ref().len() as u64);
    }
}
