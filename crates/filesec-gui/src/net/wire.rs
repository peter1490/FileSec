//! Length-prefixed framing over a `TcpStream`.
//!
//! Every handshake message and every record is sent as `u32_be length ‖ bytes`.
//! This is the only place that touches the socket for reads/writes; it hands
//! `filesec_core::transport` opaque byte buffers. A hard `MAX_FRAME` cap bounds
//! how much a peer can make us allocate before authentication.

use std::io::{self, Read, Write};

/// Largest frame we will read. Handshake/control messages are small; data records
/// are a 64 KiB plaintext chunk plus AEAD and framing overhead. 16 MiB is far
/// above any legitimate frame and caps a hostile peer's allocation request.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Write one length-prefixed frame and flush it.
pub fn write_frame(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large to send"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(data)?;
    w.flush()
}

/// Read one length-prefixed frame, rejecting anything larger than [`MAX_FRAME`].
pub fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds the maximum allowed size",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}
