//! Length-prefixed framing over a `TcpStream`.
//!
//! Every handshake message and every record is sent as `u32_be length ‖ bytes`.
//! This is the only place that touches the socket for reads/writes; it hands
//! `filesec_core::transport` opaque byte buffers. A per-frame cap bounds how much
//! a peer can make us allocate before authentication — and the cap is split so an
//! *unauthenticated* handshake/control frame is held to a far tighter limit than
//! a bulk `Data` record.

use std::io::{self, Read, Write};

/// Largest **data** frame we will read: a 64 KiB plaintext chunk plus AEAD and
/// framing overhead. 16 MiB is far above any legitimate data record yet caps a
/// hostile peer's allocation request once the session is authenticated.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Largest **handshake / control** frame we will read (Hello, Auth, Confirm,
/// Offer, OfferDecision, Done). These carry only small fixed structures — public
/// keys, nonces, signatures, a filename and a size — so 64 KiB is generous. The
/// pre-authentication handshake frames in particular must never be sized from the
/// bulk-data cap: a dialer that has proven nothing should not be able to make the
/// listener allocate megabytes. Substantially below [`MAX_FRAME`] by design.
pub const MAX_HANDSHAKE_FRAME: usize = 64 * 1024;

/// Write one length-prefixed frame and flush it.
pub fn write_frame(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large to send"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(data)?;
    w.flush()
}

/// Read one length-prefixed frame, rejecting anything larger than `max` before
/// allocating the buffer.
pub fn read_frame_bounded(r: &mut impl Read, max: usize) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds the maximum allowed size",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read one bulk `Data` frame, rejecting anything larger than [`MAX_FRAME`].
pub fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    read_frame_bounded(r, MAX_FRAME)
}

/// Read one handshake/control frame, rejecting anything larger than
/// [`MAX_HANDSHAKE_FRAME`] — a far tighter cap for the pre-/just-authenticated
/// phase than the bulk-data path uses.
pub fn read_handshake_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    read_frame_bounded(r, MAX_HANDSHAKE_FRAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Just the 4-byte length prefix: a bounded read rejects on the declared
    /// length before it ever reads (or allocates) the body.
    fn length_prefix(len: u32) -> Vec<u8> {
        len.to_be_bytes().to_vec()
    }

    // The handshake cap must stay below the data cap; `a_frame_between_the_caps_is_data_only`
    // exercises that invariant end to end (a frame just over the handshake cap is
    // still readable as a data record).

    #[test]
    fn handshake_reader_rejects_oversized_before_body_read() {
        let mut c = Cursor::new(length_prefix((MAX_HANDSHAKE_FRAME + 1) as u32));
        let err = read_handshake_frame(&mut c).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn data_reader_rejects_oversized_before_body_read() {
        let mut c = Cursor::new(length_prefix((MAX_FRAME + 1) as u32));
        let err = read_frame(&mut c).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_frame_between_the_caps_is_data_only() {
        // A frame just over the handshake cap is a valid bulk data record but must
        // be refused when read as a handshake/control frame.
        let len = (MAX_HANDSHAKE_FRAME + 1) as u32;
        let mut frame = length_prefix(len);
        frame.resize(frame.len() + len as usize, 0u8);
        assert!(read_handshake_frame(&mut Cursor::new(frame.clone())).is_err());
        let got = read_frame(&mut Cursor::new(frame)).unwrap();
        assert_eq!(got.len(), len as usize);
    }

    #[test]
    fn write_then_read_roundtrips() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        assert_eq!(
            read_handshake_frame(&mut Cursor::new(buf)).unwrap(),
            b"hello"
        );
    }
}
