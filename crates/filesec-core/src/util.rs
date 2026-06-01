//! Miscellaneous helpers with no better home.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix time in seconds. Returns 0 if the system clock is before the
/// epoch (never panics).
#[must_use]
pub fn now_unix() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    }
}

/// Lowercase hex encoding.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

/// Render bytes as a grouped uppercase base32 "safety number" (groups of 4
/// characters separated by `-`) for human out-of-band comparison.
#[must_use]
pub fn safety_number(bytes: &[u8]) -> String {
    let encoded = data_encoding::BASE32_NOPAD.encode(bytes);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 4);
    for (i, ch) in encoded.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(ch);
    }
    out
}
