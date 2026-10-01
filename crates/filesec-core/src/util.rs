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

/// Whether `c` is an invisible or text-reordering *format* character: bidi
/// embeddings/overrides/isolates and marks, zero-width characters, invisible
/// operators, soft hyphen, deprecated format controls, interlinear annotation
/// marks, and Unicode tag characters.
///
/// They have no legitimate place in a display name or a file name, and they
/// are the classic tools for visual spoofing: `report\u{202E}gpj.exe` renders as
/// `reportexe.jpg`, and zero-width or tag characters hide text entirely.
/// Identity display names drop them; new vault paths reject them.
#[must_use]
pub fn is_spoofing_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}' |               // soft hyphen (invisible unless wrapped)
        '\u{061C}' |               // Arabic letter mark
        '\u{180E}' |               // Mongolian vowel separator
        '\u{200B}'..='\u{200F}' | // ZWSP, ZWNJ, ZWJ, LRM, RLM
        '\u{202A}'..='\u{202E}' | // LRE, RLE, PDF, LRO, RLO (bidi overrides)
        '\u{2060}'..='\u{2064}' | // word joiner + invisible math operators
        '\u{2066}'..='\u{206F}' | // LRI, RLI, FSI, PDI + deprecated format controls
        '\u{FEFF}' |               // BOM / zero-width no-break space
        '\u{FFF9}'..='\u{FFFB}' | // interlinear annotation controls
        '\u{E0001}' | '\u{E0020}'..='\u{E007F}') // tag characters
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

/// Reduce a safety number (or anything a human typed while comparing one) to a
/// canonical form for equality checks: keep only ASCII alphanumerics, uppercase
/// them, and drop everything else (the grouping dashes, spaces, and stray line
/// breaks people introduce when reading a code aloud or pasting it). Two
/// safety numbers are "the same" iff their normalized forms are equal.
#[must_use]
pub fn normalize_safety_number(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}
