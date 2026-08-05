//! Non-secret UI preferences.
//!
//! This is the one thing FileSec stores **unencrypted** by choice. Every other
//! file in the data directory is either the passphrase-protected keystore or a
//! container encrypted to the user's own identity — see [`crate::store`]. The
//! theme has to be applied to the very first frame, which is painted *before*
//! there is an unlocked [`Identity`](filesec_core::identity::Identity) to
//! decrypt anything with, so an encrypted preference could not do its job: the
//! unlock screen itself would always flash in the wrong theme.
//!
//! Encoded as CBOR through `filesec_core::codec`, the same as the plaintext
//! `.state-anchors` file it sits beside — no new dependency, no new format.
//!
//! # Nothing confidential may be added here
//!
//! This file is unauthenticated, is not covered by the rollback/high-water
//! anchor machinery, and is readable by anything that can read the data
//! directory. The entire consequence of an attacker rewriting it is that the
//! app opens in the wrong colour. Anything with security meaning — auto-unlock
//! secrets, passkey slots, contact trust state — belongs in the OS keychain or
//! the encrypted store, never in this file.

use serde::{Deserialize, Serialize};

/// On-disk format version. Bump when a field's meaning changes; a file written
/// by a *newer* build is discarded in favour of defaults rather than
/// misinterpreted.
pub const PREFS_VERSION: u16 = 1;

/// The persisted UI preferences.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prefs {
    pub version: u16,
    pub theme: ThemeChoice,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            version: PREFS_VERSION,
            theme: ThemeChoice::default(),
        }
    }
}

/// Which appearance the user picked.
///
/// Mirrors `egui::ThemePreference` deliberately rather than reusing it: this
/// module is the persistence model and stays free of any UI dependency, so
/// [`crate::store`] can round-trip it without pulling egui in. The mapping to
/// egui lives in [`crate::theme::apply_choice`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemeChoice {
    /// Follow the OS appearance. The default, and what every build before this
    /// one did unconditionally.
    #[default]
    System,
    Light,
    Dark,
}

impl ThemeChoice {
    /// The three choices in the order the Settings page shows them.
    pub const ALL: [Self; 3] = [Self::System, Self::Light, Self::Dark];

    /// Label for the Settings page selector.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::System => "System",
            Self::Light => "Light",
            Self::Dark => "Dark",
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_default_follows_the_system() {
        assert_eq!(ThemeChoice::default(), ThemeChoice::System);
        assert_eq!(Prefs::default().theme, ThemeChoice::System);
        assert_eq!(Prefs::default().version, PREFS_VERSION);
    }

    #[test]
    fn every_choice_survives_a_cbor_round_trip() {
        for choice in ThemeChoice::ALL {
            let prefs = Prefs {
                theme: choice,
                ..Prefs::default()
            };
            let bytes = filesec_core::codec::to_vec(&prefs).unwrap();
            let back: Prefs = filesec_core::codec::from_slice(&bytes).unwrap();
            assert_eq!(back, prefs, "{choice:?} did not round-trip");
        }
    }

    #[test]
    fn all_lists_every_variant_exactly_once() {
        // Guards the Settings selector against silently losing a choice —
        // "follow the system" in particular, which used to be the gear button's
        // only job.
        let mut seen = ThemeChoice::ALL.to_vec();
        seen.dedup();
        assert_eq!(seen.len(), 3);
        assert!(ThemeChoice::ALL.contains(&ThemeChoice::System));
    }
}
