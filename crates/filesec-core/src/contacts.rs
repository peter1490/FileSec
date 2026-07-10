//! Contact book: other parties' public identities and their trust state.
//!
//! FileSec uses a manual / trust-on-first-use model — there is no PKI or CA. A
//! contact is [`Trust::Unverified`] until the user compares its safety number
//! out-of-band and marks it [`Trust::Verified`].

use serde::{Deserialize, Serialize};

use crate::codec;
use crate::error::Result;
use crate::identity::PublicIdentity;

/// Trust level the user has assigned to a contact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Trust {
    /// Imported but the fingerprint has not been confirmed out-of-band.
    Unverified,
    /// The user confirmed the safety number through a trusted side channel.
    Verified,
}

/// A single contact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    /// The contact's public identity.
    pub identity: PublicIdentity,
    /// Assigned trust level.
    pub trust: Trust,
    /// Unix time the contact was added.
    pub added_at: i64,
    /// Unix time the user last marked this contact [`Trust::Verified`], or
    /// `None` while it is unverified. Cleared whenever trust drops back to
    /// unverified. Defaulted on load so contact books written before this field
    /// existed deserialize cleanly.
    #[serde(default)]
    pub verified_at: Option<i64>,
}

impl Contact {
    /// The contact's fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.identity.fingerprint()
    }
}

/// What an [`ContactBook::upsert`] did, so callers can warn the user before a
/// surprising change takes effect. The fingerprint is the stable cryptographic
/// identity, so a re-import can only ever change the *advisory display name* of
/// an existing contact — never its keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpsertOutcome {
    /// A brand-new contact was inserted (always [`Trust::Unverified`]).
    Added,
    /// An existing contact was re-imported with an identical display name;
    /// nothing observable changed.
    Unchanged,
    /// An existing contact's display name changed. The keys (and therefore the
    /// fingerprint and any verification) are unchanged, but the rename is worth
    /// surfacing — a renamed *verified* contact can be a social-engineering
    /// signal worth a second look.
    Renamed {
        /// The previously stored display name.
        old: String,
        /// The incoming display name.
        new: String,
        /// Whether the contact was [`Trust::Verified`] at the time of the rename.
        was_verified: bool,
    },
}

/// The full contact book, persisted as CBOR.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ContactBook {
    /// All known contacts.
    pub contacts: Vec<Contact>,
}

impl ContactBook {
    /// Insert or update a contact by fingerprint. Updating preserves the
    /// existing trust level (re-importing a key never silently re-trusts it,
    /// and never silently downgrades a verified contact). Returns an
    /// [`UpsertOutcome`] describing what changed so callers can warn the user.
    ///
    /// The incoming display name is **sanitized before it is stored** (F13):
    /// imported identities carry attacker-controlled names, so bidi/invisible
    /// controls are stripped and whitespace normalized here, at the single point
    /// where an untrusted name enters persistent state. Every later read of
    /// `contact.identity.name` is therefore already safe to display, and rename
    /// detection compares the sanitized forms.
    pub fn upsert(&mut self, mut identity: PublicIdentity, now: i64) -> UpsertOutcome {
        identity.name = crate::identity::sanitize_display_name(&identity.name);
        let fpr = identity.fingerprint();
        if let Some(existing) = self.contacts.iter_mut().find(|c| c.fingerprint() == fpr) {
            let old = existing.identity.name.clone();
            let new = identity.name.clone();
            let was_verified = existing.trust == Trust::Verified;
            existing.identity = identity;
            if old == new {
                UpsertOutcome::Unchanged
            } else {
                UpsertOutcome::Renamed {
                    old,
                    new,
                    was_verified,
                }
            }
        } else {
            self.contacts.push(Contact {
                identity,
                trust: Trust::Unverified,
                added_at: now,
                verified_at: None,
            });
            UpsertOutcome::Added
        }
    }

    /// Look up a contact by fingerprint.
    #[must_use]
    pub fn find(&self, fingerprint: &[u8; 32]) -> Option<&Contact> {
        self.contacts
            .iter()
            .find(|c| &c.fingerprint() == fingerprint)
    }

    /// Set a contact's trust level, stamping (or clearing) the verification
    /// time accordingly. Returns `true` if the contact existed.
    pub fn set_trust(&mut self, fingerprint: &[u8; 32], trust: Trust, now: i64) -> bool {
        if let Some(c) = self
            .contacts
            .iter_mut()
            .find(|c| &c.fingerprint() == fingerprint)
        {
            c.trust = trust;
            c.verified_at = match trust {
                Trust::Verified => Some(now),
                Trust::Unverified => None,
            };
            true
        } else {
            false
        }
    }

    /// Remove a contact by fingerprint. Returns `true` if one was removed.
    pub fn remove(&mut self, fingerprint: &[u8; 32]) -> bool {
        let before = self.contacts.len();
        self.contacts.retain(|c| &c.fingerprint() != fingerprint);
        self.contacts.len() != before
    }

    /// Serialize to CBOR bytes for storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        codec::to_vec(self)
    }

    /// Parse from CBOR bytes.
    ///
    /// Contact display names are re-sanitized on load (F13) so a book written
    /// before display-name sanitization existed still yields safe names in memory;
    /// sanitization is idempotent, so books written by the current code are
    /// unchanged. Every in-memory `ContactBook` therefore holds display-safe names.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut book: Self = codec::from_slice(bytes)?;
        for c in &mut book.contacts {
            c.identity.name = crate::identity::sanitize_display_name(&c.identity.name);
        }
        Ok(book)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn upsert_sanitizes_the_stored_display_name() {
        let mut id = Identity::generate("Mallory", 0).unwrap().public();
        // A bidi-override + zero-width spoof in the imported name.
        id.name = "photo\u{202E}gpj.exe\u{200B}".to_string();
        let mut book = ContactBook::default();
        assert_eq!(book.upsert(id.clone(), 1), UpsertOutcome::Added);
        // The persisted contact name is already safe — no bidi/invisible chars.
        assert_eq!(book.contacts[0].identity.name, "photogpj.exe");
        // Re-importing the same hostile name is a no-op (compares sanitized forms).
        assert_eq!(book.upsert(id, 2), UpsertOutcome::Unchanged);
    }

    #[test]
    fn upsert_rename_compares_sanitized_names() {
        let base = Identity::generate("Alice", 0).unwrap();
        let mut a = base.public();
        a.name = "Alice".to_string();
        let mut book = ContactBook::default();
        book.upsert(a, 1);
        // A "rename" that only adds a stripped bidi control is not a real change.
        let mut b = base.public();
        b.name = "Alice\u{202E}".to_string();
        assert_eq!(book.upsert(b, 2), UpsertOutcome::Unchanged);
    }
}
