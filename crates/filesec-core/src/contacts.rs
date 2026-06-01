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
}

impl Contact {
    /// The contact's fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.identity.fingerprint()
    }
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
    /// and never silently downgrades a verified contact).
    pub fn upsert(&mut self, identity: PublicIdentity, now: i64) {
        let fpr = identity.fingerprint();
        if let Some(existing) = self.contacts.iter_mut().find(|c| c.fingerprint() == fpr) {
            existing.identity = identity;
        } else {
            self.contacts.push(Contact {
                identity,
                trust: Trust::Unverified,
                added_at: now,
            });
        }
    }

    /// Look up a contact by fingerprint.
    #[must_use]
    pub fn find(&self, fingerprint: &[u8; 32]) -> Option<&Contact> {
        self.contacts
            .iter()
            .find(|c| &c.fingerprint() == fingerprint)
    }

    /// Set a contact's trust level. Returns `true` if the contact existed.
    pub fn set_trust(&mut self, fingerprint: &[u8; 32], trust: Trust) -> bool {
        if let Some(c) = self
            .contacts
            .iter_mut()
            .find(|c| &c.fingerprint() == fingerprint)
        {
            c.trust = trust;
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        codec::from_slice(bytes)
    }
}
