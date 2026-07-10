//! Rollback-resistant state metadata shared by every local persistence format.
//!
//! Authentication (AEAD, a signature, or both) is supplied by the containing
//! format. This module defines the canonical binding and hash-chain rules, while
//! the GUI persistence layer keeps the latest [`StateAnchor`] outside the state
//! object (in the OS secure store where available).

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const STATE_HASH_CONTEXT: &[u8] = b"FileSec local state hash v1";
const STATE_AAD_CONTEXT: &[u8] = b"FileSec local state authenticated data v1";

/// Hash value used before an object's first protected state.
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// The security-sensitive local object represented by a state record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateObjectType {
    /// The passphrase/passkey-protected private identity keystore.
    Keystore,
    /// The encrypted contact book and its trust decisions.
    Contacts,
    /// The encrypted registry of local vaults.
    Registry,
    /// One encrypted v2 vault manifest.
    VaultManifest,
}

impl StateObjectType {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Keystore => b"keystore",
            Self::Contacts => b"contacts",
            Self::Registry => b"registry",
            Self::VaultManifest => b"vault-manifest",
        }
    }
}

impl std::fmt::Display for StateObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Keystore => "keystore",
            Self::Contacts => "contacts",
            Self::Registry => "registry",
            Self::VaultManifest => "vault manifest",
        };
        f.write_str(name)
    }
}

/// Authenticated, hash-chained metadata embedded in one state object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateMetadata {
    /// Identity that owns this state.
    pub identity_fingerprint: [u8; 32],
    /// Kind of state object.
    pub object_type: StateObjectType,
    /// Stable identifier within the object's type (for example, a vault id).
    pub object_id: String,
    /// Cryptographic suite used by the containing format (`0` for keystores).
    pub suite_id: u16,
    /// Monotonically increasing state generation. Protected state starts at 1.
    pub epoch: u64,
    /// Hash of the immediately preceding state, or [`GENESIS_HASH`] at genesis.
    pub previous_state_hash: [u8; 32],
    /// Hash of this metadata (except this field) and the canonical payload bytes.
    pub current_state_hash: [u8; 32],
}

impl StateMetadata {
    /// Construct the next state for `payload`, linked to `previous` when present.
    pub fn next(
        identity_fingerprint: [u8; 32],
        object_type: StateObjectType,
        object_id: impl Into<String>,
        suite_id: u16,
        previous: Option<&StateAnchor>,
        payload: &[u8],
    ) -> Result<Self> {
        let object_id = object_id.into();
        let (epoch, previous_state_hash) = match previous {
            Some(anchor) => {
                if anchor.identity_fingerprint != identity_fingerprint
                    || anchor.object_type != object_type
                    || anchor.object_id != object_id
                {
                    return Err(Error::StateMismatch(format!("{object_type} {object_id}")));
                }
                (
                    anchor
                        .epoch
                        .checked_add(1)
                        .ok_or(Error::Format("state epoch overflow"))?,
                    anchor.current_state_hash,
                )
            }
            None => (1, GENESIS_HASH),
        };
        let mut state = Self {
            identity_fingerprint,
            object_type,
            object_id,
            suite_id,
            epoch,
            previous_state_hash,
            current_state_hash: GENESIS_HASH,
        };
        state.current_state_hash = state.expected_hash(payload);
        Ok(state)
    }

    /// Verify that `payload` is exactly the content committed by this record.
    pub fn verify_payload(&self, payload: &[u8]) -> Result<()> {
        if self.epoch == 0 || self.current_state_hash != self.expected_hash(payload) {
            return Err(Error::StateMismatch(self.label()));
        }
        Ok(())
    }

    /// Canonical bytes to authenticate as AEAD associated data or sign.
    pub fn authenticated_data(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160 + self.object_id.len());
        append_lp(&mut out, STATE_AAD_CONTEXT);
        append_lp(&mut out, &self.identity_fingerprint);
        append_lp(&mut out, self.object_type.tag());
        append_lp(&mut out, self.object_id.as_bytes());
        append_lp(&mut out, &self.suite_id.to_le_bytes());
        append_lp(&mut out, &self.epoch.to_le_bytes());
        append_lp(&mut out, &self.previous_state_hash);
        append_lp(&mut out, &self.current_state_hash);
        out
    }

    /// A human-readable, non-secret object label for diagnostics.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{} {}", self.object_type, self.object_id)
    }

    fn expected_hash(&self, payload: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        update_lp(&mut h, STATE_HASH_CONTEXT);
        update_lp(&mut h, &self.identity_fingerprint);
        update_lp(&mut h, self.object_type.tag());
        update_lp(&mut h, self.object_id.as_bytes());
        update_lp(&mut h, &self.suite_id.to_le_bytes());
        update_lp(&mut h, &self.epoch.to_le_bytes());
        update_lp(&mut h, &self.previous_state_hash);
        update_lp(&mut h, payload);
        *h.finalize().as_bytes()
    }
}

/// High-water record stored independently from the authenticated state object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateAnchor {
    /// Identity that owns the anchored state.
    pub identity_fingerprint: [u8; 32],
    /// Kind of state object.
    pub object_type: StateObjectType,
    /// Stable identifier within the object's type.
    pub object_id: String,
    /// Suite committed by the current state.
    pub suite_id: u16,
    /// Highest accepted state epoch.
    pub epoch: u64,
    /// Hash committed at `epoch`.
    pub current_state_hash: [u8; 32],
}

impl StateAnchor {
    /// Make an anchor from already-authenticated state metadata.
    #[must_use]
    pub fn from_metadata(state: &StateMetadata) -> Self {
        Self {
            identity_fingerprint: state.identity_fingerprint,
            object_type: state.object_type,
            object_id: state.object_id.clone(),
            suite_id: state.suite_id,
            epoch: state.epoch,
            current_state_hash: state.current_state_hash,
        }
    }

    /// Check whether `candidate` is current or the single valid successor.
    ///
    /// Returning `Ok(false)` means it is the already-anchored state. `Ok(true)`
    /// means the caller should persist a new high-water anchor after the
    /// containing format has authenticated successfully.
    pub fn check_candidate(&self, candidate: &StateMetadata) -> Result<bool> {
        let label = candidate.label();
        if self.identity_fingerprint != candidate.identity_fingerprint
            || self.object_type != candidate.object_type
            || self.object_id != candidate.object_id
        {
            return Err(Error::StateMismatch(label));
        }
        if candidate.epoch < self.epoch {
            return Err(Error::RollbackDetected(label));
        }
        if candidate.epoch == self.epoch {
            if candidate.current_state_hash != self.current_state_hash
                || candidate.suite_id != self.suite_id
            {
                return Err(Error::StateMismatch(label));
            }
            return Ok(false);
        }
        if candidate.epoch != self.epoch.saturating_add(1)
            || candidate.previous_state_hash != self.current_state_hash
        {
            return Err(Error::StateMismatch(label));
        }
        Ok(true)
    }
}

fn append_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_le_bytes());
    out.extend_from_slice(field);
}

fn update_lp(h: &mut blake3::Hasher, field: &[u8]) {
    h.update(&(field.len() as u64).to_le_bytes());
    h.update(field);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn anchor_rejects_rollback_and_same_epoch_fork() {
        let first = StateMetadata::next(
            [7; 32],
            StateObjectType::Contacts,
            "contacts",
            1,
            None,
            b"one",
        )
        .unwrap();
        let anchor = StateAnchor::from_metadata(&first);
        assert!(!anchor.check_candidate(&first).unwrap());

        let second = StateMetadata::next(
            [7; 32],
            StateObjectType::Contacts,
            "contacts",
            1,
            Some(&anchor),
            b"two",
        )
        .unwrap();
        assert!(anchor.check_candidate(&second).unwrap());

        let mut fork = first.clone();
        fork.current_state_hash[0] ^= 1;
        assert!(matches!(
            anchor.check_candidate(&fork),
            Err(Error::StateMismatch(_))
        ));
        assert!(matches!(
            StateAnchor::from_metadata(&second).check_candidate(&first),
            Err(Error::RollbackDetected(_))
        ));
    }
}
