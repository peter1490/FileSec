//! Key derivation: Argon2id for passphrases, BLAKE3 for sub-key derivation.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::secret::{SymKey, SYM_KEY_LEN};

/// Argon2id parameters, persisted in the keystore so it can always be reopened
/// with the parameters it was created with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Number of iterations (time cost).
    pub t_cost: u32,
    /// Degree of parallelism (lanes).
    pub p_cost: u32,
}

/// Open-time safety policy for persisted/imported Argon2id parameters.
///
/// Creation paths use [`KdfParams::default`] today; this policy exists for the
/// hostile-input side: old keystores and backups may carry cheaper parameters,
/// but none may request unbounded memory, time, or lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfPolicy {
    /// Maximum Argon2 memory cost in KiB.
    pub max_m_cost: u32,
    /// Maximum Argon2 iteration count.
    pub max_t_cost: u32,
    /// Maximum Argon2 parallelism lanes.
    pub max_p_cost: u32,
}

impl KdfPolicy {
    /// Open policy for persisted local keystores and imported identity backups.
    /// Allows legacy/test low-cost values, but rejects zeros and resource spikes.
    pub const fn open() -> Self {
        Self {
            max_m_cost: 256 * 1024,
            max_t_cost: 10,
            max_p_cost: 4,
        }
    }

    /// Validate before constructing `argon2::Params`, so hostile values never
    /// reach Argon2's allocation path.
    pub fn validate(self, params: KdfParams) -> Result<()> {
        if params.m_cost == 0 {
            return Err(Error::KdfParams("memory cost must be non-zero"));
        }
        if params.t_cost == 0 {
            return Err(Error::KdfParams("iteration count must be non-zero"));
        }
        if params.p_cost == 0 {
            return Err(Error::KdfParams("parallelism must be non-zero"));
        }
        if params.m_cost > self.max_m_cost {
            return Err(Error::KdfParams("memory cost exceeds local policy"));
        }
        if params.t_cost > self.max_t_cost {
            return Err(Error::KdfParams("iteration count exceeds local policy"));
        }
        if params.p_cost > self.max_p_cost {
            return Err(Error::KdfParams("parallelism exceeds local policy"));
        }
        let min_memory_for_lanes = params
            .p_cost
            .checked_mul(8)
            .ok_or(Error::KdfParams("parallelism is invalid"))?;
        if params.m_cost < min_memory_for_lanes {
            return Err(Error::KdfParams("memory cost is too low for parallelism"));
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        // ~64 MiB, 3 passes, 1 lane: memory-hard yet interactive on a desktop.
        Self {
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl KdfParams {
    /// Validate against the open-time policy for persisted or imported state.
    pub fn validate_for_open(self) -> Result<()> {
        KdfPolicy::open().validate(self)
    }
}

/// Derive a 256-bit master key from a passphrase and salt using Argon2id.
pub fn derive_master_key(passphrase: &[u8], salt: &[u8], params: KdfParams) -> Result<SymKey> {
    params.validate_for_open()?;
    let p = Params::new(
        params.m_cost,
        params.t_cost,
        params.p_cost,
        Some(SYM_KEY_LEN),
    )
    .map_err(|_| Error::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = [0u8; SYM_KEY_LEN];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|_| Error::Kdf)?;
    let key = SymKey::from_bytes(out);
    out.zeroize();
    Ok(key)
}

/// Derive a domain-separated 256-bit sub-key from input keying material with
/// BLAKE3. `context` must be a unique, hard-coded label per use site.
pub fn derive_subkey(context: &str, ikm: &[u8]) -> SymKey {
    let mut bytes = blake3::derive_key(context, ikm);
    let key = SymKey::from_bytes(bytes);
    bytes.zeroize();
    key
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn accepted_low_cost_test_params() -> KdfParams {
        KdfParams {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn open_policy_accepts_explicit_low_cost_test_params() {
        accepted_low_cost_test_params().validate_for_open().unwrap();
    }

    #[test]
    fn open_policy_rejects_zero_values_before_argon2() {
        for params in [
            KdfParams {
                m_cost: 0,
                ..accepted_low_cost_test_params()
            },
            KdfParams {
                t_cost: 0,
                ..accepted_low_cost_test_params()
            },
            KdfParams {
                p_cost: 0,
                ..accepted_low_cost_test_params()
            },
        ] {
            assert!(matches!(
                params.validate_for_open(),
                Err(Error::KdfParams(_))
            ));
            assert!(matches!(
                derive_master_key(b"passphrase", b"1234567890abcdef", params),
                Err(Error::KdfParams(_))
            ));
        }
    }

    #[test]
    fn open_policy_rejects_resource_spikes_before_argon2() {
        let policy = KdfPolicy::open();
        for params in [
            KdfParams {
                m_cost: policy.max_m_cost + 1,
                ..accepted_low_cost_test_params()
            },
            KdfParams {
                t_cost: policy.max_t_cost + 1,
                ..accepted_low_cost_test_params()
            },
            KdfParams {
                p_cost: policy.max_p_cost + 1,
                ..accepted_low_cost_test_params()
            },
        ] {
            assert!(matches!(
                params.validate_for_open(),
                Err(Error::KdfParams(_))
            ));
        }
    }

    #[test]
    fn open_policy_rejects_malformed_memory_lane_ratio() {
        let params = KdfParams {
            m_cost: 7,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(matches!(
            params.validate_for_open(),
            Err(Error::KdfParams(_))
        ));
    }
}
