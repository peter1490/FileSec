//! ML-KEM-768 key encapsulation (the post-quantum half of hybrid suite `0x0101`).
//!
//! This is a thin, panic-free wrapper over the RustCrypto [`ml_kem`] crate. It is
//! **never used on its own** — [`crate::envelope`] always combines an ML-KEM
//! shared secret with an X25519 shared secret through a KDF, so a break of
//! ML-KEM cannot weaken the classical baseline (and vice-versa).
//!
//! Key material is handled as raw bytes so it can be persisted by the keystore
//! and forwarded by builds compiled without the `pqc` feature. Keypairs are
//! represented by their 64-byte seed (`d || z`); the public encapsulation key is
//! re-derived from the seed on demand. All entropy is drawn from the same OS
//! CSPRNG ([`crate::secret`]) used by the rest of the crate — we deliberately do
//! **not** enable `ml-kem`'s own `getrandom` feature (which would pull a second,
//! newer getrandom and raise the MSRV); instead we feed a fresh uniformly-random
//! 32-byte value into the deterministic encapsulation API, which is exactly what
//! the library's randomized `encapsulate` does internally.

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, FromSeed, TryKeyInit};
use ml_kem::{Ciphertext, EncapsulationKey, Key, KeyExport, MlKem768};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::random_array;

/// Length of an ML-KEM-768 encapsulation (public) key.
pub const PUBLIC_LEN: usize = 1184;
/// Length of an ML-KEM-768 ciphertext (encapsulated key).
pub const CIPHERTEXT_LEN: usize = 1088;
/// Length of the keypair seed (`d || z`) we persist.
pub const SEED_LEN: usize = 64;
/// Length of the shared secret ML-KEM derives.
pub const SHARED_LEN: usize = 32;

/// Re-derive the decapsulation/encapsulation keypair from a stored seed.
fn keypair_from_seed(
    seed: &[u8],
) -> Result<(
    ml_kem::DecapsulationKey<MlKem768>,
    EncapsulationKey<MlKem768>,
)> {
    if seed.len() != SEED_LEN {
        return Err(Error::BadKey("ml-kem seed length"));
    }
    let mut arr = [0u8; SEED_LEN];
    arr.copy_from_slice(seed);
    let seed_arr = Array::from(arr);
    arr.iter_mut().for_each(|b| *b = 0);
    Ok(MlKem768::from_seed(&seed_arr))
}

/// Generate a fresh keypair, returning `(public_key_bytes, seed)`.
pub fn generate() -> Result<(Vec<u8>, Zeroizing<[u8; SEED_LEN]>)> {
    let seed = Zeroizing::new(random_array::<SEED_LEN>()?);
    let public = public_from_seed(seed.as_slice())?;
    Ok((public, seed))
}

/// Re-derive the public encapsulation key bytes from a stored seed.
pub fn public_from_seed(seed: &[u8]) -> Result<Vec<u8>> {
    let (_dk, ek) = keypair_from_seed(seed)?;
    Ok(ek.to_bytes().as_slice().to_vec())
}

/// Sender side: encapsulate a fresh shared secret to `recipient_public`,
/// returning `(ciphertext, shared_secret)`.
///
/// The 32-byte message `m` is fresh OS entropy per call, so this is equivalent
/// in security to the library's randomized `encapsulate`.
pub fn encapsulate(recipient_public: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_LEN]>)> {
    if recipient_public.len() != PUBLIC_LEN {
        return Err(Error::BadKey("ml-kem public key length"));
    }
    let key = Key::<EncapsulationKey<MlKem768>>::try_from(recipient_public)
        .map_err(|_| Error::BadKey("ml-kem public key"))?;
    let ek = <EncapsulationKey<MlKem768> as TryKeyInit>::new(&key)
        .map_err(|_| Error::BadKey("ml-kem public key"))?;
    let m = Zeroizing::new(random_array::<32>()?);
    let (ct, shared) = ek.encapsulate_deterministic(&Array::from(*m));
    let mut shared_arr = [0u8; SHARED_LEN];
    shared_arr.copy_from_slice(shared.as_slice());
    Ok((ct.as_slice().to_vec(), Zeroizing::new(shared_arr)))
}

/// Recipient side: decapsulate `ciphertext` with our stored `seed`, recovering
/// the shared secret.
///
/// ML-KEM decapsulation never fails — an invalid ciphertext yields a
/// pseudo-random shared secret (implicit rejection). The mismatch surfaces one
/// layer up: a wrong shared secret derives a wrong key-wrapping key and the AEAD
/// open of the content key fails with [`Error::Auth`].
pub fn decapsulate(seed: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<[u8; SHARED_LEN]>> {
    if ciphertext.len() != CIPHERTEXT_LEN {
        return Err(Error::BadKey("ml-kem ciphertext length"));
    }
    let (dk, _ek) = keypair_from_seed(seed)?;
    let ct = Ciphertext::<MlKem768>::try_from(ciphertext)
        .map_err(|_| Error::BadKey("ml-kem ciphertext"))?;
    let shared = dk.decapsulate(&ct);
    let mut arr = [0u8; SHARED_LEN];
    arr.copy_from_slice(shared.as_slice());
    Ok(Zeroizing::new(arr))
}
