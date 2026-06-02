//! ML-DSA-65 digital signatures (the post-quantum half of hybrid suite `0x0101`).
//!
//! A thin, panic-free wrapper over the RustCrypto [`ml_dsa`] crate. As with
//! [`crate::mlkem`], this is never used alone: a hybrid container is signed with
//! **both** Ed25519 and ML-DSA and an importer requires *both* signatures to
//! verify, so forging requires breaking both schemes — the post-quantum
//! signature can only ever *add* assurance over the classical baseline.
//!
//! Keypairs are represented by their 32-byte seed (`ξ`); the verifying key and
//! signatures are re-derived deterministically. We use the seed and the
//! deterministic signing path so no extra RNG dependency is pulled (all entropy
//! comes from [`crate::secret`], same as the rest of the crate).

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Signature, Signer, SigningKey,
    Verifier, VerifyingKey, B32,
};

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::random_array;

/// Length of an ML-DSA-65 verifying (public) key.
pub const PUBLIC_LEN: usize = 1952;
/// Length of an ML-DSA-65 signature.
pub const SIGNATURE_LEN: usize = 3309;
/// Length of the keypair seed we persist.
pub const SEED_LEN: usize = 32;

/// Re-derive the signing key from a stored seed.
fn signing_key_from_seed(seed: &[u8]) -> Result<SigningKey<MlDsa65>> {
    if seed.len() != SEED_LEN {
        return Err(Error::BadKey("ml-dsa seed length"));
    }
    let mut arr = [0u8; SEED_LEN];
    arr.copy_from_slice(seed);
    let b32 = B32::from(arr);
    arr.iter_mut().for_each(|b| *b = 0);
    Ok(SigningKey::<MlDsa65>::from_seed(&b32))
}

/// Generate a fresh keypair, returning `(public_key_bytes, seed)`.
pub fn generate() -> Result<(Vec<u8>, Zeroizing<[u8; SEED_LEN]>)> {
    let seed = Zeroizing::new(random_array::<SEED_LEN>()?);
    let public = public_from_seed(seed.as_slice())?;
    Ok((public, seed))
}

/// Re-derive the verifying (public) key bytes from a stored seed.
pub fn public_from_seed(seed: &[u8]) -> Result<Vec<u8>> {
    let sk = signing_key_from_seed(seed)?;
    Ok(sk.verifying_key().encode().as_slice().to_vec())
}

/// Sign `message` with the keypair reconstructed from `seed` (deterministic
/// ML-DSA, empty context), returning the detached signature bytes.
pub fn sign(seed: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let sk = signing_key_from_seed(seed)?;
    Ok(sk.sign(message).encode().as_slice().to_vec())
}

/// Verify a detached `signature` over `message` against `public`. Returns
/// [`Error::BadSignature`] on any failure (bad length, malformed key/signature,
/// or a verification mismatch).
pub fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    if public.len() != PUBLIC_LEN {
        return Err(Error::BadKey("ml-dsa public key length"));
    }
    if signature.len() != SIGNATURE_LEN {
        return Err(Error::BadSignature);
    }
    let vk_enc = EncodedVerifyingKey::<MlDsa65>::try_from(public)
        .map_err(|_| Error::BadKey("ml-dsa public key"))?;
    let vk = VerifyingKey::<MlDsa65>::decode(&vk_enc);
    let sig_enc =
        EncodedSignature::<MlDsa65>::try_from(signature).map_err(|_| Error::BadSignature)?;
    let sig = Signature::<MlDsa65>::decode(&sig_enc).ok_or(Error::BadSignature)?;
    vk.verify(message, &sig).map_err(|_| Error::BadSignature)
}
