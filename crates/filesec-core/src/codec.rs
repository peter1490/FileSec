//! Small CBOR (de)serialization helpers over `ciborium`.
//!
//! All structured metadata in FileSec (keystore, contacts, public identities,
//! container header and manifest) is encoded as CBOR. These helpers centralize
//! the error mapping so callers never see the underlying library error types.

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{Error, Result};

/// Serialize a value to a CBOR byte vector.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|_| Error::Serialization)?;
    Ok(buf)
}

/// Deserialize a value from CBOR bytes. Fails cleanly on malformed input.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).map_err(|_| Error::Serialization)
}
