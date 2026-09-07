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

/// Deserialize exactly one CBOR value, rejecting trailing bytes and nesting
/// deeper than 64 levels. Fails cleanly on malformed input.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let mut remaining = bytes;
    let value = ciborium::de::from_reader_with_recursion_limit(&mut remaining, 64)
        .map_err(|_| Error::Serialization)?;
    if !remaining.is_empty() {
        return Err(Error::Serialization);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn rejects_trailing_values_and_garbage() {
        let bytes = to_vec(&42u64).unwrap();
        assert_eq!(from_slice::<u64>(&bytes).unwrap(), 42);
        for tail in [0x00, 0xff] {
            let mut extra = bytes.clone();
            extra.push(tail);
            assert!(from_slice::<u64>(&extra).is_err());
        }
    }

    #[test]
    fn rejects_excessive_nesting() {
        let mut bytes = vec![0x81; 128]; // nested one-element arrays
        bytes.push(0x00);
        assert!(from_slice::<ciborium::Value>(&bytes).is_err());
    }
}
