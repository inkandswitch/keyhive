//! The [`Encode`] and [`Decode`] traits.
//!
//! The laws they satisfy, and why canonicality is a security requirement,
//! are in the crate docs.

use crate::{encoded::Encoded, error::DecodeError};
use alloc::vec::Vec;

/// Serialize a value into its canonical byte form.
pub trait Encode {
    /// Append the canonical encoding of `self` to `out`.
    fn encode_into(&self, out: &mut Vec<u8>);

    /// Encode `self` into a fresh [`Encoded<Self>`].
    fn encode(&self) -> Encoded<Self>
    where
        Self: Sized,
    {
        let mut bytes = Vec::new();
        self.encode_into(&mut bytes);
        Encoded::from_bytes_unchecked(bytes)
    }
}

/// Deserialize a value from its canonical byte form, rejecting any other form.
pub trait Decode: Sized {
    /// Decode `bytes`, failing unless they are exactly the canonical encoding
    /// of a value.
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError>;
}

/// The empty encoding, for types parameterised by a payload they do not use.
///
/// Canonical by construction: one value, one encoding, and `decode` accepts
/// nothing else.
impl Encode for () {
    fn encode_into(&self, _out: &mut Vec<u8>) {}
}

impl Decode for () {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

/// Bytes encode as themselves, which is canonical: distinct values differ.
impl Encode for alloc::vec::Vec<u8> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl Decode for alloc::vec::Vec<u8> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `()` has one value and one encoding: empty. Anything else is rejected.
    #[test]
    fn unit_is_the_empty_encoding() {
        assert!(().encode().is_empty());
        assert_eq!(<()>::decode(&[]), Ok(()));
        assert_eq!(<()>::decode(&[0]), Err(DecodeError::TrailingBytes));
    }

    /// Bytes encode as themselves, so the codec laws hold trivially.
    #[test]
    fn bytes_encode_as_themselves() {
        let value = alloc::vec![0u8, 7, 255];
        assert_eq!(value.encode().as_bytes(), value.as_slice());
        assert_eq!(Vec::<u8>::decode(&value), Ok(value.clone()));
        assert_eq!(Vec::<u8>::decode(&[]), Ok(Vec::new()));
    }
}
