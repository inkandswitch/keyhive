//! The [`Encode`] and [`Decode`] traits.
//!
//! Every implementation MUST satisfy:
//!
//! 1. `decode(encode(x)) == x` — round trip.
//! 2. `encode(decode(b)) == b` for every `b` that `decode` accepts — canonicality.
//!
//! See the crate docs for why the second law is a security requirement.

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
    /// Decode `bytes`, which MUST be exactly the canonical encoding of a value.
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
