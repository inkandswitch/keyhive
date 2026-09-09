//! Encoding traits and the [`Encoded<T>`] byte container shared by Keyhive crates.
//!
//! Keyhive is moving to a bespoke binary codec. This crate holds only the parts
//! every other crate needs to agree on: the [`Encode`] and [`Decode`] traits and
//! the [`Encoded<T>`] type that carries a value's bytes tagged with the type they
//! encode. It has no dependencies beyond `alloc` and contains no cryptography;
//! hashing an `Encoded<T>` is `keyhive_crypto`'s job.
//!
//! # Laws
//!
//! Every implementation of the two traits MUST satisfy:
//!
//! 1. `decode(encode(x)) == x` — round trip.
//! 2. `encode(decode(b)) == b` for every `b` that `decode` accepts — canonicality.
//!
//! The second law is a security requirement. Certificates travel as
//! `Encoded<T>`, and a receiver verifies signatures and computes digests over
//! the bytes it received without re-encoding. If a format admitted two byte
//! forms for one value, a peer could ship the same certificate twice with two
//! digests, and a revocation naming one would miss the other. `decode` MUST
//! reject non-canonical input.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod encoded;
pub mod error;

pub use encoded::Encoded;
pub use error::DecodeError;

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
