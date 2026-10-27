//! The [`Encode`] and [`Decode`] traits.
//!
//! The laws they satisfy, and why canonicality is a security requirement,
//! are in the crate docs.

use crate::{encoded::Encoded, error::DecodeError};
use alloc::vec::Vec;

/// Serialize a value into its canonical byte form.
///
/// An encoding need not be self-delimiting: `Vec<u8>` encodes as its raw
/// bytes, so two of them written back to back are ambiguous. [`Decode`]
/// receives exactly one value's bytes. A composite type must therefore frame
/// any field that is not fixed-width (with a length, as `keyline`'s
/// `Revocation` does for its watermarks), or its own encoding is not
/// canonical.
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

/// A [`Decode`] whose canonical encodings are prefix-free: no encoding is a
/// prefix of another, so one value can be read off the front of a longer
/// input.
///
/// This is what lets a composite type write fields back to back without
/// framing them: a fixed-width field, or a field that knows where it ends
/// (as a bijou varint does), needs no length. A type with no natural end,
/// such as raw `Vec<u8>`, does not implement it; wrap it in a framed type.
///
/// Laws, beyond [`Decode`]'s, for every value `x` and every `rest`:
///
/// 1. `decode_next(encode(x) ‖ rest) == Ok((x, rest))`.
/// 2. If `decode_next(b) == Ok((x, rest))`, then `b == encode(x) ‖ rest`.
pub trait StreamDecode: Decode {
    /// Decode one value from the front of `bytes`. Returns it and the bytes
    /// after it.
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError>;
}

/// Decode a prefix-free value that must fill `bytes` exactly: the [`Decode`]
/// implementation of every [`StreamDecode`] type.
pub fn decode_exact<T: StreamDecode>(bytes: &[u8]) -> Result<T, DecodeError> {
    match T::decode_next(bytes)? {
        (value, []) => Ok(value),
        _ => Err(DecodeError::TrailingBytes),
    }
}

/// The empty encoding, for types parameterized by a payload they do not use.
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

/// Text encodes as its UTF-8 bytes, which is canonical: distinct strings
/// differ. Like bytes, it fills what it is decoded from, so it is not
/// [`StreamDecode`]; decoding refuses bytes that are not UTF-8.
impl Encode for alloc::string::String {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}

impl Decode for alloc::string::String {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        core::str::from_utf8(bytes)
            .map(Into::into)
            .map_err(|_| DecodeError::InvalidField("utf-8"))
    }
}

/// A fixed-size array encodes as its bytes. Every value has the same length,
/// so the encoding is prefix-free.
impl<const N: usize> Encode for [u8; N] {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl<const N: usize> StreamDecode for [u8; N] {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (value, rest) = bytes
            .split_first_chunk::<N>()
            .ok_or(DecodeError::UnexpectedEnd)?;
        Ok((*value, rest))
    }
}

/// Integers encode as bijou varints: prefix-free, with exactly one encoding
/// per number.
impl Encode for u32 {
    fn encode_into(&self, out: &mut Vec<u8>) {
        bijoux::u32::encode(*self, out);
    }
}

impl Decode for u32 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl StreamDecode for u32 {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (value, consumed) = bijoux::u32::decode(bytes).map_err(|e| match e {
            bijoux::u32::DecodeError::BufferTooShort => DecodeError::UnexpectedEnd,
            bijoux::u32::DecodeError::Overflow => DecodeError::InvalidField("bijou32"),
        })?;
        let rest = bytes.get(consumed..).ok_or(DecodeError::UnexpectedEnd)?;
        Ok((value, rest))
    }
}

impl Encode for u64 {
    fn encode_into(&self, out: &mut Vec<u8>) {
        bijoux::u64::encode(*self, out);
    }
}

impl Decode for u64 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl StreamDecode for u64 {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (value, consumed) = bijoux::u64::decode(bytes).map_err(|e| match e {
            bijoux::u64::DecodeError::BufferTooShort => DecodeError::UnexpectedEnd,
            bijoux::u64::DecodeError::Overflow => DecodeError::InvalidField("bijou64"),
        })?;
        let rest = bytes.get(consumed..).ok_or(DecodeError::UnexpectedEnd)?;
        Ok((value, rest))
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

    /// Every law of a prefix-free codec, over generated values and suffixes,
    /// and over arbitrary input for canonicality.
    fn stream_laws<T>()
    where
        T: 'static
            + for<'a> arbitrary::Arbitrary<'a>
            + StreamDecode
            + Encode
            + core::fmt::Debug
            + PartialEq,
    {
        bolero::check!()
            .with_arbitrary::<(T, Vec<u8>)>()
            .for_each(|(value, rest)| {
                let mut bytes = value.encode().into_bytes();
                assert_eq!(T::decode(&bytes).as_ref(), Ok(value), "round trip");
                bytes.extend_from_slice(rest);
                let (next, after) = T::decode_next(&bytes).expect("the next value decodes");
                assert_eq!(&next, value, "stream round trip");
                assert_eq!(after, rest.as_slice(), "the rest is untouched");
            });
        bolero::check!()
            .with_arbitrary::<Vec<u8>>()
            .for_each(|bytes| {
                if let Ok((value, rest)) = T::decode_next(bytes) {
                    let mut again = value.encode().into_bytes();
                    again.extend_from_slice(rest);
                    assert_eq!(&again, bytes, "canonical");
                }
            });
    }

    #[test]
    fn arrays_stream() {
        stream_laws::<[u8; 0]>();
        stream_laws::<[u8; 2]>();
        stream_laws::<[u8; 32]>();
    }

    #[test]
    fn integers_stream() {
        stream_laws::<u32>();
        stream_laws::<u64>();
    }

    /// Exact decoding rejects anything after the value.
    #[test]
    fn decode_rejects_trailing_bytes() {
        assert_eq!(
            <[u8; 2]>::decode(&[1, 2, 3]),
            Err(DecodeError::TrailingBytes)
        );
        assert_eq!(<[u8; 2]>::decode(&[1]), Err(DecodeError::UnexpectedEnd));
        assert_eq!(u32::decode(&[0, 0]), Err(DecodeError::TrailingBytes));
        assert_eq!(u64::decode(&[]), Err(DecodeError::UnexpectedEnd));
    }

    /// Pins the bijou encodings at the tier boundaries the integer impls rely on.
    #[test]
    fn integer_known_answers() {
        assert_eq!(0u32.encode().as_bytes(), &[0]);
        assert_eq!(127u64.encode().as_bytes(), &[127]);
        assert!(u64::MAX.encode().len() > 8);
        assert_eq!(u64::decode(u64::MAX.encode().as_bytes()), Ok(u64::MAX));
    }
}
