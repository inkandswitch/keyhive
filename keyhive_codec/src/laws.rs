//! Property tests for the [laws](crate#laws), for any type with an
//! [`Arbitrary`] generator. Call them from a `#[test]`; each runs under
//! `bolero`, so `cargo bolero` can fuzz it too.
//!
//! The generator must produce only values the type can encode canonically
//! (for a key, a point in canonical form), since round trip is checked for
//! every generated value.

use crate::traits::{Decode, Encode, StreamDecode};
use alloc::vec::Vec;
use arbitrary::Arbitrary;
use core::fmt::Debug;

/// _Round trip:_ `decode(encode(x)) == x`.
pub fn round_trip<T>()
where
    T: for<'a> Arbitrary<'a> + Debug + Decode + Encode + PartialEq + 'static,
{
    bolero::check!().with_arbitrary::<T>().for_each(|value| {
        assert_eq!(
            &T::decode(value.encode().as_bytes()).expect("round trip"),
            value
        );
    });
}

/// _Canonicality_ near valid encodings: mutate the encoding of an arbitrary
/// `T`, and whatever still decodes must re-encode to exactly those bytes.
///
/// Random byte strings almost never decode, so a raw-bytes harness would
/// rarely reach its assertion. Starting from a valid encoding keeps the
/// mutated input near the inputs that matter: tags, counts, lengths, and
/// trailing bytes. At least one mutation is drawn (it may be a no-op).
pub fn canonical_near<T>()
where
    T: for<'a> Arbitrary<'a> + Debug + Decode + Encode + 'static,
{
    bolero::check!()
        .with_arbitrary::<(T, Mutation, Vec<Mutation>)>()
        .for_each(|(value, first, rest)| {
            let mut bytes = value.encode().into_bytes();
            for m in core::iter::once(first).chain(rest) {
                m.apply(&mut bytes);
            }
            if let Ok(decoded) = T::decode(&bytes) {
                assert_eq!(decoded.encode().as_bytes(), bytes.as_slice());
            }
        });
}

/// The [`StreamDecode`] laws: `decode_next(encode(x) ‖ rest)` returns `x` and
/// `rest`, and whatever `decode_next` accepts, even near a valid encoding, is
/// exactly an encoding followed by the rest it returns.
pub fn stream<T>()
where
    T: for<'a> Arbitrary<'a> + Debug + Encode + PartialEq + StreamDecode + 'static,
{
    bolero::check!()
        .with_arbitrary::<(T, Vec<u8>, Option<Mutation>)>()
        .for_each(|(value, rest, mutation)| {
            let mut bytes = value.encode().into_bytes();
            bytes.extend_from_slice(rest);
            match mutation {
                None => {
                    let (decoded, tail) = T::decode_next(&bytes).expect("encoding then rest");
                    assert_eq!(&decoded, value);
                    assert_eq!(tail, rest.as_slice());
                }
                Some(m) => {
                    m.apply(&mut bytes);
                    if let Ok((decoded, tail)) = T::decode_next(&bytes) {
                        let mut again = decoded.encode().into_bytes();
                        again.extend_from_slice(tail);
                        assert_eq!(again, bytes);
                    }
                }
            }
        });
}

/// One edit to a byte string. Positions wrap modulo the current length, so
/// every mutation applies to any input.
#[derive(Debug, Clone, Arbitrary)]
pub enum Mutation {
    /// XOR one byte with `mask`.
    Flip { at: usize, mask: u8 },

    /// Insert `byte` before position `at`.
    Insert { at: usize, byte: u8 },

    /// Remove one byte.
    Remove { at: usize },

    /// Keep only the first `len` bytes.
    Truncate { len: usize },
}

impl Mutation {
    /// Apply the edit to `bytes`.
    pub fn apply(&self, bytes: &mut Vec<u8>) {
        match *self {
            Mutation::Flip { at, mask } if !bytes.is_empty() => {
                let i = at % bytes.len();
                bytes[i] ^= mask;
            }
            Mutation::Insert { at, byte } => bytes.insert(at % (bytes.len() + 1), byte),
            Mutation::Remove { at } if !bytes.is_empty() => {
                bytes.remove(at % bytes.len());
            }
            Mutation::Truncate { len } => bytes.truncate(len % (bytes.len() + 1)),
            Mutation::Flip { .. } | Mutation::Remove { .. } => {}
        }
    }
}
