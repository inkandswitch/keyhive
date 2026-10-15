//! Length- and count-prefixed encodings, and the collection codecs built on
//! them.
//!
//! A count or length is a bijou32 varint. Every element type is
//! [`StreamDecode`], so a collection decodes in one pass with no framing per
//! element. Decoding never allocates from a declared count: each element
//! consumes at least one byte, so a count larger than the input fails with
//! [`DecodeError::UnexpectedEnd`] once the input runs out.
//!
//! Sets and maps encode in ascending order without repeats, and decoding
//! rejects anything else with [`DecodeError::UnsortedKeys`], so each value
//! has exactly one encoding.

use crate::{
    error::DecodeError,
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

/// Append a count or length as bijou32.
///
/// # Panics
///
/// Past `u32::MAX`. Encoded values are held in memory, and nothing Keyhive
/// encodes approaches four billion elements; a byte length that might is
/// encoded as bijou64 by its own type.
pub fn encode_len(len: usize, out: &mut Vec<u8>) {
    u32::try_from(len)
        .expect("counts and lengths fit in a u32")
        .encode_into(out);
}

/// A count or length from the front of `bytes`, and the bytes after it.
pub fn decode_len(bytes: &[u8]) -> Result<(usize, &[u8]), DecodeError> {
    let (len, rest) = u32::decode_next(bytes).map_err(|e| match e {
        DecodeError::InvalidField(_) => DecodeError::InvalidField("length"),
        other => other,
    })?;
    let len = usize::try_from(len).map_err(|_| DecodeError::InvalidField("length"))?;
    Ok((len, rest))
}

/// Append `bytes` with its length.
pub fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    encode_len(bytes.len(), out);
    out.extend_from_slice(bytes);
}

/// Length-prefixed bytes from the front of `bytes`, and the bytes after them.
pub fn decode_bytes(bytes: &[u8]) -> Result<(&[u8], &[u8]), DecodeError> {
    let (len, rest) = decode_len(bytes)?;
    if len > rest.len() {
        return Err(DecodeError::UnexpectedEnd);
    }
    Ok(rest.split_at(len))
}

/// Append a count, then each item in order.
pub fn encode_list<'a, T: Encode + 'a, I>(items: I, out: &mut Vec<u8>)
where
    I: IntoIterator<Item = &'a T>,
    I::IntoIter: ExactSizeIterator,
{
    let items = items.into_iter();
    encode_len(items.len(), out);
    items.for_each(|item| item.encode_into(out));
}

/// A counted list from the front of `bytes`, in order, and the bytes after it.
pub fn decode_list<T: StreamDecode>(bytes: &[u8]) -> Result<(Vec<T>, &[u8]), DecodeError> {
    let (count, mut rest) = decode_len(bytes)?;
    let mut items = Vec::new();
    for _ in 0..count {
        let (item, after) = T::decode_next(rest)?;
        items.push(item);
        rest = after;
    }
    Ok((items, rest))
}

/// A counted list that must be strictly ascending, and the bytes after it.
fn decode_ascending<T: StreamDecode + Ord>(bytes: &[u8]) -> Result<(Vec<T>, &[u8]), DecodeError> {
    let (items, rest) = decode_list::<T>(bytes)?;
    if items.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DecodeError::UnsortedKeys);
    }
    Ok((items, rest))
}

/// A count, then the elements in ascending order.
impl<T: Encode> Encode for BTreeSet<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_list(self, out);
    }
}

impl<T: StreamDecode + Ord> Decode for BTreeSet<T> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl<T: StreamDecode + Ord> StreamDecode for BTreeSet<T> {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (items, rest) = decode_ascending::<T>(bytes)?;
        Ok((items.into_iter().collect(), rest))
    }
}

/// A count, then each key followed by its value, in ascending key order.
impl<K: Encode, V: Encode> Encode for BTreeMap<K, V> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_len(self.len(), out);
        for (key, value) in self {
            key.encode_into(out);
            value.encode_into(out);
        }
    }
}

impl<K: StreamDecode + Ord, V: StreamDecode> Decode for BTreeMap<K, V> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl<K: StreamDecode + Ord, V: StreamDecode> StreamDecode for BTreeMap<K, V> {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (count, mut rest) = decode_len(bytes)?;
        let mut map = BTreeMap::new();
        for _ in 0..count {
            let (key, after_key) = K::decode_next(rest)?;
            if map.last_key_value().is_some_and(|(last, _)| *last >= key) {
                return Err(DecodeError::UnsortedKeys);
            }
            let (value, after_value) = V::decode_next(after_key)?;
            map.insert(key, value);
            rest = after_value;
        }
        Ok((map, rest))
    }
}

/// Tag `0` for `None`; tag `1` followed by the value for `Some`.
impl<T: Encode> Encode for Option<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            None => out.push(0),
            Some(value) => {
                out.push(1);
                value.encode_into(out);
            }
        }
    }
}

impl<T: StreamDecode> Decode for Option<T> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl<T: StreamDecode> StreamDecode for Option<T> {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        match bytes.split_first() {
            None => Err(DecodeError::UnexpectedEnd),
            Some((0, rest)) => Ok((None, rest)),
            Some((1, rest)) => {
                let (value, rest) = T::decode_next(rest)?;
                Ok((Some(value), rest))
            }
            Some((&tag, _)) => Err(DecodeError::InvalidTag(tag)),
        }
    }
}

#[cfg(all(test, feature = "laws"))]
mod tests {
    use super::*;
    use crate::laws::{canonical_near, round_trip, stream};

    #[test]
    fn collection_laws() {
        round_trip::<BTreeSet<u32>>();
        canonical_near::<BTreeSet<u32>>();
        stream::<BTreeSet<u32>>();
        round_trip::<BTreeMap<u32, [u8; 3]>>();
        canonical_near::<BTreeMap<u32, [u8; 3]>>();
        stream::<BTreeMap<u32, [u8; 3]>>();
        round_trip::<Option<u64>>();
        canonical_near::<Option<u64>>();
        stream::<Option<u64>>();
    }

    #[test]
    fn sets_and_maps_must_ascend() {
        // Count 2, then 1, 1: a repeat.
        assert_eq!(
            BTreeSet::<u32>::decode(&[2, 1, 1]),
            Err(DecodeError::UnsortedKeys)
        );
        // Count 2, then 2, 1: descending.
        assert_eq!(
            BTreeSet::<u32>::decode(&[2, 2, 1]),
            Err(DecodeError::UnsortedKeys)
        );
        assert_eq!(
            BTreeMap::<u32, [u8; 1]>::decode(&[2, 2, 0, 1, 0]),
            Err(DecodeError::UnsortedKeys)
        );
    }

    #[test]
    fn a_count_beyond_the_input_fails_without_allocating_for_it() {
        // bijou32 for u32::MAX, then one element.
        let mut bytes = Vec::new();
        encode_len(u32::MAX as usize, &mut bytes);
        bytes.push(7);
        assert_eq!(
            decode_list::<u32>(&bytes).map(|(items, _)| items),
            Err(DecodeError::UnexpectedEnd)
        );
    }

    #[test]
    fn lengths_beyond_the_input_fail() {
        assert_eq!(decode_bytes(&[3, 1, 2]), Err(DecodeError::UnexpectedEnd));
        assert_eq!(decode_bytes(&[2, 1, 2, 9]), Ok((&[1, 2][..], &[9][..])));
    }

    #[test]
    fn option_tags_are_zero_and_one() {
        assert_eq!(Option::<u32>::None.encode().as_bytes(), &[0]);
        assert_eq!(Some(5u32).encode().as_bytes(), &[1, 5]);
        assert_eq!(Option::<u32>::decode(&[2]), Err(DecodeError::InvalidTag(2)));
    }
}
