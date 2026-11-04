use keyhive_codec::{
    error::DecodeError,
    prefixed::{decode_len, encode_len},
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use keyhive_content::reference::ContentRef;
use keyhive_crypto::{secret::Sink, symmetric_key::SymmetricKey};
use std::collections::{HashMap, HashSet};

/// What a document holds that cannot be recomputed: its content heads and
/// the keys of the content it has written or read. Its CGKA group is
/// rebuilt from the archive's CGKA operations, its membership is Keyline's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentArchive<T: ContentRef> {
    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,
    pub(crate) content_keys: HashMap<T, SymmetricKey>,
}

impl<T: ContentRef> DocumentArchive<T> {
    /// The length of this document's encoding, found without writing a
    /// content key.
    pub(crate) fn encoded_len(&self) -> usize {
        /// A content key's length.
        const KEY_LEN: usize = 32;

        refs_len(self.content_heads.iter(), 0)
            + refs_len(self.content_state.iter(), 0)
            + refs_len(self.content_keys.keys(), KEY_LEN)
    }

    /// The [`Encode`] layout, below. The only place it is written: into a
    /// `Vec` to encode, and into a wiped buffer to store an archive.
    pub(crate) fn write_into<S: Sink>(&self, out: &mut S) {
        write_refs(self.content_heads.iter().map(|r| (r, &[][..])), out);
        write_refs(self.content_state.iter().map(|r| (r, &[][..])), out);
        write_refs(
            self.content_keys.iter().map(|(r, k)| (r, k.as_slice())),
            out,
        );
    }
}

/// `content_heads ‖ content_state ‖ content_keys`, each a count and then its
/// entries in ascending order of their refs' encodings. An entry is a ref,
/// followed in `content_keys` by its 32-byte key. Content refs need not be
/// ordered, but their bytes are.
///
/// `out` is not wiped and may reallocate, so this leaves copies of the content
/// keys. To store them, use [`Archive::encode_zeroizing`](crate::archive::Archive::encode_zeroizing).
impl<T: ContentRef> Encode for DocumentArchive<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.write_into(out);
    }
}

impl<T: ContentRef> Decode for DocumentArchive<T> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl<T: ContentRef> StreamDecode for DocumentArchive<T> {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (content_heads, rest) = decode_refs(bytes, |rest| Ok(((), rest)))?;
        let (content_state, rest) = decode_refs(rest, |rest| Ok(((), rest)))?;
        let (content_keys, rest) = decode_refs(rest, |rest| {
            let (key, rest) = rest
                .split_first_chunk::<32>()
                .ok_or(DecodeError::UnexpectedEnd)?;
            Ok((SymmetricKey::from(key), rest))
        })?;
        Ok((
            DocumentArchive {
                content_heads: content_heads.into_iter().map(|(r, ())| r).collect(),
                content_state: content_state.into_iter().map(|(r, ())| r).collect(),
                content_keys: content_keys.into_iter().collect(),
            },
            rest,
        ))
    }
}

/// The length [`write_refs`] writes for `refs`, each followed by
/// `value_len` bytes.
fn refs_len<'a, T: Encode + 'a>(
    refs: impl ExactSizeIterator<Item = &'a T>,
    value_len: usize,
) -> usize {
    let mut count = Vec::new();
    encode_len(refs.len(), &mut count);
    count.len()
        + refs
            .map(|r| r.encode().as_bytes().len() + value_len)
            .sum::<usize>()
}

/// A count, then each ref followed by its value's bytes, in ascending order of
/// the refs' encodings.
fn write_refs<'a, T: Encode + 'a, S: Sink>(
    entries: impl Iterator<Item = (&'a T, &'a [u8])>,
    out: &mut S,
) {
    let mut encoded: Vec<_> = entries
        .map(|(r, value)| (r.encode().into_bytes(), value))
        .collect();
    // Sorted by the refs' encodings alone, so the keys after them are never compared.
    encoded.sort_by(|a, b| a.0.cmp(&b.0));
    let mut count = Vec::new();
    encode_len(encoded.len(), &mut count);
    out.put(&count);
    for (r, value) in encoded {
        out.put(&r);
        out.put(value);
    }
}

/// Refuses refs out of order or repeated, so each collection has one
/// encoding. `value` decodes what follows each ref.
fn decode_refs<T: ContentRef, V>(
    bytes: &[u8],
    value: impl Fn(&[u8]) -> Result<(V, &[u8]), DecodeError>,
) -> Result<(Vec<(T, V)>, &[u8]), DecodeError> {
    let (count, mut rest) = decode_len(bytes)?;
    let mut refs = Vec::new();
    let mut previous: Option<&[u8]> = None;
    for _ in 0..count {
        let (r, after) = T::decode_next(rest)?;
        let encoded = &rest[..rest.len() - after.len()];
        if previous.is_some_and(|p| p >= encoded) {
            return Err(DecodeError::UnsortedKeys);
        }
        previous = Some(encoded);
        let (v, after) = value(after)?;
        refs.push((r, v));
        rest = after;
    }
    Ok((refs, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_keys_round_trip_with_their_refs() {
        let archive = DocumentArchive::<[u8; 32]> {
            content_heads: HashSet::new(),
            content_state: HashSet::new(),
            content_keys: (0..8u8)
                .map(|n| ([n; 32], SymmetricKey::from([n.wrapping_add(100); 32])))
                .collect(),
        };
        assert_eq!(
            DocumentArchive::decode(&archive.encode().into_bytes()),
            Ok(archive)
        );
    }

    /// Refs whose encodings differ in length (a varint behind an optional
    /// tag), from a pair of arbitrary values.
    fn archive_of(
        heads: &HashSet<Option<u32>>,
        state: &HashSet<Option<u32>>,
        keys: &[(Option<u32>, [u8; 32])],
    ) -> DocumentArchive<Option<u32>> {
        DocumentArchive {
            content_heads: heads.clone(),
            content_state: state.clone(),
            content_keys: keys
                .iter()
                .map(|(r, k)| (*r, SymmetricKey::from(k)))
                .collect(),
        }
    }

    fn assert_length_is_exact(archive: &DocumentArchive<Option<u32>>) {
        let bytes = archive.encode().into_bytes();
        assert_eq!(archive.encoded_len(), bytes.len());
        assert_eq!(DocumentArchive::decode(&bytes).as_ref(), Ok(archive));
    }

    /// The length is found exactly, without writing a key, whatever the refs'
    /// encodings and however many there are.
    #[test]
    fn the_encoded_length_is_exact() {
        bolero::check!()
            .with_type::<(
                HashSet<Option<u32>>,
                HashSet<Option<u32>>,
                Vec<(Option<u32>, [u8; 32])>,
            )>()
            .for_each(|(heads, state, keys)| {
                assert_length_is_exact(&archive_of(heads, state, keys));
            });
    }

    /// A count above 251 takes more than one byte (bijou32).
    #[test]
    fn the_encoded_length_is_exact_for_multi_byte_counts() {
        let refs: HashSet<_> = (0..300u32).map(Some).collect();
        let keys: Vec<_> = (0..300u32).map(|n| (Some(n * 1000), [7; 32])).collect();
        assert_length_is_exact(&archive_of(&refs, &refs, &keys));
    }
}
