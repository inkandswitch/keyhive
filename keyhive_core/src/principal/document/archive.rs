use keyhive_codec::{
    error::DecodeError,
    prefixed::{decode_len, encode_len},
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use keyhive_content::reference::ContentRef;
use keyhive_crypto::symmetric_key::SymmetricKey;
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

/// `content_heads ‖ content_state ‖ content_keys`, each a count and then its
/// entries in ascending order of their refs' encodings. An entry is a ref,
/// followed in `content_keys` by its 32-byte key. Content refs need not be
/// ordered, but their bytes are.
impl<T: ContentRef> Encode for DocumentArchive<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_refs(self.content_heads.iter().map(|r| (r, &[][..])), out);
        encode_refs(self.content_state.iter().map(|r| (r, &[][..])), out);
        encode_refs(
            self.content_keys.iter().map(|(r, k)| (r, k.as_slice())),
            out,
        );
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
            let (key, rest) = <[u8; 32]>::decode_next(rest)?;
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

/// A count, then each ref followed by its value's bytes, in ascending order of
/// the refs' encodings.
fn encode_refs<'a, T: Encode + 'a>(
    entries: impl Iterator<Item = (&'a T, &'a [u8])>,
    out: &mut Vec<u8>,
) {
    let mut encoded: Vec<_> = entries
        .map(|(r, value)| (r.encode().into_bytes(), value))
        .collect();
    encoded.sort();
    encode_len(encoded.len(), out);
    for (r, value) in encoded {
        out.extend_from_slice(&r);
        out.extend_from_slice(value);
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
}
