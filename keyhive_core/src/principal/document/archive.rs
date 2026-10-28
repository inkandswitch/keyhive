use keyhive_codec::{
    error::DecodeError,
    prefixed::{decode_len, encode_len},
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use keyhive_content::reference::ContentRef;
use std::collections::HashSet;

/// What a document holds that cannot be recomputed: its content heads. Its
/// CGKA group is rebuilt from the archive's CGKA operations, its membership
/// is Keyline's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentArchive<T: ContentRef> {
    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,
}

/// `content_heads ‖ content_state`, each a count and then the refs in
/// ascending order of their encodings: content refs need not be ordered, but
/// their bytes are.
impl<T: ContentRef> Encode for DocumentArchive<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_refs(&self.content_heads, out);
        encode_refs(&self.content_state, out);
    }
}

impl<T: ContentRef> Decode for DocumentArchive<T> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl<T: ContentRef> StreamDecode for DocumentArchive<T> {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (content_heads, rest) = decode_refs(bytes)?;
        let (content_state, rest) = decode_refs(rest)?;
        Ok((
            DocumentArchive {
                content_heads,
                content_state,
            },
            rest,
        ))
    }
}

fn encode_refs<T: Encode>(refs: &HashSet<T>, out: &mut Vec<u8>) {
    let mut encoded: Vec<_> = refs.iter().map(|r| r.encode().into_bytes()).collect();
    encoded.sort();
    encode_len(encoded.len(), out);
    encoded
        .iter()
        .for_each(|bytes| out.extend_from_slice(bytes));
}

/// Refuses refs out of order or repeated, so each set has one encoding.
fn decode_refs<T: ContentRef>(bytes: &[u8]) -> Result<(HashSet<T>, &[u8]), DecodeError> {
    let (count, mut rest) = decode_len(bytes)?;
    let mut refs = HashSet::new();
    let mut previous: Option<&[u8]> = None;
    for _ in 0..count {
        let (r, after) = T::decode_next(rest)?;
        let encoded = &rest[..rest.len() - after.len()];
        if previous.is_some_and(|p| p >= encoded) {
            return Err(DecodeError::UnsortedKeys);
        }
        previous = Some(encoded);
        refs.insert(r);
        rest = after;
    }
    Ok((refs, rest))
}
