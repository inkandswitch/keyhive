//! The (plaintext) container for causal encryption.

use keyhive_codec::{
    error::DecodeError,
    prefixed::{decode_len, encode_len},
    traits::{Decode, Encode, StreamDecode},
};
use keyhive_crypto::{
    content::reference::ContentRef, read_capability::ReadCap, symmetric_key::SymmetricKey,
};
use std::collections::HashMap;

/// A container for an arbitrary payload and the [`ReadCap`]s required to identify and decrypt its ancestors.
///
/// This is the core primitive of [causal encryption]. In the diagram below, each large block represents
/// an [`Envelope`], which are decrypted in turn by their successors.
///
/// ```text
/// ┌─ read cap ─┐     ┌─ e9j ────────┐     ┌─ g6z ────────┐   ┌─ oUz ───┐
/// │ pointer ───┼────>│ op 5, op 6   │     │ op 1         │   │ new doc │
/// │ key        │     │ ancestor 1 ──┼────>│ ancestor 1 ──┼──>│         │
/// └────────────┘     │ ancestor 2 ──┼─┐   └──────────────┘   │         │
///                    └──────────────┘ │                      │         │
///                                     │   ┌─ Xa2 ────────┐   │         │
///                                     └──>│ op 2, 3, 4   │   │         │
///                                         │ ancestor 1 ──┼──>│         │
///                                         └──────────────┘   └─────────┘
/// ```
///
/// Each ancestor is a pointer to an envelope and the key that decrypts it; a
/// read capability is the same pair for the newest one.
///
/// [causal encryption]: https://github.com/inkandswitch/keyhive/blob/main/design/causal_encryption.md
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope<C: ContentRef, T> {
    /// The plaintext payload.
    pub plaintext: T,

    /// Any ancestors that this envelope depends on.
    pub ancestors: HashMap<C, SymmetricKey>,
}

impl<C: ContentRef, T> Envelope<C, T> {
    /// Extract the [read capabilities][ReadCap] for the ancestors of this envelope.
    pub fn ancestor_read_caps(&self) -> Vec<ReadCap<C>> {
        self.ancestors
            .iter()
            .map(|(id, key)| ReadCap {
                id: id.clone(),
                key: *key,
            })
            .collect()
    }
}

/// `count ‖ ( content_ref ‖ key )* ‖ payload`: the ancestors in ascending order
/// of their content refs' encodings, so the bytes do not depend on the map's
/// order and a streaming reader has every ancestor's key first, then the
/// payload through its own codec. The payload comes last, so it needs no
/// length.
impl<C: ContentRef, T: Encode> Encode for Envelope<C, T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        let mut ancestors: Vec<(Vec<u8>, [u8; 32])> = self
            .ancestors
            .iter()
            .map(|(content_ref, key)| (content_ref.encode().into_bytes(), (*key).into()))
            .collect();
        ancestors.sort_unstable();
        encode_len(ancestors.len(), out);
        for (content_ref, key) in &ancestors {
            out.extend_from_slice(content_ref);
            out.extend_from_slice(key);
        }
        self.plaintext.encode_into(out);
    }
}

/// Refuses ancestors out of order or repeated, so each envelope has one
/// encoding; the payload's own codec decides what follows them.
impl<C: ContentRef, T: Decode> Decode for Envelope<C, T> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (count, mut rest) = decode_len(bytes)?;
        let mut ancestors = HashMap::new();
        let mut previous: Option<&[u8]> = None;
        for _ in 0..count {
            let (content_ref, after_ref) = C::decode_next(rest)?;
            let encoded = &rest[..rest.len() - after_ref.len()];
            if previous.is_some_and(|p| p >= encoded) {
                return Err(DecodeError::UnsortedKeys);
            }
            let (key, after_key) = <[u8; 32]>::decode_next(after_ref)?;
            ancestors.insert(content_ref, SymmetricKey::from(key));
            previous = Some(encoded);
            rest = after_key;
        }
        Ok(Envelope {
            plaintext: T::decode(rest)?,
            ancestors,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Env = Envelope<[u8; 32], Vec<u8>>;

    fn envelope(ancestors: &[u8], payload: &[u8]) -> Env {
        Envelope {
            plaintext: payload.to_vec(),
            ancestors: ancestors
                .iter()
                .map(|&n| ([n; 32], SymmetricKey::from([n.wrapping_add(100); 32])))
                .collect(),
        }
    }

    fn arbitrary_envelope(ancestors: &[([u8; 32], [u8; 32])], payload: &[u8]) -> Env {
        Envelope {
            plaintext: payload.to_vec(),
            ancestors: ancestors
                .iter()
                .map(|(content_ref, key)| (*content_ref, SymmetricKey::from(*key)))
                .collect(),
        }
    }

    #[test]
    fn envelopes_round_trip() {
        bolero::check!()
            .with_arbitrary::<(Vec<([u8; 32], [u8; 32])>, Vec<u8>)>()
            .for_each(|(ancestors, payload)| {
                let original = arbitrary_envelope(ancestors, payload);
                let bytes = original.encode();
                assert_eq!(Env::decode(bytes.as_bytes()), Ok(original));
            });
    }

    /// Mutating a valid encoding (a byte flipped, inserted or removed, or the
    /// end cut off) either fails to decode or gives an envelope that encodes
    /// to exactly those bytes.
    #[test]
    fn an_envelope_has_exactly_one_encoding() {
        use keyhive_codec::laws::Mutation;

        bolero::check!()
            .with_arbitrary::<(Vec<([u8; 32], [u8; 32])>, Vec<u8>, Mutation, Vec<Mutation>)>()
            .for_each(|(ancestors, payload, first, rest)| {
                let mut bytes = arbitrary_envelope(ancestors, payload).encode().into_bytes();
                for m in core::iter::once(first).chain(rest) {
                    m.apply(&mut bytes);
                }
                if let Ok(decoded) = Env::decode(&bytes) {
                    assert_eq!(decoded.encode().as_bytes(), bytes);
                }
            });
    }

    /// A `HashMap` iterates in any order; the bytes do not depend on it.
    #[test]
    fn ancestors_are_written_in_order_of_their_content_refs() {
        let bytes = envelope(&[9, 4, 7, 1], b"").encode().into_bytes();
        let refs: Vec<u8> = (0..4).map(|i| bytes[1 + i * 64]).collect();
        assert_eq!(refs, [1, 4, 7, 9]);
    }

    #[test]
    fn decoding_refuses_unsorted_or_repeated_ancestors() {
        let entry = |n: u8| [[n; 32], [0; 32]].concat();
        for (what, entries) in [
            ("unsorted", [entry(2), entry(1)]),
            ("repeated", [entry(1), entry(1)]),
        ] {
            let bytes = [vec![2], entries.concat()].concat();
            assert!(
                Env::decode(&bytes) == Err(DecodeError::UnsortedKeys),
                "{what}"
            );
        }
    }

    /// The payload's own codec decides what follows the ancestors: a
    /// fixed-size payload refuses bytes left over.
    #[test]
    fn a_payload_refuses_what_its_codec_refuses() {
        let envelope: Envelope<[u8; 32], [u8; 4]> = Envelope {
            plaintext: *b"four",
            ancestors: HashMap::new(),
        };
        let mut bytes = envelope.encode().into_bytes();
        assert_eq!(Envelope::decode(&bytes), Ok(envelope));
        bytes.push(0);
        assert_eq!(
            Envelope::<[u8; 32], [u8; 4]>::decode(&bytes),
            Err(DecodeError::TrailingBytes)
        );
    }
}
