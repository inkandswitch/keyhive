//! The (plaintext) container for causal encryption.

use bincode::Options;
use derivative::Derivative;
use keyhive_codec::{
    error::DecodeError,
    prefixed::{decode_len, encode_len},
    traits::StreamDecode,
};
use keyhive_crypto::{
    content::reference::ContentRef, read_capability::ReadCap, symmetric_key::SymmetricKey,
};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use thiserror::Error;
#[cfg_attr(all(doc, feature = "mermaid_docs"), aquamarine::aquamarine)]
/// A container for an arbitrary payload and the [`ReadCap`]s required to identify and decrypt its ancestors.
///
/// This is the core primitive of [causal encryption]. In the diagram below, each large block represents
/// an [`Envelope`], which are decrypted in turn by their successors.
///
/// ```mermaid
/// flowchart
///     subgraph genesis["oUz 🔓"]
///       a[New Doc]
///     end
///
///     subgraph block1["g6z 🔓"]
///       op1[Op 1]
///
///       subgraph block1ancestors[Ancestors]
///         subgraph block1ancestor1[Ancestor 1]
///           pointer1_1["Pointer #️⃣"]
///           key1_1["Key 🔑"]
///         end
///       end
///     end
///
///     pointer1_1 --> genesis
///
///     subgraph block2["Xa2 🔓"]
///         op2[Op 2]
///         op3[Op 3]
///         op4[Op 4]
///
///       subgraph block2ancestors[Ancestors]
///         subgraph block2ancestor1[Ancestor 1]
///           pointer2_1["Pointer #️⃣"]
///           key2_1["Key 🔑"]
///         end
///       end
///     end
///
///     pointer2_1 --> genesis
///
///     subgraph block3["e9j 🔓"]
///       op5[Op 5]
///       op6[Op 6]
///
///       subgraph block3ancestors[Ancestors]
///         subgraph block3ancestor1[Ancestor 1]
///           pointer3_1["Pointer #️⃣"]
///           key3_1["Key 🔑"]
///         end
///
///         subgraph block3ancestor2[Ancestor 2]
///           pointer3_2["Pointer #️⃣"]
///           key3_2["Key 🔑"]
///         end
///       end
///     end
///
///     pointer3_1 --> block1
///     pointer3_2 --> block2
///
///     subgraph head[Read Capability]
///       pointer_head["Pointer #️⃣"]
///       key_head["Key 🔑"]
///     end
///
///     pointer_head --> block3
/// ```
///
/// [causal encryption]: https://github.com/inkandswitch/keyhive/blob/main/design/causal_encryption.md
#[derive(Debug, Clone, PartialEq, Eq, Derivative)]
pub struct Envelope<C: ContentRef + DeserializeOwned, T: Serialize> {
    /// The plaintext payload.
    pub plaintext: T,

    /// Any ancestors that this envelope depends on.
    #[derivative(
        PartialOrd(compare_with = "crate::util::partial_eq::hash_map_keys"),
        Hash(hash_with = "crate::util::hasher::hash_map_keys")
    )]
    pub ancestors: HashMap<C, SymmetricKey>,
}

impl<T: Serialize, C: ContentRef + DeserializeOwned> Envelope<C, T> {
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

impl<C: ContentRef + DeserializeOwned, T: Serialize> Envelope<C, T> {
    /// `ancestor_count ‖ ( content_ref ‖ key:32 )* ‖ payload`, the ancestors
    /// sorted by their content refs' encodings, so a streaming reader has
    /// every ancestor's key first.
    ///
    /// The payload is still bincode, until the plaintext gets a codec of its
    /// own in the serde removal; hence the name.
    pub fn serde_encode(&self) -> Result<Vec<u8>, bincode::Error> {
        let mut ancestors: Vec<(Vec<u8>, [u8; 32])> = self
            .ancestors
            .iter()
            .map(|(content_ref, key)| (content_ref.encode().into_bytes(), (*key).into()))
            .collect();
        ancestors.sort_unstable();

        let mut out = Vec::new();
        encode_len(ancestors.len(), &mut out);
        for (content_ref, key) in &ancestors {
            out.extend_from_slice(content_ref);
            out.extend_from_slice(key);
        }
        out.extend(payload_options().serialize(&self.plaintext)?);
        Ok(out)
    }
}

impl<C: ContentRef + DeserializeOwned, T: Serialize + DeserializeOwned> Envelope<C, T> {
    /// Inverse of [`Envelope::serde_encode`]. Refuses ancestors out of order or
    /// repeated, and payload bytes left over, so each envelope has one encoding.
    pub fn serde_decode(bytes: &[u8]) -> Result<Self, EnvelopeDecodeError> {
        let (count, mut rest) = decode_len(bytes)?;
        let mut ancestors = HashMap::new();
        let mut previous: Option<&[u8]> = None;
        for _ in 0..count {
            let (content_ref, after_ref) = C::decode_next(rest)?;
            let encoded = &rest[..rest.len() - after_ref.len()];
            if previous.is_some_and(|p| p >= encoded) {
                return Err(DecodeError::UnsortedKeys.into());
            }
            let (key, after_key) = <[u8; 32]>::decode_next(after_ref)?;
            ancestors.insert(content_ref, SymmetricKey::from(key));
            previous = Some(encoded);
            rest = after_key;
        }
        let plaintext = payload_options().deserialize(rest)?;
        Ok(Envelope {
            plaintext,
            ancestors,
        })
    }
}

/// Why an envelope did not decode.
#[derive(Debug, Error)]
pub enum EnvelopeDecodeError {
    /// The ancestors are malformed, out of order, or repeated.
    #[error(transparent)]
    Ancestors(#[from] DecodeError),

    /// The payload does not deserialize, or has bytes left over.
    #[error(transparent)]
    Payload(#[from] bincode::Error),
}

/// `bincode::serialize`'s encoding, refusing trailing bytes.
fn payload_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
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
                let bytes = original.serde_encode().expect("encodes");
                assert_eq!(Env::serde_decode(&bytes).expect("decodes"), original);
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
                let mut bytes = arbitrary_envelope(ancestors, payload)
                    .serde_encode()
                    .expect("encodes");
                for m in core::iter::once(first).chain(rest) {
                    m.apply(&mut bytes);
                }
                if let Ok(decoded) = Env::serde_decode(&bytes) {
                    assert_eq!(decoded.serde_encode().expect("encodes"), bytes);
                }
            });
    }

    /// A `HashMap` iterates in any order; the bytes do not depend on it.
    #[test]
    fn ancestors_are_written_in_order_of_their_content_refs() {
        let bytes = envelope(&[9, 4, 7, 1], b"")
            .serde_encode()
            .expect("encodes");
        let refs: Vec<u8> = (0..4).map(|i| bytes[1 + i * 64]).collect();
        assert_eq!(refs, [1, 4, 7, 9]);
    }

    #[test]
    fn decoding_refuses_unsorted_or_repeated_ancestors() {
        let entry = |n: u8| [[n; 32], [0; 32]].concat();
        let payload = payload_options()
            .serialize(&Vec::<u8>::new())
            .expect("serializes");
        for (what, entries) in [
            ("unsorted", [entry(2), entry(1)]),
            ("repeated", [entry(1), entry(1)]),
        ] {
            let bytes = [vec![2], entries.concat(), payload.clone()].concat();
            assert!(
                matches!(
                    Env::serde_decode(&bytes),
                    Err(EnvelopeDecodeError::Ancestors(DecodeError::UnsortedKeys))
                ),
                "{what}"
            );
        }
    }

    #[test]
    fn decoding_refuses_payload_bytes_left_over() {
        let mut bytes = envelope(&[1], b"payload").serde_encode().expect("encodes");
        bytes.push(0);
        assert!(matches!(
            Env::serde_decode(&bytes),
            Err(EnvelopeDecodeError::Payload(_))
        ));
    }
}
