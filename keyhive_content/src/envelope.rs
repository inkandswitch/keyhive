//! The (plaintext) container for causal encryption.

use crate::{
    ancestor_key::AncestorKey,
    encrypted::{encode_ancestors, encode_envelope, ContentDecryptError, EncryptedContent},
    padding::unpadded_len,
    reference::ContentRef,
};
use keyhive_codec::{
    error::DecodeError,
    prefixed::decode_len,
    traits::{Decode, Encode},
};
use keyhive_crypto::{identifier::Identifier, symmetric_key::SymmetricKey};
use std::{collections::HashMap, vec::Vec};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use crate::{encrypted::encode_body, padding::PaddedBody};

/// A container for an arbitrary payload and the references and keys of its ancestors.
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

impl<C: ContentRef, T: Encode> Envelope<C, T> {
    /// The envelope's encoding, the same bytes as [`Encode`] gives, in a buffer
    /// that is wiped when dropped: it carries its ancestors' keys.
    ///
    /// The buffer never grows, so it leaves no copy of a key behind.
    pub fn encode_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        let payload = Zeroizing::new(self.plaintext.encode().into_bytes());
        encode_envelope(&self.ancestors, &payload)
    }

    /// The body a block encrypts: this envelope, padded as
    /// [`ApplicationSecret::try_encrypt`](crate::application_secret::ApplicationSecret::try_encrypt)
    /// pads it.
    #[cfg(test)]
    pub(crate) fn padded_body(&self) -> PaddedBody {
        let payload = Zeroizing::new(self.plaintext.encode().into_bytes());
        encode_body(&self.ancestors, &payload)
    }
}

/// `count ‖ ( content_ref ‖ key )* ‖ payload`: the ancestors in ascending order
/// of their content refs' encodings, so the bytes do not depend on the map's
/// order and a streaming reader has every ancestor's key first, then the
/// payload through its own codec. The payload comes last, so it needs no
/// length.
///
/// `out` is not wiped and may reallocate, so this leaves copies of the
/// ancestors' keys. To store an envelope, use [`Envelope::encode_zeroizing`].
impl<C: ContentRef, T: Encode> Encode for Envelope<C, T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_ancestors(&self.ancestors, out);
        self.plaintext.encode_into(out);
    }
}

/// Refuses ancestors out of order or repeated, so each envelope has one
/// encoding; the payload's own codec decides what follows them.
///
/// This decodes an envelope, not a decrypted body: a body is padded, and with
/// a byte payload the padding would come back as part of it. To read a block,
/// use [`Envelope::open`], which strips the padding first.
impl<C: ContentRef, T: Decode> Decode for Envelope<C, T> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (ancestors, payload) = decode_ancestors(bytes)?;
        Ok(Envelope {
            plaintext: T::decode(payload)?,
            ancestors,
        })
    }
}

/// The ancestors at the start of an envelope's encoding and the payload
/// after them.
fn decode_ancestors<C: ContentRef>(
    bytes: &[u8],
) -> Result<(HashMap<C, SymmetricKey>, &[u8]), DecodeError> {
    let (count, mut rest) = decode_len(bytes)?;
    let mut ancestors = HashMap::new();
    let mut previous: Option<&[u8]> = None;
    for _ in 0..count {
        let (content_ref, after_ref) = C::decode_next(rest)?;
        let encoded = &rest[..rest.len() - after_ref.len()];
        if previous.is_some_and(|p| p >= encoded) {
            return Err(DecodeError::UnsortedKeys);
        }
        let (key, after_key) = after_ref
            .split_first_chunk::<32>()
            .ok_or(DecodeError::UnexpectedEnd)?;
        ancestors.insert(content_ref, SymmetricKey::from(key));
        previous = Some(encoded);
        rest = after_key;
    }
    Ok((ancestors, rest))
}

impl<C: ContentRef> Envelope<C, Vec<u8>> {
    /// Decrypt `encrypted` with `key`, for the document `doc_id`, and decode
    /// its body, which is always an envelope. Returns it with `key` as the
    /// block's [`AncestorKey`]. The payload keeps the decrypted buffer rather
    /// than a copy of it.
    ///
    /// The ancestors' keys in the body are wiped, whether or not it decodes.
    pub fn open<P>(
        encrypted: &EncryptedContent<P, C>,
        key: &SymmetricKey,
        doc_id: Identifier,
    ) -> Result<(Self, AncestorKey<C>), OpenEnvelopeError> {
        let mut body = encrypted.try_decrypt(key, doc_id)?;
        let unpadded = unpadded_len(&body)?;
        body.truncate(unpadded);
        let (ancestors, payload) = decode_ancestors(&body)?;
        let payload_start = body.len() - payload.len();
        body[..payload_start].zeroize();
        body.drain(..payload_start);
        Ok((
            Envelope {
                plaintext: core::mem::take(&mut *body),
                ancestors,
            },
            // We have just demonstrated that `key` can decrypt the content
            // for `encrypted.content_ref` for `doc_id`.
            AncestorKey::new(encrypted.content_ref.clone(), doc_id, key.clone()),
        ))
    }
}

/// Why [`Envelope::open`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OpenEnvelopeError {
    /// The body did not decrypt.
    #[error(transparent)]
    Decrypt(#[from] ContentDecryptError),

    /// The body decrypted, but is not an envelope. Only a writer with the
    /// block's key can produce this.
    #[error("the content is not an envelope: {0}")]
    Decode(#[from] DecodeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{application_secret::GroupSecret, encrypted::PredecessorRefs, padding::MARKER};
    use ed25519_dalek::SigningKey;
    use keyhive_crypto::share_key::ShareSecretKey;
    use std::vec;

    type Env = Envelope<[u8; 32], Vec<u8>>;
    type Encrypted = EncryptedContent<Vec<u8>, [u8; 32]>;

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

    /// The wiped encoding is the envelope's encoding, byte for byte, and the
    /// decoder, which shares nothing with the writer, reads it back.
    #[test]
    fn an_envelope_encodes_the_same_into_a_wiped_buffer() {
        bolero::check!()
            .with_arbitrary::<(Vec<([u8; 32], [u8; 32])>, Vec<u8>)>()
            .for_each(|(ancestors, payload)| {
                let envelope = arbitrary_envelope(ancestors, payload);
                let wiped = envelope.encode_zeroizing();
                assert_eq!(wiped.as_slice(), envelope.encode().as_bytes());
                assert_eq!(Env::decode(wiped.as_slice()).as_ref(), Ok(&envelope));
            });
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

    fn encrypt(body: &PaddedBody) -> (Encrypted, SymmetricKey, Identifier) {
        let key = SymmetricKey::from([1; 32]);
        let doc_id = Identifier::from(&SigningKey::from_bytes(&[2; 32]));
        let encrypted = EncryptedContent::encrypt(
            &key,
            doc_id,
            [3; 32],
            PredecessorRefs::digest(&[]),
            [4; 32].into(),
            [5; 32].into(),
            body,
        )
        .expect("a fresh key encrypts");
        (encrypted, key, doc_id)
    }

    #[test]
    fn an_encrypted_envelope_opens_to_itself() {
        bolero::check!()
            .with_arbitrary::<(Vec<([u8; 32], [u8; 32])>, Vec<u8>)>()
            .for_each(|(ancestors, payload)| {
                let original = arbitrary_envelope(ancestors, payload);
                let (encrypted, key, doc_id) = encrypt(&original.padded_body());
                let opened = Env::open(&encrypted, &key, doc_id).map(|(envelope, _)| envelope);
                assert_eq!(opened, Ok(original));
            });
    }

    /// What a writer encrypts opens to its payload and ancestors, through the
    /// production path: `try_encrypt` pads, `open` strips exactly the
    /// padding, even when the payload itself ends like padding.
    #[test]
    fn a_write_opens_to_its_payload_and_ancestors() {
        bolero::check!()
            .with_arbitrary::<(Vec<u8>, Vec<u8>, u8)>()
            .for_each(|(ancestor_refs, payload, last)| {
                let doc_id = Identifier::from(&SigningKey::from_bytes(&[2; 32]));
                let ancestors: Vec<_> = ancestor_refs
                    .iter()
                    .map(|&n| AncestorKey::new([n; 32], doc_id, SymmetricKey::from([n ^ 1; 32])))
                    .collect();
                let refs: Vec<_> = ancestor_refs.iter().map(|&n| [n; 32]).collect();
                let mut payload = payload.clone();
                payload.push(*last);
                payload.extend([MARKER, 0, 0]);

                let secret = GroupSecret(ShareSecretKey::force_from_bytes([1; 32]))
                    .derive_application_secret(
                        &[9u8; 32],
                        &PredecessorRefs::digest(&refs),
                        &[5; 32].into(),
                    );
                let (encrypted, own) = secret
                    .try_encrypt::<Vec<u8>>(doc_id, &ancestors, &payload)
                    .expect("the ancestors are the predecessors");
                let (opened, _) =
                    Env::open(&encrypted, own.key_ref(), doc_id).expect("its own key opens it");
                assert_eq!(opened.plaintext, payload);
                assert_eq!(
                    opened.ancestors,
                    ancestors
                        .iter()
                        .map(|a| (*a.content_ref(), a.key()))
                        .collect::<HashMap<_, _>>()
                );
            });
    }

    #[test]
    fn a_body_that_is_not_an_envelope_does_not_open() {
        // A count of one ancestor, with no ancestor after it, padded.
        let (encrypted, key, doc_id) = encrypt(&PaddedBody::pad(&[1]));
        assert_eq!(
            Env::open(&encrypted, &key, doc_id).map(|(envelope, _)| envelope),
            Err(OpenEnvelopeError::Decode(DecodeError::UnexpectedEnd))
        );
    }

    /// A body without padding does not open, unless it happens to end like
    /// padding.
    #[test]
    fn an_unpadded_body_does_not_open() {
        let unpadded = envelope(&[1], b"hi").encode().into_bytes();
        let (encrypted, key, doc_id) = encrypt(&PaddedBody::unchecked(&unpadded));
        assert_eq!(
            Env::open(&encrypted, &key, doc_id).map(|(envelope, _)| envelope),
            Err(OpenEnvelopeError::Decode(DecodeError::InvalidField(
                "padding"
            )))
        );
    }
}
