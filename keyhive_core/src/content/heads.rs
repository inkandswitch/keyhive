//! [`ContentHeads`]: how a revocation says which of a document's content to
//! keep.

use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode, StreamDecode},
};

/// The heads of one document's content: the set of content references a
/// revocation's `retain` names for that document.
///
/// Keyline carries it per subject in `Revocation::retain`, as the
/// `RetentionWatermark`, and never reads it. The content layer does: content
/// at or before these heads is kept.
///
/// It is a set of `T`, not Automerge's own heads type, so that other content
/// systems' versions fit too. Automerge's heads are a set of change hashes;
/// a system versioned by a vector clock would use one `(actor, counter)`
/// entry per actor.
///
/// # Encoding
///
/// The heads back to back, in ascending order of their encodings, each once.
/// `T` is a [`StreamDecode`], so each head knows where it ends: fixed-size
/// heads, such as Automerge's 32-byte hashes, need no framing at all, and an
/// Automerge watermark is exactly `32 × k` bytes. There is no count, because
/// the `retain` entry around it is already length-prefixed. Ordering by
/// encoding rather than by `T`'s own order keeps the wire form independent
/// of how a consumer implements `Ord`.
///
/// `T`'s encodings must not be empty. A prefix-free type with an empty
/// encoding has only one value, which would be no use as a head.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContentHeads<T>(
    /// Sorted by encoding, without repeats. The only ways in, [`FromIterator`]
    /// and [`Decode`], both establish it.
    Vec<T>,
);

impl<T> ContentHeads<T> {
    /// The heads, in ascending order of their encodings.
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// How many heads there are.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are none. An empty watermark keeps none of the
    /// document's content, which differs from a `retain` with no entry for
    /// the document at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// Manual: the derive would add a spurious `T: Default` bound.
impl<T> Default for ContentHeads<T> {
    fn default() -> Self {
        ContentHeads(Vec::new())
    }
}

/// Sorts by encoding and drops repeats, in any input order.
impl<T: Encode> FromIterator<T> for ContentHeads<T> {
    fn from_iter<I: IntoIterator<Item = T>>(heads: I) -> Self {
        let mut keyed: Vec<(Vec<u8>, T)> = heads
            .into_iter()
            .map(|head| (head.encode().into_bytes(), head))
            .collect();
        keyed.sort_by(|(a, _), (b, _)| a.cmp(b));
        keyed.dedup_by(|(a, _), (b, _)| a == b);
        ContentHeads(keyed.into_iter().map(|(_, head)| head).collect())
    }
}

impl<T> IntoIterator for ContentHeads<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Encode> Encode for ContentHeads<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        for head in &self.0 {
            head.encode_into(out);
        }
    }
}

/// Rejects heads out of order or repeated, an empty head, and anything that
/// is not a whole number of heads.
impl<T: StreamDecode> Decode for ContentHeads<T> {
    fn decode(mut bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut heads = Vec::new();
        let mut previous: Option<&[u8]> = None;
        while !bytes.is_empty() {
            let (head, rest) = T::decode_next(bytes)?;
            let encoded = bytes
                .get(..bytes.len() - rest.len())
                .ok_or(DecodeError::UnexpectedEnd)?;
            if encoded.is_empty() {
                return Err(DecodeError::InvalidField("empty content head"));
            }
            if previous.is_some_and(|p| p >= encoded) {
                return Err(DecodeError::UnsortedKeys);
            }
            heads.push(head);
            previous = Some(encoded);
            bytes = rest;
        }
        Ok(ContentHeads(heads))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::{BTreeMap, BTreeSet},
        fmt,
    };

    #[test]
    fn heads_iterate_as_they_were_given() {
        let given = BTreeSet::from([[1u8; 2], [2u8; 2], [3u8; 2]]);
        let heads = ContentHeads::from_iter(given.iter().copied());
        assert_eq!(heads.into_iter().collect::<BTreeSet<_>>(), given);
    }

    /// A short head, so arbitrary bytes often decode and canonicality is
    /// exercised on real watermarks.
    type Short = [u8; 2];

    fn round_trips<T: Encode + StreamDecode + fmt::Debug + PartialEq>(heads: &ContentHeads<T>) {
        assert_eq!(
            ContentHeads::<T>::decode(heads.encode().as_bytes()).as_ref(),
            Ok(heads)
        );
    }

    fn canonical<T: Encode + StreamDecode>(bytes: &[u8]) {
        if let Ok(heads) = ContentHeads::<T>::decode(bytes) {
            assert_eq!(heads.encode().as_bytes(), bytes, "canonical");
        }
    }

    #[test]
    fn fixed_size_heads_round_trip_packed() {
        bolero::check!()
            .with_type::<Vec<[u8; 32]>>()
            .for_each(|hashes| {
                let heads: ContentHeads<[u8; 32]> = hashes.iter().copied().collect();
                round_trips(&heads);
                assert_eq!(heads.encode().len(), 32 * heads.len(), "no framing");
                let reversed: ContentHeads<[u8; 32]> = hashes.iter().rev().copied().collect();
                assert_eq!(reversed, heads, "input order does not matter");
            });
    }

    #[test]
    fn variable_length_heads_round_trip() {
        bolero::check!()
            .with_type::<Vec<u64>>()
            .for_each(|counters| {
                round_trips(&counters.iter().copied().collect::<ContentHeads<u64>>());
            });
    }

    #[test]
    fn decode_is_canonical() {
        bolero::check!().with_type::<Vec<u8>>().for_each(|bytes| {
            canonical::<Short>(bytes);
            canonical::<u32>(bytes);
        });
    }

    /// Pins the encoding: sorted by bytes, repeats dropped, nothing else.
    #[test]
    fn known_answer() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let heads: ContentHeads<[u8; 32]> = [b, a, b].into_iter().collect();
        assert_eq!(heads.as_slice(), &[a, b]);
        assert_eq!(heads.encode().as_bytes(), [a, b].concat().as_slice());
        assert!(ContentHeads::<[u8; 32]>::default().encode().is_empty());
    }

    #[test]
    fn decode_rejects_non_canonical_forms() {
        let (a, b): (Short, Short) = ([1, 1], [2, 2]);
        let decode = |parts: &[Short]| ContentHeads::<Short>::decode(&parts.concat());
        assert_eq!(decode(&[b, a]), Err(DecodeError::UnsortedKeys));
        assert_eq!(decode(&[a, a]), Err(DecodeError::UnsortedKeys));
        assert_eq!(
            ContentHeads::<Short>::decode(&[1, 1, 2]),
            Err(DecodeError::UnexpectedEnd),
            "not a whole number of heads"
        );
        assert_eq!(
            ContentHeads::<[u8; 0]>::decode(&[]),
            Ok(ContentHeads::default())
        );
    }

    /// The watermark rides in a signed revocation's `retain` and comes back
    /// intact through the wire form and verification.
    #[test]
    fn rides_in_a_signed_revocation() {
        use ed25519_dalek::SigningKey;
        use keyhive_crypto::{digest::Digest, identifier::Identifier, verified::Verified};
        use keyline::{
            certificate::{Certificate, VerifiedCertificate},
            delegation::Delegation,
            power::Power,
            revocation::Revocation,
        };

        let key = SigningKey::from_bytes(&[7; 32]);
        let issuer = Identifier::from(&key);
        let document = Identifier::from(&SigningKey::from_bytes(&[8; 32]));
        let target = Delegation::new(document, document, Power::Read);
        let heads: ContentHeads<[u8; 32]> = [[3; 32], [4; 32]].into_iter().collect();

        let revocation = Revocation::new(Digest::of(&issuer, &target.encode()))
            .retaining(BTreeMap::from([(document, heads.clone())]));
        let signed = Verified::sign_sync(&revocation, &key).expect("signed by its issuer");
        let wire = VerifiedCertificate::from(signed)
            .into_certificate()
            .encode();

        let received = Certificate::<ContentHeads<[u8; 32]>>::decode(wire.as_bytes())
            .expect("decodes")
            .verify()
            .expect("verifies");
        let VerifiedCertificate::Revocation(received) = received else {
            panic!("a revocation comes back a revocation");
        };
        assert_eq!(received.payload().retain.get(&document), Some(&heads));
    }
}
