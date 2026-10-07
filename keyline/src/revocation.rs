//! Revocations: signed withdrawals of a delegation by hash.

use crate::{delegation::Delegation, id::Id};
use alloc::{collections::BTreeMap, vec::Vec};
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::{digest::Digest, domain_separator::Domain, verifiable::Verifiable};

/// A signed statement that a delegation no longer holds.
///
/// Validity is unconditional: any well-signed revocation is admitted to the
/// set. Its _effect_ is scoped by the issuer's admin reach: the target is
/// dead on every route that transits a node the issuer ever held `Admin` over,
/// or the issuer's own node, and inert elsewhere. Admin reach is computed on the
/// revocation-free graph and only grows, so a revocation's reach is permanent.
///
/// There is no `subject`: effect is scoped by the admin reach, not by the issuer's
/// choice. A `subject` field was rejected because every rotation would then
/// moot every standing revocation; see `design/keyline/alternatives.md`.
///
/// The type of `revoke` makes revoking a revocation unwritable. Repair is by
/// issuing a new delegation with [`Delegation::reissue`], never by un-revoking.
///
/// # `retain`
///
/// What becomes of the content a removed key already wrote is a question the
/// authority graph cannot answer. `retain` carries the issuer's answer: per
/// subject, a retention watermark bounding which of that content to keep.
/// Evaluation never reads it, as it never reads [`Delegation::citation`]; the
/// layer that materializes content does. `W` is bounded by [`Encode`] +
/// [`Decode`] so that watermarks are canonically encoded like every other
/// field. The map is incomplete by construction; see the `retain` section of
/// `design/keyline/implementation.md`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound = "W: serde::Serialize + serde::de::DeserializeOwned")
)]
pub struct Revocation<W> {
    /// Signer. Determines the admin reach that scopes the effect.
    pub issuer: Id,

    /// The delegation being revoked, by content address.
    pub revoke: Digest<Delegation>,

    /// Per-subject retention watermarks. Ignored by evaluation.
    pub retain: BTreeMap<Id, W>,
}

impl<W> Revocation<W> {
    /// `issuer` withdraws the delegation with this payload digest, naming no
    /// retention watermarks.
    pub fn new(issuer: Id, revoke: Digest<Delegation>) -> Self {
        Revocation {
            issuer,
            revoke,
            retain: BTreeMap::new(),
        }
    }

    /// The same revocation, carrying retention watermarks.
    pub fn retaining(self, retain: BTreeMap<Id, W>) -> Self {
        Revocation { retain, ..self }
    }
}

impl<W: Encode> Revocation<W> {
    /// The revocation's identity: what a re-issued [`Delegation::citation`]
    /// names, and its key in the set ([`crate::certificate::CertificateId`]).
    ///
    /// Typed as [`RevocationId`] rather than `Digest<Revocation<W>>` so that a
    /// [`Delegation`] can name a revocation without being parameterized by a
    /// watermark type it never uses.
    pub fn digest(&self) -> Digest<RevocationId> {
        Digest::of(&self.encode()).coerce()
    }
}

/// The identity of a revocation, independent of the watermark type it carries.
///
/// Only ever a phantom parameter of [`Digest`]; it has no values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RevocationId {}

impl<W> Domain for Revocation<W> {
    const CONTEXT: &'static str = "keyline/v0/revocation";
}

impl<W> Verifiable for Revocation<W> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.issuer.verifying_key()
    }
}

// Layout:  issuer ‖ revoke ‖ count:u32 ‖ entry*
//   entry: id ‖ len:u32 ‖ value
//
// `retain` is the crate's only variable-length field, so it is the only place
// canonicality is not free. `decode` rejects unsorted or repeated subjects and
// unconsumed bytes; lengths are fixed-width big-endian; `W::decode` rejects a
// non-canonical value.
const BASE_LEN: usize = Id::LEN + Digest::<Delegation>::LEN + 4;

/// The smallest an entry can be: a subject and a length, with an empty value.
const MIN_ENTRY_LEN: usize = Id::LEN + 4;

/// `bytes[at..at + len]`, or `UnexpectedEnd`.
///
/// Checked because `len` comes off the wire: on a 32-bit target (Wasm) a
/// declared length near `u32::MAX` overflows `at + len`.
fn slice_at(bytes: &[u8], at: usize, len: usize) -> Result<&[u8], DecodeError> {
    at.checked_add(len)
        .and_then(|end| bytes.get(at..end))
        .ok_or(DecodeError::UnexpectedEnd)
}

/// A length as the wire's `u32`. Panics past `u32::MAX`, which no
/// certificate approaches.
fn len_u32(len: usize) -> u32 {
    u32::try_from(len).expect("retain lengths fit in a u32")
}

fn u32_at(bytes: &[u8], at: usize) -> Result<usize, DecodeError> {
    let raw: [u8; 4] = slice_at(bytes, at, 4)?
        .try_into()
        .expect("slice_at returns exactly the requested length");
    Ok(u32::from_be_bytes(raw) as usize)
}

impl<W: Encode> Encode for Revocation<W> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.issuer.encode_into(out);
        out.extend_from_slice(self.revoke.as_slice());
        out.extend_from_slice(&len_u32(self.retain.len()).to_be_bytes());
        // `BTreeMap` iterates in ascending key order, which is the canonical one.
        for (subject, value) in &self.retain {
            subject.encode_into(out);
            let encoded = value.encode();
            out.extend_from_slice(&len_u32(encoded.len()).to_be_bytes());
            out.extend_from_slice(encoded.as_bytes());
        }
    }
}

impl<W: Decode> Decode for Revocation<W> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < BASE_LEN {
            return Err(DecodeError::UnexpectedEnd);
        }
        let issuer = Id::decode_field(&bytes[..Id::LEN], "issuer")?;
        let raw: [u8; Digest::<Delegation>::LEN] = bytes[Id::LEN..BASE_LEN - 4]
            .try_into()
            .expect("BASE_LEN bytes are present");
        let count = u32_at(bytes, BASE_LEN - 4)?;
        // Reject a count the input cannot hold before looping over it, so no
        // input makes decoding loop more than `bytes.len() / MIN_ENTRY_LEN` times.
        if count > (bytes.len() - BASE_LEN) / MIN_ENTRY_LEN {
            return Err(DecodeError::UnexpectedEnd);
        }

        let mut retain = BTreeMap::new();
        let mut at = BASE_LEN;
        let mut previous: Option<Id> = None;
        for _ in 0..count {
            let subject = Id::decode_field(slice_at(bytes, at, Id::LEN)?, "retain subject")?;
            if previous.is_some_and(|p| p >= subject) {
                return Err(DecodeError::UnsortedKeys);
            }
            previous = Some(subject);
            at += Id::LEN;

            let len = u32_at(bytes, at)?;
            at += 4;
            retain.insert(subject, W::decode(slice_at(bytes, at, len)?)?);
            at += len;
        }
        if at != bytes.len() {
            return Err(DecodeError::TrailingBytes);
        }

        Ok(Revocation {
            issuer,
            revoke: Digest::from(raw),
            retain,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, W: arbitrary::Arbitrary<'a>> arbitrary::Arbitrary<'a> for Revocation<W> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw: [u8; Digest::<Delegation>::LEN] = u.arbitrary()?;
        Ok(Revocation {
            issuer: u.arbitrary()?,
            revoke: Digest::from(raw),
            retain: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        signed::Signed,
        test_utils::{id, signing_key},
    };

    /// A watermark type with a variable-length encoding, so the `retain` codec is
    /// exercised on values of differing size rather than a fixed stand-in.
    type Watermark = Vec<u8>;

    fn sample() -> Revocation<Watermark> {
        Revocation::new(id(1), Digest::from([3u8; 32]))
    }

    /// A revocation names its own issuer, and only that issuer's key signs
    /// and verifies it.
    #[test]
    fn signs_and_verifies_only_as_its_issuer() {
        let r = sample();
        assert_eq!(Verifiable::verifying_key(&r), id(1).verifying_key());
        let verified = Signed::try_sign(&r, &signing_key(1))
            .expect("the issuer's key signs")
            .verify()
            .expect("and verifies");
        assert_eq!(verified.payload(), &r);
        assert!(Signed::try_sign(&r, &signing_key(2)).is_err());
    }

    #[test]
    fn encoded_length_without_retain() {
        assert_eq!(sample().encode().len(), BASE_LEN);
    }

    #[test]
    fn retain_round_trip() {
        let r = sample().retaining(BTreeMap::from([
            (id(2), alloc::vec![1, 2, 3]),
            (id(3), Vec::new()),
        ]));
        let encoded = r.encode();
        assert_eq!(
            Revocation::<Watermark>::decode(encoded.as_bytes()),
            Ok(r.clone())
        );
        // 2 entries: (id + len + 3) + (id + len + 0)
        assert_eq!(encoded.len(), BASE_LEN + (Id::LEN + 4 + 3) + (Id::LEN + 4));
        assert_ne!(
            sample().digest(),
            r.digest(),
            "`retain` is covered by the digest"
        );
    }

    #[test]
    fn rejects_wrong_lengths() {
        let bytes = sample().encode().into_bytes();
        assert_eq!(
            Revocation::<Watermark>::decode(&bytes[..bytes.len() - 1]),
            Err(DecodeError::UnexpectedEnd)
        );
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            Revocation::<Watermark>::decode(&longer),
            Err(DecodeError::TrailingBytes)
        );
    }

    /// Out-of-order keys, repeated keys, and a count that disagrees with the
    /// entries are each rejected.
    #[test]
    fn rejects_non_canonical_retain() {
        let r = sample().retaining(BTreeMap::from([
            (id(2), alloc::vec![7]),
            (id(3), alloc::vec![8]),
        ]));
        let good = r.encode().into_bytes();

        // Entries transposed: descending rather than ascending.
        let entry = Id::LEN + 4 + 1;
        let mut swapped = good[..BASE_LEN].to_vec();
        swapped.extend_from_slice(&good[BASE_LEN + entry..BASE_LEN + 2 * entry]);
        swapped.extend_from_slice(&good[BASE_LEN..BASE_LEN + entry]);
        assert_eq!(
            Revocation::<Watermark>::decode(&swapped),
            Err(DecodeError::UnsortedKeys)
        );

        // The same subject twice.
        let mut repeated = good[..BASE_LEN].to_vec();
        repeated.extend_from_slice(&good[BASE_LEN..BASE_LEN + entry]);
        repeated.extend_from_slice(&good[BASE_LEN..BASE_LEN + entry]);
        assert_eq!(
            Revocation::<Watermark>::decode(&repeated),
            Err(DecodeError::UnsortedKeys)
        );

        // A count that disagrees with the entries present.
        let mut miscounted = good.clone();
        miscounted[BASE_LEN - 1] = 1;
        assert_eq!(
            Revocation::<Watermark>::decode(&miscounted),
            Err(DecodeError::TrailingBytes)
        );
    }

    /// A declared entry length past the end of input is truncation, not a panic.
    #[test]
    fn rejects_oversized_entry_length() {
        let r = sample().retaining(BTreeMap::from([(id(2), alloc::vec![7])]));
        let mut bytes = r.encode().into_bytes();
        let len_at = BASE_LEN + Id::LEN;
        bytes[len_at..len_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            Revocation::<Watermark>::decode(&bytes),
            Err(DecodeError::UnexpectedEnd)
        );
        assert_eq!(
            slice_at(&bytes, usize::MAX, 1),
            Err(DecodeError::UnexpectedEnd),
            "the end offset overflows"
        );
    }

    /// A count larger than the remaining input could hold is rejected up
    /// front; a count that exactly fills it (empty values) is not.
    #[test]
    fn rejects_a_count_the_input_cannot_hold() {
        let r = sample().retaining(BTreeMap::from([(id(2), Vec::new()), (id(3), Vec::new())]));
        let bytes = r.encode().into_bytes();
        assert_eq!(bytes.len(), BASE_LEN + 2 * MIN_ENTRY_LEN);
        assert_eq!(Revocation::<Watermark>::decode(&bytes), Ok(r));

        for count in [3, u32::MAX] {
            let mut claimed = bytes.clone();
            claimed[BASE_LEN - 4..BASE_LEN].copy_from_slice(&count.to_be_bytes());
            assert_eq!(
                Revocation::<Watermark>::decode(&claimed),
                Err(DecodeError::UnexpectedEnd),
                "count {count}"
            );
        }
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn codec_laws() {
        bolero::check!()
            .with_arbitrary::<Revocation<Watermark>>()
            .for_each(|r| {
                let encoded = r.encode();
                let decoded = Revocation::decode(encoded.as_bytes()).expect("round trip");
                assert_eq!(&decoded, r);
            });
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn decode_is_canonical() {
        crate::test_utils::decode_is_canonical_near::<Revocation<Watermark>>();
    }
}
