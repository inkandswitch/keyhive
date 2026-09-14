//! Revocations: signed withdrawals of a delegation by hash.

use crate::{delegation::Delegation, id::Id};
use alloc::{collections::BTreeMap, vec::Vec};
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::{digest::Digest, verifiable::Verifiable};

/// A signed statement that a delegation no longer holds.
///
/// Validity is unconditional: any well-signed revocation is admitted to the
/// set. Its _effect_ is scoped by the issuer's admin reach: the target is
/// dead on every route that transits a node the issuer ever held `Admin` over,
/// or the issuer's own node, and inert elsewhere. Admin reach is computed on the
/// revocation-free graph and only grows, so a revocation's reach is permanent.
///
/// There is no `sub`: effect is scoped by the admin reach, not by the issuer's
/// choice. A jurisdiction field was rejected because every rotation would then
/// moot every standing denial, forcing the deny list to be re-signed; see
/// `design/keyline/alternatives.md`.
///
/// The type of `revoke` makes revoking a revocation unwritable. Repair is by
/// re-granting with [`Delegation::reissue`], never by un-denying.
///
/// # `keep`
///
/// Revoking a key raises a second question the authority graph cannot answer:
/// what becomes of the content that key already wrote. `keep` carries the
/// revoker's answer — a retention watermark, opaque to this crate. Evaluation
/// never reads it, exactly as it never reads [`Delegation::seen`]; the layer
/// that materialises content does.
///
/// The keys are subjects — documents, in `keyhive_core`'s reading, though this
/// crate does not distinguish them from any other node. `C` is the per-subject
/// watermark, bounded only by [`Encode`] + [`Decode`] so it is canonically
/// encoded like every other field. Carrying the whole map as opaque bytes
/// instead would put a hole in the canonicality law precisely at the
/// certificate digest: two encodings of one watermark would be two
/// certificates for one act.
///
/// The map is not exhaustive and cannot be. A role's portfolio grows by late
/// binding, so a subject supplied after this revocation was signed can never
/// appear here, and partial visibility means the revoker may not have seen
/// every subject that already exists. What to do for an unnamed subject is
/// therefore the content layer's policy, and naming none — an empty map — is
/// only the extreme of that same incompleteness, not a distinct instruction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound = "C: serde::Serialize + serde::de::DeserializeOwned")
)]
pub struct Revocation<C> {
    /// Signer. Determines the admin reach that scopes the effect.
    pub iss: Id,

    /// The delegation being revoked, by content address.
    pub revoke: Digest<Delegation>,

    /// Per-subject retention watermarks. Ignored by evaluation.
    pub keep: BTreeMap<Id, C>,
}

impl<C> Revocation<C> {
    /// `iss` withdraws the delegation with this payload digest, naming no
    /// retention watermarks.
    pub fn new(iss: Id, revoke: Digest<Delegation>) -> Self {
        Revocation {
            iss,
            revoke,
            keep: BTreeMap::new(),
        }
    }

    /// The same revocation, carrying retention watermarks.
    pub fn keeping(self, keep: BTreeMap<Id, C>) -> Self {
        Revocation { keep, ..self }
    }
}

impl<C: Encode> Revocation<C> {
    /// Content address of the payload: what a re-issued
    /// [`Delegation::seen`] names. Digest of the revocation's own encoding,
    /// without the [`crate::certificate::Certificate`] kind tag.
    ///
    /// Typed as [`RevocationId`] rather than `Digest<Revocation<C>>` so that a
    /// [`Delegation`] can name a revocation without being parameterised by a
    /// content type it never uses.
    pub fn digest(&self) -> Digest<RevocationId> {
        Digest::of(&self.encode()).coerce()
    }
}

/// The identity of a revocation, independent of the content type it carries.
///
/// Only ever a phantom parameter of [`Digest`]; it has no values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RevocationId {}

impl<C> Verifiable for Revocation<C> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.iss.verifying_key()
    }
}

// Layout:  iss ‖ revoke ‖ count:u32 ‖ entry*
//   entry: id ‖ len:u32 ‖ value
//
// `keep` is the crate's only variable-length field, so it is the only place
// canonicality is not free. Three rules make it so, and `decode` enforces all
// three: entries ascend by `Id` with no repeats (one ordering per map), lengths
// are fixed-width big-endian (one encoding per number), and the input must be
// consumed exactly (no slack to hide bytes in). `C::decode` supplies the fourth
// by rejecting a non-canonical value, which is why this field is typed rather
// than opaque.
const BASE_LEN: usize = Id::LEN + 32 + 4;

fn u32_at(bytes: &[u8], at: usize) -> Result<usize, DecodeError> {
    let raw: [u8; 4] = bytes
        .get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or(DecodeError::UnexpectedEnd)?;
    Ok(u32::from_be_bytes(raw) as usize)
}

impl<C: Encode> Encode for Revocation<C> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.iss.encode_into(out);
        out.extend_from_slice(self.revoke.as_slice());
        out.extend_from_slice(&(self.keep.len() as u32).to_be_bytes());
        // `BTreeMap` iterates in ascending key order, which is the canonical one.
        for (subject, value) in &self.keep {
            subject.encode_into(out);
            let encoded = value.encode();
            out.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            out.extend_from_slice(encoded.as_bytes());
        }
    }
}

impl<C: Decode> Decode for Revocation<C> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < BASE_LEN {
            return Err(DecodeError::UnexpectedEnd);
        }
        let iss = Id::decode(&bytes[..Id::LEN])?;
        let raw: [u8; 32] = bytes[Id::LEN..Id::LEN + 32]
            .try_into()
            .map_err(|_| DecodeError::UnexpectedEnd)?;
        let count = u32_at(bytes, Id::LEN + 32)?;

        let mut keep = BTreeMap::new();
        let mut at = BASE_LEN;
        let mut previous: Option<Id> = None;
        for _ in 0..count {
            let subject = Id::decode(
                bytes
                    .get(at..at + Id::LEN)
                    .ok_or(DecodeError::UnexpectedEnd)?,
            )?;
            if previous.is_some_and(|p| p >= subject) {
                return Err(DecodeError::InvalidField(
                    "keep: unsorted or repeated subject",
                ));
            }
            previous = Some(subject);
            at += Id::LEN;

            let len = u32_at(bytes, at)?;
            at += 4;
            let value = bytes.get(at..at + len).ok_or(DecodeError::UnexpectedEnd)?;
            keep.insert(subject, C::decode(value)?);
            at += len;
        }
        if at != bytes.len() {
            return Err(DecodeError::TrailingBytes);
        }

        Ok(Revocation {
            iss,
            revoke: Digest::from(raw),
            keep,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, C: arbitrary::Arbitrary<'a>> arbitrary::Arbitrary<'a> for Revocation<C> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw: [u8; 32] = u.arbitrary()?;
        Ok(Revocation {
            iss: u.arbitrary()?,
            revoke: Digest::from(raw),
            keep: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::id;

    /// A watermark type with a variable-length encoding, so the `keep` codec is
    /// exercised on values of differing size rather than a fixed stand-in.
    type Keep = Vec<u8>;

    fn sample() -> Revocation<Keep> {
        Revocation::new(id(1), Digest::from([3u8; 32]))
    }

    #[test]
    fn encoded_length_without_keep() {
        assert_eq!(sample().encode().len(), BASE_LEN);
    }

    #[test]
    fn keep_round_trips() {
        let r = sample().keeping(BTreeMap::from([
            (id(2), alloc::vec![1, 2, 3]),
            (id(3), Vec::new()),
        ]));
        let encoded = r.encode();
        assert_eq!(
            Revocation::<Keep>::decode(encoded.as_bytes()),
            Ok(r.clone())
        );
        // 2 entries: (id + len + 3) + (id + len + 0)
        assert_eq!(encoded.len(), BASE_LEN + (Id::LEN + 4 + 3) + (Id::LEN + 4));
        assert_ne!(
            sample().digest(),
            r.digest(),
            "keep is covered by the digest"
        );
    }

    #[test]
    fn rejects_wrong_lengths() {
        let bytes = sample().encode().into_bytes();
        assert_eq!(
            Revocation::<Keep>::decode(&bytes[..bytes.len() - 1]),
            Err(DecodeError::UnexpectedEnd)
        );
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            Revocation::<Keep>::decode(&longer),
            Err(DecodeError::TrailingBytes)
        );
    }

    /// The three ways a `keep` map could have two encodings, each rejected.
    #[test]
    fn rejects_non_canonical_keep() {
        let r = sample().keeping(BTreeMap::from([
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
            Revocation::<Keep>::decode(&swapped),
            Err(DecodeError::InvalidField(
                "keep: unsorted or repeated subject"
            ))
        );

        // The same subject twice.
        let mut repeated = good[..BASE_LEN].to_vec();
        repeated.extend_from_slice(&good[BASE_LEN..BASE_LEN + entry]);
        repeated.extend_from_slice(&good[BASE_LEN..BASE_LEN + entry]);
        assert_eq!(
            Revocation::<Keep>::decode(&repeated),
            Err(DecodeError::InvalidField(
                "keep: unsorted or repeated subject"
            ))
        );

        // A count that disagrees with the entries present.
        let mut miscounted = good.clone();
        miscounted[BASE_LEN - 1] = 1;
        assert_eq!(
            Revocation::<Keep>::decode(&miscounted),
            Err(DecodeError::TrailingBytes)
        );
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn codec_laws() {
        bolero::check!()
            .with_arbitrary::<Revocation<Keep>>()
            .for_each(|r| {
                let encoded = r.encode();
                let decoded = Revocation::decode(encoded.as_bytes()).expect("round trip");
                assert_eq!(&decoded, r);
                assert_eq!(decoded.encode(), encoded);
            });
    }

    #[test]
    fn decode_is_canonical() {
        bolero::check!().with_type::<Vec<u8>>().for_each(|bytes| {
            if let Ok(r) = Revocation::<Keep>::decode(bytes) {
                assert_eq!(r.encode().as_bytes(), bytes.as_slice());
            }
        });
    }
}
