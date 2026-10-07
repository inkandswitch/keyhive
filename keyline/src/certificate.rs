//! The unit of the set: a delegation or a revocation.

use crate::{delegation::Delegation, id::Id, revocation::Revocation};
use alloc::vec::Vec;
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::verifiable::Verifiable;

/// Either kind of certificate. This is what [`crate::contract::Keyline::insert`]
/// takes and what the set holds.
///
/// Encoded as a one-byte kind tag followed by the certificate's own encoding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound = "W: serde::Serialize + serde::de::DeserializeOwned")
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Certificate<W> {
    /// A grant.
    Delegation(Delegation),

    /// A withdrawal of a grant.
    Revocation(Revocation<W>),
}

impl<W> Certificate<W> {
    /// The signer of either kind.
    pub fn issuer(&self) -> Id {
        match self {
            Certificate::Delegation(d) => d.issuer,
            Certificate::Revocation(r) => r.issuer,
        }
    }

    /// The delegation, if this certificate is one.
    pub fn as_delegation(&self) -> Option<&Delegation> {
        match self {
            Certificate::Delegation(d) => Some(d),
            Certificate::Revocation(_) => None,
        }
    }

    /// The revocation, if this certificate is one.
    pub fn as_revocation(&self) -> Option<&Revocation<W>> {
        match self {
            Certificate::Delegation(_) => None,
            Certificate::Revocation(r) => Some(r),
        }
    }
}

impl<W> From<Delegation> for Certificate<W> {
    fn from(d: Delegation) -> Self {
        Certificate::Delegation(d)
    }
}

impl<W> From<Revocation<W>> for Certificate<W> {
    fn from(r: Revocation<W>) -> Self {
        Certificate::Revocation(r)
    }
}

impl<W> Verifiable for Certificate<W> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.issuer().verifying_key()
    }
}

// One-byte kind tag, then the certificate's own encoding.
const TAG_DELEGATION: u8 = 0;
const TAG_REVOCATION: u8 = 1;

impl<W: Encode> Encode for Certificate<W> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Certificate::Delegation(d) => {
                out.push(TAG_DELEGATION);
                d.encode_into(out);
            }
            Certificate::Revocation(r) => {
                out.push(TAG_REVOCATION);
                r.encode_into(out);
            }
        }
    }
}

impl<W: Decode> Decode for Certificate<W> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (tag, rest) = bytes.split_first().ok_or(DecodeError::UnexpectedEnd)?;
        match *tag {
            TAG_DELEGATION => Delegation::decode(rest).map(Certificate::Delegation),
            TAG_REVOCATION => Revocation::decode(rest).map(Certificate::Revocation),
            other => Err(DecodeError::InvalidTag(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Variable-length, to exercise the `retain` codec through the wrapper.
    type Watermark = Vec<u8>;

    #[test]
    fn accessors_select_the_right_kind() {
        use crate::{power::Power, test_utils::id};
        let d = Delegation::new(id(1), id(2), id(3), Power::Read);
        let r: Revocation<Watermark> = Revocation::new(id(4), d.digest());

        let as_delegation: Certificate<Watermark> = d.into();
        assert_eq!(as_delegation.as_delegation(), Some(&d));
        assert_eq!(as_delegation.as_revocation(), None);
        assert_eq!(as_delegation.issuer(), id(1));

        let as_revocation: Certificate<Watermark> = r.clone().into();
        assert_eq!(as_revocation.as_delegation(), None);
        assert_eq!(as_revocation.as_revocation(), Some(&r));
        assert_eq!(as_revocation.issuer(), id(4));
    }

    #[test]
    fn empty_and_bad_tag() {
        assert_eq!(
            Certificate::<Watermark>::decode(&[]),
            Err(DecodeError::UnexpectedEnd)
        );
        assert_eq!(
            Certificate::<Watermark>::decode(&[7]),
            Err(DecodeError::InvalidTag(7))
        );
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn codec_laws() {
        bolero::check!()
            .with_arbitrary::<Certificate<Watermark>>()
            .for_each(|c| {
                let encoded = c.encode();
                let decoded = Certificate::decode(encoded.as_bytes()).expect("round trip");
                assert_eq!(&decoded, c);
                assert_eq!(decoded.encode(), encoded);
            });
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn decode_is_canonical() {
        crate::test_utils::decode_is_canonical_near::<Certificate<Watermark>>();
    }
}
