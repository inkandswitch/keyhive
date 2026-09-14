//! The unit of the set: a delegation or a revocation.

use crate::{delegation::Delegation, id::Id, revocation::Revocation};
use alloc::vec::Vec;
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::verifiable::Verifiable;

/// Either kind of certificate. This is what [`crate::keyline::Keyline::insert`]
/// takes and what the set holds.
///
/// Encoded as a one-byte kind tag followed by the certificate's own encoding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound = "C: serde::Serialize + serde::de::DeserializeOwned")
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Certificate<C> {
    /// A grant.
    Delegation(Delegation),

    /// A withdrawal of a grant.
    Revocation(Revocation<C>),
}

impl<C> Certificate<C> {
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
    pub fn as_revocation(&self) -> Option<&Revocation<C>> {
        match self {
            Certificate::Delegation(_) => None,
            Certificate::Revocation(r) => Some(r),
        }
    }
}

impl<C> From<Delegation> for Certificate<C> {
    fn from(d: Delegation) -> Self {
        Certificate::Delegation(d)
    }
}

impl<C> From<Revocation<C>> for Certificate<C> {
    fn from(r: Revocation<C>) -> Self {
        Certificate::Revocation(r)
    }
}

impl<C> Verifiable for Certificate<C> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.issuer().verifying_key()
    }
}

// One-byte kind tag, then the certificate's own encoding.
const TAG_DELEGATION: u8 = 0;
const TAG_REVOCATION: u8 = 1;

impl<C: Encode> Encode for Certificate<C> {
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

impl<C: Decode> Decode for Certificate<C> {
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

    /// Variable-length, to exercise the `retains` codec through the wrapper.
    type Keep = Vec<u8>;

    #[test]
    fn empty_and_bad_tag() {
        assert_eq!(
            Certificate::<Keep>::decode(&[]),
            Err(DecodeError::UnexpectedEnd)
        );
        assert_eq!(
            Certificate::<Keep>::decode(&[7]),
            Err(DecodeError::InvalidTag(7))
        );
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn codec_laws() {
        bolero::check!()
            .with_arbitrary::<Certificate<Keep>>()
            .for_each(|c| {
                let encoded = c.encode();
                let decoded = Certificate::decode(encoded.as_bytes()).expect("round trip");
                assert_eq!(&decoded, c);
                assert_eq!(decoded.encode(), encoded);
            });
    }

    #[test]
    fn decode_is_canonical() {
        bolero::check!().with_type::<Vec<u8>>().for_each(|bytes| {
            if let Ok(c) = Certificate::<Keep>::decode(bytes) {
                assert_eq!(c.encode().as_bytes(), bytes.as_slice());
            }
        });
    }
}
