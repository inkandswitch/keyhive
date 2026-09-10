//! Revocations: signed withdrawals of a delegation by hash.

use crate::{delegation::Delegation, id::Id};
use alloc::vec::Vec;
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::digest::Digest;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Revocation {
    /// Signer. Determines the admin reach that scopes the effect.
    pub iss: Id,

    /// The delegation being revoked, by content address.
    pub revoke: Digest<Delegation>,
}

impl Revocation {
    pub fn new(iss: Id, revoke: Digest<Delegation>) -> Self {
        Revocation { iss, revoke }
    }

    /// Content address of the payload: what a re-issued
    /// [`Delegation::seen`] names. Digest of the revocation's own encoding,
    /// without the [`crate::certificate::Certificate`] kind tag.
    pub fn digest(&self) -> Digest<Revocation> {
        Digest::of(&self.encode())
    }
}

// Fixed-width layout: iss ‖ revoke. Placeholder until the bespoke codec lands.
const LEN: usize = Id::LEN + 32;

impl Encode for Revocation {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.iss.encode_into(out);
        out.extend_from_slice(self.revoke.as_slice());
    }
}

impl Decode for Revocation {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        match bytes.len().cmp(&LEN) {
            core::cmp::Ordering::Less => return Err(DecodeError::UnexpectedEnd),
            core::cmp::Ordering::Greater => return Err(DecodeError::TrailingBytes),
            core::cmp::Ordering::Equal => {}
        }
        let iss = Id::decode(&bytes[..Id::LEN])?;
        let raw: [u8; 32] = bytes[Id::LEN..]
            .try_into()
            .expect("length checked to be exactly LEN");
        Ok(Revocation {
            iss,
            revoke: Digest::from(raw),
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Revocation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw: [u8; 32] = u.arbitrary()?;
        Ok(Revocation {
            iss: u.arbitrary()?,
            revoke: Digest::from(raw),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::id;

    #[test]
    fn encoded_length() {
        let r = Revocation::new(id(1), Digest::from([3u8; 32]));
        assert_eq!(r.encode().len(), LEN);
    }

    #[test]
    fn rejects_wrong_lengths() {
        let r = Revocation::new(id(1), Digest::from([3u8; 32]));
        let bytes = r.encode().into_bytes();
        assert_eq!(
            Revocation::decode(&bytes[..bytes.len() - 1]),
            Err(DecodeError::UnexpectedEnd)
        );
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(Revocation::decode(&longer), Err(DecodeError::TrailingBytes));
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn codec_laws() {
        bolero::check!()
            .with_arbitrary::<Revocation>()
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
            if let Ok(r) = Revocation::decode(bytes) {
                assert_eq!(r.encode().as_bytes(), bytes.as_slice());
            }
        });
    }
}
