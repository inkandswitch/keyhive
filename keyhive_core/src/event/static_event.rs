//! Serializable version of [`Event`][super::Event].

use crate::principal::{
    group::{delegation::StaticDelegation, revocation::StaticRevocation},
    individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
};
use beekem::operation::CgkaOperation;
use derive_more::{From, TryInto};
use keyhive_crypto::{content::reference::ContentRef, signed::SerdeSigned, verified::Signed};
use serde::{Deserialize, Serialize};

/// Serailizable version of [`Event`][super::Event].
///
/// This is useful for sending over a network or storing to disk.
/// However the references contained in `StaticEvent`s may be missing
/// dependencies, unlike [`Event`][super::Event]s.
#[derive(Debug, Clone, PartialEq, Eq, From, Hash, TryInto, Serialize, Deserialize)]
pub enum StaticEvent<T: ContentRef = [u8; 32]> {
    /// Prekeys were expanded, as received: verified on receipt.
    PrekeysExpanded(Signed<AddKeyOp>),

    /// A prekey was rotated, as received: verified on receipt.
    PrekeyRotated(Signed<RotateKeyOp>),

    /// A CGKA operation was performed.
    CgkaOperation(Box<SerdeSigned<CgkaOperation>>),

    /// A delegation was created.
    Delegated(SerdeSigned<StaticDelegation<T>>),

    /// A delegation was revoked.
    Revoked(SerdeSigned<StaticRevocation<T>>),
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, T: arbitrary::Arbitrary<'a> + ContentRef> arbitrary::Arbitrary<'a> for StaticEvent<T> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Signatures are junk: these exercise encoding, not verification.
        fn junk<'a, V: arbitrary::Arbitrary<'a> + keyhive_codec::traits::Encode>(
            u: &mut arbitrary::Unstructured<'a>,
        ) -> arbitrary::Result<Signed<V>> {
            Ok(Signed::new(
                u.arbitrary()?,
                keyhive_codec::traits::Encode::encode(&V::arbitrary(u)?),
                ed25519_dalek::Signature::from_bytes(&u.arbitrary()?),
            ))
        }

        let variant = u.int_in_range(0..=4)?;
        match variant {
            0 => Ok(Self::PrekeysExpanded(junk::<AddKeyOp>(u)?)),
            1 => Ok(Self::PrekeyRotated(junk::<RotateKeyOp>(u)?)),
            2 => Ok(Self::CgkaOperation(Box::new(SerdeSigned::arbitrary(u)?))),
            3 => Ok(Self::Delegated(SerdeSigned::arbitrary(u)?)),
            4 => Ok(Self::Revoked(SerdeSigned::arbitrary(u)?)),
            _ => unreachable!(),
        }
    }
}
