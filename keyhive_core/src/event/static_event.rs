//! Serializable version of [`Event`][super::Event].

use crate::{
    content::heads::ContentHeads,
    principal::individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
};
use beekem::operation::CgkaOperation;
use derive_more::{From, TryInto};
use keyhive_crypto::{
    content::reference::ContentRef,
    signed::Signed,
    verified::{self},
};
use keyline::{delegation::Delegation, revocation::Revocation};
use serde::{Deserialize, Serialize};

/// Serailizable version of [`Event`][super::Event].
///
/// This is useful for sending over a network or storing to disk.
/// However the references contained in `StaticEvent`s may be missing
/// dependencies, unlike [`Event`][super::Event]s.
#[derive(Debug, Clone, PartialEq, Eq, From, Hash, TryInto, Serialize, Deserialize)]
pub enum StaticEvent<T: ContentRef> {
    /// Prekeys were expanded, as received: verified on receipt.
    PrekeysExpanded(verified::Signed<AddKeyOp>),

    /// A prekey was rotated, as received: verified on receipt.
    PrekeyRotated(verified::Signed<RotateKeyOp>),

    /// A CGKA operation was performed.
    CgkaOperation(Box<Signed<CgkaOperation>>),

    /// A Keyline delegation, as received: verified on receipt.
    Delegated(verified::Signed<Delegation>),

    /// A Keyline revocation, as received: verified on receipt.
    Revoked(verified::Signed<Revocation<ContentHeads<T>>>),
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, T: arbitrary::Arbitrary<'a> + ContentRef> arbitrary::Arbitrary<'a> for StaticEvent<T> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Signatures are junk: these exercise encoding, not verification.
        fn junk<'a, V: arbitrary::Arbitrary<'a> + keyhive_codec::traits::Encode>(
            u: &mut arbitrary::Unstructured<'a>,
        ) -> arbitrary::Result<verified::Signed<V>> {
            Ok(verified::Signed::from_parts(
                u.arbitrary()?,
                keyhive_codec::traits::Encode::encode(&V::arbitrary(u)?),
                ed25519_dalek::Signature::from_bytes(&u.arbitrary()?),
            ))
        }

        let variant = u.int_in_range(0..=3)?;
        match variant {
            0 => Ok(Self::PrekeysExpanded(junk::<AddKeyOp>(u)?)),
            1 => Ok(Self::PrekeyRotated(junk::<RotateKeyOp>(u)?)),
            2 => Ok(Self::CgkaOperation(Box::new(u.arbitrary()?))),
            // Delegations only: a revocation's watermark type has no
            // `Arbitrary`.
            3 => Ok(Self::Delegated(junk::<Delegation>(u)?)),
            _ => unreachable!(),
        }
    }
}
