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
    /// Prekeys were expanded.
    PrekeysExpanded(Box<Signed<AddKeyOp>>),

    /// A prekey was rotated.
    PrekeyRotated(Box<Signed<RotateKeyOp>>),

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
        let variant = u.int_in_range(0..=3)?;
        match variant {
            0 => Ok(Self::PrekeysExpanded(Box::new(u.arbitrary()?))),
            1 => Ok(Self::PrekeyRotated(Box::new(u.arbitrary()?))),
            2 => Ok(Self::CgkaOperation(Box::new(u.arbitrary()?))),
            // Delegations only: a revocation's watermark type has no
            // `Arbitrary`, and the signature is junk either way.
            3 => Ok(Self::Delegated(verified::Signed::from_parts(
                keyhive_codec::traits::Encode::encode(&Delegation::arbitrary(u)?),
                ed25519_dalek::Signature::from_bytes(&u.arbitrary()?),
            ))),
            _ => unreachable!(),
        }
    }
}
