//! Serializable version of [`Event`][super::Event].

use crate::principal::{
    group::{delegation::StaticDelegation, revocation::StaticRevocation},
    individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
};
use beekem::operation::CgkaOperation;
use derive_more::{From, TryInto};
use keyhive_crypto::{content::reference::ContentRef, signed::SerdeSigned};
use serde::{Deserialize, Serialize};

/// Serailizable version of [`Event`][super::Event].
///
/// This is useful for sending over a network or storing to disk.
/// However the references contained in `StaticEvent`s may be missing
/// dependencies, unlike [`Event`][super::Event]s.
#[derive(Debug, Clone, PartialEq, Eq, From, Hash, TryInto, Serialize, Deserialize)]
pub enum StaticEvent<T: ContentRef = [u8; 32]> {
    /// Prekeys were expanded.
    PrekeysExpanded(Box<SerdeSigned<AddKeyOp>>),

    /// A prekey was rotated.
    PrekeyRotated(Box<SerdeSigned<RotateKeyOp>>),

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
        let variant = u.int_in_range(0..=4)?;
        match variant {
            0 => Ok(Self::PrekeysExpanded(Box::new(SerdeSigned::arbitrary(u)?))),
            1 => Ok(Self::PrekeyRotated(Box::new(SerdeSigned::arbitrary(u)?))),
            2 => Ok(Self::CgkaOperation(Box::new(SerdeSigned::arbitrary(u)?))),
            3 => Ok(Self::Delegated(SerdeSigned::arbitrary(u)?)),
            4 => Ok(Self::Revoked(SerdeSigned::arbitrary(u)?)),
            _ => unreachable!(),
        }
    }
}
