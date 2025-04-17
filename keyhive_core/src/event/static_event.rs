//! Serializable version of [`Event`][super::Event].

use crate::{
    cgka::operation::CgkaOperation,
    content::reference::ContentRef,
    crypto::signed::Signed,
    principal::{
        group::{delegation::StaticDelegation, revocation::StaticRevocation},
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
    },
};
use derive_more::{From, TryInto};
use serde::{Deserialize, Serialize};

/// Serailizable version of [`Event`][super::Event].
///
/// This is useful for sending over a network or storing to disk.
/// However the references contained in `StaticEvent`s may be missing
/// dependencies, unlike [`Event`][super::Event]s.
#[derive(Debug, Clone, PartialEq, Eq, From, TryInto, Serialize, Deserialize)]
pub enum StaticEvent<T: ContentRef = [u8; 32]> {
    /// Prekeys were expanded.
    PrekeysExpanded(Box<Signed<AddKeyOp>>),

    /// A prekey was rotated.
    PrekeyRotated(Box<Signed<RotateKeyOp>>),

    /// A CGKA operation was performed.
    CgkaOperation(Box<Signed<CgkaOperation>>),

    /// A delegation was created.
    Delegated(Signed<StaticDelegation<T>>),

    /// A delegation was revoked.
    Revoked(Signed<StaticRevocation<T>>),
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, T: arbitrary::Arbitrary<'a> + ContentRef> arbitrary::Arbitrary<'a> for StaticEvent<T> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let variant = u.int_in_range(0..=4)?;
        match variant {
            0 => Ok(Self::PrekeysExpanded(Box::new(Signed::arbitrary(u)?))),
            1 => Ok(Self::PrekeyRotated(Box::new(Signed::arbitrary(u)?))),
            2 => Ok(Self::CgkaOperation(Box::new(Signed::arbitrary(u)?))),
            3 => Ok(Self::Delegated(Signed::arbitrary(u)?)),
            4 => Ok(Self::Revoked(Signed::arbitrary(u)?)),
            _ => unreachable!(),
        }
    }
}
