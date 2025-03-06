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

#[derive(Debug, Clone, PartialEq, Eq, From, TryInto, Serialize, Deserialize)]
pub enum StaticEvent<T: ContentRef = [u8; 32]> {
    // Prekeys
    PrekeysExpanded(Signed<AddKeyOp>),
    PrekeyRotated(Signed<RotateKeyOp>),

    // Cgka
    CgkaOperation(Signed<CgkaOperation>),

    // Membership
    Delegated(Signed<StaticDelegation<T>>),
    Revoked(Signed<StaticRevocation<T>>),
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, T: arbitrary::Arbitrary<'a> + ContentRef> arbitrary::Arbitrary<'a> for StaticEvent<T> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let variant = u.int_in_range(0..=4)?;
        match variant {
            0 => Ok(Self::PrekeysExpanded(Signed::arbitrary(u)?)),
            1 => Ok(Self::PrekeyRotated(Signed::arbitrary(u)?)),
            2 => Ok(Self::CgkaOperation(Signed::arbitrary(u)?)),
            3 => Ok(Self::Delegated(Signed::arbitrary(u)?)),
            4 => Ok(Self::Revoked(Signed::arbitrary(u)?)),
            _ => unreachable!(),
        }
    }
}
