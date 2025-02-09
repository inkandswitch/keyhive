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
