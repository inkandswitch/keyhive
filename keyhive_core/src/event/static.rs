use crate::cgka::CgkaOperation;

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
