use crate::principal::identifier::Identifier;
use derive_more::{From, Into};
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use keyhive_crypto::{
    id::{Id, InvalidId},
    verifiable::Verifiable,
};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};

/// A group identifier.
#[derive(
    Debug,
    Copy,
    Clone,
    Dupe,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    From,
    Into,
    Serialize,
    Deserialize,
)]
pub struct GroupId(pub(crate) Identifier);

impl GroupId {
    /// Lift a generic identifier to a group identifier.
    pub fn new(identifier: Identifier) -> Self {
        Self(identifier)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Verifiable for GroupId {
    fn verifying_key(&self) -> VerifyingKey {
        self.0.into()
    }
}

impl Display for GroupId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<GroupId> for Id {
    type Error = InvalidId;

    fn try_from(id: GroupId) -> Result<Id, InvalidId> {
        Identifier::from(id).try_into()
    }
}

impl From<Id> for GroupId {
    fn from(id: Id) -> Self {
        Identifier::from(id).into()
    }
}
