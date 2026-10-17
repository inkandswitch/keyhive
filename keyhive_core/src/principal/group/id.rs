use dupe::Dupe;
use ed25519_dalek::{SigningKey, VerifyingKey};
use keyhive_crypto::{
    id::{Id, InvalidId},
    verifiable::Verifiable,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A group identifier.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GroupId(pub(crate) Id);

impl GroupId {
    /// Lift a generic identifier to a group identifier.
    pub fn new(id: Id) -> Self {
        Self(id)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Dupe for GroupId {}

impl From<Id> for GroupId {
    fn from(id: Id) -> Self {
        GroupId(id)
    }
}

impl From<GroupId> for Id {
    fn from(id: GroupId) -> Self {
        id.0
    }
}

impl From<&SigningKey> for GroupId {
    fn from(key: &SigningKey) -> Self {
        GroupId(Id::from(key))
    }
}

impl TryFrom<VerifyingKey> for GroupId {
    type Error = InvalidId;

    fn try_from(key: VerifyingKey) -> Result<Self, InvalidId> {
        Id::try_from(key).map(GroupId)
    }
}

impl Verifiable for GroupId {
    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

/// The whole key, `0x`-prefixed.
impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}
