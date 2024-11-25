use crate::{
    crypto::{verifiable::Verifiable, verifying_key::VerifyingKey},
    principal::identifier::Identifier,
};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};

/// A group identifier.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

impl From<GroupId> for Identifier {
    fn from(group_id: GroupId) -> Identifier {
        group_id.0
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
