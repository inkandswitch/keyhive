use crate::principal::{identifier::Identifier, verifiable::Verifiable};
use dupe::Dupe;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Copy, Dupe, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
pub struct IndividualId(pub Identifier);

impl IndividualId {
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

impl From<Identifier> for IndividualId {
    fn from(identifier: Identifier) -> Self {
        IndividualId(identifier)
    }
}

impl From<IndividualId> for Identifier {
    fn from(individual_id: IndividualId) -> Self {
        individual_id.0
    }
}

impl From<ed25519_dalek::VerifyingKey> for IndividualId {
    fn from(verifying_key: ed25519_dalek::VerifyingKey) -> Self {
        IndividualId(verifying_key.into())
    }
}

impl From<&ed25519_dalek::VerifyingKey> for IndividualId {
    fn from(verifying_key: &ed25519_dalek::VerifyingKey) -> Self {
        IndividualId((*verifying_key).into())
    }
}

impl std::fmt::Display for IndividualId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Verifiable for IndividualId {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }
}
