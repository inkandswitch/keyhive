use crate::{crypto::verifiable::Verifiable, principal::identifier::Identifier};
use derive_more::Display;
use dupe::Dupe;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Display, Copy, Dupe, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct IndividualId(pub Identifier);

impl IndividualId {
    pub fn new(identifier: Identifier) -> Self {
        Self(identifier)
    }

    #[cfg(any(test, feature = "test_utils"))]
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        Identifier::generate(csprng).into()
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

impl Verifiable for IndividualId {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }
}
