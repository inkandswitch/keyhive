use beekem::id::MemberId;
use dupe::Dupe;
use ed25519_dalek::{SigningKey, VerifyingKey};
use keyhive_crypto::{
    identifier::{Identifier, InvalidIdentifier},
    verifiable::Verifiable,
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct IndividualId(pub Identifier);

impl IndividualId {
    pub fn new(identifier: Identifier) -> Self {
        Self(identifier)
    }

    #[cfg(any(test, feature = "test_utils"))]
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        Self::from(&SigningKey::generate(csprng))
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

impl fmt::Display for IndividualId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl Dupe for IndividualId {}

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

/// A signing key's verifying key is always a valid [`Identifier`].
impl From<&SigningKey> for IndividualId {
    fn from(key: &SigningKey) -> Self {
        IndividualId(Identifier::from(key))
    }
}

impl TryFrom<VerifyingKey> for IndividualId {
    type Error = InvalidIdentifier;

    fn try_from(key: VerifyingKey) -> Result<Self, InvalidIdentifier> {
        Identifier::try_from(key).map(IndividualId)
    }
}

impl From<MemberId> for IndividualId {
    fn from(member_id: MemberId) -> Self {
        IndividualId(member_id.id())
    }
}

impl From<IndividualId> for MemberId {
    fn from(id: IndividualId) -> Self {
        MemberId::from(id.0)
    }
}

impl Verifiable for IndividualId {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }
}
