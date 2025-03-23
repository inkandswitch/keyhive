use crate::{
    crypto::verifiable::Verifiable,
    principal::{identifier::Identifier, membered::id::MemberedId},
};
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

#[derive(Copy, Dupe, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct DocumentId(pub(crate) Identifier);

impl DocumentId {
    #[cfg(any(feature = "test_utils", test))]
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        Self(Identifier::generate(csprng))
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

impl From<DocumentId> for Identifier {
    fn from(id: DocumentId) -> Identifier {
        id.0
    }
}

impl From<Identifier> for DocumentId {
    fn from(id: Identifier) -> DocumentId {
        DocumentId(id)
    }
}

impl From<DocumentId> for MemberedId {
    fn from(id: DocumentId) -> MemberedId {
        MemberedId::DocumentId(id)
    }
}

impl Verifiable for DocumentId {
    fn verifying_key(&self) -> VerifyingKey {
        self.0.into()
    }
}

impl Debug for DocumentId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DocumentId({})", self.0)
    }
}

impl Display for DocumentId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}
