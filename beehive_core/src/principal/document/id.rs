use crate::principal::{identifier::Identifier, membered::id::MemberedId, verifiable::Verifiable};
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(
    Debug, Copy, Dupe, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
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

impl Display for DocumentId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
