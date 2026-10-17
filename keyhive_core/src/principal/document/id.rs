use crate::principal::membered::id::MemberedId;
use beekem::id::TreeId;
use dupe::Dupe;
use ed25519_dalek::{SigningKey, VerifyingKey};
use keyhive_crypto::{
    id::{Id, InvalidId},
    verifiable::Verifiable,
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct DocumentId(pub(crate) Id);

impl DocumentId {
    #[cfg(any(feature = "test_utils", test))]
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

impl Dupe for DocumentId {}

impl From<Id> for DocumentId {
    fn from(id: Id) -> Self {
        DocumentId(id)
    }
}

impl From<DocumentId> for Id {
    fn from(id: DocumentId) -> Self {
        id.0
    }
}

impl From<&SigningKey> for DocumentId {
    fn from(key: &SigningKey) -> Self {
        DocumentId(Id::from(key))
    }
}

impl TryFrom<VerifyingKey> for DocumentId {
    type Error = InvalidId;

    fn try_from(key: VerifyingKey) -> Result<Self, InvalidId> {
        Id::try_from(key).map(DocumentId)
    }
}

impl From<DocumentId> for MemberedId {
    fn from(id: DocumentId) -> MemberedId {
        MemberedId::DocumentId(id)
    }
}

impl From<TreeId> for DocumentId {
    fn from(tree: TreeId) -> Self {
        DocumentId(tree.id())
    }
}

impl From<DocumentId> for TreeId {
    fn from(id: DocumentId) -> Self {
        TreeId::from(id.0)
    }
}

impl Verifiable for DocumentId {
    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

impl fmt::Debug for DocumentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DocumentId({self})")
    }
}

/// The whole key, `0x`-prefixed.
impl fmt::Display for DocumentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}
