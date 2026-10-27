use crate::principal::membered::id::MemberedId;
use beekem::id::TreeId;
use dupe::Dupe;
use ed25519_dalek::{SigningKey, VerifyingKey};
use keyhive_crypto::{
    identifier::{Identifier, InvalidIdentifier},
    verifiable::Verifiable,
};
use std::fmt;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct DocumentId(pub(crate) Identifier);

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

impl From<Identifier> for DocumentId {
    fn from(id: Identifier) -> Self {
        DocumentId(id)
    }
}

impl From<DocumentId> for Identifier {
    fn from(id: DocumentId) -> Self {
        id.0
    }
}

impl From<&SigningKey> for DocumentId {
    fn from(key: &SigningKey) -> Self {
        DocumentId(Identifier::from(key))
    }
}

impl TryFrom<VerifyingKey> for DocumentId {
    type Error = InvalidIdentifier;

    fn try_from(key: VerifyingKey) -> Result<Self, InvalidIdentifier> {
        Identifier::try_from(key).map(DocumentId)
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

/// Its identifier's 32 bytes.
impl keyhive_codec::traits::Encode for DocumentId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
    }
}

impl keyhive_codec::traits::Decode for DocumentId {
    fn decode(bytes: &[u8]) -> Result<Self, keyhive_codec::error::DecodeError> {
        keyhive_codec::traits::decode_exact(bytes)
    }
}

impl keyhive_codec::traits::StreamDecode for DocumentId {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), keyhive_codec::error::DecodeError> {
        let (id, rest) = Identifier::decode_next(bytes)?;
        Ok((DocumentId(id), rest))
    }
}
