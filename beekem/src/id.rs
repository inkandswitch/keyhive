//! Identity newtypes for BeeKEM tree members and documents.

use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
};
use keyhive_crypto::verifiable::Verifiable;
use serde::{Deserialize, Serialize};

/// A group member identity, wrapping an Ed25519 verifying key.
///
/// This replaces `IndividualId` from keyhive_core for use within
/// the BeeKEM crate boundary.
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct MemberId(pub ed25519_dalek::VerifyingKey);

impl MemberId {
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

impl PartialEq for MemberId {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for MemberId {}

impl Hash for MemberId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state)
    }
}

impl PartialOrd for MemberId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MemberId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl fmt::Debug for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemberId(")?;
        keyhive_crypto::hex::bytes_as_hex(self.as_bytes().iter(), f)?;
        write!(f, ")")
    }
}

impl fmt::Display for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        keyhive_crypto::hex::bytes_as_hex(self.as_bytes().iter(), f)
    }
}

impl Verifiable for MemberId {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0
    }
}

impl From<ed25519_dalek::VerifyingKey> for MemberId {
    fn from(vk: ed25519_dalek::VerifyingKey) -> Self {
        Self(vk)
    }
}

impl From<&ed25519_dalek::VerifyingKey> for MemberId {
    fn from(vk: &ed25519_dalek::VerifyingKey) -> Self {
        Self(*vk)
    }
}

impl From<MemberId> for ed25519_dalek::VerifyingKey {
    fn from(id: MemberId) -> Self {
        id.0
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for MemberId {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes = u.bytes(32)?;
        let arr = <[u8; 32]>::try_from(bytes).expect("32 bytes");
        let sk = ed25519_dalek::SigningKey::from_bytes(&arr);
        Ok(Self(sk.verifying_key()))
    }
}

/// A tree/document identity, wrapping an Ed25519 verifying key.
///
/// This replaces `DocumentId` from keyhive_core for use within
/// the BeeKEM crate boundary.
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct TreeId(pub ed25519_dalek::VerifyingKey);

impl TreeId {
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

impl PartialEq for TreeId {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for TreeId {}

impl Hash for TreeId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state)
    }
}

impl PartialOrd for TreeId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TreeId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl fmt::Debug for TreeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TreeId(")?;
        keyhive_crypto::hex::bytes_as_hex(self.as_bytes().iter(), f)?;
        write!(f, ")")
    }
}

impl fmt::Display for TreeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        keyhive_crypto::hex::bytes_as_hex(self.as_bytes().iter(), f)
    }
}

impl Verifiable for TreeId {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0
    }
}

impl From<ed25519_dalek::VerifyingKey> for TreeId {
    fn from(vk: ed25519_dalek::VerifyingKey) -> Self {
        Self(vk)
    }
}

impl From<&ed25519_dalek::VerifyingKey> for TreeId {
    fn from(vk: &ed25519_dalek::VerifyingKey) -> Self {
        Self(*vk)
    }
}

impl From<TreeId> for ed25519_dalek::VerifyingKey {
    fn from(id: TreeId) -> Self {
        id.0
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for TreeId {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes = u.bytes(32)?;
        let arr = <[u8; 32]>::try_from(bytes).expect("32 bytes");
        let sk = ed25519_dalek::SigningKey::from_bytes(&arr);
        Ok(Self(sk.verifying_key()))
    }
}
