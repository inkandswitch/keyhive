//! Identity newtypes for BeeKEM tree members and documents.
//!
//! Both wrap a validated [`Identifier`]: a canonical Ed25519 verifying key
//! outside the small-order subgroup.

use core::fmt;
use ed25519_dalek::{SigningKey, VerifyingKey};
use keyhive_codec::{
    error::DecodeError,
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use keyhive_crypto::{
    identifier::{Identifier, InvalidIdentifier},
    verifiable::Verifiable,
};
use serde::{Deserialize, Serialize};

/// A group member: the individual at a leaf of the tree.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MemberId(Identifier);

impl MemberId {
    /// The member's key.
    pub fn id(&self) -> Identifier {
        self.0
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
    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

impl From<Identifier> for MemberId {
    fn from(id: Identifier) -> Self {
        Self(id)
    }
}

impl From<MemberId> for Identifier {
    fn from(member: MemberId) -> Self {
        member.0
    }
}

/// A signing key's verifying key is always a valid [`Identifier`].
impl From<&SigningKey> for MemberId {
    fn from(key: &SigningKey) -> Self {
        Self(Identifier::from(key))
    }
}

impl TryFrom<VerifyingKey> for MemberId {
    type Error = InvalidIdentifier;

    fn try_from(key: VerifyingKey) -> Result<Self, InvalidIdentifier> {
        Identifier::try_from(key).map(Self)
    }
}

impl From<MemberId> for VerifyingKey {
    fn from(member: MemberId) -> Self {
        member.0.verifying_key()
    }
}

impl Encode for MemberId {
    fn encode_into(&self, out: &mut alloc::vec::Vec<u8>) {
        self.0.encode_into(out);
    }
}

impl Decode for MemberId {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl StreamDecode for MemberId {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (id, rest) = Identifier::decode_next(bytes).map_err(|e| match e {
            DecodeError::InvalidField(_) => DecodeError::InvalidField("member_id"),
            other => other,
        })?;
        Ok((Self(id), rest))
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for MemberId {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed: [u8; 32] = u.arbitrary()?;
        Ok(Self::from(&SigningKey::from_bytes(&seed)))
    }
}

/// A tree's document.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TreeId(Identifier);

impl TreeId {
    /// The document's key.
    pub fn id(&self) -> Identifier {
        self.0
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
    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

impl From<Identifier> for TreeId {
    fn from(id: Identifier) -> Self {
        Self(id)
    }
}

impl From<TreeId> for Identifier {
    fn from(tree: TreeId) -> Self {
        tree.0
    }
}

/// A signing key's verifying key is always a valid [`Identifier`].
impl From<&SigningKey> for TreeId {
    fn from(key: &SigningKey) -> Self {
        Self(Identifier::from(key))
    }
}

impl TryFrom<VerifyingKey> for TreeId {
    type Error = InvalidIdentifier;

    fn try_from(key: VerifyingKey) -> Result<Self, InvalidIdentifier> {
        Identifier::try_from(key).map(Self)
    }
}

impl From<TreeId> for VerifyingKey {
    fn from(tree: TreeId) -> Self {
        tree.0.verifying_key()
    }
}

impl Encode for TreeId {
    fn encode_into(&self, out: &mut alloc::vec::Vec<u8>) {
        self.0.encode_into(out);
    }
}

impl Decode for TreeId {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl StreamDecode for TreeId {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (id, rest) = Identifier::decode_next(bytes).map_err(|e| match e {
            DecodeError::InvalidField(_) => DecodeError::InvalidField("tree_id"),
            other => other,
        })?;
        Ok((Self(id), rest))
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for TreeId {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed: [u8; 32] = u.arbitrary()?;
        Ok(Self::from(&SigningKey::from_bytes(&seed)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_laws() {
        keyhive_codec::laws::round_trip::<MemberId>();
        keyhive_codec::laws::canonical_near::<MemberId>();
        keyhive_codec::laws::stream::<MemberId>();
        keyhive_codec::laws::round_trip::<TreeId>();
        keyhive_codec::laws::canonical_near::<TreeId>();
        keyhive_codec::laws::stream::<TreeId>();
    }

    /// A key comes back out as it went in, through `verifying_key` and
    /// through the conversion, for members and trees alike.
    #[test]
    fn keys_round_trip() {
        bolero::check!().with_type::<[u8; 32]>().for_each(|seed| {
            let key = SigningKey::from_bytes(seed);
            let vk = key.verifying_key();

            let member = MemberId::from(&key);
            assert_eq!(member.verifying_key(), vk);
            assert_eq!(VerifyingKey::from(member), vk);
            assert_eq!(MemberId::try_from(vk), Ok(member));

            let tree = TreeId::from(&key);
            assert_eq!(tree.verifying_key(), vk);
            assert_eq!(VerifyingKey::from(tree), vk);
            assert_eq!(TreeId::try_from(vk), Ok(tree));
        });
    }

    #[test]
    fn a_small_order_key_is_not_a_member() {
        use curve25519_dalek::constants::EIGHT_TORSION;
        let weak = VerifyingKey::from_bytes(&EIGHT_TORSION[1].compress().to_bytes())
            .expect("a small-order point decompresses");
        assert_eq!(MemberId::try_from(weak), Err(InvalidIdentifier::SmallOrder));
        assert_eq!(TreeId::try_from(weak), Err(InvalidIdentifier::SmallOrder));
    }
}
