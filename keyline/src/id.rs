//! Node identity: an Ed25519 verifying key.

use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
};
use ed25519_dalek::VerifyingKey;
use keyhive_codec::{Decode, DecodeError, Encode};

/// A node in the authority graph.
///
/// Every principal, role, document, and group is an `Id`. Keyline attaches no
/// meaning to which is which; the layer above does.
// TODO(keyhive_types): unify with `keyhive_core::Identifier` and `beekem::MemberId`.
#[derive(Copy, Clone)]
pub struct Id(VerifyingKey);

impl Id {
    pub const LEN: usize = 32;

    pub fn new(key: VerifyingKey) -> Self {
        Id(key)
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        self.0.as_bytes()
    }

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        self.0.to_bytes()
    }
}

impl From<VerifyingKey> for Id {
    fn from(key: VerifyingKey) -> Self {
        Id(key)
    }
}

impl From<Id> for VerifyingKey {
    fn from(id: Id) -> Self {
        id.0
    }
}

impl PartialEq for Id {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Id {}

impl Hash for Id {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state)
    }
}

impl PartialOrd for Id {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Id {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({self})")
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.as_bytes()[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "…")
    }
}

impl Encode for Id {
    fn encode_into(&self, out: &mut alloc::vec::Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}

impl Decode for Id {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let arr: [u8; Self::LEN] =
            bytes
                .try_into()
                .map_err(|_| match bytes.len().cmp(&Self::LEN) {
                    Ordering::Less => DecodeError::UnexpectedEnd,
                    _ => DecodeError::TrailingBytes,
                })?;
        VerifyingKey::from_bytes(&arr)
            .map(Id)
            .map_err(|_| DecodeError::InvalidField("id"))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Id {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Id {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        VerifyingKey::deserialize(d).map(Id)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for Id {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed: [u8; 32] = u.arbitrary()?;
        Ok(Id(VerifyingKey::from(&ed25519_dalek::SigningKey::from(
            seed,
        ))))
    }
}
