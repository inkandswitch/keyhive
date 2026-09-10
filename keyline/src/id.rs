//! Node identity: an Ed25519 verifying key.

use core::{cmp::Ordering, fmt};
use ed25519_dalek::VerifyingKey;
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::verifiable::Verifiable;

/// A node in the authority graph.
///
/// Every principal, role, document, and group is an `Id`. Keyline attaches no
/// meaning to which is which; the layer above does.
///
/// Stored as the 32-byte compressed key, not as [`VerifyingKey`] (which caches
/// the decompressed point and is roughly 200 bytes). Every constructor checks
/// that the bytes are a valid curve point, so [`Id::verifying_key`] cannot fail.
// TODO(keyhive_types): unify with `keyhive_core::Identifier` and `beekem::MemberId`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id([u8; 32]);

impl Id {
    pub const LEN: usize = 32;

    pub fn new(key: VerifyingKey) -> Self {
        Id(key.to_bytes())
    }

    /// Construct from raw bytes, checking that they are a valid verifying key.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, InvalidId> {
        VerifyingKey::from_bytes(&bytes)
            .map(|_| Id(bytes))
            .map_err(|_| InvalidId)
    }

    /// Decompress to a [`VerifyingKey`] for signature verification.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.0).expect("Id bytes were validated at construction")
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl From<VerifyingKey> for Id {
    fn from(key: VerifyingKey) -> Self {
        Id::new(key)
    }
}

impl From<Id> for VerifyingKey {
    fn from(id: Id) -> Self {
        id.verifying_key()
    }
}

impl Verifiable for Id {
    fn verifying_key(&self) -> VerifyingKey {
        Id::verifying_key(self)
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({self})")
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "…")
    }
}

impl Encode for Id {
    fn encode_into(&self, out: &mut alloc::vec::Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Decode for Id {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| match bytes.len().cmp(&Id::LEN) {
                Ordering::Less => DecodeError::UnexpectedEnd,
                _ => DecodeError::TrailingBytes,
            })?;
        Id::from_bytes(arr).map_err(|_| DecodeError::InvalidField("id"))
    }
}

/// The bytes are not a valid Ed25519 verifying key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("bytes are not a valid Ed25519 verifying key")]
pub struct InvalidId;

#[cfg(feature = "serde")]
impl serde::Serialize for Id {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Id {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes: [u8; 32] = serde::Deserialize::deserialize(d)?;
        Id::from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Id {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed: [u8; 32] = u.arbitrary()?;
        Ok(Id::new(VerifyingKey::from(
            &ed25519_dalek::SigningKey::from(seed),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_is_thirty_two_bytes() {
        assert_eq!(core::mem::size_of::<Id>(), 32);
    }

    #[test]
    fn rejects_non_curve_points() {
        // 0x02 repeated is not a decompressable Edwards y-coordinate.
        assert_eq!(Id::from_bytes([0x02; 32]), Err(InvalidId));
        assert_eq!(
            Id::decode(&[0x02; 32]),
            Err(DecodeError::InvalidField("id"))
        );
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn round_trips_through_verifying_key() {
        bolero::check!().with_arbitrary::<Id>().for_each(|id| {
            assert_eq!(Id::new(id.verifying_key()), *id);
            assert_eq!(Id::decode(id.as_bytes()), Ok(*id));
        });
    }
}
