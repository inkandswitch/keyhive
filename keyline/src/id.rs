//! Node identity: an Ed25519 verifying key.

use alloc::vec::Vec;
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
pub struct Id([u8; Self::LEN]);

impl Id {
    /// Length of the compressed verifying key, in bytes.
    pub const LEN: usize = 32;

    /// The `Id` of a verifying key.
    pub fn new(key: VerifyingKey) -> Self {
        Id(key.to_bytes())
    }

    /// Construct from raw bytes, checking that they are a valid verifying key.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Result<Self, InvalidId> {
        VerifyingKey::from_bytes(&bytes)
            .map(|_| Id(bytes))
            .map_err(|_| InvalidId)
    }

    /// Decompress to a [`VerifyingKey`] for signature verification.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.0).expect("Id bytes were validated at construction")
    }

    /// The compressed verifying key.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// The compressed verifying key, by value.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
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
    fn encode_into(&self, out: &mut Vec<u8>) {
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
        d.deserialize_bytes(IdVisitor)
    }
}

/// Reads what [`Id`]'s `Serialize` writes: a byte string. Self-describing
/// formats that render bytes as a list (JSON) arrive as a sequence instead.
/// Both paths check the length and that the bytes are a curve point.
#[cfg(feature = "serde")]
struct IdVisitor;

#[cfg(feature = "serde")]
impl<'de> serde::de::Visitor<'de> for IdVisitor {
    type Value = Id;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the {} bytes of an Ed25519 verifying key", Id::LEN)
    }

    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Id, E> {
        let bytes: [u8; Id::LEN] = v
            .try_into()
            .map_err(|_| E::invalid_length(v.len(), &self))?;
        Id::from_bytes(bytes).map_err(E::custom)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Id, A::Error> {
        let mut bytes = [0u8; Id::LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = seq
                .next_element()?
                .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
        }
        if seq.next_element::<u8>()?.is_some() {
            return Err(serde::de::Error::invalid_length(Id::LEN + 1, &self));
        }
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
    #[cfg(feature = "serde")]
    use alloc::string::ToString;

    #[test]
    fn rejects_non_curve_points() {
        // 0x02 repeated is not a decompressable Edwards y-coordinate.
        assert_eq!(Id::from_bytes([0x02; 32]), Err(InvalidId));
        assert_eq!(
            Id::decode(&[0x02; 32]),
            Err(DecodeError::InvalidField("id"))
        );
    }

    fn sample() -> Id {
        Id::new(VerifyingKey::from(&ed25519_dalek::SigningKey::from(
            [7u8; 32],
        )))
    }

    #[test]
    fn conversions_agree() {
        let id = sample();
        let key = id.verifying_key();
        assert_eq!(&id.to_bytes(), id.as_bytes());
        assert_eq!(id.to_bytes(), key.to_bytes());
        assert_eq!(VerifyingKey::from(id), key);
        assert_eq!(Id::from(key), id);
        assert_eq!(Verifiable::verifying_key(&id), key);
    }

    #[test]
    fn decode_rejects_wrong_lengths_distinctly() {
        let bytes = sample().to_bytes();
        assert_eq!(Id::decode(&bytes[..31]), Err(DecodeError::UnexpectedEnd));
        assert_eq!(Id::decode(&[]), Err(DecodeError::UnexpectedEnd));
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(Id::decode(&longer), Err(DecodeError::TrailingBytes));
    }

    /// Through a positional format with no type tags, where a disagreement
    /// between `Serialize` and `Deserialize` misreads instead of erroring.
    #[test]
    #[cfg(feature = "serde")]
    fn serde_round_trips_through_postcard() {
        let id = sample();
        let bytes = postcard::to_allocvec(&id).expect("serialize");
        let (decoded, rest) = postcard::take_from_bytes::<Id>(&bytes).expect("deserialize");
        assert_eq!(decoded, id);
        assert!(rest.is_empty(), "every byte written is read back");
    }

    /// The sequence path, as a self-describing format like JSON delivers it.
    #[test]
    #[cfg(feature = "serde")]
    fn serde_accepts_a_byte_sequence_of_exactly_the_right_length() {
        use serde::{de::value::SeqDeserializer, Deserialize};
        type Seq<I> = SeqDeserializer<I, serde::de::value::Error>;

        let id = sample();
        let exact = Seq::new(id.to_bytes().into_iter());
        assert_eq!(Id::deserialize(exact), Ok(id));

        let short = Seq::new(id.to_bytes()[..31].to_vec().into_iter());
        assert_eq!(
            Id::deserialize(short).map_err(|e| e.to_string()),
            Err("invalid length 31, expected the 32 bytes of an Ed25519 verifying key".into())
        );

        let mut extra = id.to_bytes().to_vec();
        extra.push(0);
        assert_eq!(
            Id::deserialize(Seq::new(extra.into_iter())).map_err(|e| e.to_string()),
            Err("invalid length 33, expected the 32 bytes of an Ed25519 verifying key".into())
        );

        let not_a_point = Seq::new([0x02u8; 32].into_iter());
        assert!(Id::deserialize(not_a_point).is_err());
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
