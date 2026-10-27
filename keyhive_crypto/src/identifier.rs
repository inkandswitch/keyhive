//! Identity: a validated Ed25519 verifying key, with a canonical codec.

use crate::verifiable::Verifiable;
use alloc::vec::Vec;
use core::fmt;
use ed25519_dalek::{SigningKey, VerifyingKey};
use keyhive_codec::{
    error::DecodeError,
    traits::{decode_exact, Decode, Encode, StreamDecode},
};

/// An Ed25519 verifying key that names a principal.
///
/// Every principal, document, and group is an `Identifier`; so is every node of
/// Keyline's authority graph. The type attaches no meaning to which is which.
///
/// Stored as the 32-byte compressed key, not as [`VerifyingKey`] (which caches
/// the decompressed point and is roughly 200 bytes). Every constructor checks
/// that the bytes are the canonical encoding of a curve point outside the
/// small-order subgroup, so [`Identifier::verifying_key`] cannot fail and each
/// key has exactly one `Identifier`.
///
/// Formatting: [`Debug`](fmt::Debug) and [`LowerHex`](fmt::LowerHex) show the
/// whole key (`{:#x}` adds `0x`); [`Display`](fmt::Display) shows the first
/// four bytes, for logs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Identifier([u8; Self::LEN]);

impl Identifier {
    /// Length of the compressed verifying key, in bytes.
    pub const LEN: usize = 32;

    /// Construct from raw bytes.
    ///
    /// Rejects bytes that do not decompress, a non-canonical encoding of a
    /// point (the y-coordinate not reduced mod p), and the eight small-order
    /// points, any of which would give one key two `Identifier`s or a key that
    /// verifies forged signatures.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Result<Self, InvalidIdentifier> {
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| InvalidIdentifier::NotAPoint)?;
        if key.to_edwards().compress().to_bytes() != bytes {
            Err(InvalidIdentifier::NonCanonical)
        } else if key.is_weak() {
            Err(InvalidIdentifier::SmallOrder)
        } else {
            Ok(Identifier(bytes))
        }
    }

    /// Decompress to a [`VerifyingKey`] for signature verification.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.0).expect("Identifier bytes were validated at construction")
    }

    /// The compressed verifying key.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// The compressed verifying key, by value.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        self.0
    }

    /// [`Identifier::decode`] for a named field of a larger encoding, so that
    /// an invalid key reports which field it was.
    pub fn decode_field(bytes: &[u8], field: &'static str) -> Result<Self, DecodeError> {
        Identifier::decode(bytes).map_err(|e| match e {
            DecodeError::InvalidField(_) => DecodeError::InvalidField(field),
            other => other,
        })
    }
}

/// A signing key's verifying key is always canonical and of prime order.
impl From<&SigningKey> for Identifier {
    fn from(key: &SigningKey) -> Self {
        Identifier(key.verifying_key().to_bytes())
    }
}

impl TryFrom<VerifyingKey> for Identifier {
    type Error = InvalidIdentifier;

    fn try_from(key: VerifyingKey) -> Result<Self, InvalidIdentifier> {
        Identifier::from_bytes(key.to_bytes())
    }
}

impl From<Identifier> for VerifyingKey {
    fn from(id: Identifier) -> Self {
        id.verifying_key()
    }
}

impl Verifiable for Identifier {
    fn verifying_key(&self) -> VerifyingKey {
        Identifier::verifying_key(self)
    }
}

/// The full key, so that two `Identifier`s sharing a prefix differ in test
/// output.
impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Identifier(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "…")
    }
}

/// The whole key in hex; `{:#x}` prefixes `0x`.
impl fmt::LowerHex for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::hex::bytes_as_hex(self.0.iter(), f)
    }
}

impl Encode for Identifier {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Decode for Identifier {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

/// Fixed-width, so prefix-free.
impl StreamDecode for Identifier {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (raw, rest) = <[u8; Identifier::LEN]>::decode_next(bytes)?;
        Identifier::from_bytes(raw)
            .map(|id| (id, rest))
            .map_err(|_| DecodeError::InvalidField("id"))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Identifier {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed: [u8; 32] = u.arbitrary()?;
        Ok(Identifier::from(&ed25519_dalek::SigningKey::from(seed)))
    }
}

/// Why bytes are not an [`Identifier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidIdentifier {
    /// The bytes do not decompress to a curve point.
    #[error("bytes are not an Ed25519 curve point")]
    NotAPoint,

    /// The bytes decompress, but are not the point's canonical encoding.
    #[error("bytes are a non-canonical encoding of a curve point")]
    NonCanonical,

    /// The point is in the small-order subgroup.
    #[error("curve point has small order")]
    SmallOrder,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::String};

    #[test]
    fn lower_hex_is_the_whole_key() {
        let id = Identifier::from(&SigningKey::from_bytes(&[7; 32]));
        let hex: String = id.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(format!("{id:x}"), hex);
        assert_eq!(format!("{id:#x}"), format!("0x{hex}"));
    }

    #[test]
    fn rejects_non_curve_points() {
        // 0x02 repeated is not a decompressable Edwards y-coordinate.
        assert_eq!(
            Identifier::from_bytes([0x02; 32]),
            Err(InvalidIdentifier::NotAPoint)
        );
        assert_eq!(
            Identifier::decode(&[0x02; 32]),
            Err(DecodeError::InvalidField("id"))
        );
    }

    #[test]
    fn rejects_small_order_points() {
        use curve25519_dalek::constants::EIGHT_TORSION;
        for point in EIGHT_TORSION {
            assert_eq!(
                Identifier::from_bytes(point.compress().to_bytes()),
                Err(InvalidIdentifier::SmallOrder)
            );
        }
    }

    /// `y + p` for small `y` still fits in 255 bits and decompresses to the
    /// same point as `y`. Each such encoding must be rejected, not given an
    /// `Identifier` of its own.
    #[test]
    fn rejects_non_canonical_encodings() {
        // p = 2^255 - 19, little-endian.
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;

        let rejected = (0u8..19)
            .filter_map(|y| {
                let mut bytes = p;
                bytes[0] = p[0] + y;
                VerifyingKey::from_bytes(&bytes).ok().map(|_| bytes)
            })
            .inspect(|bytes| {
                assert_eq!(
                    Identifier::from_bytes(*bytes),
                    Err(InvalidIdentifier::NonCanonical)
                )
            })
            .count();
        assert!(rejected > 0, "some y + p decompresses");
    }

    fn sample() -> Identifier {
        Identifier::from(&ed25519_dalek::SigningKey::from([7u8; 32]))
    }

    #[test]
    fn conversions_agree() {
        let id = sample();
        let key = id.verifying_key();
        assert_eq!(&id.to_bytes(), id.as_bytes());
        assert_eq!(id.to_bytes(), key.to_bytes());
        assert_eq!(VerifyingKey::from(id), key);
        assert_eq!(Identifier::try_from(key), Ok(id));
        assert_eq!(Verifiable::verifying_key(&id), key);
    }

    #[test]
    fn decode_rejects_wrong_lengths_distinctly() {
        let bytes = sample().to_bytes();
        assert_eq!(
            Identifier::decode(&bytes[..31]),
            Err(DecodeError::UnexpectedEnd)
        );
        assert_eq!(Identifier::decode(&[]), Err(DecodeError::UnexpectedEnd));
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(Identifier::decode(&longer), Err(DecodeError::TrailingBytes));
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn codec_laws() {
        keyhive_codec::laws::round_trip::<Identifier>();
        keyhive_codec::laws::canonical_near::<Identifier>();
        keyhive_codec::laws::stream::<Identifier>();
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn round_trips_through_verifying_key() {
        bolero::check!()
            .with_arbitrary::<Identifier>()
            .for_each(|id| {
                assert_eq!(Identifier::try_from(id.verifying_key()), Ok(*id));
                assert_eq!(Identifier::decode(id.as_bytes()), Ok(*id));
            });
    }
}
