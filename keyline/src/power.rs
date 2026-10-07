//! Power levels.

use alloc::vec::Vec;
use core::{cmp::Ordering, fmt};
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};

/// What an edge conveys. Totally ordered; each level implies the ones below.
///
/// `Relay`, `Read`, and `Edit` govern what may travel along a route. `Admin` is
/// the sole governance level: it places the subject in the holder's admin
/// reach, which is what gives third-party revocations their reach. Attenuation
/// along a route is `min`; combination across routes is `max`.
///
/// # Ordering and encoding are separate
///
/// The lattice is [`Power::rank`]; the wire tag is the discriminant, an ASCII
/// letter (`L` for reLay, `R`, `E`, `A`). Keeping them apart means a level added later
/// takes any free byte and sits wherever its rank puts it, with no renumbering
/// and so no rehashing of certificates already in a set. Nothing may derive the
/// order from the tag: `A` is the top of the lattice and the lowest byte of the
/// four.
// TODO(keyhive_types): `keyhive_core::Access` is the same type; unify at
// integration and settle which name survives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum Power {
    /// Sync and forward ciphertext; cannot decrypt.
    Relay = b'L',
    /// Decrypt content.
    Read = b'R',
    /// Write content.
    Edit = b'E',
    /// Manage membership; act as the subject for revocation.
    Admin = b'A',
}

impl Power {
    /// Every level, ascending. `Relay < Read < Edit < Admin`.
    pub const ALL: [Power; 4] = [Power::Relay, Power::Read, Power::Edit, Power::Admin];

    /// Position in the lattice, counting from `Relay`. The wire tag is
    /// deliberately not this; see the type's documentation.
    pub fn rank(self) -> usize {
        match self {
            Power::Relay => 0,
            Power::Read => 1,
            Power::Edit => 2,
            Power::Admin => 3,
        }
    }

    /// At least `Read`: may decrypt.
    pub fn is_reader(self) -> bool {
        self >= Power::Read
    }

    /// At least `Edit`: may write.
    pub fn is_editor(self) -> bool {
        self >= Power::Edit
    }

    /// Exactly `Admin`: may govern.
    pub fn is_admin(self) -> bool {
        self == Power::Admin
    }
}

impl Ord for Power {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Power {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl TryFrom<u8> for Power {
    type Error = InvalidPower;

    fn try_from(byte: u8) -> Result<Self, InvalidPower> {
        match byte {
            b'L' => Ok(Power::Relay),
            b'R' => Ok(Power::Read),
            b'E' => Ok(Power::Edit),
            b'A' => Ok(Power::Admin),
            other => Err(InvalidPower(other)),
        }
    }
}

impl fmt::Display for Power {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Power::Relay => "Relay",
            Power::Read => "Read",
            Power::Edit => "Edit",
            Power::Admin => "Admin",
        })
    }
}

impl Encode for Power {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(*self as u8);
    }
}

impl Decode for Power {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        match bytes {
            [] => Err(DecodeError::UnexpectedEnd),
            [b] => Power::try_from(*b).map_err(|InvalidPower(t)| DecodeError::InvalidTag(t)),
            _ => Err(DecodeError::TrailingBytes),
        }
    }
}

/// The byte is not a power level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0} is not a power level")]
pub struct InvalidPower(u8);

#[cfg(test)]
mod tests {
    use super::*;

    /// The lattice is [`Power::rank`], not the wire tag. `Admin` is the top of
    /// the order and the lowest of the four bytes, so anything that derived the
    /// order from the discriminant would fail here.
    #[test]
    fn order_is_the_rank_not_the_tag() {
        assert!(Power::ALL.is_sorted());
        assert_eq!(Power::ALL.map(Power::rank), [0, 1, 2, 3]);
        assert!(Power::Admin > Power::Relay);
        assert!((Power::Admin as u8) < (Power::Relay as u8));
    }

    /// What each level may do, as a truth table over the whole ladder.
    #[test]
    fn capability_predicates() {
        let table = Power::ALL.map(|p| (p.is_reader(), p.is_editor(), p.is_admin()));
        assert_eq!(
            table,
            [
                (false, false, false), // Relay
                (true, false, false),  // Read
                (true, true, false),   // Edit
                (true, true, true),    // Admin
            ]
        );
    }

    #[test]
    fn codec_round_trip_and_canonical() {
        for a in Power::ALL {
            let e = a.encode();
            assert_eq!(e.as_bytes().len(), 1, "tags are one byte");
            assert_eq!(e.decode(), Ok(a));
        }
        assert_eq!(
            Power::ALL.map(|a| a as u8),
            [b'L', b'R', b'E', b'A'],
            "tags are ASCII letters"
        );
        for byte in 0..=u8::MAX {
            match Power::ALL.iter().find(|p| **p as u8 == byte) {
                Some(p) => assert_eq!(Power::decode(&[byte]), Ok(*p)),
                None => assert_eq!(Power::decode(&[byte]), Err(DecodeError::InvalidTag(byte))),
            }
        }
        assert_eq!(Power::decode(b"EE"), Err(DecodeError::TrailingBytes));
        assert_eq!(Power::decode(&[]), Err(DecodeError::UnexpectedEnd));
    }
}
