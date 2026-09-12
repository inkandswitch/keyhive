//! Access levels.

use alloc::vec::Vec;
use core::{cmp::Ordering, fmt};
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};

/// What an edge conveys. Totally ordered; each level implies the ones below.
///
/// `Relay`, `Read`, and `Edit` are conveyance levels: what may travel along a
/// route. `Admin` is the governance level: it places the subject in the
/// holder's admin reach, which is what gives third-party revocations their
/// reach. Attenuation along a route is `min`; combination across routes is `max`.
///
/// # Ordering and encoding are separate
///
/// The lattice is [`Access::rank`]; the wire tag is the discriminant, an ASCII
/// initial (`L`, `R`, `E`, `A`). Keeping them apart means a level added later
/// takes any free byte and sits wherever its rank puts it, with no renumbering
/// and so no rehashing of certificates already in a set. Nothing may derive the
/// order from the tag: `A` is the top of the lattice and the lowest byte of the
/// four.
// TODO(keyhive_types): `keyhive_core::Access` is the same type; unify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum Access {
    /// Sync and forward ciphertext; cannot decrypt.
    Relay = b'L',
    /// Decrypt content.
    Read = b'R',
    /// Write content.
    Edit = b'E',
    /// Manage membership; act as the subject for revocation.
    Admin = b'A',
}

impl Access {
    /// Every level, ascending. `Relay < Read < Edit < Admin`.
    pub const ALL: [Access; 4] = [Access::Relay, Access::Read, Access::Edit, Access::Admin];

    /// Position in the lattice, counting from `Relay`. The wire tag is
    /// deliberately not this; see the type's documentation.
    pub fn rank(self) -> usize {
        match self {
            Access::Relay => 0,
            Access::Read => 1,
            Access::Edit => 2,
            Access::Admin => 3,
        }
    }

    /// At least `Read`: may decrypt.
    pub fn is_reader(self) -> bool {
        self >= Access::Read
    }

    /// At least `Edit`: may write.
    pub fn is_editor(self) -> bool {
        self >= Access::Edit
    }

    /// Exactly `Admin`: may govern.
    pub fn is_admin(self) -> bool {
        self == Access::Admin
    }
}

impl Ord for Access {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Access {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl TryFrom<u8> for Access {
    type Error = InvalidAccess;

    fn try_from(byte: u8) -> Result<Self, InvalidAccess> {
        match byte {
            b'L' => Ok(Access::Relay),
            b'R' => Ok(Access::Read),
            b'E' => Ok(Access::Edit),
            b'A' => Ok(Access::Admin),
            other => Err(InvalidAccess(other)),
        }
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Access::Relay => "Relay",
            Access::Read => "Read",
            Access::Edit => "Edit",
            Access::Admin => "Admin",
        })
    }
}

impl Encode for Access {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(*self as u8);
    }
}

impl Decode for Access {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        match bytes {
            [] => Err(DecodeError::UnexpectedEnd),
            [b] => Access::try_from(*b).map_err(|InvalidAccess(t)| DecodeError::InvalidTag(t)),
            _ => Err(DecodeError::TrailingBytes),
        }
    }
}

/// The byte is not an access level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0} is not an access level")]
pub struct InvalidAccess(u8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering() {
        assert!(Access::Relay < Access::Read);
        assert!(Access::Read < Access::Edit);
        assert!(Access::Edit < Access::Admin);
        assert!(Access::ALL.is_sorted());
    }

    /// The lattice is [`Access::rank`], not the wire tag. `Admin` is the top of
    /// the order and the lowest of the four bytes, so anything that derived the
    /// order from the discriminant would fail here.
    #[test]
    fn order_is_independent_of_the_tag() {
        assert!(Access::Admin > Access::Relay);
        assert!((Access::Admin as u8) < (Access::Relay as u8));
        assert_eq!(Access::ALL.map(Access::rank), [0, 1, 2, 3]);
    }

    #[test]
    fn codec_round_trip_and_canonical() {
        for a in Access::ALL {
            let e = a.encode();
            assert_eq!(e.as_bytes().len(), 1, "tags are one byte");
            assert_eq!(e.decode().unwrap(), a);
        }
        assert_eq!(
            Access::ALL.map(|a| a as u8),
            [b'L', b'R', b'E', b'A'],
            "tags are the ASCII initials"
        );
        assert_eq!(Access::decode(&[0]), Err(DecodeError::InvalidTag(0)));
        assert_eq!(Access::decode(b"l"), Err(DecodeError::InvalidTag(b'l')));
        assert_eq!(Access::decode(b"EE"), Err(DecodeError::TrailingBytes));
        assert_eq!(Access::decode(&[]), Err(DecodeError::UnexpectedEnd));
    }
}
