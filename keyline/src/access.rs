//! Access levels.

use alloc::vec::Vec;
use core::fmt;
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
// TODO(keyhive_types): `keyhive_core::Access` is the same type; unify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum Access {
    /// Sync and forward ciphertext; cannot decrypt.
    Relay = 0,
    /// Decrypt content.
    Read = 1,
    /// Write content.
    Edit = 2,
    /// Manage membership; act as the subject for revocation.
    Admin = 3,
}

impl Access {
    /// Every level, ascending. `Relay < Read < Edit < Admin`.
    pub const ALL: [Access; 4] = [Access::Relay, Access::Read, Access::Edit, Access::Admin];

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

impl TryFrom<u8> for Access {
    type Error = InvalidAccess;

    fn try_from(byte: u8) -> Result<Self, InvalidAccess> {
        match byte {
            0 => Ok(Access::Relay),
            1 => Ok(Access::Read),
            2 => Ok(Access::Edit),
            3 => Ok(Access::Admin),
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
    }

    #[test]
    fn codec_round_trip_and_canonical() {
        for a in Access::ALL {
            let e = a.encode();
            assert_eq!(e.as_bytes().len(), 1);
            assert_eq!(e.decode().unwrap(), a);
        }
        assert_eq!(Access::decode(&[4]), Err(DecodeError::InvalidTag(4)));
        assert_eq!(Access::decode(&[0, 0]), Err(DecodeError::TrailingBytes));
        assert_eq!(Access::decode(&[]), Err(DecodeError::UnexpectedEnd));
    }
}
