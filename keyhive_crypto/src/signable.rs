//! What Keyhive signs and content-addresses: one prefix, and a version and
//! kind from one registry, so a signature or digest of one type never stands
//! for another, or for anything else the same key signs.

use alloc::vec::Vec;
use keyhive_codec::traits::{Decode, Encode};

/// What every Keyhive signature and content address starts with, so that a
/// Keyhive signature verifies for nothing else the same key signs.
pub const PREFIX: &[u8] = b"keyhive\0";

/// A signed type's permanent number in the one registry of kinds.
///
/// One key signs Keyline certificates, key agreement operations and prekey
/// operations, so their kinds come from one table across the workspace. A
/// retired number is never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Kind(u8);

impl Kind {
    /// A Keyline delegation.
    pub const DELEGATION: Kind = Kind(0x01);

    /// A Keyline revocation.
    pub const REVOCATION: Kind = Kind(0x02);

    /// A digest of a Keyline certificate set: hashed, never signed or sent.
    pub const CERTIFICATE_SET: Kind = Kind(0x03);

    /// Every kind in the registry.
    pub const ALL: [Kind; 3] = [Kind::DELEGATION, Kind::REVOCATION, Kind::CERTIFICATE_SET];

    /// The registered kind with byte `b`, if any.
    pub fn from_u8(b: u8) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.0 == b)
    }

    /// The kind's byte, as it appears in a frame.
    pub const fn to_u8(self) -> u8 {
        self.0
    }
}

/// A type with a place in the registry: what its signatures and digests are
/// separated by. Its kind is permanent; its version changes with its encoding.
///
/// A signed value travels as `version ‖ kind ‖ signature ‖ payload`, and the
/// signature and digest cover [`message`]: the [`PREFIX`], then the same
/// version and kind, then the payload. So everything stored but the signature
/// is signed, and a tampered version or kind fails verification.
///
/// A type that is only hashed, never signed, implements `Kinded` without a
/// codec, and so is not [`Signable`].
pub trait Kinded {
    /// The type's number in the registry.
    const KIND: Kind;

    /// The version of the type's encoding.
    const VERSION: u8;
}

/// A [`Kinded`] type with a canonical codec: what can be signed and verified.
///
/// Implemented for every such type; implement [`Kinded`] instead.
pub trait Signable: Kinded + Encode + Decode {}

impl<T: Kinded + Encode + Decode> Signable for T {}

/// What a signature over an encoding of `T` covers, and what its digest
/// hashes: [`PREFIX`] ‖ version ‖ kind ‖ `payload`.
///
/// A free function rather than a trait method, so that no implementation can
/// override it and make a signature and a digest cover different bytes.
pub fn message<T: Kinded>(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREFIX.len() + 2 + payload.len());
    out.extend_from_slice(PREFIX);
    out.push(T::VERSION);
    out.push(T::KIND.to_u8());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    #[test]
    fn kinds_are_distinct() {
        let distinct: BTreeSet<u8> = Kind::ALL.iter().map(|k| k.to_u8()).collect();
        assert_eq!(distinct.len(), Kind::ALL.len());
    }
}
