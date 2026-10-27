//! What Keyhive signs and content-addresses: every frame starts with the `KH`
//! tag, a kind from one registry and a version, so a signature or digest of
//! one type never stands for another, or for anything else the same key
//! signs.

use crate::identifier::Identifier;
use alloc::vec::Vec;
use keyhive_codec::traits::{Decode, Encode};

/// The first two bytes of every Keyhive frame, and of what every signature and
/// digest covers, so that a Keyhive signature verifies for nothing else the
/// same key signs. A frame stored on its own is recognizable by it.
pub const TAG: [u8; 2] = *b"KH";

/// A signed type's permanent number in the one registry of kinds.
///
/// One key signs Keyline certificates, CGKA operations, prekey operations and
/// an application's own bytes, so their kinds come from one table across the
/// workspace. A retired number is never reused. Kinds are numbered with ASCII
/// letters by convention, so a frame reads `KHD…` in a hexdump; any byte may
/// be used once the letters run out. `I` is reserved: an archive starts with
/// `KHIV`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Kind(u8);

impl Kind {
    /// A Keyline delegation.
    pub const DELEGATION: Kind = Kind(b'D');

    /// A Keyline revocation.
    pub const REVOCATION: Kind = Kind(b'R');

    /// A digest of a Keyline certificate set: hashed, never signed or sent.
    pub const CERTIFICATE_SET: Kind = Kind(b'S');

    /// A prekey an individual adds to the set it publishes.
    pub const ADD_KEY: Kind = Kind(b'P');

    /// A prekey an individual retires and replaces (`T` for "turn over":
    /// `R` is taken).
    pub const ROTATE_KEY: Kind = Kind(b'T');

    /// Bytes an application signs, which Keyhive gives no meaning.
    pub const BYTES: Kind = Kind(b'B');

    /// Every kind in the registry.
    pub const ALL: [Kind; 6] = [
        Kind::DELEGATION,
        Kind::REVOCATION,
        Kind::CERTIFICATE_SET,
        Kind::ADD_KEY,
        Kind::ROTATE_KEY,
        Kind::BYTES,
    ];

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
/// A signed statement travels as a frame,
/// `"KH" ‖ kind ‖ version ‖ issuer ‖ payload_len ‖ payload ‖ signature`, and its
/// signature and digest cover [`message`]: the frame without its signature.
/// So everything stored but the signature is signed, and a tampered kind,
/// version, issuer or length fails verification.
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

/// The start of a statement's frame, before its payload:
/// `"KH" ‖ kind ‖ version ‖ issuer ‖ payload_len`, the length a bijou64 varint.
pub fn head<T: Kinded>(issuer: &Identifier, payload_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAG.len() + 2 + Identifier::LEN + 9);
    out.extend_from_slice(&TAG);
    out.push(T::KIND.to_u8());
    out.push(T::VERSION);
    issuer.encode_into(&mut out);
    (payload_len as u64).encode_into(&mut out);
    out
}

/// The bytes a statement's signature covers: its [`head`] followed by its
/// payload. That is the whole frame except the signature.
///
/// The statement's [`Digest`](crate::digest::Digest) hashes the same bytes,
/// so it identifies the statement rather than one signature over it.
///
/// This is a free function rather than a trait method, so that no
/// implementation can override it and make a signature cover different bytes
/// than the digest.
pub fn message<T: Kinded>(issuer: &Identifier, payload: &[u8]) -> Vec<u8> {
    let mut out = head::<T>(issuer, payload.len());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    #[test]
    fn every_kind_is_found_by_its_byte() {
        for kind in Kind::ALL {
            assert_eq!(Kind::from_u8(kind.to_u8()), Some(kind));
        }
        assert_eq!(
            Kind::from_u8(b'I'),
            None,
            "reserved: an archive starts with KHIV"
        );
    }

    #[test]
    fn kinds_are_distinct() {
        let distinct: BTreeSet<u8> = Kind::ALL.iter().map(|k| k.to_u8()).collect();
        assert_eq!(distinct.len(), Kind::ALL.len());
        assert!(
            !distinct.contains(&b'I'),
            "`I` is reserved for the archive's `KHIV`"
        );
    }
}
