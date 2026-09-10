//! Delegations: signed edges granting an access level over a subject.

use crate::{access::Access, id::Id, revocation::Revocation};
use alloc::vec::Vec;
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::{digest::Digest, verifiable::Verifiable};

/// An edge in the authority graph.
///
/// Reads: _`iss` asserts that `aud` may exercise `can` over `sub`_. The edge
/// rides `iss`'s own standing over `sub`: `aud` receives
/// `min(can, iss's effective level over sub)`, and the edge is live only while
/// `iss` reaches `sub`.
///
/// Anyone may issue a delegation over any subject. Admin is not required to
/// grant; it matters for revocation reach.
///
/// # `seen`
///
/// Ed25519 is deterministic and certificates are content-addressed, so
/// re-issuing an identical delegation produces the identical certificate: same
/// bytes, same signature, same hash. `seen` exists so that a grant identical to
/// a revoked one can be re-issued with a fresh hash. It names the revocation the
/// issuer has seen and is re-issuing past, documents the heal, and has no other
/// semantics: evaluation ignores it entirely. Absent means first issuance.
///
/// It names the revocation rather than the revoked delegation because the
/// latter's digest is a function of the fields being re-issued (so it adds no
/// information and a second heal would collide), and because a revocation is
/// the only event that ever poisons a hash. When several revocations name the
/// same delegation, any of them serves.
///
/// A random nonce was rejected in its place because it would flip the fail
/// direction: accidental duplicate issuance would yield independently live
/// certificates that a single revocation cannot cover. See
/// `design/keyline/alternatives.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Delegation {
    /// Signer. The edge rides this key's standing over `sub`.
    pub iss: Id,

    /// Recipient.
    pub aud: Id,

    /// Scope: which subject's routes this edge may participate in. A role key
    /// here is membership in that role. `iss == sub` is a root edge: the subject
    /// grounding its own authority, which the evaluator treats like any other
    /// edge because every subject stands at `Admin` over itself by axiom.
    pub sub: Id,

    /// Requested level; clamped by the issuer's own level, never raised.
    pub can: Access,

    /// The revocation this delegation is re-issued past. Ignored by evaluation.
    pub seen: Option<Digest<Revocation>>,
}

impl Delegation {
    pub fn new(iss: Id, aud: Id, sub: Id, can: Access) -> Self {
        Delegation {
            iss,
            aud,
            sub,
            can,
            seen: None,
        }
    }

    /// Re-issue this delegation past a revocation, giving it a fresh hash.
    pub fn reissue(self, seen: Digest<Revocation>) -> Self {
        Delegation {
            seen: Some(seen),
            ..self
        }
    }

    /// Content address of the payload: what a [`Revocation`] names.
    ///
    /// This is the digest of the delegation's own encoding, not of the
    /// [`crate::certificate::Certificate`] wrapper (which carries a kind tag).
    pub fn digest(&self) -> Digest<Delegation> {
        Digest::of(&self.encode())
    }
}

impl Verifiable for Delegation {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.iss.verifying_key()
    }
}

// Fixed-width layout: iss ‖ aud ‖ sub ‖ can ‖ seen_tag ‖ seen?
// Placeholder until the bespoke codec lands; see design/keyline/implementation.md.

/// Encoded length without `seen`.
const BASE_LEN: usize = Id::LEN * 3 + 1 + 1;

/// Encoded length with `seen`.
const SEEN_LEN: usize = BASE_LEN + 32;

const SEEN_ABSENT: u8 = 0;
const SEEN_PRESENT: u8 = 1;

impl Encode for Delegation {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.iss.encode_into(out);
        self.aud.encode_into(out);
        self.sub.encode_into(out);
        self.can.encode_into(out);
        match &self.seen {
            None => out.push(SEEN_ABSENT),
            Some(seen) => {
                out.push(SEEN_PRESENT);
                out.extend_from_slice(seen.as_slice());
            }
        }
    }
}

impl Decode for Delegation {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < BASE_LEN {
            return Err(DecodeError::UnexpectedEnd);
        }

        let (ids, rest) = bytes.split_at(Id::LEN * 3);
        let iss = Id::decode(&ids[..Id::LEN])?;
        let aud = Id::decode(&ids[Id::LEN..Id::LEN * 2])?;
        let sub = Id::decode(&ids[Id::LEN * 2..])?;
        let can = Access::try_from(rest[0])?;

        let seen = match rest[1] {
            SEEN_ABSENT => {
                if bytes.len() != BASE_LEN {
                    return Err(DecodeError::TrailingBytes);
                }
                None
            }
            SEEN_PRESENT => {
                if bytes.len() < SEEN_LEN {
                    return Err(DecodeError::UnexpectedEnd);
                }
                if bytes.len() > SEEN_LEN {
                    return Err(DecodeError::TrailingBytes);
                }
                let raw: [u8; 32] = rest[2..]
                    .try_into()
                    .expect("length checked to be exactly SEEN_LEN");
                Some(Digest::from(raw))
            }
            other => return Err(DecodeError::InvalidTag(other)),
        };

        Ok(Delegation {
            iss,
            aud,
            sub,
            can,
            seen,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Delegation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seen: Option<[u8; 32]> = u.arbitrary()?;
        Ok(Delegation {
            iss: u.arbitrary()?,
            aud: u.arbitrary()?,
            sub: u.arbitrary()?,
            can: u.arbitrary()?,
            seen: seen.map(Digest::from),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::id;

    #[test]
    fn seen_changes_hash_and_nothing_else() {
        let d = Delegation::new(id(1), id(2), id(3), Access::Edit);
        let r = d.reissue(Digest::from([9u8; 32]));
        assert_eq!((r.iss, r.aud, r.sub, r.can), (d.iss, d.aud, d.sub, d.can));
        assert_ne!(Digest::of(&d.encode()), Digest::of(&r.encode()));
    }

    #[test]
    fn encoded_lengths() {
        let d = Delegation::new(id(1), id(2), id(3), Access::Read);
        assert_eq!(d.encode().len(), BASE_LEN);
        assert_eq!(d.reissue(Digest::from([0u8; 32])).encode().len(), SEEN_LEN);
    }

    #[test]
    fn rejects_non_canonical() {
        let d = Delegation::new(id(1), id(2), id(3), Access::Read);
        let mut bytes = d.encode().into_bytes();

        // trailing byte after an absent `seen`
        bytes.push(0);
        assert_eq!(Delegation::decode(&bytes), Err(DecodeError::TrailingBytes));
        bytes.pop();

        // bad seen tag
        let last = bytes.len() - 1;
        bytes[last] = 2;
        assert_eq!(Delegation::decode(&bytes), Err(DecodeError::InvalidTag(2)));

        // bad access tag
        bytes[last] = 0;
        bytes[last - 1] = 7;
        assert_eq!(Delegation::decode(&bytes), Err(DecodeError::InvalidTag(7)));

        // present tag with too few bytes
        bytes[last - 1] = 0;
        bytes[last] = 1;
        assert_eq!(Delegation::decode(&bytes), Err(DecodeError::UnexpectedEnd));

        // truncated
        assert_eq!(
            Delegation::decode(&bytes[..10]),
            Err(DecodeError::UnexpectedEnd)
        );
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn codec_laws() {
        bolero::check!()
            .with_arbitrary::<Delegation>()
            .for_each(|d| {
                let encoded = d.encode();
                let decoded = Delegation::decode(encoded.as_bytes()).expect("round trip");
                assert_eq!(&decoded, d);
                assert_eq!(decoded.encode(), encoded);
            });
    }

    #[test]
    fn decode_is_canonical() {
        // Any byte string that decodes must re-encode to itself.
        bolero::check!().with_type::<Vec<u8>>().for_each(|bytes| {
            if let Ok(d) = Delegation::decode(bytes) {
                assert_eq!(d.encode().as_bytes(), bytes.as_slice());
            }
        });
    }
}
