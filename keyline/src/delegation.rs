//! Delegations: signed edges granting an power level over a subject.

use crate::{id::Id, power::Power, revocation::RevocationId};
use alloc::vec::Vec;
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::{digest::Digest, verifiable::Verifiable};

/// An edge in the authority graph.
///
/// Reads: _`issuer` asserts that `audience` may exercise `power` over `subject`_. The edge
/// rides `issuer`'s own standing over `subject`: `audience` receives
/// `min(can, issuer's effective level over subject)`, and the edge is live only while
/// `issuer` reaches `subject`.
///
/// Anyone may issue a delegation over any subject. Admin is not required to
/// grant; it matters for revocation reach.
///
/// # `cites`
///
/// Ed25519 is deterministic and certificates are content-addressed, so
/// re-issuing an identical delegation produces the identical certificate: same
/// bytes, same signature, same hash. `cites` exists so that a grant identical to
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
    /// Signer. The edge rides this key's standing over `subject`.
    pub issuer: Id,

    /// Recipient.
    pub audience: Id,

    /// Scope: which subject's routes this edge may participate in. A role key
    /// here is membership in that role. `issuer == subject` is a root edge: the subject
    /// grounding its own authority, which the evaluator treats like any other
    /// edge because every subject stands at `Admin` over itself by axiom.
    pub subject: Id,

    /// Requested level; clamped by the issuer's own level, never raised.
    pub power: Power,

    /// The revocation this delegation is re-issued past. Ignored by evaluation.
    pub cites: Option<Digest<RevocationId>>,
}

impl Delegation {
    /// A first issuance: `issuer` grants `audience` `power` over `subject`, with no `cites`.
    pub fn new(issuer: Id, audience: Id, subject: Id, power: Power) -> Self {
        Delegation {
            issuer,
            audience,
            subject,
            power,
            cites: None,
        }
    }

    /// Re-issue this delegation past a revocation, giving it a fresh hash.
    pub fn reissue(self, cites: Digest<RevocationId>) -> Self {
        Delegation {
            cites: Some(cites),
            ..self
        }
    }

    /// Content address of the payload: what a [`crate::revocation::Revocation`] names.
    ///
    /// This is the digest of the delegation's own encoding, not of the
    /// [`crate::certificate::Certificate`] wrapper (which carries a kind tag).
    pub fn digest(&self) -> Digest<Delegation> {
        Digest::of(&self.encode())
    }
}

impl Verifiable for Delegation {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.issuer.verifying_key()
    }
}

// Fixed-width layout: issuer ‖ audience ‖ subject ‖ power ‖ cites_tag ‖ cites?
// Placeholder until the bespoke codec lands; see design/keyline/implementation.md.

/// Encoded length without `cites`.
const BASE_LEN: usize = Id::LEN * 3 + 1 + 1;

/// Encoded length with `cites`.
const SEEN_LEN: usize = BASE_LEN + 32;

const SEEN_ABSENT: u8 = 0;
const SEEN_PRESENT: u8 = 1;

impl Encode for Delegation {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.issuer.encode_into(out);
        self.audience.encode_into(out);
        self.subject.encode_into(out);
        self.power.encode_into(out);
        match &self.cites {
            None => out.push(SEEN_ABSENT),
            Some(cites) => {
                out.push(SEEN_PRESENT);
                out.extend_from_slice(cites.as_slice());
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
        let issuer = Id::decode(&ids[..Id::LEN])?;
        let audience = Id::decode(&ids[Id::LEN..Id::LEN * 2])?;
        let subject = Id::decode(&ids[Id::LEN * 2..])?;
        let power = Power::try_from(rest[0]).map_err(|_| DecodeError::InvalidTag(rest[0]))?;

        let cites = match rest[1] {
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
                let Ok(raw) = <[u8; 32]>::try_from(&rest[2..]) else {
                    return Err(DecodeError::UnexpectedEnd);
                };
                Some(Digest::from(raw))
            }
            other => return Err(DecodeError::InvalidTag(other)),
        };

        Ok(Delegation {
            issuer,
            audience,
            subject,
            power,
            cites,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Delegation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let cites: Option<[u8; 32]> = u.arbitrary()?;
        Ok(Delegation {
            issuer: u.arbitrary()?,
            audience: u.arbitrary()?,
            subject: u.arbitrary()?,
            power: u.arbitrary()?,
            cites: cites.map(Digest::from),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::id;

    #[test]
    fn seen_changes_hash_and_nothing_else() {
        let d = Delegation::new(id(1), id(2), id(3), Power::Edit);
        let r = d.reissue(Digest::from([9u8; 32]));
        assert_eq!(
            (r.issuer, r.audience, r.subject, r.power),
            (d.issuer, d.audience, d.subject, d.power)
        );
        assert_ne!(Digest::of(&d.encode()), Digest::of(&r.encode()));
    }

    #[test]
    fn encoded_lengths() {
        let d = Delegation::new(id(1), id(2), id(3), Power::Read);
        assert_eq!(d.encode().len(), BASE_LEN);
        assert_eq!(d.reissue(Digest::from([0u8; 32])).encode().len(), SEEN_LEN);
    }

    #[test]
    fn rejects_non_canonical() {
        let d = Delegation::new(id(1), id(2), id(3), Power::Read);
        let mut bytes = d.encode().into_bytes();

        // trailing byte after an absent `cites`
        bytes.push(0);
        assert_eq!(Delegation::decode(&bytes), Err(DecodeError::TrailingBytes));
        bytes.pop();

        // bad cites tag
        let last = bytes.len() - 1;
        bytes[last] = 2;
        assert_eq!(Delegation::decode(&bytes), Err(DecodeError::InvalidTag(2)));

        // bad power tag
        bytes[last] = 0;
        bytes[last - 1] = 7;
        assert_eq!(Delegation::decode(&bytes), Err(DecodeError::InvalidTag(7)));

        // present tag with too few bytes (restore a valid `power` first)
        bytes[last - 1] = Power::Read as u8;
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
