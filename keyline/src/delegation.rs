//! Delegations: signed edges granting a power level over a subject.

use crate::{id::Id, power::Power, revocation::RevocationId};
use alloc::vec::Vec;
use core::cmp::Ordering;
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::{digest::Digest, domain_separator::Domain, verifiable::Verifiable};

/// An edge in the authority graph.
///
/// Reads: _`issuer` asserts that `audience` may exercise `power` over `subject`_. The edge
/// rides `issuer`'s own standing over `subject`: `audience` receives
/// `min(power, issuer's effective power over subject)`, and the edge is live only while
/// `issuer` reaches `subject`.
///
/// Anyone may issue a delegation over any subject. Issuing needs no Admin;
/// Admin matters for revocation reach.
///
/// # `citation`
///
/// Certificates are content-addressed, so re-issuing an identical delegation
/// produces the same digest: the same certificate. `citation` lets a
/// delegation identical to a revoked one be re-issued with a fresh digest. It
/// names the revocation the issuer is re-issuing past, and evaluation ignores
/// it. Absent means first issuance. When several revocations name the same
/// delegation, any of them serves. For why it names a revocation, and why not
/// a random nonce, see `design/keyline/alternatives.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Delegation {
    /// Signer. The edge rides this key's standing over `subject`.
    pub issuer: Id,

    /// The key the delegation is issued to.
    pub audience: Id,

    /// Scope: which subject's routes this edge may participate in. A role key
    /// here is membership in that role. `issuer == subject` is a root edge: the subject
    /// grounding its own authority, which the evaluator treats like any other
    /// edge because every subject stands at `Admin` over itself by axiom.
    pub subject: Id,

    /// Requested level; clamped by the issuer's own level, never raised.
    pub power: Power,

    /// The revocation this delegation is re-issued past. Ignored by evaluation.
    pub citation: Option<Digest<RevocationId>>,
}

impl Delegation {
    /// A first issuance: `issuer` grants `audience` `power` over `subject`, with no `citation`.
    pub fn new(issuer: Id, audience: Id, subject: Id, power: Power) -> Self {
        Delegation {
            issuer,
            audience,
            subject,
            power,
            citation: None,
        }
    }

    /// Re-issue this delegation past a revocation, giving it a fresh hash.
    pub fn reissue(self, citation: Digest<RevocationId>) -> Self {
        Delegation {
            citation: Some(citation),
            ..self
        }
    }

    /// The delegation's identity: what a [`crate::revocation::Revocation`]
    /// names, and its key in the set ([`crate::certificate::CertificateId`]).
    pub fn digest(&self) -> Digest<Delegation> {
        Digest::of(&self.encode())
    }
}

impl Domain for Delegation {
    const CONTEXT: &'static str = "keyline/v0/delegation";
}

impl Verifiable for Delegation {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.issuer.verifying_key()
    }
}

// Fixed-width layout: issuer ‖ audience ‖ subject ‖ power ‖ citation_tag ‖ citation?
// Placeholder until the bespoke codec lands; see design/keyline/implementation.md.

/// Encoded length without `citation`.
const BASE_LEN: usize = Id::LEN * 3 + 1 + 1;

/// Encoded length with `citation`.
const CITATION_LEN: usize = BASE_LEN + Digest::<RevocationId>::LEN;

const CITATION_ABSENT: u8 = 0;
const CITATION_PRESENT: u8 = 1;

impl Encode for Delegation {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.issuer.encode_into(out);
        self.audience.encode_into(out);
        self.subject.encode_into(out);
        self.power.encode_into(out);
        match &self.citation {
            None => out.push(CITATION_ABSENT),
            Some(citation) => {
                out.push(CITATION_PRESENT);
                out.extend_from_slice(citation.as_slice());
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
        let issuer = Id::decode_field(&ids[..Id::LEN], "issuer")?;
        let audience = Id::decode_field(&ids[Id::LEN..Id::LEN * 2], "audience")?;
        let subject = Id::decode_field(&ids[Id::LEN * 2..], "subject")?;
        let power = Power::decode(&rest[..1])?;

        let citation = match rest[1] {
            CITATION_ABSENT => {
                if bytes.len() != BASE_LEN {
                    return Err(DecodeError::TrailingBytes);
                }
                None
            }
            CITATION_PRESENT => match bytes.len().cmp(&CITATION_LEN) {
                Ordering::Less => return Err(DecodeError::UnexpectedEnd),
                Ordering::Greater => return Err(DecodeError::TrailingBytes),
                Ordering::Equal => {
                    let raw: [u8; Digest::<RevocationId>::LEN] = rest[2..]
                        .try_into()
                        .expect("exactly CITATION_LEN bytes leaves a digest after the tags");
                    Some(Digest::from(raw))
                }
            },
            other => return Err(DecodeError::InvalidTag(other)),
        };

        Ok(Delegation {
            issuer,
            audience,
            subject,
            power,
            citation,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Delegation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let citation: Option<[u8; Digest::<RevocationId>::LEN]> = u.arbitrary()?;
        Ok(Delegation {
            issuer: u.arbitrary()?,
            audience: u.arbitrary()?,
            subject: u.arbitrary()?,
            power: u.arbitrary()?,
            citation: citation.map(Digest::from),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::id;

    #[test]
    fn citation_changes_hash_and_nothing_else() {
        let d = Delegation::new(id(1), id(2), id(3), Power::Edit);
        let r = d.reissue(Digest::from([9u8; 32]));
        assert_eq!(
            (r.issuer, r.audience, r.subject, r.power),
            (d.issuer, d.audience, d.subject, d.power)
        );
        assert_ne!(d.digest(), r.digest());
    }

    #[test]
    fn encoded_lengths() {
        let d = Delegation::new(id(1), id(2), id(3), Power::Read);
        assert_eq!(d.encode().len(), BASE_LEN);
        assert_eq!(
            d.reissue(Digest::from([0u8; 32])).encode().len(),
            CITATION_LEN
        );
    }

    #[test]
    fn rejects_non_canonical() {
        let d = Delegation::new(id(1), id(2), id(3), Power::Read);
        let mut bytes = d.encode().into_bytes();

        // trailing byte after an absent `citation`
        bytes.push(0);
        assert_eq!(Delegation::decode(&bytes), Err(DecodeError::TrailingBytes));
        bytes.pop();

        // bad citation tag
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

        // present tag with one byte too many
        let mut long = d.reissue(Digest::from([5u8; 32])).encode().into_bytes();
        long.push(0);
        assert_eq!(Delegation::decode(&long), Err(DecodeError::TrailingBytes));

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
            });
    }

    /// Pins the wire encoding and the domain-separated digest of one fixed
    /// delegation. Changing the codec or the context must change this test
    /// on purpose.
    #[test]
    fn known_answer() {
        let hex = |bytes: &[u8]| -> alloc::string::String {
            bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
        };
        let d = Delegation::new(id(1), id(2), id(3), Power::Edit);
        assert_eq!(
            hex(d.encode().as_bytes()),
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c\
             8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394\
             ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1\
             4500"
        );
        assert_eq!(
            hex(d.digest().as_slice()),
            "e90472356fc5650ce40a68ab372fe1f8236c2b58b1239fdb013b2c71b3747451"
        );
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn decode_is_canonical() {
        crate::test_utils::decode_is_canonical_near::<Delegation>();
    }
}
