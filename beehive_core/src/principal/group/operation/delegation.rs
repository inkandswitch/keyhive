use super::revocation::Revocation;
// FIXME move opetaion to same level
use super::Operation;
use crate::access::Access;
use crate::crypto::hash::Hash;
use crate::crypto::signed::Signed;
use crate::principal::agent::Agent;
use crate::principal::{identifier::Identifier, membered::MemberedId};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Delegation {
    pub subject: MemberedId, // FIXME ref?
    pub can: Access,
    pub delegator: Identifier,
    /// The operation that added the delegator/from.
    // FIXME: Invariant: these should only be Operation::Delegation
    pub delegator_proof: Option<Hash<Signed<Operation>>>,
    pub delegate: Agent, // FIXME an ID, not statelsss.. make &Agent? AgentId?

    /// Multiple branches could have revoked this agent. We need to prove
    /// we're after all of them.
    // FIXME: Invariant: these should only be Operation::Revocation
    pub after_revocations: Vec<Hash<Signed<Operation>>>,
    // pub after_content: Vec<(Document, Hash<ContentOp>)>, // FIXME
}

impl fmt::Display for Delegation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Delegation: {} can {} from {} to {:?}", // FIXME :?
            self.subject, self.can, self.delegator, self.delegate
        )
    }
}

impl From<Delegation> for Vec<u8> {
    fn from(delegation: Delegation) -> Vec<u8> {
        // FIXME autogenerated
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&delegation.subject.to_bytes());
        // FIXME! bytes.extend_from_slice(&delegation.can.to_bytes());
        bytes.extend_from_slice(&delegation.delegator.to_bytes());
        // FIXME!
        // bytes.extend_from_slice(&delegation.proof.iter().fold(Vec::new(), |mut acc, hash| {
        //     acc.extend_from_slice(&hash.to_bytes());
        //     acc
        // }));
        // FIXME bytes.extend_from_slice(&delegation.to.to_bytes());
        // FIXME
        // bytes.extend_from_slice(
        //     &delegation
        //         .after_auth
        //         .iter()
        //         .fold(Vec::new(), |mut acc, hash| {
        //             acc.extend_from_slice(&hash.to_bytes());
        //             acc
        //         }),
        // );
        bytes
    }
}
