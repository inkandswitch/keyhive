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

    pub from: Identifier,
    pub proof: Vec<Hash<Operation>>, // FIXME option<Hash<Operation>>?

    pub to: Agent, // FIXME an ID, not statelsss.. make &Agent? AgentId?

    pub after_auth: Vec<Hash<Signed<Operation>>>,
    // pub after_content: Vec<(Document, Hash<ContentOp>)>, // FIXME
}

impl fmt::Display for Delegation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Delegation: {} can {} from {} to {:?}", // FIXME :?
            self.subject, self.can, self.from, self.to
        )
    }
}

impl From<Delegation> for Vec<u8> {
    fn from(_delegation: Delegation) -> Vec<u8> {
        todo!()
    }
}
