// FIXME move opetaion to same level
use super::Operation;
use crate::access::Access;
use crate::crypto::hash::Hash;
use crate::crypto::signed::Signed;
use crate::principal::agent::Agent;
use crate::principal::{identifier::Identifier, membered::MemberedId};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Delegation {
    pub subject: MemberedId, // FIXME ref?
    pub can: Access,

    pub from: Identifier,
    pub proof: Vec<Hash<Operation>>,

    pub to: Agent, // FIXME an ID, not statelsss.. make &Agent? AgentId?

    pub after_auth: Vec<Hash<Signed<Operation>>>,
    // pub after_content: Vec<(Document, Hash<ContentOp>)>, // FIXME
}

impl From<Delegation> for Vec<u8> {
    fn from(_delegation: Delegation) -> Vec<u8> {
        todo!()
    }
}
