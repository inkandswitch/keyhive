use super::Operation;
use crate::access::Access;
use crate::crypto::hash::Hash;
use crate::principal::{membered::MemberedId, stateless::Stateless};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Delegation {
    pub subject: MemberedId, // FIXME ref?
    pub can: Access,

    pub from: Stateless,
    pub proof: Vec<Hash<Operation>>,

    pub to: Stateless, // FIXME an ID, not statelsss.. make &Agent? AgentId?

    pub after_auth: Vec<Hash<Operation>>,
    // pub after_content: Vec<(Document, Hash<ContentOp>)>, // FIXME
}
