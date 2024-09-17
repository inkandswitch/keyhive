use super::Operation;
use crate::access::Access;
use crate::crypto::hash::Hash;
use crate::principal::{individual::Individual, membered::MemberedId};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Delegation {
    pub subject: MemberedId, // FIXME ref?
    pub can: Access,

    pub from: Individual,
    pub proof: Vec<Hash<Operation>>,

    pub to: Individual, // FIXME an ID, not statelsss.. make &Agent? AgentId?

    pub after_auth: Vec<Hash<Operation>>,
    // pub after_content: Vec<(Document, Hash<ContentOp>)>, // FIXME
}
