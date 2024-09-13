use crate::access::Access;
use crate::capability::Capability;
use crate::hash::{CAStore, Hash};
use crate::principal::{
    agent::Agent, document::Document, stateful::Stateful, stateless::Stateless,
};
use topological_sort::DependencyLink;

use super::Operation;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash)]
pub struct Delegation {
    pub from: Stateless,
    pub to: Agent,
    pub subject: Stateful, // FIXME or doc
    pub can: Access,

    pub proof: Vec<Hash<Operation>>,
    pub after_auth: Vec<Hash<Operation>>,
    // pub after_content: Vec<(Document, Hash<ContentOp>)>, // FIXME
}
