use super::{
    active::Active,
    document::{Document, DocumentId},
    group::{id::GroupId, Group},
    identifier::Identifier,
    individual::Individual,
    verifiable::Verifiable,
};
use crate::content::reference::ContentRef;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum Agent<'a, T: ContentRef> {
    Active(Active),
    Individual(Individual),
    Group(Group<'a, T>),
    Document(Document<'a, T>),
}

impl<'a, T: ContentRef> Agent<'a, T> {
    pub fn id(&self) -> AgentId {
        match self {
            Agent::Active(a) => a.id(),
            Agent::Individual(i) => AgentId::IndividualId(i.id),
            Agent::Group(g) => g.agent_id(),
            Agent::Document(d) => d.agent_id(),
        }
    }
}

impl<'a, T: ContentRef> From<Active> for Agent<'a, T> {
    fn from(a: Active) -> Self {
        Agent::Active(a)
    }
}

impl<'a, T: ContentRef> From<Individual> for Agent<'a, T> {
    fn from(i: Individual) -> Self {
        Agent::Individual(i)
    }
}

impl<'a, T: ContentRef> From<Group<'a, T>> for Agent<'a, T> {
    fn from(g: Group<'a, T>) -> Self {
        Agent::Group(g)
    }
}

impl<'a, T: ContentRef> From<Document<'a, T>> for Agent<'a, T> {
    fn from(d: Document<'a, T>) -> Self {
        Agent::Document(d)
    }
}

impl<'a, T: ContentRef> Verifiable for Agent<'a, T> {
    fn verifying_key(&self) -> VerifyingKey {
        match self {
            Agent::Active(a) => a.verifying_key(),
            Agent::Individual(i) => i.verifying_key(),
            Agent::Group(g) => g.verifying_key(),
            Agent::Document(d) => d.verifying_key(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AgentId {
    ActiveId(Identifier),
    IndividualId(Identifier),
    GroupId(Identifier),
    DocumentId(Identifier),
}

impl AgentId {
    pub fn as_bytes(&self) -> [u8; 32] {
        match self {
            AgentId::ActiveId(i) => i.to_bytes(),
            AgentId::IndividualId(i) => i.to_bytes(),
            AgentId::GroupId(i) => i.to_bytes(),
            AgentId::DocumentId(i) => i.to_bytes(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            AgentId::ActiveId(i) => i.as_bytes(),
            AgentId::IndividualId(i) => i.as_bytes(),
            AgentId::GroupId(i) => i.as_bytes(),
            AgentId::DocumentId(i) => i.as_bytes(),
        }
    }
}

impl<'a, T: ContentRef> From<Agent<'a, T>> for AgentId {
    fn from(a: Agent<'a, T>) -> Self {
        a.id()
    }
}

impl<'a, T: ContentRef> From<&Agent<'a, T>> for AgentId {
    fn from(a: &Agent<'a, T>) -> Self {
        a.id()
    }
}

// FIXME add IndividualID
impl From<Identifier> for AgentId {
    fn from(id: Identifier) -> Self {
        AgentId::IndividualId(id)
    }
}

impl From<GroupId> for AgentId {
    fn from(id: GroupId) -> Self {
        AgentId::GroupId(id.0)
    }
}

impl From<DocumentId> for AgentId {
    fn from(id: DocumentId) -> Self {
        AgentId::DocumentId(id.0)
    }
}

impl From<AgentId> for Identifier {
    fn from(id: AgentId) -> Self {
        match id {
            AgentId::ActiveId(i) => i,
            AgentId::IndividualId(i) => i,
            AgentId::GroupId(i) => i,
            AgentId::DocumentId(i) => i,
        }
    }
}
