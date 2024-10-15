use super::{
    document::Document, group::Group, identifier::Identifier, individual::Individual,
    verifiable::Verifiable,
};
use ed25519_dalek::VerifyingKey;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Agent<T: Serialize> {
    Individual(Individual),
    Group(Group<T>),
    Document(Document<T>),
}

impl<T: Serialize> Agent<T> {
    pub fn id(&self) -> AgentId {
        match self {
            Agent::Individual(i) => AgentId::IndividualId(i.id),
            Agent::Group(g) => AgentId::GroupId(*g.id()),
            Agent::Document(d) => AgentId::DocumentId(*d.id()),
        }
    }
}

impl<T: Serialize> From<Individual> for Agent<T> {
    fn from(s: Individual) -> Self {
        Agent::Individual(s)
    }
}

impl<T: Serialize> From<Group<T>> for Agent<T> {
    fn from(g: Group<T>) -> Self {
        Agent::Group(g)
    }
}

impl<T: Serialize> From<Document<T>> for Agent<T> {
    fn from(d: Document<T>) -> Self {
        Agent::Document(d)
    }
}

impl<T: Serialize> Verifiable for Agent<T> {
    fn verifying_key(&self) -> VerifyingKey {
        match self {
            Agent::Individual(i) => i.verifying_key(),
            Agent::Group(g) => g.verifying_key(),
            Agent::Document(d) => d.verifying_key(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum AgentId {
    IndividualId(Identifier),
    GroupId(Identifier),
    DocumentId(Identifier),
}

impl AgentId {
    pub fn as_bytes(&self) -> [u8; 32] {
        match self {
            AgentId::IndividualId(i) => i.to_bytes(),
            AgentId::GroupId(i) => i.to_bytes(),
            AgentId::DocumentId(i) => i.to_bytes(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            AgentId::IndividualId(i) => i.as_bytes(),
            AgentId::GroupId(i) => i.as_bytes(),
            AgentId::DocumentId(i) => i.as_bytes(),
        }
    }
}
