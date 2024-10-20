use super::{
    active::Active,
    document::{id::DocumentId, Document},
    group::{id::GroupId, Group},
    identifier::Identifier,
    individual::{id::IndividualId, Individual},
    verifiable::Verifiable,
};
use crate::content::reference::ContentRef;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// Immutable union over all agent types.
///
/// This type is very lightweight to clone, since it only contains immutable references to the actual agents.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize)]
pub enum Agent<'a, T: ContentRef> {
    Active(&'a Active),
    Individual(&'a Individual),
    Group(&'a Group<'a, T>),
    Document(&'a Document<'a, T>),
}

impl<'a, T: ContentRef> Agent<'a, T> {
    pub fn id(&self) -> Identifier {
        match self {
            Agent::Active(a) => a.id().into(),
            Agent::Individual(i) => i.id().into(),
            Agent::Group(g) => g.group_id().into(),
            Agent::Document(d) => d.doc_id().into(),
        }
    }

    pub fn agent_id(&self) -> AgentId {
        match self {
            Agent::Active(a) => a.agent_id(),
            Agent::Individual(i) => i.agent_id(),
            Agent::Group(g) => g.agent_id(),
            Agent::Document(d) => d.agent_id(),
        }
    }
}

impl<'a, T: ContentRef> From<&'a Active> for Agent<'a, T> {
    fn from(a: &'a Active) -> Self {
        Agent::Active(a)
    }
}

impl<'a, T: ContentRef> From<&'a Individual> for Agent<'a, T> {
    fn from(i: &'a Individual) -> Self {
        Agent::Individual(i)
    }
}

impl<'a, T: ContentRef> From<&'a Group<'a, T>> for Agent<'a, T> {
    fn from(g: &'a Group<'a, T>) -> Self {
        Agent::Group(g)
    }
}

impl<'a, T: ContentRef> From<&'a Document<'a, T>> for Agent<'a, T> {
    fn from(d: &'a Document<'a, T>) -> Self {
        Agent::Document(d)
    }
}

impl<'a, T: ContentRef> Verifiable for Agent<'a, T> {
    fn verifying_key(&self) -> VerifyingKey {
        match self {
            Agent::Active(a) => a.verifying_key(),
            Agent::Individual(i) => i.verifying_key(),
            Agent::Group(g) => g.verifying_key(),
            Agent::Document(d) => d.group.verifying_key(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AgentId {
    ActiveId(IndividualId),
    IndividualId(IndividualId),
    GroupId(GroupId),
    DocumentId(DocumentId),
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
        a.agent_id()
    }
}

impl<'a, T: ContentRef> From<&Agent<'a, T>> for AgentId {
    fn from(a: &Agent<'a, T>) -> Self {
        a.agent_id()
    }
}

impl From<IndividualId> for AgentId {
    fn from(id: IndividualId) -> Self {
        AgentId::IndividualId(id)
    }
}

impl From<GroupId> for AgentId {
    fn from(id: GroupId) -> Self {
        AgentId::GroupId(id)
    }
}

impl From<DocumentId> for AgentId {
    fn from(id: DocumentId) -> Self {
        AgentId::DocumentId(id)
    }
}

impl From<AgentId> for Identifier {
    fn from(id: AgentId) -> Self {
        match id {
            AgentId::ActiveId(i) => i.into(),
            AgentId::IndividualId(i) => i.into(),
            AgentId::GroupId(i) => i.into(),
            AgentId::DocumentId(i) => i.into(),
        }
    }
}
