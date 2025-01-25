use crate::{
    crypto::verifiable::Verifiable,
    principal::{
        document::id::DocumentId, group::id::GroupId, identifier::Identifier,
        individual::id::IndividualId,
    },
};
use derive_more::Display;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Display, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
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

impl Verifiable for AgentId {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            AgentId::ActiveId(i) => i.verifying_key(),
            AgentId::IndividualId(i) => i.verifying_key(),
            AgentId::GroupId(i) => i.verifying_key(),
            AgentId::DocumentId(i) => i.verifying_key(),
        }
    }
}
