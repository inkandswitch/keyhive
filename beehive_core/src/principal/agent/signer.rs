use super::id::AgentId;
use crate::principal::{
    active::Active, document::id::DocumentId, group::id::GroupId, individual::id::IndividualId,
    verifiable::Verifiable,
};
use dupe::Dupe;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSigner {
    id: SignerId,
    key: ed25519_dalek::SigningKey,
}

impl AgentSigner {
    pub(crate) fn new(agent_id: AgentId, key: ed25519_dalek::SigningKey) -> Option<Self> {
        if agent_id.verifying_key() != key.verifying_key() {
            return None;
        }

        let id = match agent_id {
            AgentId::ActiveId(id) => SignerId::Individual(id),
            AgentId::IndividualId(id) => SignerId::Individual(id),
            AgentId::GroupId(id) => SignerId::Group(id),
            AgentId::DocumentId(id) => SignerId::Document(id),
        };

        Some(AgentSigner { id, key })
    }

    pub(crate) fn id(&self) -> SignerId {
        self.id
    }

    pub(crate) fn key(&self) -> &ed25519_dalek::SigningKey {
        &self.key
    }

    pub(crate) fn from_active(active: &Active) -> Self {
        AgentSigner {
            id: SignerId::Individual(active.individual.id()),
            key: active.signer.clone(),
        }
    }

    pub(crate) fn individual_signer_from_key(key: ed25519_dalek::SigningKey) -> Self {
        AgentSigner {
            id: SignerId::Individual(IndividualId(key.verifying_key().into())),
            key,
        }
    }

    pub(crate) fn group_signer_from_key(key: ed25519_dalek::SigningKey) -> Self {
        AgentSigner {
            id: SignerId::Group(GroupId(key.verifying_key().into())),
            key,
        }
    }

    pub(crate) fn document_signer_from_key(key: ed25519_dalek::SigningKey) -> Self {
        AgentSigner {
            id: SignerId::Document(DocumentId(key.verifying_key().into())),
            key,
        }
    }
}

impl From<AgentSigner> for AgentId {
    fn from(signer: AgentSigner) -> Self {
        signer.id.into()
    }
}

impl Dupe for AgentSigner {
    fn dupe(&self) -> Self {
        Self {
            id: self.id.dupe(),
            key: self.key.clone(),
        }
    }
}

impl Verifiable for AgentSigner {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id.verifying_key()
    }
}

#[derive(Debug, Clone, Dupe, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignerId {
    // NOTE: no `Active`, because that doesn't mean anything to anyone else
    Individual(IndividualId),
    Group(GroupId),
    Document(DocumentId),
}

impl Verifiable for SignerId {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            Self::Individual(id) => id.verifying_key(),
            Self::Group(id) => id.verifying_key(),
            Self::Document(id) => id.verifying_key(),
        }
    }
}

impl From<SignerId> for AgentId {
    fn from(id: SignerId) -> Self {
        match id {
            SignerId::Individual(id) => AgentId::IndividualId(id),
            SignerId::Group(id) => AgentId::GroupId(id),
            SignerId::Document(id) => AgentId::DocumentId(id),
        }
    }
}

impl From<AgentId> for SignerId {
    fn from(id: AgentId) -> Self {
        match id {
            AgentId::ActiveId(id) => SignerId::Individual(id),
            AgentId::IndividualId(id) => SignerId::Individual(id),
            AgentId::GroupId(id) => SignerId::Group(id),
            AgentId::DocumentId(id) => SignerId::Document(id),
        }
    }
}
