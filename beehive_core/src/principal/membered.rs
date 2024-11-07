use super::{
    agent::AgentId,
    document::{id::DocumentId, Document},
    group::{id::GroupId, operation::delegation::Delegation, Group},
    identifier::Identifier,
    verifiable::Verifiable,
};
use crate::{
    content::reference::ContentRef,
    crypto::signed::{Signed, SigningError},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, rc::Rc};

/// The union of Agents that have updatable membership
#[derive(Debug, PartialEq, Eq)]
pub enum Membered<'a, T: ContentRef> {
    Group(&'a mut Group<T>),
    Document(&'a mut Document<T>),
}

impl<'a, T: ContentRef> Membered<'a, T> {
    pub fn get_capability(&self, agent_id: &AgentId) -> Option<&Rc<Signed<Delegation<T>>>> {
        match self {
            Membered::Group(group) => group.get_capability(agent_id),
            Membered::Document(doc) => doc.get_capabilty(agent_id),
        }
    }

    pub fn agent_id(&self) -> AgentId {
        match self {
            Membered::Group(group) => group.agent_id(),
            Membered::Document(document) => document.agent_id(),
        }
    }

    pub fn membered_id(&self) -> MemberedId {
        match self {
            Membered::Group(group) => MemberedId::GroupId(group.group_id()),
            Membered::Document(document) => MemberedId::DocumentId(document.doc_id()),
        }
    }

    pub fn members(&self) -> &HashMap<AgentId, Vec<Rc<Signed<Delegation<T>>>>> {
        match self {
            Membered::Group(group) => group.members(),
            Membered::Document(document) => document.members(),
        }
    }

    pub fn add_member(&mut self, delegation: Signed<Delegation<T>>) {
        match self {
            Membered::Group(group) => {
                group.add_delegation(delegation);
            }
            Membered::Document(document) => document.add_member(delegation),
        }
    }

    pub fn revoke_member(
        &mut self,
        member_id: &AgentId,
        signing_key: &ed25519_dalek::SigningKey,
        relevant_docs: &[&Rc<Document<T>>],
    ) -> Result<(), SigningError> {
        match self {
            Membered::Group(group) => group.revoke_member(member_id, signing_key, relevant_docs),
            Membered::Document(document) => {
                document.revoke_member(member_id, signing_key, relevant_docs)
            }
        }
    }
}

impl<'a, T: ContentRef> From<&'a mut Group<T>> for Membered<'a, T> {
    fn from(group: &'a mut Group<T>) -> Self {
        Membered::Group(group)
    }
}

impl<'a, T: ContentRef> From<&'a mut Document<T>> for Membered<'a, T> {
    fn from(document: &'a mut Document<T>) -> Self {
        Membered::Document(document)
    }
}

impl<'a, T: ContentRef> Verifiable for Membered<'a, T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            Membered::Group(group) => group.verifying_key(),
            Membered::Document(document) => document.verifying_key(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MemberedId {
    GroupId(GroupId),
    DocumentId(DocumentId),
}

impl MemberedId {
    pub fn to_bytes(&self) -> [u8; 32] {
        match self {
            MemberedId::GroupId(group_id) => group_id.to_bytes(),
            MemberedId::DocumentId(document_id) => document_id.to_bytes(),
        }
    }
}

impl fmt::Display for MemberedId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MemberedId::GroupId(group_id) => group_id.fmt(f),
            MemberedId::DocumentId(document_id) => document_id.fmt(f),
        }
    }
}

impl Verifiable for MemberedId {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            MemberedId::GroupId(group_id) => group_id.verifying_key(),
            MemberedId::DocumentId(document_id) => document_id.verifying_key(),
        }
    }
}

impl From<MemberedId> for Identifier {
    fn from(membered_id: MemberedId) -> Self {
        match membered_id {
            MemberedId::GroupId(group_id) => group_id.into(),
            MemberedId::DocumentId(document_id) => document_id.into(),
        }
    }
}

impl From<GroupId> for MemberedId {
    fn from(group_id: GroupId) -> Self {
        MemberedId::GroupId(group_id)
    }
}
