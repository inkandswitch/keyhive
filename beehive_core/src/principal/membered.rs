use super::{
    agent::{Agent, AgentId},
    document::{id::DocumentId, Document},
    group::{
        id::GroupId,
        operation::{delegation::Delegation, revocation::Revocation},
        Group,
    },
    identifier::Identifier,
    verifiable::Verifiable,
};
use crate::{
    content::reference::ContentRef,
    crypto::signed::{Signed, SigningError},
};
use dupe::{Dupe, OptionDupedExt};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, collections::HashMap, fmt, rc::Rc};

/// The union of Agents that have updatable membership
#[derive(Debug, Clone, Dupe, PartialEq, Eq)]
pub enum Membered<T: ContentRef> {
    Group(Rc<RefCell<Group<T>>>),
    Document(Rc<RefCell<Document<T>>>),
}

impl<T: ContentRef> Membered<T> {
    pub fn get_capability(&self, agent_id: &AgentId) -> Option<Rc<Signed<Delegation<T>>>> {
        match self {
            Membered::Group(group) => group.borrow().get_capability(agent_id).duped(),
            Membered::Document(doc) => doc.borrow().get_capabilty(agent_id).duped(),
        }
    }

    pub fn agent_id(&self) -> AgentId {
        match self {
            Membered::Group(group) => group.borrow().agent_id(),
            Membered::Document(document) => document.borrow().agent_id(),
        }
    }

    pub fn membered_id(&self) -> MemberedId {
        match self {
            Membered::Group(group) => MemberedId::GroupId(group.borrow().group_id().into()),
            Membered::Document(document) => {
                MemberedId::DocumentId(document.borrow().doc_id().into())
            }
        }
    }

    pub fn members(&self) -> HashMap<AgentId, Vec<Rc<Signed<Delegation<T>>>>> {
        match self {
            Membered::Group(group) => group.borrow().members().clone(),
            Membered::Document(document) => document.borrow().members().clone(),
        }
    }

    pub fn add_member<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        delegation: Signed<Delegation<T>>,
        csprng: &mut R,
    ) {
        match self {
            Membered::Group(group) => {
                group.borrow_mut().add_delegation(delegation);
            }
            Membered::Document(document) => document.borrow_mut().add_member(delegation, csprng),
        }
    }

    pub fn revoke_member(
        &mut self,
        member_id: AgentId,
        signing_key: &ed25519_dalek::SigningKey,
        relevant_docs: &[&Rc<RefCell<Document<T>>>],
    ) -> Result<(), SigningError> {
        match self {
            Membered::Group(group) => {
                group
                    .borrow_mut()
                    .revoke_member(member_id, signing_key, relevant_docs)
            }
            Membered::Document(document) => {
                document
                    .borrow_mut()
                    .revoke_member(member_id, signing_key, relevant_docs)
            }
        }
    }

    pub fn get_agent_revocations(&self, agent: &Agent<T>) -> Vec<Rc<Signed<Revocation<T>>>> {
        match self {
            Membered::Group(group) => group.borrow().get_agent_revocations(agent),
            Membered::Document(document) => document.borrow().get_agent_revocations(agent),
        }
    }
}

impl<T: ContentRef> From<Rc<RefCell<Group<T>>>> for Membered<T> {
    fn from(group: Rc<RefCell<Group<T>>>) -> Self {
        Membered::Group(group)
    }
}

impl<T: ContentRef> From<Rc<RefCell<Document<T>>>> for Membered<T> {
    fn from(document: Rc<RefCell<Document<T>>>) -> Self {
        Membered::Document(document)
    }
}

impl<T: ContentRef> Verifiable for Membered<T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            Membered::Group(group) => group.borrow().verifying_key(),
            Membered::Document(document) => document.borrow().verifying_key(),
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
