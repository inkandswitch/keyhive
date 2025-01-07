pub mod id;
pub mod unknown_error;

use super::{
    agent::{Agent, AgentId},
    document::Document,
    group::{
        operation::{delegation::Delegation, revocation::Revocation},
        state::AddError,
        Group,
    },
    verifiable::Verifiable,
};
use crate::{
    content::reference::ContentRef,
    crypto::signed::{Signed, SigningError},
};
use dupe::{Dupe, OptionDupedExt};
use id::MemberedId;
use std::{cell::RefCell, collections::HashMap, rc::Rc};

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

    pub fn add_member(&mut self, delegation: Signed<Delegation<T>>) {
        match self {
            Membered::Group(group) => {
                group.borrow_mut().add_delegation(delegation);
            }
            Membered::Document(document) => {
                document.borrow_mut().add_member(delegation);
            }
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

    pub fn receive_delegation(&self, delegation: Signed<Delegation<T>>) -> Result<(), AddError> {
        match self {
            Membered::Group(group) => group.borrow_mut().receive_delegation(delegation),
            Membered::Document(document) => document.borrow_mut().receive_delegation(delegation),
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
