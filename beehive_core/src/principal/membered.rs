pub mod id;

use super::{
    agent::{id::AgentId, Agent},
    document::{id::DocumentId, AddMemberError, AddMemberUpdate, Document, RevokeMemberUpdate},
    group::{
        error::AddError,
        operation::{delegation::Delegation, revocation::Revocation},
        Group, RevokeMemberError,
    },
    verifiable::Verifiable,
};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed},
    util::content_addressed_map::CaMap,
};
use dupe::{Dupe, OptionDupedExt};
use id::MemberedId;
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    rc::Rc,
};

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
            Membered::Document(doc) => doc.borrow().get_capability(agent_id).duped(),
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
            Membered::Group(group) => MemberedId::GroupId(group.borrow().group_id()),
            Membered::Document(document) => MemberedId::DocumentId(document.borrow().doc_id()),
        }
    }

    pub fn delegation_heads(&self) -> CaMap<Signed<Delegation<T>>> {
        match self {
            Membered::Group(group) => group.borrow().delegation_heads().clone(),
            Membered::Document(document) => document.borrow().delegation_heads().clone(),
        }
    }

    pub fn revocation_heads(&self) -> CaMap<Signed<Revocation<T>>> {
        match self {
            Membered::Group(group) => group.borrow().revocation_heads().clone(),
            Membered::Document(document) => document.borrow().revocation_heads().clone(),
        }
    }

    pub fn members(&self) -> HashMap<AgentId, Vec<Rc<Signed<Delegation<T>>>>> {
        match self {
            Membered::Group(group) => group.borrow().members().clone(),
            Membered::Document(document) => document.borrow().members().clone(),
        }
    }

    pub fn add_member(
        &mut self,
        member_to_add: Agent<T>,
        can: Access,
        signing_key: &ed25519_dalek::SigningKey,
        other_relevant_docs: &[&Document<T>],
    ) -> Result<AddMemberUpdate<T>, AddMemberError> {
        match self {
            Membered::Group(group) => Ok(AddMemberUpdate {
                delegation: group.borrow_mut().add_member(
                    member_to_add,
                    can,
                    signing_key,
                    other_relevant_docs,
                )?,
                cgka_ops: vec![],
            }),
            Membered::Document(document) => document.borrow_mut().add_member(
                member_to_add,
                can,
                signing_key,
                other_relevant_docs,
            ),
        }
    }

    pub fn revoke_member(
        &mut self,
        member_id: AgentId,
        signing_key: &ed25519_dalek::SigningKey,
        relevant_docs: &mut BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<RevokeMemberUpdate<T>, RevokeMemberError> {
        match self {
            Membered::Group(group) => Ok(RevokeMemberUpdate {
                revocations: group.borrow_mut().revoke_member(
                    member_id,
                    signing_key,
                    relevant_docs,
                )?,
                cgka_ops: vec![],
            }),
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

    pub fn receive_delegation(
        &self,
        delegation: Rc<Signed<Delegation<T>>>,
    ) -> Result<Digest<Signed<Delegation<T>>>, AddError> {
        match self {
            Membered::Group(group) => Ok(group.borrow_mut().receive_delegation(delegation)?),
            Membered::Document(document) => {
                Ok(document.borrow_mut().receive_delegation(delegation)?)
            }
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
