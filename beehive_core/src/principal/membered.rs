use super::{
    agent::{Agent, AgentId},
    document::Document,
    group::{
        operation::{delegation::Delegation, revocation::Revocation},
        Group,
    },
    identifier::Identifier,
    verifiable::Verifiable,
};
use crate::{content::reference::ContentRef, crypto::signed::Signed};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt};

/// The union of Agents that have updatable membership
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Membered<'a, T: ContentRef> {
    Group(Group<'a, T>),
    Document(Document<'a, T>),
}

impl<'a, T: ContentRef> Membered<'a, T> {
    pub fn get_capability(&self, agent_id: &AgentId) -> Option<&'a Box<Signed<Delegation<'a, T>>>> {
        match self {
            Membered::Group(group) => group.get_capability(agent_id),
            Membered::Document(doc) => doc.get_capabilty(agent_id),
        }
    }

    pub fn member_id(&self) -> MemberedId {
        match self {
            Membered::Group(group) => MemberedId::GroupId(group.id().into()),
            Membered::Document(document) => MemberedId::DocumentId(document.id().into()),
        }
    }

    // FIXME make a trait and apply to children
    pub fn members(&self) -> &HashMap<AgentId, &'a Box<Signed<Delegation<'a, T>>>> {
        match self {
            Membered::Group(group) => &group.members,
            Membered::Document(document) => &document.members,
        }
    }

    pub fn add_member(&'a mut self, delegation: Signed<Delegation<'a, T>>) {
        match self {
            Membered::Group(group) => {
                group.add_member(delegation);
            }
            Membered::Document(document) => document.add_member(delegation),
        }
    }

    pub fn revoke_member(&'a mut self, revocation: Signed<Revocation<'a, T>>) {
        match self {
            Membered::Group(group) => {
                group.revoke(revocation);
            }
            Membered::Document(_document) => todo!(), // document.revoke_authorization(agent),
        }
    }
}

impl<'a, T: ContentRef> From<Membered<'a, T>> for Agent<'a, T> {
    fn from(membered: Membered<'a, T>) -> Self {
        match membered {
            Membered::Group(group) => group.into(),
            Membered::Document(document) => document.into(),
        }
    }
}

impl<'a, T: ContentRef> TryFrom<Agent<'a, T>> for Membered<'a, T> {
    type Error = &'static str; // FIXME

    fn try_from(agent: Agent<'a, T>) -> Result<Self, Self::Error> {
        match agent {
            Agent::Group(group) => Ok(Membered::Group(group)),
            Agent::Document(document) => Ok(Membered::Document(document)),
            _ => Err("Agent is not a membered type"),
        }
    }
}

impl<'a, T: ContentRef> From<Group<'a, T>> for Membered<'a, T> {
    fn from(group: Group<'a, T>) -> Self {
        Membered::Group(group)
    }
}

impl<'a, T: ContentRef> From<Document<'a, T>> for Membered<'a, T> {
    fn from(document: Document<'a, T>) -> Self {
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

// FIXME pass proof of existence?
// FIXME need at all?
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MemberedId {
    GroupId(Identifier),
    DocumentId(Identifier),
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
            MemberedId::GroupId(group_id) => write!(f, "{}", group_id),
            MemberedId::DocumentId(document_id) => write!(f, "{}", document_id),
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
            MemberedId::GroupId(group_id) => group_id,
            MemberedId::DocumentId(document_id) => document_id,
        }
    }
}
