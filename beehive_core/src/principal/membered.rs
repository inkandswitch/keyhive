use super::{
    agent::Agent, document::Document, group::operation::delegation::Delegation,
    group::operation::revocation::Revocation, group::Group, identifier::Identifier,
    verifiable::Verifiable,
};
use crate::crypto::signed::Signed;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// The union of Agents that have updatable membership
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Membered<T: Serialize> {
    Group(Group<T>),
    Document(Document<T>),
}

impl<T: Serialize> Membered<T> {
    // FIXME get_capability?
    pub fn get(&self, agent: &Agent<T>) -> Option<&Signed<Delegation<T>>> {
        match self {
            Membered::Group(group) => group.get(agent),
            Membered::Document(doc) => doc.get(agent),
        }
    }

    pub fn member_id(&self) -> MemberedId<T> {
        match self {
            Membered::Group(group) => MemberedId::GroupId(group.id().clone()),
            Membered::Document(document) => MemberedId::DocumentId(document.id().clone()),
        }
    }

    // FIXME make a trait and apply to children
    pub fn members(&self) -> &BTreeMap<&Agent<T>, &Signed<Delegation<T>>> {
        match self {
            Membered::Group(group) => group.members,
            Membered::Document(document) => document.members,
        }
    }

    pub fn add_member(&mut self, delegation: Signed<Delegation<T>>) {
        match self {
            Membered::Group(group) => {
                group.add_member(delegation);
            }
            Membered::Document(document) => document.add_member(delegation),
        }
    }

    pub fn revoke_member(&mut self, revocation: Signed<Revocation<T>>) {
        match self {
            Membered::Group(group) => {
                group.revoke(revocation);
            }
            Membered::Document(_document) => todo!(), // document.revoke_authorization(agent),
        }
    }
}

impl<T: Serialize> From<Membered<T>> for Agent<T> {
    fn from(membered: Membered<T>) -> Self {
        match membered {
            Membered::Group(group) => group.into(),
            Membered::Document(document) => document.into(),
        }
    }
}

impl<T: Serialize> TryFrom<Agent<T>> for Membered<T> {
    type Error = &'static str; // FIXME

    fn try_from(agent: Agent<T>) -> Result<Self, Self::Error> {
        match agent {
            Agent::Group(group) => Ok(Membered::Group(group)),
            Agent::Document(document) => Ok(Membered::Document(document)),
            _ => Err("Agent is not a membered type"),
        }
    }
}

impl<T: Serialize> From<Group<T>> for Membered<T> {
    fn from(group: Group<T>) -> Self {
        Membered::Group(group)
    }
}

impl<T: Serialize> From<Document<T>> for Membered<T> {
    fn from(document: Document<T>) -> Self {
        Membered::Document(document)
    }
}

impl<T: Serialize> Verifiable for Membered<T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            Membered::Group(group) => group.verifying_key(),
            Membered::Document(document) => document.verifying_key(),
        }
    }
}

// FIXME pass proof of existence?
// FIXME need at all?
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd , Ord Hash, Serialize, Deserialize)]
pub enum MemberedId {
    GroupId(Identifier),
    DocumentId(Identifier),
}

impl<T: Serialize> MemberedId<T> {
    pub fn to_bytes(&self) -> [u8; 32] {
        match self {
            MemberedId::GroupId(group_id) => group_id.to_bytes(),
            MemberedId::DocumentId(document_id) => document_id.to_bytes(),
        }
    }
}

impl<T: Serialize> fmt::Display for MemberedId<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MemberedId::GroupId(group_id) => write!(f, "{}", group_id),
            MemberedId::DocumentId(document_id) => write!(f, "{}", document_id),
        }
    }
}

impl<T: Serialize> Verifiable for MemberedId<T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            MemberedId::GroupId(group_id) => group_id.verifying_key(),
            MemberedId::DocumentId(document_id) => document_id.verifying_key(),
        }
    }
}

// impl<T: Serialize> From<MemberedId<T>> for Identifier<Membered<T>> {
//     fn from(membered_id: MemberedId<T>) -> Self {
//         match membered_id {
//             MemberedId::GroupId(group_id) => Identifier { key: group_id,
//             MemberedId::DocumentId(document_id) => document_id,
//         }
//     }
// }
