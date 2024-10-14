use super::{
    agent::Agent, document::Document, group::operation::delegation::Delegation,
    group::operation::revocation::Revocation, group::Group, identifier::Identifier,
    traits::Verifiable,
};
use crate::crypto::signed::Signed;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// The union of Agents that have updatable membership
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Membered<'a, T: Clone + Ord + Serialize> {
    Group(&'a Group<'a, T>),
    Document(&'a Document<'a, T>),
}

impl<'a, T: Clone + Ord + Serialize> Membered<'a, T> {
    // FIXME get_capability?
    pub fn get(&self, agent: &Agent<T>) -> Option<&Signed<Delegation<T>>> {
        match self {
            Membered::Group(group) => group.get(agent),
            Membered::Document(doc) => doc.get(agent),
        }
    }

    pub fn member_id(&self) -> MemberedId {
        match self {
            Membered::Group(group) => MemberedId::GroupId(group.id()),
            Membered::Document(document) => MemberedId::DocumentId(document.id()),
        }
    }

    // FIXME make a trait and apply to children
    pub fn members(&self) -> &BTreeMap<&Agent<'a, T>, &Signed<Delegation<'a, T>>> {
        match self {
            Membered::Group(group) => &group.members,
            Membered::Document(document) => &document.members,
        }
    }

    pub fn add_member(&mut self, delegation: Signed<Delegation<'a, T>>) {
        match self {
            Membered::Group(group) => {
                group.add_member(delegation);
            }
            Membered::Document(document) => document.add_member(delegation),
        }
    }

    pub fn revoke_member(&mut self, revocation: Signed<Revocation<'a, T>>) {
        match self {
            Membered::Group(group) => {
                group.revoke(revocation);
            }
            Membered::Document(_document) => todo!(), // document.revoke_authorization(agent),
        }
    }
}

impl<'a, T: Clone + Ord + Serialize> From<Membered<'a, T>> for Agent<'a, T> {
    fn from(membered: Membered<'a, T>) -> Self {
        match membered {
            Membered::Group(group) => (*group.clone()).into(),
            Membered::Document(document) => (*document.clone()).into(),
        }
    }
}

impl<'a, T: Clone + Ord + Serialize> TryFrom<&'a Agent<'a, T>> for Membered<'a, T> {
    type Error = &'static str; // FIXME

    fn try_from(agent: &'a Agent<'a, T>) -> Result<Self, Self::Error> {
        match agent {
            Agent::Group(group) => Ok(Membered::Group(&group)),
            Agent::Document(document) => Ok(Membered::Document(&document)),
            _ => Err("Agent is not a membered type"),
        }
    }
}

impl<'a, T: Clone + Ord + Serialize> From<&'a Group<'a, T>> for Membered<'a, T> {
    fn from(group: &'a Group<'a, T>) -> Self {
        Membered::Group(group)
    }
}

impl<'a, T: Clone + Ord + Serialize> From<&'a Document<'a, T>> for Membered<'a, T> {
    fn from(document: &'a Document<'a, T>) -> Self {
        Membered::Document(document)
    }
}

impl<'a, T: Clone + Ord + Serialize> Verifiable for Membered<'a, T> {
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
