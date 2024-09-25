use super::agent::Agent;
use super::document::Document;
use super::group::Group;
use super::identifier::Identifier;
use super::traits::Verifiable;
use crate::access::Access;
use crate::crypto::signed::Signed;
use crate::operation::delegation::Delegation;
use crate::operation::revocation::Revocation;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Membered {
    Group(Group),
    Document(Document),
}

impl Membered {
    pub fn member_id(&self) -> MemberedId {
        match self {
            Membered::Group(group) => MemberedId::GroupId(group.id().clone()),
            Membered::Document(_document) => todo!(), // MemberedId::DocumentId(document.id.clone()),
        }
    }

    // FIXME make a trait and apply to children
    pub fn members(&self) -> BTreeMap<Agent, (Access, Signed<Delegation>)> {
        match self {
            Membered::Group(group) => group.delegates.clone(), // FIXME NEEDS lifetimes, just being slapdash here
            Membered::Document(document) => document.delegates.clone(),
        }
    }

    pub fn add_member(&mut self, delegation: Signed<Delegation>) {
        todo!()
        // match self {
        //     Membered::Group(group) => {
        //         group.add_member(delegation);
        //     }
        //     Membered::Document(_document) => todo!(), // document.add_authorization(agent, access, delegation),
        // }
    }

    pub fn revoke_member(&mut self, revocation: Signed<Revocation>) {
        todo!()
        // match self {
        //     Membered::Group(group) => {
        //         group.revoke(revocation);
        //     }
        //     Membered::Document(_document) => todo!(), // document.revoke_authorization(agent),
        // }
    }
}

impl From<Membered> for Agent {
    fn from(membered: Membered) -> Self {
        match membered {
            Membered::Group(group) => group.into(),
            Membered::Document(document) => document.into(),
        }
    }
}

impl From<Group> for Membered {
    fn from(group: Group) -> Self {
        Membered::Group(group)
    }
}

impl From<Document> for Membered {
    fn from(document: Document) -> Self {
        Membered::Document(document)
    }
}

impl Verifiable for Membered {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            Membered::Group(group) => group.verifying_key(),
            Membered::Document(document) => document.verifying_key(),
        }
    }
}

// FIXE pass proof of existence?
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
