use super::agent::Agent;
use super::document::Document;
use super::group::Group;
use super::identifier::Identifier;
use super::traits::Verifiable;
use crate::access::Access;
use crate::crypto::signed::Signed;
use crate::operation::delegation::Delegation;
use crate::operation::revocation::Revocation;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Membered {
    Group(Group),
    Document(Document),
}

impl Membered {
    pub fn member_id(&self) -> MemberedId {
        match self {
            Membered::Group(group) => MemberedId::GroupId(group.id.clone()),
            Membered::Document(_document) => todo!(), // MemberedId::DocumentId(document.id.clone()),
        }
    }

    // FIXME make a trait and apply to children
    pub fn members(&self) -> BTreeMap<Agent, (Access, Signed<Delegation>)> {
        match self {
            Membered::Group(group) => group.delegates.clone(), // FIXME NEEDS lifetimes, just being slapdash here
            Membered::Document(_document) => todo!(),          // document.authorizations.clone(),
        }
    }

    pub fn add_member(&mut self, delegation: Signed<Delegation>) {
        match self {
            Membered::Group(group) => {
                group.add_member(delegation);
            }
            Membered::Document(_document) => todo!(), // document.add_authorization(agent, access, delegation),
        }
    }

    pub fn revoke_member(&mut self, revocation: Signed<Revocation>) {
        match self {
            Membered::Group(group) => {
                group.revoke(revocation);
            }
            Membered::Document(_document) => todo!(), // document.revoke_authorization(agent),
        }
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemberedId {
    GroupId(Identifier),
    DocumentId(Identifier),
}

impl Verifiable for MemberedId {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            MemberedId::GroupId(group_id) => group_id.verifying_key(),
            MemberedId::DocumentId(document_id) => document_id.verifying_key(),
        }
    }
}
