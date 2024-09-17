use super::agent::Agent;
use super::document::Document;
use super::group::Group;
use super::identifier::Identifier;
use super::traits::Verifiable;
use crate::access::Access;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Membered {
    Group(Group),
    Document(Document),
}

impl Membered {
    // FIXME make a trait and apply to children
    pub fn members(&self) -> BTreeMap<Agent, Access> {
        match self {
            Membered::Group(group) => group.delegates.clone(), // FIXME NEEDS lifetimes, just being slapdash here
            Membered::Document(document) => document.authorizations.clone(),
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
