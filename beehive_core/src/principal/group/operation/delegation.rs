// FIXME move opetaion to same level
use super::revocation::Revocation;
use crate::{
    access::Access,
    crypto::{digest::Digest, signed::Signed},
    principal::{document::Document, identifier::Identifier},
    util::content_addressed_map::CaMap,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Delegation<T: Serialize> {
    pub can: Access,

    pub proof: Option<Digest<Signed<Delegation<T>>>>,
    pub delegate: Identifier,

    pub after_revocations: Vec<Digest<Signed<Revocation<T>>>>,
    pub after_content: BTreeMap<Identifier, Vec<T>>, // FIXME DocId
}

impl<T: Serialize> Delegation<T> {
    // FIXME make trait?
    pub fn after(
        &self,
    ) -> (
        &[Digest<Signed<Delegation<T>>>],
        &[Digest<Signed<Revocation<T>>>],
        &BTreeMap<Identifier<Document<T>>, Vec<T>>,
    ) {
        (&[], &self.after_revocations.as_slice(), &self.after_content)
    }
}

impl<T: Serialize> Signed<Delegation<T>> {
    pub fn subject(&self, store: &CaMap<Self>) -> ed25519_dalek::VerifyingKey {
        let mut head = self;

        while let Some(parent_hash) = head.payload.proof {
            if let Some(parent) = store.get(&parent_hash) {
                head = parent;
            } else {
                todo!("FIXME")
            }
        }

        head.verifying_key
    }
}

impl<T: Serialize> PartialOrd for Delegation<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.can.cmp(&other.can))
    }
}

impl<T: Serialize> Ord for Delegation<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.can.cmp(&other.can)
    }
}
