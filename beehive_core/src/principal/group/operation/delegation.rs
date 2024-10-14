// FIXME move opetaion to same level
use super::revocation::Revocation;
use crate::{
    access::Access,
    crypto::{digest::Digest, signed::Signed},
    principal::{agent::Agent, document::Document, identifier::Identifier, traits::Verifiable},
};
use serde::Serialize;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Delegation<'a, T: Clone + Ord + Serialize> {
    pub can: Access,

    pub proof: Option<&'a Signed<Delegation<'a, T>>>,
    pub delegate: &'a Agent<'a, T>,

    pub after_revocations: Vec<&'a Signed<Revocation<'a, T>>>,
    pub after_content: Vec<(&'a Document<'a, T>, Digest<T>)>,
}

impl<'a, T: Clone + Ord + Serialize> Signed<Delegation<'a, T>> {
    pub fn subject(&self) -> Identifier {
        let mut head = self;

        while let Some(parent) = head.payload.proof {
            head = parent;
        }

        head.author()
    }
}

// FIXME test
impl<'a, T: Clone + Ord + Serialize> Hash for Delegation<'a, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.can.hash(state);

        if let Some(proof) = self.proof {
            Digest::hash(proof).hash(state);
        }

        self.delegate.id().hash(state);

        self.after_revocations
            .iter()
            .for_each(|revocation| Digest::hash(revocation).hash(state));

        self.after_content.iter().for_each(|(doc, digest)| {
            doc.id().hash(state);
            digest.hash(state);
        });
    }
}
