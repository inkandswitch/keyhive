// FIXME move to Group

use super::delegation::{Delegation, StaticDelegation};
use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed},
    principal::{agent::AgentId, document::Document, identifier::Identifier},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Revocation<'a, T: ContentRef> {
    pub revoke: &'a Signed<Delegation<'a, T>>,

    // FIXME probably will just make this look at the ambient state,
    // but in the meantime this is just so much easier
    pub proof: &'a Signed<Delegation<'a, T>>,

    pub after_content: BTreeMap<&'a Document<'a, T>, Vec<&'a T>>,
}

impl<'a, T: ContentRef> Revocation<'a, T> {
    pub fn subject(&self) -> Identifier {
        self.revoke.subject()
    }

    pub fn after(
        &self,
    ) -> (
        Vec<&'a Signed<Delegation<'a, T>>>,
        Vec<&'a Signed<Revocation<'a, T>>>,
        &BTreeMap<&'a Document<'a, T>, Vec<&'a T>>,
    ) {
        let (dlgs, revs) = self.after_auth();
        (dlgs, revs, &self.after_content)
    }

    pub fn after_auth(
        &self,
    ) -> (
        Vec<&'a Signed<Delegation<'a, T>>>,
        Vec<&'a Signed<Revocation<'a, T>>>,
    ) {
        (vec![self.revoke], vec![])
    }
}

impl<'a, T: ContentRef> Signed<Revocation<'a, T>> {
    pub fn subject(&self) -> Identifier {
        self.payload.subject()
    }
}

impl<'a, T: ContentRef> PartialOrd for Revocation<'a, T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.revoke.partial_cmp(other.revoke) {
            Some(std::cmp::Ordering::Equal) => match self.proof.partial_cmp(other.proof) {
                Some(std::cmp::Ordering::Equal) => self
                    .after_content
                    .iter()
                    .zip(other.after_content.iter())
                    .fold(
                        Some(std::cmp::Ordering::Equal),
                        |acc, ((doc1, content1), (doc2, content2))| {
                            if let Some(std::cmp::Ordering::Equal) = acc {
                                match doc1.id().partial_cmp(&doc2.id()) {
                                    Some(std::cmp::Ordering::Equal) => {
                                        content1.iter().zip(content2.iter()).fold(
                                            Some(std::cmp::Ordering::Equal),
                                            |acc, (content1, content2)| {
                                                if let Some(std::cmp::Ordering::Equal) = acc {
                                                    content1.partial_cmp(content2)
                                                } else {
                                                    acc
                                                }
                                            },
                                        )
                                    }
                                    other => other,
                                }
                            }
                        },
                    ),
                other => other,
            },
            other => other,
        }
    }
}

impl<'a, T: ContentRef> Ord for Revocation<'a, T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StaticRevocation<T: ContentRef> {
    pub revoke: Digest<Signed<StaticDelegation<T>>>,

    // FIXME probably will just make this look at the ambient state,
    // but in the meantime this is just so much easier
    pub proof: Digest<Signed<StaticDelegation<T>>>,

    pub after_content: BTreeMap<Identifier, Vec<T>>,
}

impl<'a, T: ContentRef> From<Revocation<'a, T>> for StaticRevocation<T> {
    fn from(revocation: Revocation<'a, T>) -> Self {
        Self {
            revoke: Digest::hash(&revocation.revoke.map(|r| r.into())),
            proof: Digest::hash(&revocation.proof.map(|p| p.into())),
            after_content: BTreeMap::from_iter(
                revocation
                    .after_content
                    .iter()
                    .map(|(doc, content)| (doc.id().into(), content)),
            ),
        }
    }
}
