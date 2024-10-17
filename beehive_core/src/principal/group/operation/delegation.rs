// FIXME move opetaion to same level
use super::revocation::{Revocation, StaticRevocation};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed},
    principal::{agent::Agent, document::Document, identifier::Identifier},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, hash::Hash};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Delegation<'a, T: ContentRef> {
    pub can: Access,

    pub proof: Option<&'a Signed<Delegation<'a, T>>>,
    pub delegate: &'a Agent<'a, T>,

    pub after_revocations: Vec<&'a Signed<Revocation<'a, T>>>,
    pub after_content: BTreeMap<&'a Document<'a, T>, Vec<T>>,
}

impl<'a, T: ContentRef> Delegation<'a, T> {
    // FIXME make trait?
    pub fn after(
        &'a self,
    ) -> (
        Vec<&'a Signed<Delegation<'a, T>>>,
        Vec<&'a Signed<Revocation<'a, T>>>,
        &'a BTreeMap<&'a Document<'a, T>, Vec<T>>,
    ) {
        let (dlgs, revs) = self.after_auth();
        (dlgs, revs, &self.after_content)
    }

    pub fn after_auth(
        &'a self,
    ) -> (
        Vec<&'a Signed<Delegation<'a, T>>>,
        Vec<&'a Signed<Revocation<'a, T>>>,
    ) {
        let dlgs = if let Some(proof) = self.proof {
            vec![proof]
        } else {
            vec![]
        };

        (dlgs, self.after_revocations.clone())
    }
}

impl<'a, T: ContentRef> Signed<Delegation<'a, T>> {
    pub fn subject(&self) -> Identifier {
        let mut head = self;

        while let Some(parent) = head.payload.proof {
            head = parent;
        }

        head.verifying_key.into()
    }
}

// FIXME test FIXME just and compare?
impl<'a, T: ContentRef> PartialOrd for Delegation<'a, T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.can.partial_cmp(&other.can) {
            Some(std::cmp::Ordering::Equal) => {
                match self.delegate.id().partial_cmp(&other.delegate.id()) {
                    Some(std::cmp::Ordering::Equal) => {
                        let self_after = self.after();
                        let other_after = other.after();

                        match self_after.0.len().partial_cmp(&other_after.0.len()) {
                            Some(std::cmp::Ordering::Equal) => {
                                match self_after.1.len().partial_cmp(&other_after.1.len()) {
                                    Some(std::cmp::Ordering::Equal) => {
                                        let self_after = self_after
                                            .0
                                            .iter()
                                            .map(|d| d.subject())
                                            .collect::<Vec<_>>();
                                        let other_after = other_after
                                            .0
                                            .iter()
                                            .map(|d| d.subject())
                                            .collect::<Vec<_>>();

                                        self_after.partial_cmp(&other_after)
                                    }
                                    other => other,
                                }
                            }
                            other => other,
                        }
                    }
                    other => other,
                }
            }
            other => other,
        }
    }
}

impl<'a, T: ContentRef + Ord> Ord for Delegation<'a, T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        StaticDelegation::from(self.clone()).cmp(&StaticDelegation::from(other.clone()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StaticDelegation<T: ContentRef> {
    pub can: Access,

    pub proof: Option<Digest<Signed<StaticDelegation<T>>>>,
    pub delegate: Identifier,

    pub after_revocations: Vec<Digest<Signed<StaticRevocation<T>>>>,
    pub after_content: BTreeMap<Identifier, Vec<T>>,
}

impl<'a, T: ContentRef> From<Delegation<'a, T>> for StaticDelegation<T> {
    fn from(delegation: Delegation<'a, T>) -> Self {
        Self {
            can: delegation.can,
            proof: delegation.proof.map(|p| Digest::hash(&p.map(|d| d.into()))),
            delegate: delegation.delegate.id().into(),
            after_revocations: delegation
                .after_revocations
                .iter()
                .map(|revocation| Digest::hash(&revocation.map(|r| r.into())))
                .collect(),
            after_content: BTreeMap::from_iter(
                delegation
                    .after_content
                    .iter()
                    .map(|(document, content)| (document.id().into(), content.clone())),
            ),
        }
    }
}
