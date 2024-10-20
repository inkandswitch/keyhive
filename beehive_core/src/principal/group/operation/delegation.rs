use super::revocation::{Revocation, StaticRevocation};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed},
    principal::{
        agent::{Agent, AgentId},
        document::{id::DocumentId, Document},
        identifier::Identifier,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, hash::Hash};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Delegation<'a, T: ContentRef> {
    pub delegate: &'a Agent<'a, T>,
    pub can: Access,

    pub proof: Option<&'a Signed<Delegation<'a, T>>>,
    pub after_revocations: Vec<&'a Signed<Revocation<'a, T>>>,
    pub after_content: BTreeMap<DocumentId, (&'a Document<'a, T>, Vec<T>)>,
}

impl<'a, T: ContentRef> Delegation<'a, T> {
    pub fn subject(&self, issuer: AgentId) -> Identifier {
        if let Some(proof) = self.proof {
            proof.subject()
        } else {
            issuer.into()
        }
    }

    pub fn after(
        &'a self,
    ) -> (
        Vec<&'a Signed<Delegation<'a, T>>>,
        Vec<&'a Signed<Revocation<'a, T>>>,
        &'a BTreeMap<DocumentId, (&'a Document<'a, T>, Vec<T>)>,
    ) {
        let (dlgs, revs) = self.after_auth();
        (
            dlgs.map(|d| vec![d]).unwrap_or(vec![]),
            revs.to_vec(),
            &self.after_content,
        )
    }

    pub fn after_auth(
        &'a self,
    ) -> (
        Option<&'a Signed<Delegation<'a, T>>>,
        &[&'a Signed<Revocation<'a, T>>],
    ) {
        (self.proof, &self.after_revocations)
    }

    pub fn is_root(&self) -> bool {
        self.proof.is_none()
    }
}

impl<'a, T: ContentRef> Signed<Delegation<'a, T>> {
    pub fn subject(&self) -> Identifier {
        let mut head = self;

        while let Some(parent) = head.payload().proof {
            head = parent;
        }

        head.id()
    }
}

// FIXME test FIXME just and compare?
impl<'a, T: ContentRef> PartialOrd for Delegation<'a, T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.can.partial_cmp(&other.can) {
            Some(std::cmp::Ordering::Equal) => {
                match self
                    .delegate
                    .agent_id()
                    .partial_cmp(&other.delegate.agent_id())
                {
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StaticDelegation<T: ContentRef> {
    pub can: Access,

    pub proof: Option<Digest<Signed<StaticDelegation<T>>>>,
    pub delegate: Identifier,

    pub after_revocations: Vec<Digest<Signed<StaticRevocation<T>>>>,
    pub after_content: BTreeMap<DocumentId, Vec<T>>,
}

impl<'a, T: ContentRef> From<Delegation<'a, T>> for StaticDelegation<T> {
    fn from(delegation: Delegation<'a, T>) -> Self {
        Self {
            can: delegation.can,
            proof: delegation.proof.map(|p| Digest::hash(&p).coerce()),
            delegate: delegation.delegate.id(),
            after_revocations: delegation
                .after_revocations
                .iter()
                .map(|revocation| Digest::hash(*revocation).coerce()) // FIXME remove coerce, add specific fincton for op <-> del
                .collect(),
            after_content: delegation
                .after_content
                .into_iter()
                .map(|(doc_id, (_, content))| (doc_id, content))
                .collect(),
        }
    }
}
