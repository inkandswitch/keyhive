use super::revocation::{Revocation, StaticRevocation};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        signed::{Signed, SigningError},
    },
    principal::{
        agent::{Agent, AgentId},
        document::{id::DocumentId, Document},
        identifier::Identifier,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, hash::Hash, rc::Rc};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation<T: ContentRef> {
    pub(crate) delegate: Agent<T>,
    pub(crate) can: Access,

    pub(crate) proof: Option<Rc<Signed<Delegation<T>>>>,
    pub(crate) after_revocations: Vec<Rc<Signed<Revocation<T>>>>,
    pub(crate) after_content: BTreeMap<DocumentId, (Rc<Document<T>>, Vec<T>)>,
}

impl<T: ContentRef> Delegation<T> {
    pub fn subject(&self, issuer: AgentId) -> Identifier {
        if let Some(proof) = &self.proof {
            proof.subject()
        } else {
            issuer.into()
        }
    }

    pub fn after(
        &self,
    ) -> (
        Vec<Rc<Signed<Delegation<T>>>>,
        Vec<Rc<Signed<Revocation<T>>>>,
        &BTreeMap<DocumentId, (Rc<Document<T>>, Vec<T>)>,
    ) {
        let (dlgs, revs) = self.after_auth();
        (
            dlgs.map(|d| vec![d]).unwrap_or(vec![]),
            revs.to_vec(),
            &self.after_content,
        )
    }

    pub fn after_auth(
        &self,
    ) -> (
        Option<Rc<Signed<Delegation<T>>>>,
        &[Rc<Signed<Revocation<T>>>],
    ) {
        (self.proof.clone(), &self.after_revocations)
    }

    pub fn is_root(&self) -> bool {
        self.proof.is_none()
    }
}

impl<T: ContentRef> Signed<Delegation<T>> {
    pub fn subject(&self) -> Identifier {
        let mut head = self;

        while let Some(parent) = &head.payload().proof {
            head = &parent;
        }

        head.id()
    }
}

// FIXME test FIXME just and compare?
// impl<'a, T: ContentRef> PartialOrd for Delegation<'a, T> {
//     fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
//         let self_after = self.after();
//         let other_after = other.after();
//
//         match self.can.partial_cmp(&other.can) {
//             Some(std::cmp::Ordering::Equal) => {
//                 match self
//                     .delegate
//                     .agent_id()
//                     .partial_cmp(&other.delegate.agent_id())
//                 {
//                     Some(std::cmp::Ordering::Equal) => {
//                         match self_after.0.len().partial_cmp(&other_after.0.len()) {
//                             Some(std::cmp::Ordering::Equal) => {
//                                 match self_after.1.len().partial_cmp(&other_after.1.len()) {
//                                     Some(std::cmp::Ordering::Equal) => {
//                                         let self_after = self_after
//                                             .0
//                                             .iter()
//                                             .map(|d| d.subject())
//                                             .collect::<Vec<_>>();
//                                         let other_after = other_after
//                                             .0
//                                             .iter()
//                                             .map(|d| d.subject())
//                                             .collect::<Vec<_>>();
//
//                                         self_after.partial_cmp(&other_after)
//                                     }
//                                     other => other,
//                                 }
//                             }
//                             other => other,
//                         }
//                     }
//                     other => other,
//                 }
//             }
//             other => other,
//         }
//     }
// }

impl<T: ContentRef> Serialize for Delegation<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // FIXME could be a heavy clone since this is used to hash
        // FIXME ...ooooor use the hash of teh static delehation as an ID... probably this actually
        StaticDelegation::from(self.clone()).serialize(serializer)
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

impl<T: ContentRef> From<Delegation<T>> for StaticDelegation<T> {
    fn from(delegation: Delegation<T>) -> Self {
        Self {
            can: delegation.can,
            proof: delegation.proof.map(|p| Digest::hash(p.as_ref()).coerce()),
            delegate: delegation.delegate.id(),
            after_revocations: delegation
                .after_revocations
                .iter()
                .map(|revocation| Digest::hash(revocation.as_ref()).coerce()) // FIXME remove coerce, add specific fincton for op <-> del
                .collect(),
            after_content: delegation
                .after_content
                .into_iter()
                .map(|(doc_id, (_, content))| (doc_id, content))
                .collect(),
        }
    }
}

/// Errors that can occur when using an active agent.
#[derive(Debug, Error)]
pub enum DelegationError {
    /// The active agent is trying to delegate a capability that they do not have.
    #[error("Rights escelation: attempted to delegate a capability that the active agent does not have.")]
    Escelation,

    /// Signature failed
    #[error("{0}")]
    SigningError(#[from] SigningError),
}
