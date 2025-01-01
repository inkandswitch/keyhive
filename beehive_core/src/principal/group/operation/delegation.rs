use super::revocation::{Revocation, StaticRevocation};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        signed::{Signed, SigningError},
        signer::ed_signer::EdSigner,
    },
    principal::{
        agent::{Agent, AgentId},
        document::{id::DocumentId, Document},
        identifier::Identifier,
    },
};
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, collections::BTreeMap, hash::Hash, rc::Rc};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation<T: ContentRef, S: EdSigner> {
    pub(crate) delegate: Agent<T, S>,
    pub(crate) can: Access,

    pub(crate) proof: Option<Rc<Signed<Delegation<T, S>>>>,
    pub(crate) after_revocations: Vec<Rc<Signed<Revocation<T, S>>>>,
    pub(crate) after_content: BTreeMap<DocumentId, (Rc<RefCell<Document<T, S>>>, Vec<T>)>,
}

impl<T: ContentRef, S: EdSigner> Delegation<T, S> {
    pub fn subject(&self, issuer: AgentId) -> Identifier {
        if let Some(proof) = &self.proof {
            proof.subject()
        } else {
            issuer.into()
        }
    }

    pub fn delegate(&self) -> &Agent<T, S> {
        &self.delegate
    }

    pub fn can(&self) -> Access {
        self.can
    }

    pub fn proof(&self) -> Option<&Rc<Signed<Delegation<T, S>>>> {
        self.proof.as_ref()
    }

    pub fn after(
        &self,
    ) -> (
        Vec<Rc<Signed<Delegation<T, S>>>>,
        Vec<Rc<Signed<Revocation<T, S>>>>,
        &BTreeMap<DocumentId, (Rc<RefCell<Document<T, S>>>, Vec<T>)>,
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
        Option<Rc<Signed<Delegation<T, S>>>>,
        &[Rc<Signed<Revocation<T, S>>>],
    ) {
        (self.proof.dupe(), &self.after_revocations)
    }

    pub fn is_root(&self) -> bool {
        self.proof.is_none()
    }
}

impl<T: ContentRef, S: EdSigner> Signed<Delegation<T, S>> {
    pub fn subject(&self) -> Identifier {
        let mut head = self;

        while let Some(parent) = &head.payload().proof {
            head = parent;
        }

        head.id()
    }
}

impl<T: ContentRef, S: EdSigner> Serialize for Delegation<T, S> {
    fn serialize<Ser: serde::Serializer>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error> {
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

impl<T: ContentRef, S: EdSigner> From<Delegation<T, S>> for StaticDelegation<T> {
    fn from(delegation: Delegation<T, S>) -> Self {
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
    #[error("Rights escalation: attempted to delegate a capability that the active agent does not have.")]
    Escalation,

    /// Signature failed
    #[error("{0}")]
    SigningError(#[from] SigningError),
}
