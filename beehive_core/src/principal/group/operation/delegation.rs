use super::revocation::{Revocation, StaticRevocation};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        signed::{Signed, SigningError},
    },
    principal::{
        agent::{id::AgentId, Agent},
        document::id::DocumentId,
        identifier::Identifier,
    },
};
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, hash::Hash, rc::Rc};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation<T: ContentRef> {
    pub(crate) delegate: Agent<T>,
    pub(crate) can: Access,

    pub(crate) proof: Option<Rc<Signed<Delegation<T>>>>,
    pub(crate) after_revocations: Vec<Rc<Signed<Revocation<T>>>>,
    pub(crate) after_content: BTreeMap<DocumentId, Vec<T>>,
}

impl<T: ContentRef> Delegation<T> {
    pub fn subject(&self, issuer: AgentId) -> Identifier {
        if let Some(proof) = &self.proof {
            proof.subject()
        } else {
            issuer.into()
        }
    }

    pub fn delegate(&self) -> &Agent<T> {
        &self.delegate
    }

    pub fn can(&self) -> Access {
        self.can
    }

    pub fn proof(&self) -> Option<&Rc<Signed<Delegation<T>>>> {
        self.proof.as_ref()
    }

    pub fn after_revocations(&self) -> &[Rc<Signed<Revocation<T>>>] {
        &self.after_revocations
    }

    pub fn after(
        &self,
    ) -> (
        Vec<Rc<Signed<Delegation<T>>>>,
        Vec<Rc<Signed<Revocation<T>>>>,
        &BTreeMap<DocumentId, Vec<T>>,
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
        (self.proof.dupe(), &self.after_revocations)
    }

    pub fn is_root(&self) -> bool {
        self.proof.is_none()
    }

    pub fn proof_lineage(&self) -> Vec<Rc<Signed<Delegation<T>>>> {
        let mut lineage = vec![];
        let mut head = self;

        while let Some(proof) = &head.proof {
            lineage.push(proof.dupe());
            head = proof.payload();
        }

        lineage
    }

    pub fn is_descendant_of(&self, maybe_ancestor: &Signed<Delegation<T>>) -> bool {
        let mut head = self;

        while let Some(proof) = &head.proof {
            if proof.as_ref() == maybe_ancestor {
                return true;
            }

            head = proof.payload();
        }

        false
    }

    pub fn is_ancestor_of(&self, maybe_descendant: &Signed<Delegation<T>>) -> bool {
        let mut head = maybe_descendant.payload();

        while let Some(proof) = &head.proof {
            if proof.as_ref().payload() == self {
                return true;
            }

            head = proof.payload();
        }

        false
    }
}

impl<T: ContentRef> Signed<Delegation<T>> {
    pub fn subject(&self) -> Identifier {
        let mut head = self;

        while let Some(parent) = &head.payload().proof {
            head = parent;
        }

        head.id()
    }
}

impl<T: ContentRef> Serialize for Delegation<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        StaticDelegation::from(self.clone()).serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
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
            proof: delegation.proof.map(|p| Digest::hash(p.as_ref()).into()),
            delegate: delegation.delegate.id(),
            after_revocations: delegation
                .after_revocations
                .iter()
                .map(|revocation| Digest::hash(revocation.as_ref()).into())
                .collect(),
            after_content: delegation.after_content,
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
