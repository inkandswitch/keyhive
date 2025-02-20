use super::{
    dependencies::Dependencies,
    revocation::{Revocation, StaticRevocation},
};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        signed::{Signed, SigningError},
    },
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::{
        agent::{id::AgentId, Agent},
        document::id::DocumentId,
        identifier::Identifier,
    },
};
use derive_where::derive_where;
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, hash::Hash, rc::Rc};
use thiserror::Error;

#[derive(Debug, Clone)]
#[derive_where(PartialEq; T)]
pub struct Delegation<T: ContentRef = [u8; 32], L: MembershipListener<T> = NoListener> {
    pub(crate) delegate: Agent<T, L>,
    pub(crate) can: Access,

    pub(crate) proof: Option<Rc<Signed<Delegation<T, L>>>>,
    pub(crate) after_revocations: Vec<Rc<Signed<Revocation<T, L>>>>,
    pub(crate) after_content: BTreeMap<DocumentId, Vec<T>>,
}

impl<T: ContentRef, L: MembershipListener<T>> Eq for Delegation<T, L> {}

impl<T: ContentRef, L: MembershipListener<T>> Delegation<T, L> {
    pub fn subject_id(&self, issuer: AgentId) -> Identifier {
        if let Some(proof) = &self.proof {
            proof.subject_id()
        } else {
            issuer.into()
        }
    }

    pub fn delegate(&self) -> &Agent<T, L> {
        &self.delegate
    }

    pub fn can(&self) -> Access {
        self.can
    }

    pub fn proof(&self) -> Option<&Rc<Signed<Delegation<T, L>>>> {
        self.proof.as_ref()
    }

    pub fn after_revocations(&self) -> &[Rc<Signed<Revocation<T, L>>>] {
        &self.after_revocations
    }

    pub fn after(&self) -> Dependencies<T, L> {
        let AfterAuth {
            optional_delegation,
            revocations,
        } = self.after_auth();

        Dependencies {
            delegations: optional_delegation
                .map(|delegation| vec![delegation])
                .unwrap_or_default(),
            revocations: revocations.to_vec(),
            content: &self.after_content,
        }
    }

    pub fn after_auth(&self) -> AfterAuth<T, L> {
        AfterAuth {
            optional_delegation: self.proof.dupe(),
            revocations: &self.after_revocations,
        }
    }

    pub fn is_root(&self) -> bool {
        self.proof.is_none()
    }

    pub fn proof_lineage(&self) -> Vec<Rc<Signed<Delegation<T, L>>>> {
        let mut lineage = vec![];
        let mut head = self;

        while let Some(proof) = &head.proof {
            lineage.push(proof.dupe());
            head = proof.payload();
        }

        lineage
    }

    pub fn is_descendant_of(&self, maybe_ancestor: &Signed<Delegation<T, L>>) -> bool {
        let mut head = self;

        while let Some(proof) = &head.proof {
            if proof.as_ref() == maybe_ancestor {
                return true;
            }

            head = proof.payload();
        }

        false
    }

    pub fn is_ancestor_of(&self, maybe_descendant: &Signed<Delegation<T, L>>) -> bool {
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

impl<T: ContentRef, L: MembershipListener<T>> Signed<Delegation<T, L>> {
    pub fn subject_id(&self) -> Identifier {
        let mut head = self;

        while let Some(proof) = &head.payload.proof {
            head = proof;
        }

        head.issuer.into()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> Serialize for Delegation<T, L> {
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

impl<T: ContentRef, L: MembershipListener<T>> From<Delegation<T, L>> for StaticDelegation<T> {
    fn from(delegation: Delegation<T, L>) -> Self {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AfterAuth<'a, T: ContentRef = [u8; 32], L: MembershipListener<T> = NoListener> {
    pub(crate) optional_delegation: Option<Rc<Signed<Delegation<T, L>>>>,
    pub(crate) revocations: &'a [Rc<Signed<Revocation<T, L>>>],
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
