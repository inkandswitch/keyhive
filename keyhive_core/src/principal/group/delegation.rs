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
        signer::async_signer::AsyncSigner,
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
use std::{collections::BTreeMap, hash::Hash, sync::Arc};
use thiserror::Error;

#[derive_where(Debug, Clone, PartialEq; T)]
pub struct Delegation<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    pub(crate) delegate: Agent<S, T, L>,
    pub(crate) can: Access,

    pub(crate) proof: Option<Arc<Signed<Delegation<S, T, L>>>>,
    pub(crate) after_revocations: Vec<Arc<Signed<Revocation<S, T, L>>>>,
    pub(crate) after_content: BTreeMap<DocumentId, Vec<T>>,
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Eq for Delegation<S, T, L> {}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Delegation<S, T, L> {
    pub fn subject_id(&self, issuer: AgentId) -> Identifier {
        if let Some(proof) = &self.proof {
            proof.subject_id()
        } else {
            issuer.into()
        }
    }

    pub fn delegate(&self) -> &Agent<S, T, L> {
        &self.delegate
    }

    pub fn can(&self) -> Access {
        self.can
    }

    #[allow(clippy::type_complexity)]
    pub fn proof(&self) -> Option<&Arc<Signed<Delegation<S, T, L>>>> {
        self.proof.as_ref()
    }

    #[allow(clippy::type_complexity)]
    pub fn after_revocations(&self) -> &[Arc<Signed<Revocation<S, T, L>>>] {
        &self.after_revocations
    }

    pub fn after(&self) -> Dependencies<'_, S, T, L> {
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

    pub fn after_auth(&self) -> AfterAuth<'_, S, T, L> {
        AfterAuth {
            optional_delegation: self.proof.dupe(),
            revocations: &self.after_revocations,
        }
    }

    pub fn is_root(&self) -> bool {
        self.proof.is_none()
    }

    pub fn proof_lineage(&self) -> Vec<Arc<Signed<Delegation<S, T, L>>>> {
        let mut lineage = vec![];
        let mut head = self;

        while let Some(proof) = &head.proof {
            lineage.push(proof.dupe());
            head = proof.payload();
        }

        lineage
    }

    pub fn is_descendant_of(&self, maybe_ancestor: &Signed<Delegation<S, T, L>>) -> bool {
        let mut head = self;

        while let Some(proof) = &head.proof {
            if proof.as_ref() == maybe_ancestor {
                return true;
            }

            head = proof.payload();
        }

        false
    }

    pub fn is_ancestor_of(&self, maybe_descendant: &Signed<Delegation<S, T, L>>) -> bool {
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

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Signed<Delegation<S, T, L>> {
    pub fn subject_id(&self) -> Identifier {
        let mut head = self;

        while let Some(proof) = &head.payload.proof {
            head = proof;
        }

        head.issuer.into()
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Serialize for Delegation<S, T, L> {
    fn serialize<Z: serde::Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
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

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, T: ContentRef + arbitrary::Arbitrary<'a>> arbitrary::Arbitrary<'a>
    for StaticDelegation<T>
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let can = Access::arbitrary(u)?;
        let proof = u.arbitrary()?;
        let delegate = Identifier::arbitrary(u)?;
        let after_revocations = u.arbitrary()?;
        let after_content = u.arbitrary()?;

        Ok(Self {
            can,
            proof,
            delegate,
            after_revocations,
            after_content,
        })
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<Delegation<S, T, L>>
    for StaticDelegation<T>
{
    fn from(delegation: Delegation<S, T, L>) -> Self {
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
pub struct AfterAuth<
    'a,
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    #[allow(clippy::type_complexity)]
    pub(crate) optional_delegation: Option<Arc<Signed<Delegation<S, T, L>>>>,

    #[allow(clippy::type_complexity)]
    pub(crate) revocations: &'a [Arc<Signed<Revocation<S, T, L>>>],
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
