use super::{
    delegation::{Delegation, StaticDelegation},
    dependencies::Dependencies,
};
use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed, signer::async_signer::AsyncSigner},
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::{agent::id::AgentId, document::id::DocumentId, identifier::Identifier},
};
use derive_where::derive_where;
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

#[derive(PartialEq, Eq)]
#[derive_where(Debug, Clone; T)]
pub struct Revocation<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    pub(crate) revoke: Arc<Signed<Delegation<S, T, L>>>,
    pub(crate) proof: Option<Arc<Signed<Delegation<S, T, L>>>>,
    pub(crate) after_content: BTreeMap<DocumentId, Vec<T>>,
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Revocation<S, T, L> {
    pub fn subject_id(&self) -> Identifier {
        self.revoke.subject_id()
    }

    pub fn revoked(&self) -> &Arc<Signed<Delegation<S, T, L>>> {
        &self.revoke
    }

    pub fn revoked_id(&self) -> AgentId {
        self.revoke.payload().delegate.agent_id()
    }

    pub fn proof(&self) -> Option<Arc<Signed<Delegation<S, T, L>>>> {
        self.proof.dupe()
    }

    pub fn after(&self) -> Dependencies<'_, S, T, L> {
        let mut delegations = vec![self.revoke.dupe()];
        if let Some(dlg) = &self.proof {
            delegations.push(dlg.clone());
        }

        Dependencies {
            delegations,
            revocations: vec![],
            content: &self.after_content,
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Signed<Revocation<S, T, L>> {
    pub fn subject_id(&self) -> Identifier {
        self.payload.subject_id()
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> std::hash::Hash
    for Revocation<S, T, L>
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.revoke.hash(state);
        self.proof.hash(state);

        let mut vec = self.after_content.iter().collect::<Vec<_>>();
        vec.sort_by_key(|(doc_id, _)| *doc_id);
        vec.hash(state);
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Serialize for Revocation<S, T, L> {
    fn serialize<Z: serde::Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
        StaticRevocation::from(self.clone()).serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct StaticRevocation<T: ContentRef = [u8; 32]> {
    /// The [`Delegation`] being revoked.
    pub revoke: Digest<Signed<StaticDelegation<T>>>,

    /// Proof that the revoker is allowed to perform this revocation.
    pub proof: Option<Digest<Signed<StaticDelegation<T>>>>,

    /// The heads of relevant [`Document`] content at time of revocation.
    pub after_content: BTreeMap<DocumentId, Vec<T>>,
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<Revocation<S, T, L>>
    for StaticRevocation<T>
{
    fn from(revocation: Revocation<S, T, L>) -> Self {
        Self {
            revoke: Digest::hash(revocation.revoke.as_ref()).into(),
            proof: revocation.proof.map(|p| Digest::hash(p.as_ref()).into()),
            after_content: revocation.after_content,
        }
    }
}
