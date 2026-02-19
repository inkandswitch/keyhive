use super::{
    delegation::{Delegation, StaticDelegation},
    dependencies::Dependencies,
};
use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed, signer::async_signer::{AsyncSigner, AsyncSignerLocal, AsyncSignerSend}},
    listener::membership::MembershipListener,
    principal::{agent::id::AgentId, document::id::DocumentId, identifier::Identifier},
};
use derive_where::derive_where;
use dupe::Dupe;
use future_form::{FutureForm, Local, Sendable};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

#[derive(PartialEq, Eq)]
#[derive_where(Debug, Clone; T)]
pub struct Revocation<K: FutureForm + ?Sized, S: AsyncSigner<K>, T: ContentRef, L: MembershipListener<K, S, T>> {
    pub(crate) revoke: Arc<Signed<Delegation<K, S, T, L>>>,
    pub(crate) proof: Option<Arc<Signed<Delegation<K, S, T, L>>>>,
    pub(crate) after_content: BTreeMap<DocumentId, Vec<T>>,
}

impl<K: FutureForm + ?Sized, S: AsyncSigner<K>, T: ContentRef, L: MembershipListener<K, S, T>> Revocation<K, S, T, L> {
    pub fn subject_id(&self) -> Identifier {
        self.revoke.subject_id()
    }

    pub fn revoked(&self) -> &Arc<Signed<Delegation<K, S, T, L>>> {
        &self.revoke
    }

    pub fn revoked_id(&self) -> AgentId {
        self.revoke.payload().delegate.agent_id()
    }

    pub fn proof(&self) -> Option<Arc<Signed<Delegation<K, S, T, L>>>> {
        self.proof.dupe()
    }

    pub fn after(&self) -> Dependencies<'_, K, S, T, L> {
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

impl<K: FutureForm + ?Sized, S: AsyncSigner<K>, T: ContentRef, L: MembershipListener<K, S, T>> Signed<Revocation<K, S, T, L>> {
    pub fn subject_id(&self) -> Identifier {
        self.payload.subject_id()
    }
}

impl<K: FutureForm + ?Sized, S: AsyncSigner<K>, T: ContentRef, L: MembershipListener<K, S, T>> std::hash::Hash
    for Revocation<K, S, T, L>
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.revoke.hash(state);
        self.proof.hash(state);

        let mut vec = self.after_content.iter().collect::<Vec<_>>();
        vec.sort_by_key(|(doc_id, _)| *doc_id);
        vec.hash(state);
    }
}

macro_rules! impl_serialize_revocation {
    (sendable) => {
        impl<
            S: AsyncSignerSend + Send + Sync,
            T: ContentRef,
            L: MembershipListener<Sendable, S, T> + Send + Sync,
        > Serialize for Revocation<Sendable, S, T, L> {
            impl_serialize_revocation!(@body Sendable);
        }
    };
    (local) => {
        impl<
            S: AsyncSignerLocal,
            T: ContentRef,
            L: MembershipListener<Local, S, T>,
        > Serialize for Revocation<Local, S, T, L> {
            impl_serialize_revocation!(@body Local);
        }
    };
    (@body $K:ty) => {
        fn serialize<Z: serde::Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
            StaticRevocation::from(self.clone()).serialize(serializer)
        }
    };
}

impl_serialize_revocation!(sendable);
impl_serialize_revocation!(local);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct StaticRevocation<T: ContentRef> {
    /// The [`Delegation`] being revoked.
    pub revoke: Digest<Signed<StaticDelegation<T>>>,

    /// Proof that the revoker is allowed to perform this revocation.
    pub proof: Option<Digest<Signed<StaticDelegation<T>>>>,

    /// The heads of relevant [`Document`] content at time of revocation.
    pub after_content: BTreeMap<DocumentId, Vec<T>>,
}

macro_rules! impl_from_revocation_for_static {
    (sendable) => {
        impl<S: AsyncSignerSend + Send + Sync, T: ContentRef, L: MembershipListener<Sendable, S, T> + Send + Sync> From<Revocation<Sendable, S, T, L>> for StaticRevocation<T> {
            impl_from_revocation_for_static!(@body Sendable);
        }
    };
    (local) => {
        impl<S: AsyncSignerLocal, T: ContentRef, L: MembershipListener<Local, S, T>> From<Revocation<Local, S, T, L>> for StaticRevocation<T> {
            impl_from_revocation_for_static!(@body Local);
        }
    };
    (@body $K:ty) => {
        fn from(revocation: Revocation<$K, S, T, L>) -> Self {
            Self {
                revoke: Digest::hash(revocation.revoke.as_ref()).into(),
                proof: revocation.proof.map(|p| Digest::hash(p.as_ref()).into()),
                after_content: revocation.after_content,
            }
        }
    };
}

impl_from_revocation_for_static!(sendable);
impl_from_revocation_for_static!(local);
