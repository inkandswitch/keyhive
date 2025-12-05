//! [`Revocation`] storage.

use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed, signer::async_signer::AsyncSigner},
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::{agent::id::AgentId, group::revocation::Revocation},
    util::content_addressed_map::CaMap,
};
use derive_where::derive_where;
use dupe::Dupe;
use futures::lock::Mutex;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

/// [`Revocation`] storage.
#[allow(clippy::type_complexity)]
#[derive(Default)]
#[derive_where(Debug, Clone; T)]
pub struct RevocationStore<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    revocations: Arc<Mutex<CaMap<Signed<Revocation<S, T, L>>>>>,
    agent_to_revocations: Arc<Mutex<HashMap<AgentId, HashSet<Arc<Signed<Revocation<S, T, L>>>>>>>,
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> RevocationStore<S, T, L> {
    /// Create a new revocation store.
    pub fn new() -> Self {
        Self {
            revocations: Arc::new(Mutex::new(CaMap::new())),
            agent_to_revocations: Arc::new(Mutex::new(HashMap::default())),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn revocations(&self) -> &Arc<Mutex<CaMap<Signed<Revocation<S, T, L>>>>> {
        &self.revocations
    }

    pub async fn len(&self) -> usize {
        self.revocations.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Retrieve a [`Revocation`] by its [`Digest`].
    pub async fn get(
        &self,
        key: &Digest<Signed<Revocation<S, T, L>>>,
    ) -> Option<Arc<Signed<Revocation<S, T, L>>>> {
        let locked = self.revocations.lock().await;
        locked.get(key).cloned()
    }

    /// Check if a [`Digest`] is present in the store.
    pub async fn contains_key(&self, key: &Digest<Signed<Revocation<S, T, L>>>) -> bool {
        let locked = self.revocations.lock().await;
        locked.contains_key(key)
    }

    /// Check if a [`Revocation`] is present in the store.
    pub async fn contains_value(&self, value: &Signed<Revocation<S, T, L>>) -> bool {
        let locked = self.revocations.lock().await;
        locked.contains_value(value)
    }

    /// Insert a [`Revocation`] into the store.
    #[allow(clippy::mutable_key_type)]
    pub async fn insert(
        &self,
        revocation: Arc<Signed<Revocation<S, T, L>>>,
    ) -> Digest<Signed<Revocation<S, T, L>>> {
        let mut locked_revocations = self.revocations.lock().await;
        let digest = locked_revocations.insert(revocation.dupe());
        let mut agent_to_revocations = self.agent_to_revocations.lock().await;
        let agent_id = revocation.payload.revoke.payload.delegate().agent_id();
        agent_to_revocations
            .entry(agent_id)
            .or_default()
            .insert(revocation);
        digest
    }

    /// Get all [`Revocation`]s for a given [`AgentId`].
    pub async fn get_revocations_for_agent(
        &self,
        agent_id: &AgentId,
    ) -> Option<HashSet<Arc<Signed<Revocation<S, T, L>>>>> {
        let agent_to_revocations = self.agent_to_revocations.lock().await;
        agent_to_revocations.get(agent_id).cloned()
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Dupe for RevocationStore<S, T, L> {
    fn dupe(&self) -> Self {
        Self {
            revocations: self.revocations.dupe(),
            agent_to_revocations: self.agent_to_revocations.dupe(),
        }
    }
}
