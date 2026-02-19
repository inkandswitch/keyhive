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
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

/// [`Revocation`] storage.
#[allow(clippy::type_complexity)]
#[derive(Default)]
#[derive_where(Debug, Clone, Hash; T)]
pub struct RevocationStore<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    revocations: CaMap<Signed<Revocation<S, T, L>>>,
    #[derive_where(skip(Hash))]
    agent_to_revocations: HashMap<AgentId, HashSet<Arc<Signed<Revocation<S, T, L>>>>>,
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> RevocationStore<S, T, L> {
    /// Create a new revocation store.
    pub fn new() -> Self {
        Self {
            revocations: CaMap::new(),
            agent_to_revocations: HashMap::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.revocations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Retrieve a [`Revocation`] by its [`Digest`].
    pub fn get(
        &self,
        key: &Digest<Signed<Revocation<S, T, L>>>,
    ) -> Option<Arc<Signed<Revocation<S, T, L>>>> {
        self.revocations.get(key).cloned()
    }

    /// Check if a [`Digest`] is present in the store.
    pub fn contains_key(&self, key: &Digest<Signed<Revocation<S, T, L>>>) -> bool {
        self.revocations.contains_key(key)
    }

    /// Check if a [`Revocation`] is present in the store.
    pub fn contains_value(&self, value: &Signed<Revocation<S, T, L>>) -> bool {
        self.revocations.contains_value(value)
    }

    /// Insert a [`Revocation`] into the store.
    #[allow(clippy::mutable_key_type)]
    pub fn insert(
        &mut self,
        revocation: Arc<Signed<Revocation<S, T, L>>>,
    ) -> Digest<Signed<Revocation<S, T, L>>> {
        let digest = self.revocations.insert(revocation.dupe());
        let agent_id = revocation.payload.revoke.payload.delegate().agent_id();
        self.agent_to_revocations
            .entry(agent_id)
            .or_default()
            .insert(revocation);
        digest
    }

    /// Remove a [`Revocation`] by its [`Digest`].
    #[allow(clippy::mutable_key_type)]
    pub fn remove_by_hash(
        &mut self,
        hash: &Digest<Signed<Revocation<S, T, L>>>,
    ) -> Option<Arc<Signed<Revocation<S, T, L>>>> {
        if let Some(revocation) = self.revocations.remove_by_hash(hash) {
            let agent_id = revocation.payload.revoke.payload.delegate().agent_id();
            if let Some(revocations_set) = self.agent_to_revocations.get_mut(&agent_id) {
                revocations_set.remove(&revocation);
                if revocations_set.is_empty() {
                    self.agent_to_revocations.remove(&agent_id);
                }
            }
            Some(revocation)
        } else {
            None
        }
    }

    /// Get all [`Revocation`]s for a given [`AgentId`].
    #[allow(clippy::type_complexity)]
    pub fn get_revocations_for_agent(
        &self,
        agent_id: &AgentId,
    ) -> Option<HashSet<Arc<Signed<Revocation<S, T, L>>>>> {
        self.agent_to_revocations.get(agent_id).cloned()
    }

    /// Iterate over all [`Revocation`]s in the store.
    #[allow(clippy::type_complexity)]
    pub fn values(
        &self,
    ) -> std::collections::hash_map::Values<
        '_,
        Digest<Signed<Revocation<S, T, L>>>,
        Arc<Signed<Revocation<S, T, L>>>,
    > {
        self.revocations.values()
    }

    /// Iterate over all keys in the store.
    #[allow(clippy::type_complexity)]
    pub fn keys(
        &self,
    ) -> std::collections::hash_map::Keys<
        '_,
        Digest<Signed<Revocation<S, T, L>>>,
        Arc<Signed<Revocation<S, T, L>>>,
    > {
        self.revocations.keys()
    }

    /// Iterate over all key-value pairs in the store.
    #[allow(clippy::type_complexity)]
    pub fn iter(
        &self,
    ) -> impl Iterator<
        Item = (
            &Digest<Signed<Revocation<S, T, L>>>,
            &Arc<Signed<Revocation<S, T, L>>>,
        ),
    > {
        self.revocations.iter()
    }

    /// Create a [`RevocationStore`] from an iterator of [`Revocation`]s.
    #[allow(clippy::mutable_key_type)]
    pub fn from_iter_direct(
        iter: impl IntoIterator<Item = Arc<Signed<Revocation<S, T, L>>>>,
    ) -> Self {
        let mut store = Self::new();
        for revocation in iter {
            store.insert(revocation);
        }
        store
    }
}
