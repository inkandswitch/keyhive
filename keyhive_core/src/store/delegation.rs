//! [`Delegation`] storage.

use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed, signer::async_signer::AsyncSigner},
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::group::delegation::Delegation,
    util::content_addressed_map::CaMap,
};
use derive_where::derive_where;
use std::sync::Arc;

/// [`Delegation`] storage.
#[allow(clippy::type_complexity)]
#[derive(Default)]
#[derive_where(Clone, Debug, Hash; T)]
pub struct DelegationStore<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    delegations: CaMap<Signed<Delegation<S, T, L>>>,
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> DelegationStore<S, T, L> {
    /// Create a new delegation store.
    pub fn new() -> Self {
        Self {
            delegations: CaMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.delegations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Retrieve a [`Delegation`] by its [`Digest`].
    pub fn get(
        &self,
        key: &Digest<Signed<Delegation<S, T, L>>>,
    ) -> Option<Arc<Signed<Delegation<S, T, L>>>> {
        self.delegations.get(key).cloned()
    }

    /// Check if a [`Digest`] is present in the store.
    pub fn contains_key(&self, key: &Digest<Signed<Delegation<S, T, L>>>) -> bool {
        self.delegations.contains_key(key)
    }

    /// Check if a [`Delegation`] is present in the store.
    pub fn contains_value(&self, value: &Signed<Delegation<S, T, L>>) -> bool {
        self.delegations.contains_value(value)
    }

    /// Insert a [`Delegation`] into the store.
    pub fn insert(
        &mut self,
        delegation: Arc<Signed<Delegation<S, T, L>>>,
    ) -> Digest<Signed<Delegation<S, T, L>>> {
        self.delegations.insert(delegation)
    }

    /// Remove a [`Delegation`] by its [`Digest`].
    pub fn remove_by_hash(
        &mut self,
        hash: &Digest<Signed<Delegation<S, T, L>>>,
    ) -> Option<Arc<Signed<Delegation<S, T, L>>>> {
        self.delegations.remove_by_hash(hash)
    }

    /// Iterate over all [`Delegation`]s in the store.
    #[allow(clippy::type_complexity)]
    pub fn values(
        &self,
    ) -> std::collections::hash_map::Values<
        '_,
        Digest<Signed<Delegation<S, T, L>>>,
        Arc<Signed<Delegation<S, T, L>>>,
    > {
        self.delegations.values()
    }

    /// Iterate over all keys in the store.
    #[allow(clippy::type_complexity)]
    pub fn keys(
        &self,
    ) -> std::collections::hash_map::Keys<
        '_,
        Digest<Signed<Delegation<S, T, L>>>,
        Arc<Signed<Delegation<S, T, L>>>,
    > {
        self.delegations.keys()
    }

    /// Iterate over all key-value pairs in the store.
    #[allow(clippy::type_complexity)]
    pub fn iter(
        &self,
    ) -> impl Iterator<
        Item = (
            &Digest<Signed<Delegation<S, T, L>>>,
            &Arc<Signed<Delegation<S, T, L>>>,
        ),
    > {
        self.delegations.iter()
    }

    /// Create a [`DelegationStore`] from an iterator of [`Delegation`]s.
    pub fn from_iter_direct(
        iter: impl IntoIterator<Item = Arc<Signed<Delegation<S, T, L>>>>,
    ) -> Self {
        let mut store = Self::new();
        for delegation in iter {
            store.insert(delegation);
        }
        store
    }
}
