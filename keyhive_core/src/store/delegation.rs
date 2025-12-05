//! [`Delegation`] storage.

use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed, signer::async_signer::AsyncSigner},
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::group::delegation::Delegation,
    util::content_addressed_map::CaMap,
};
use derive_where::derive_where;
use dupe::Dupe;
use futures::lock::Mutex;
use std::sync::Arc;

/// [`Delegation`] storage.
#[allow(clippy::type_complexity)]
#[derive(Default)]
#[derive_where(Clone, Debug; T)]
pub struct DelegationStore<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    delegations: Arc<Mutex<CaMap<Signed<Delegation<S, T, L>>>>>,
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> DelegationStore<S, T, L> {
    /// Create a new delegation store.
    pub fn new() -> Self {
        Self {
            delegations: Arc::new(Mutex::new(CaMap::new())),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn delegations(&self) -> &Arc<Mutex<CaMap<Signed<Delegation<S, T, L>>>>> {
        &self.delegations
    }

    pub async fn len(&self) -> usize {
        self.delegations.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Retrieve a [`Delegation`] by its [`Digest`].
    pub async fn get(
        &self,
        key: &Digest<Signed<Delegation<S, T, L>>>,
    ) -> Option<Arc<Signed<Delegation<S, T, L>>>> {
        let locked = self.delegations.lock().await;
        locked.get(key).cloned()
    }

    /// Check if a [`Digest`] is present in the store.
    pub async fn contains_key(&self, key: &Digest<Signed<Delegation<S, T, L>>>) -> bool {
        let locked = self.delegations.lock().await;
        locked.contains_key(key)
    }

    /// Check if a [`Delegation`] is present in the store.
    pub async fn contains_value(&self, value: &Signed<Delegation<S, T, L>>) -> bool {
        let locked = self.delegations.lock().await;
        locked.contains_value(value)
    }

    /// Insert a [`Delegation`] into the store.
    pub async fn insert(
        &self,
        delegation: Arc<Signed<Delegation<S, T, L>>>,
    ) -> Digest<Signed<Delegation<S, T, L>>> {
        let mut locked = self.delegations.lock().await;
        locked.insert(delegation)
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Dupe for DelegationStore<S, T, L> {
    fn dupe(&self) -> Self {
        Self {
            delegations: self.delegations.dupe(),
        }
    }
}
