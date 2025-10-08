//! [`Revocation`] storage.

use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed, signer::async_signer::AsyncSigner},
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::group::revocation::Revocation,
    util::content_addressed_map::CaMap,
};
use derive_where::derive_where;
use dupe::Dupe;
use futures::lock::Mutex;
use std::sync::Arc;

/// [`Revocation`] storage.
#[allow(clippy::type_complexity)]
#[derive(Default)]
#[derive_where(Debug, Clone; T)]
pub struct RevocationStore<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
>(pub Arc<Mutex<CaMap<Signed<Revocation<S, T, L>>>>>);

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> RevocationStore<S, T, L> {
    /// Create a new revocation store.
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(CaMap::new())))
    }

    /// Retrieve a [`Revocation`] by its [`Digest`].
    pub async fn get(
        &self,
        key: &Digest<Signed<Revocation<S, T, L>>>,
    ) -> Option<Arc<Signed<Revocation<S, T, L>>>> {
        let locked = self.0.lock().await;
        locked.get(key).cloned()
    }

    /// Check if a [`Digest`] is present in the store.
    pub async fn contains_key(&self, key: &Digest<Signed<Revocation<S, T, L>>>) -> bool {
        let locked = self.0.lock().await;
        locked.contains_key(key)
    }

    /// Check if a [`Revocation`] is present in the store.
    pub async fn contains_value(&self, value: &Signed<Revocation<S, T, L>>) -> bool {
        let locked = self.0.lock().await;
        locked.contains_value(value)
    }

    /// Insert a [`Revocation`] into the store.
    pub async fn insert(
        &self,
        revocation: Arc<Signed<Revocation<S, T, L>>>,
    ) -> Digest<Signed<Revocation<S, T, L>>> {
        let mut locked = self.0.lock().await;
        locked.insert(revocation)
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Dupe for RevocationStore<S, T, L> {
    fn dupe(&self) -> Self {
        Self(self.0.dupe())
    }
}
