//! [`Delegation`] storage.

use super::secret_key::traits::ShareSecretStore;
use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed, signer::async_signer::AsyncSigner},
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::group::delegation::Delegation,
    util::content_addressed_map::CaMap,
};
use derive_where::derive_where;
use dupe::Dupe;
use std::{cell::Ref, cell::RefCell, rc::Rc};

/// [`Delegation`] storage.
#[allow(clippy::type_complexity)]
#[derive(Default)]
#[derive_where(Clone, Debug; T)]
pub struct DelegationStore<
    S: AsyncSigner,
    K: ShareSecretStore,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, K, T> = NoListener,
>(pub(crate) Rc<RefCell<CaMap<Signed<Delegation<S, K, T, L>>>>>);

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    DelegationStore<S, K, T, L>
{
    /// Create a new delegation store.
    pub fn new() -> Self {
        Self(Rc::new(RefCell::new(CaMap::new())))
    }

    /// Retrieve a [`Delegation`] by its [`Digest`].
    pub fn get(
        &self,
        key: &Digest<Signed<Delegation<S, K, T, L>>>,
    ) -> Option<Rc<Signed<Delegation<S, K, T, L>>>> {
        let rc = self.0.dupe();
        let borrowed = RefCell::borrow(&rc);
        borrowed.get(key).cloned()
    }

    /// Check if a [`Digest`] is present in the store.
    pub fn contains_key(&self, key: &Digest<Signed<Delegation<S, K, T, L>>>) -> bool {
        let rc = self.0.dupe();
        let borrowed = RefCell::borrow(&rc);
        borrowed.contains_key(key)
    }

    /// Check if a [`Delegation`] is present in the store.
    pub fn contains_value(&self, value: &Signed<Delegation<S, K, T, L>>) -> bool {
        let rc = self.0.dupe();
        let borrowed = RefCell::borrow(&rc);
        borrowed.contains_value(value)
    }

    /// Insert a [`Delegation`] into the store.
    pub fn insert(
        &self,
        delegation: Rc<Signed<Delegation<S, K, T, L>>>,
    ) -> Digest<Signed<Delegation<S, K, T, L>>> {
        self.0.borrow_mut().insert(delegation)
    }

    pub fn borrow(&self) -> Ref<CaMap<Signed<Delegation<S, K, T, L>>>> {
        self.0.borrow()
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> PartialEq
    for DelegationStore<S, K, T, L>
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Eq
    for DelegationStore<S, K, T, L>
{
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    std::hash::Hash for DelegationStore<S, K, T, L>
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.borrow().hash(state);
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Dupe
    for DelegationStore<S, K, T, L>
{
    fn dupe(&self) -> Self {
        Self(self.0.dupe())
    }
}
