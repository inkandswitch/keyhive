//! [`Revocation`] storage.

use super::secret_key::traits::ShareSecretStore;
use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed, signer::async_signer::AsyncSigner},
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::group::revocation::Revocation,
    util::content_addressed_map::CaMap,
};
use derive_where::derive_where;
use dupe::Dupe;
use std::{
    cell::{Ref, RefCell, RefMut},
    rc::Rc,
};

/// [`Revocation`] storage.
#[allow(clippy::type_complexity)]
#[derive(Default)]
#[derive_where(Debug, Clone; T)]
pub struct RevocationStore<
    S: AsyncSigner,
    K: ShareSecretStore,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, K, T> = NoListener,
>(pub Rc<RefCell<CaMap<Signed<Revocation<S, K, T, L>>>>>);

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    RevocationStore<S, K, T, L>
{
    /// Create a new revocation store.
    pub fn new() -> Self {
        Self(Rc::new(RefCell::new(CaMap::new())))
    }

    /// Retrieve a [`Revocation`] by its [`Digest`].
    pub fn get(
        &self,
        key: &Digest<Signed<Revocation<S, K, T, L>>>,
    ) -> Option<Rc<Signed<Revocation<S, K, T, L>>>> {
        self.borrow().get(key).cloned()
    }

    /// Check if a [`Digest`] is present in the store.
    pub fn contains_key(&self, key: &Digest<Signed<Revocation<S, K, T, L>>>) -> bool {
        self.borrow().contains_key(key)
    }

    /// Check if a [`Revocation`] is present in the store.
    pub fn contains_value(&self, value: &Signed<Revocation<S, K, T, L>>) -> bool {
        let rc = self.0.dupe();
        let borrowed = RefCell::borrow(&rc);
        borrowed.contains_value(value)
    }

    /// Insert a [`Revocation`] into the store.
    pub fn insert(
        &self,
        revocation: Rc<Signed<Revocation<S, K, T, L>>>,
    ) -> Digest<Signed<Revocation<S, K, T, L>>> {
        self.0.borrow_mut().insert(revocation)
    }

    /// Get an immutable reference to the underlying [`CaMap`].
    pub fn borrow(&self) -> Ref<CaMap<Signed<Revocation<S, K, T, L>>>> {
        self.0.borrow()
    }

    /// Get a mutable reference to the underlying [`CaMap`].
    pub fn borrow_mut(&self) -> RefMut<CaMap<Signed<Revocation<S, K, T, L>>>> {
        self.0.borrow_mut()
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Dupe
    for RevocationStore<S, K, T, L>
{
    fn dupe(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> PartialEq
    for RevocationStore<S, K, T, L>
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Eq
    for RevocationStore<S, K, T, L>
{
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    std::hash::Hash for RevocationStore<S, K, T, L>
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.borrow().hash(state);
    }
}
