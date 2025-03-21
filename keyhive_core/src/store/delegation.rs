//! [`Delegation`] storage.

use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed, signer::async_signer::AsyncSigner},
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::group::delegation::Delegation,
    util::content_addressed_map::CaMap,
};
use dupe::Dupe;
use std::{cell::RefCell, rc::Rc};

/// [`Delegation`] storage.
#[allow(clippy::type_complexity)]
#[derive(Debug, Default, Clone, Dupe)]
pub struct DelegationStore<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
>(pub(crate) Rc<RefCell<CaMap<Signed<Delegation<S, T, L>>>>>);

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> DelegationStore<S, T, L> {
    /// Create a new delegation store.
    pub fn new() -> Self {
        Self(Rc::new(RefCell::new(CaMap::new())))
    }

    /// Retrieve a [`Delegation`] by its [`Digest`].
    pub fn get(
        &self,
        key: &Digest<Signed<Delegation<S, T, L>>>,
    ) -> Option<Rc<Signed<Delegation<S, T, L>>>> {
        let rc = self.0.dupe();
        let borrowed = RefCell::borrow(&rc);
        borrowed.get(key).cloned()
    }

    /// Check if a [`Digest`] is present in the store.
    pub fn contains_key(&self, key: &Digest<Signed<Delegation<S, T, L>>>) -> bool {
        let rc = self.0.dupe();
        let borrowed = RefCell::borrow(&rc);
        borrowed.contains_key(key)
    }

    /// Check if a [`Delegation`] is present in the store.
    pub fn contains_value(&self, value: &Signed<Delegation<S, T, L>>) -> bool {
        let rc = self.0.dupe();
        let borrowed = RefCell::borrow(&rc);
        borrowed.contains_value(value)
    }

    /// Remove a [`Delegation`] by its [`Digest`].
    pub fn remove_by_hash(
        &self,
        hash: &Digest<Signed<Delegation<S, T, L>>>,
    ) -> Option<Rc<Signed<Delegation<S, T, L>>>> {
        self.0.borrow_mut().remove_by_hash(hash)
    }

    /// Insert a [`Delegation`] into the store.
    pub fn insert(
        &self,
        delegation: Rc<Signed<Delegation<S, T, L>>>,
    ) -> Digest<Signed<Delegation<S, T, L>>> {
        self.0.borrow_mut().insert(delegation)
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> PartialEq
    for DelegationStore<S, T, L>
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Eq for DelegationStore<S, T, L> {}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> std::hash::Hash
    for DelegationStore<S, T, L>
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.borrow().hash(state);
    }
}
