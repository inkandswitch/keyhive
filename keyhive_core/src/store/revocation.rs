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

#[allow(clippy::type_complexity)]
#[derive(Default)]
#[derive_where(Debug, Clone; T)]
pub struct RevocationStore<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
>(pub Rc<RefCell<CaMap<Signed<Revocation<S, T, L>>>>>);

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> RevocationStore<S, T, L> {
    pub fn new() -> Self {
        Self(Rc::new(RefCell::new(CaMap::new())))
    }

    pub fn get(
        &self,
        key: &Digest<Signed<Revocation<S, T, L>>>,
    ) -> Option<Rc<Signed<Revocation<S, T, L>>>> {
        self.borrow().get(key).cloned()
    }

    pub fn contains_key(&self, key: &Digest<Signed<Revocation<S, T, L>>>) -> bool {
        self.borrow().contains_key(key)
    }

    pub fn contains_value(&self, value: &Signed<Revocation<S, T, L>>) -> bool {
        let rc = self.0.dupe();
        let borrowed = RefCell::borrow(&rc);
        borrowed.contains_value(value)
    }

    pub fn remove_by_hash(
        &self,
        hash: &Digest<Signed<Revocation<S, T, L>>>,
    ) -> Option<Rc<Signed<Revocation<S, T, L>>>> {
        self.0.borrow_mut().remove_by_hash(hash)
    }

    pub fn insert(
        &self,
        revocation: Rc<Signed<Revocation<S, T, L>>>,
    ) -> Digest<Signed<Revocation<S, T, L>>> {
        self.0.borrow_mut().insert(revocation)
    }

    pub fn borrow(&self) -> Ref<CaMap<Signed<Revocation<S, T, L>>>> {
        self.0.borrow()
    }

    pub fn borrow_mut(&self) -> RefMut<CaMap<Signed<Revocation<S, T, L>>>> {
        self.0.borrow_mut()
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Dupe for RevocationStore<S, T, L> {
    fn dupe(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> PartialEq
    for RevocationStore<S, T, L>
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Eq for RevocationStore<S, T, L> {}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> std::hash::Hash
    for RevocationStore<S, T, L>
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.borrow().hash(state);
    }
}
