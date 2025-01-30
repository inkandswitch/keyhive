use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed},
    listener::membership::MembershipListener,
    principal::group::delegation::Delegation,
    util::content_addressed_map::CaMap,
};
use dupe::Dupe;
use std::{
    cell::{Ref, RefCell, RefMut},
    rc::Rc,
};

#[derive(Debug, Clone, Default)]
#[allow(clippy::type_complexity)]
pub struct DelegationStore<T: ContentRef, L: MembershipListener<T>>(
    pub Rc<RefCell<CaMap<Signed<Delegation<T, L>>>>>,
);

impl<T: ContentRef, L: MembershipListener<T>> DelegationStore<T, L> {
    pub fn new() -> Self {
        Self(Rc::new(RefCell::new(CaMap::new())))
    }
    pub fn get(
        &self,
        key: &Digest<Signed<Delegation<T, L>>>,
    ) -> Option<Rc<Signed<Delegation<T, L>>>> {
        let rc = self.0.dupe();
        let borrowed = RefCell::borrow(&rc);
        borrowed.get(key).cloned()
    }

    pub fn contains_key(&self, key: &Digest<Signed<Delegation<T, L>>>) -> bool {
        let rc = self.0.dupe();
        let borrowed = RefCell::borrow(&rc);
        borrowed.contains_key(key)
    }

    pub fn contains_value(&self, value: &Signed<Delegation<T, L>>) -> bool {
        let rc = self.0.dupe();
        let borrowed = RefCell::borrow(&rc);
        borrowed.contains_value(value)
    }

    pub fn remove_by_hash(
        &self,
        hash: &Digest<Signed<Delegation<T, L>>>,
    ) -> Option<Rc<Signed<Delegation<T, L>>>> {
        self.0.borrow_mut().remove_by_hash(hash)
    }

    pub fn insert(
        &self,
        revocation: Rc<Signed<Delegation<T, L>>>,
    ) -> Digest<Signed<Delegation<T, L>>> {
        self.0.borrow_mut().insert(revocation)
    }

    pub fn borrow(&self) -> Ref<CaMap<Signed<Delegation<T, L>>>> {
        self.0.borrow()
    }

    pub fn borrow_mut(&self) -> RefMut<CaMap<Signed<Delegation<T, L>>>> {
        self.0.borrow_mut()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> Dupe for DelegationStore<T, L> {
    fn dupe(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<T: ContentRef, L: MembershipListener<T>> PartialEq for DelegationStore<T, L> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: ContentRef, L: MembershipListener<T>> Eq for DelegationStore<T, L> {}

impl<T: ContentRef, L: MembershipListener<T>> std::hash::Hash for DelegationStore<T, L> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.borrow().hash(state);
    }
}
