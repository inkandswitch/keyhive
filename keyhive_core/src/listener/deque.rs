use super::{membership::MembershipListener, prekey::PrekeyListener};
use crate::{
    content::reference::ContentRef,
    crypto::{signed::Signed, signer::async_signer::AsyncSigner},
    event::Event,
    principal::{
        group::{delegation::Delegation, revocation::Revocation},
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
    },
};
use derive_more::{From, Into};
use dupe::Dupe;
use std::{
    cell::RefCell,
    collections::VecDeque,
    hash::{Hash, Hasher},
    rc::Rc,
};

#[derive(Debug, Default, PartialEq, Eq, From, Into)]
pub struct Deque<S: AsyncSigner, T: ContentRef = [u8; 32]>(
    #[allow(clippy::type_complexity)] pub Rc<RefCell<VecDeque<Event<S, T, Deque<S, T>>>>>,
);

impl<S: AsyncSigner, T: ContentRef> Deque<S, T> {
    pub fn push(&self, event: Event<S, T, Self>) {
        let rc = self.0.dupe();
        let mut deq = (*rc).borrow_mut();
        deq.push_back(event)
    }

    pub fn pop_latest(&self) -> Option<Event<S, T, Self>> {
        let rc = self.0.dupe();
        let mut deq = (*rc).borrow_mut();
        deq.pop_front()
    }

    pub fn pop_earliest(&self) -> Option<Event<S, T, Self>> {
        let rc = self.0.dupe();
        let mut deq = (*rc).borrow_mut();
        deq.pop_back()
    }

    pub fn is_empty(&self) -> bool {
        self.0.borrow().is_empty()
    }

    pub fn clear(&self) {
        let rc = self.0.dupe();
        let mut deq = (*rc).borrow_mut();
        deq.clear()
    }
}

impl<S: AsyncSigner, T: ContentRef> Clone for Deque<S, T> {
    fn clone(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<S: AsyncSigner, T: ContentRef> Dupe for Deque<S, T> {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<S: AsyncSigner, T: ContentRef> Hash for Deque<S, T>
where
    Event<S, T, Deque<S, T>>: Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.borrow().hash(state)
    }
}

impl<S: AsyncSigner, T: ContentRef> PrekeyListener for Deque<S, T> {
    async fn on_prekeys_expanded(&self, new_prekey: &Rc<Signed<AddKeyOp>>) {
        self.push(Event::PrekeysExpanded(new_prekey.dupe()))
    }

    async fn on_prekey_rotated(&self, rotate_key: &Rc<Signed<RotateKeyOp>>) {
        self.push(Event::PrekeyRotated(rotate_key.dupe()))
    }
}

impl<S: AsyncSigner, T: ContentRef> MembershipListener<S, T> for Deque<S, T> {
    async fn on_delegation(&self, data: &Rc<Signed<Delegation<S, T, Self>>>) {
        self.push(Event::Delegated(data.dupe()))
    }

    async fn on_revocation(&self, data: &Rc<Signed<Revocation<S, T, Self>>>) {
        self.push(Event::Revoked(data.dupe()))
    }
}
