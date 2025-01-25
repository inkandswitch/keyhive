use super::{membership::MembershipListener, prekey::PrekeyListener};
use crate::{
    content::reference::ContentRef,
    crypto::signed::Signed,
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

#[derive(Debug, Clone, Dupe, Default, PartialEq, Eq, From, Into)]
pub struct Deque<T: ContentRef = [u8; 32]>(
    #[allow(clippy::type_complexity)] pub Rc<RefCell<VecDeque<Event<T, Deque<T>>>>>,
);

impl<T: ContentRef> Deque<T> {
    pub fn push(&self, event: Event<T, Self>) {
        let rc = self.0.dupe();
        let mut deq = (*rc).borrow_mut();
        deq.push_back(event)
    }

    pub fn pop_latest(&self) -> Option<Event<T, Self>> {
        let rc = self.0.dupe();
        let mut deq = (*rc).borrow_mut();
        deq.pop_front()
    }

    pub fn pop_earliest(&self) -> Option<Event<T, Self>> {
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

    pub fn to_vec(&self) -> Vec<Event<T, Self>> {
        self.0.borrow().iter().cloned().collect()
    }
}

impl<T: ContentRef> Hash for Deque<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.borrow().hash(state)
    }
}

impl<T: ContentRef> PrekeyListener for Deque<T> {
    fn on_prekeys_expanded(&self, new_prekey: &Rc<Signed<AddKeyOp>>) {
        self.push(Event::PrekeysExpanded(new_prekey.dupe()))
    }

    fn on_prekey_rotated(&self, rotate_key: &Rc<Signed<RotateKeyOp>>) {
        self.push(Event::PrekeyRotated(rotate_key.dupe()))
    }
}

impl<T: ContentRef> MembershipListener<T> for Deque<T> {
    fn on_delegation(&self, data: &Rc<Signed<Delegation<T, Self>>>) {
        self.push(Event::Delegated(data.dupe()))
    }

    fn on_revocation(&self, data: &Rc<Signed<Revocation<T, Self>>>) {
        self.push(Event::Revoked(data.dupe()))
    }
}
