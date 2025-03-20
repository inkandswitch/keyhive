use super::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener};
use crate::{
    cgka::operation::CgkaOperation,
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
    hash::{Hash, Hasher},
    rc::Rc,
};

#[derive(Debug, PartialEq, Eq, From, Into)]
pub struct Log<S: AsyncSigner, T: ContentRef = [u8; 32]>(
    pub Rc<RefCell<Vec<Event<S, T, Log<S, T>>>>>,
);

impl<S: AsyncSigner, T: ContentRef> Log<S, T> {
    pub fn new() -> Self {
        Self(Rc::new(RefCell::new(vec![])))
    }

    pub fn push(&self, event: Event<S, T, Self>) {
        let rc = self.0.dupe();
        let mut deq = (*rc).borrow_mut();
        deq.push(event)
    }

    pub fn pop(&self) -> Option<Event<S, T, Self>> {
        let rc = self.0.dupe();
        let mut deq = (*rc).borrow_mut();
        deq.pop()
    }

    pub fn is_empty(&self) -> bool {
        self.0.borrow().is_empty()
    }

    pub fn clear(&self) {
        let rc = self.0.dupe();
        let mut log = (*rc).borrow_mut();
        log.clear()
    }
}

impl<S: AsyncSigner, T: ContentRef> Clone for Log<S, T> {
    fn clone(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<S: AsyncSigner, T: ContentRef> Dupe for Log<S, T> {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<S: AsyncSigner, T: ContentRef> Hash for Log<S, T>
where
    Event<S, T, Log<S, T>>: Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.borrow().hash(state)
    }
}

impl<S: AsyncSigner, T: ContentRef> PrekeyListener for Log<S, T> {
    async fn on_prekeys_expanded(&self, new_prekey: &Rc<Signed<AddKeyOp>>) {
        self.push(Event::PrekeysExpanded(new_prekey.dupe()))
    }

    async fn on_prekey_rotated(&self, rotate_key: &Rc<Signed<RotateKeyOp>>) {
        self.push(Event::PrekeyRotated(rotate_key.dupe()))
    }
}

impl<S: AsyncSigner, T: ContentRef> MembershipListener<S, T> for Log<S, T> {
    async fn on_delegation(&self, data: &Rc<Signed<Delegation<S, T, Self>>>) {
        self.push(Event::Delegated(data.dupe()))
    }

    async fn on_revocation(&self, data: &Rc<Signed<Revocation<S, T, Self>>>) {
        self.push(Event::Revoked(data.dupe()))
    }
}

// FIXME respect sendable feature flag
impl<S: AsyncSigner, T: ContentRef> CgkaListener for Log<S, T> {
    async fn on_cgka_op(&self, data: &Rc<Signed<CgkaOperation>>) {
        self.push(Event::CgkaOperation(data.dupe()))
    }
}
