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
    store::secret_key::traits::ShareSecretStore,
};
use derive_more::{From, Into};
use derive_where::derive_where;
use dupe::Dupe;
use std::{
    cell::RefCell,
    hash::{Hash, Hasher},
    rc::Rc,
};
use tracing::instrument;

#[derive(From, Into, PartialEq, Eq)]
#[derive_where(Debug; T)]
pub struct Log<S: AsyncSigner, K: ShareSecretStore, T: ContentRef = [u8; 32]>(
    #[allow(clippy::type_complexity)] pub Rc<RefCell<Vec<Event<S, K, T, Log<S, K, T>>>>>,
);

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef> Log<S, K, T> {
    pub fn new() -> Self {
        Self(Rc::new(RefCell::new(vec![])))
    }

    pub fn push(&self, event: Event<S, K, T, Self>) {
        let rc = self.0.dupe();
        let mut deq = (*rc).borrow_mut();
        deq.push(event)
    }

    pub fn pop(&self) -> Option<Event<S, K, T, Self>> {
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

    pub fn len(&self) -> usize {
        self.0.borrow().len()
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef> Clone for Log<S, K, T> {
    fn clone(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef> Dupe for Log<S, K, T> {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef> Hash for Log<S, K, T>
where
    Event<S, K, T, Log<S, K, T>>: Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.borrow().hash(state)
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef> Default for Log<S, K, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef> PrekeyListener for Log<S, K, T> {
    #[instrument(skip(self))]
    async fn on_prekeys_expanded(&self, new_prekey: &Rc<Signed<AddKeyOp>>) {
        self.push(Event::PrekeysExpanded(new_prekey.dupe()))
    }

    #[instrument(skip(self))]
    async fn on_prekey_rotated(&self, rotate_key: &Rc<Signed<RotateKeyOp>>) {
        self.push(Event::PrekeyRotated(rotate_key.dupe()))
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef> MembershipListener<S, K, T>
    for Log<S, K, T>
{
    #[instrument(skip(self))]
    async fn on_delegation(&self, data: &Rc<Signed<Delegation<S, K, T, Self>>>) {
        self.push(Event::Delegated(data.dupe()))
    }

    #[instrument(skip(self))]
    async fn on_revocation(&self, data: &Rc<Signed<Revocation<S, K, T, Self>>>) {
        self.push(Event::Revoked(data.dupe()))
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef> CgkaListener for Log<S, K, T> {
    #[instrument(skip(self))]
    async fn on_cgka_op(&self, data: &Rc<Signed<CgkaOperation>>) {
        self.push(Event::CgkaOperation(data.dupe()))
    }
}
