use super::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener};
use crate::{
    cgka::operation::CgkaOperation,
    content::reference::ContentRef,
    crypto::{signed::Signed, verifiable::Verifiable},
    event::Event,
    principal::{
        group::{delegation::Delegation, revocation::Revocation},
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
    },
};
use derive_more::{From, Into};
use derive_where::derive_where;
use dupe::Dupe;
use future_form::{future_form, FutureForm, Local, Sendable};
use futures::lock::Mutex;
use std::sync::Arc;
use tracing::instrument;

#[derive(From, Into)]
#[derive_where(Debug; T)]
pub struct Log<S: Verifiable, T: ContentRef = [u8; 32]>(
    #[allow(clippy::type_complexity)] pub Arc<Mutex<Vec<Event<S, T, Log<S, T>>>>>,
);

impl<S: Verifiable, T: ContentRef> Log<S, T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    pub async fn push(&self, event: Event<S, T, Self>) {
        let mut locked = self.0.lock().await;
        locked.push(event)
    }

    pub async fn pop(&self) -> Option<Event<S, T, Self>> {
        let mut locked = self.0.lock().await;
        locked.pop()
    }

    pub async fn is_empty(&self) -> bool {
        let locked = self.0.lock().await;
        locked.is_empty()
    }

    pub async fn clear(&self) {
        let mut locked = self.0.lock().await;
        locked.clear()
    }

    pub async fn len(&self) -> usize {
        let locked = self.0.lock().await;
        locked.len()
    }
}

impl<S: Verifiable, T: ContentRef> Clone for Log<S, T> {
    fn clone(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<S: Verifiable, T: ContentRef> Dupe for Log<S, T> {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<S: Verifiable, T: ContentRef> Default for Log<S, T> {
    fn default() -> Self {
        Self::new()
    }
}

#[future_form(Sendable where S: Send + Sync + 'static, T: Send + Sync + 'static, Local)]
impl<K: FutureForm, S: Verifiable, T: ContentRef> PrekeyListener<K> for Log<S, T> {
    #[instrument(skip(self))]
    fn on_prekeys_expanded<'a>(
        &'a self,
        new_prekey: &'a Arc<Signed<AddKeyOp>>,
    ) -> K::Future<'a, ()> {
        let new_prekey = new_prekey.dupe();
        K::from_future(async move { self.push(Event::PrekeysExpanded(new_prekey)).await })
    }

    #[instrument(skip(self))]
    fn on_prekey_rotated<'a>(
        &'a self,
        rotate_key: &'a Arc<Signed<RotateKeyOp>>,
    ) -> K::Future<'a, ()> {
        let rotate_key = rotate_key.dupe();
        K::from_future(async move { self.push(Event::PrekeyRotated(rotate_key)).await })
    }
}

#[future_form(Sendable where S: Send + Sync + 'static, T: Send + Sync + 'static, Local)]
impl<K: FutureForm, S: Verifiable + Clone, T: ContentRef> MembershipListener<K, S, T>
    for Log<S, T>
{
    #[instrument(skip(self))]
    fn on_delegation<'a>(
        &'a self,
        data: &'a Arc<Signed<Delegation<S, T, Self>>>,
    ) -> K::Future<'a, ()> {
        let data = data.dupe();
        K::from_future(async move { self.push(Event::Delegated(data)).await })
    }

    #[instrument(skip(self))]
    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Signed<Revocation<S, T, Self>>>,
    ) -> K::Future<'a, ()> {
        let data = data.dupe();
        K::from_future(async move { self.push(Event::Revoked(data)).await })
    }
}

#[future_form(Sendable where S: Send + Sync + 'static, T: Send + Sync + 'static, Local)]
impl<K: FutureForm, S: Verifiable, T: ContentRef> CgkaListener<K> for Log<S, T> {
    #[instrument(skip(self))]
    fn on_cgka_op<'a>(&'a self, data: &'a Arc<Signed<CgkaOperation>>) -> K::Future<'a, ()> {
        let data = data.dupe();
        K::from_future(async move { self.push(Event::CgkaOperation(data)).await })
    }
}
