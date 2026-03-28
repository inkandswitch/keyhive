use super::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener};
use crate::store::secret_key::SecretKeyStore;
use crate::{
    event::Event,
    principal::{
        group::{delegation::Delegation, revocation::Revocation},
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
    },
};
use beekem::operation::CgkaOperation;
use derive_where::derive_where;
use dupe::Dupe;
use future_form::{future_form, FutureForm, Local, Sendable};
use futures::lock::Mutex;
use keyhive_crypto::{
    content::reference::ContentRef, signed::Signed, signer::async_signer::AsyncSigner,
};
use std::sync::Arc;

#[derive_where(Debug; T)]
pub struct Log<F: FutureForm, S: AsyncSigner<F>, K: SecretKeyStore<F>, T: ContentRef = [u8; 32]>(
    #[allow(clippy::type_complexity)] pub Arc<Mutex<Vec<Event<F, S, K, T, Log<F, S, K, T>>>>>,
)
where
    Log<F, S, K, T>: MembershipListener<F, S, K, T>;

impl<F: FutureForm, S: AsyncSigner<F>, K: SecretKeyStore<F>, T: ContentRef> Log<F, S, K, T>
where
    Self: MembershipListener<F, S, K, T>,
{
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    pub async fn push(&self, event: Event<F, S, K, T, Self>) {
        let mut locked = self.0.lock().await;
        locked.push(event)
    }

    pub async fn pop(&self) -> Option<Event<F, S, K, T, Self>> {
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

impl<F: FutureForm, S: AsyncSigner<F>, K: SecretKeyStore<F>, T: ContentRef> Clone
    for Log<F, S, K, T>
where
    Self: MembershipListener<F, S, K, T>,
{
    fn clone(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, K: SecretKeyStore<F>, T: ContentRef> Dupe for Log<F, S, K, T>
where
    Self: MembershipListener<F, S, K, T>,
{
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, K: SecretKeyStore<F>, T: ContentRef> Default
    for Log<F, S, K, T>
where
    Self: MembershipListener<F, S, K, T>,
{
    fn default() -> Self {
        Self::new()
    }
}

#[future_form(Sendable, Local)]
impl<
        F: FutureForm,
        S: AsyncSigner<F> + Send + Sync,
        K: SecretKeyStore<F> + Send + Sync,
        T: ContentRef + Send + Sync,
    > PrekeyListener<F> for Log<F, S, K, T>
where
    Self: MembershipListener<F, S, K, T> + Send + Sync,
{
    fn on_prekeys_expanded<'a>(
        &'a self,
        new_prekey: &'a Arc<Signed<AddKeyOp>>,
    ) -> F::Future<'a, ()> {
        F::from_future(async move { self.push(Event::PrekeysExpanded(new_prekey.dupe())).await })
    }

    fn on_prekey_rotated<'a>(
        &'a self,
        rotate_key: &'a Arc<Signed<RotateKeyOp>>,
    ) -> F::Future<'a, ()> {
        F::from_future(async move { self.push(Event::PrekeyRotated(rotate_key.dupe())).await })
    }
}

#[future_form(Sendable, Local)]
impl<
        F: FutureForm,
        S: AsyncSigner<F> + Send + Sync,
        K: SecretKeyStore<F> + Send + Sync,
        T: ContentRef + Send + Sync,
    > MembershipListener<F, S, K, T> for Log<F, S, K, T>
where
    Self: Send + Sync,
{
    fn on_delegation<'a>(
        &'a self,
        data: &'a Arc<Signed<Delegation<F, S, K, T, Self>>>,
    ) -> F::Future<'a, ()> {
        F::from_future(async move { self.push(Event::Delegated(data.dupe())).await })
    }

    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Signed<Revocation<F, S, K, T, Self>>>,
    ) -> F::Future<'a, ()> {
        F::from_future(async move { self.push(Event::Revoked(data.dupe())).await })
    }
}

#[future_form(Sendable, Local)]
impl<
        F: FutureForm,
        S: AsyncSigner<F> + Send + Sync,
        K: SecretKeyStore<F> + Send + Sync,
        T: ContentRef + Send + Sync,
    > CgkaListener<F> for Log<F, S, K, T>
where
    Self: MembershipListener<F, S, K, T> + Send + Sync,
{
    fn on_cgka_op<'a>(&'a self, data: &'a Arc<Signed<CgkaOperation>>) -> F::Future<'a, ()> {
        F::from_future(async move { self.push(Event::CgkaOperation(data.dupe())).await })
    }
}
