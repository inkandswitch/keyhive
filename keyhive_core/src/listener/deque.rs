use super::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener};
use crate::{
    event::Event,
    principal::{
        group::{delegation::Delegation, revocation::Revocation},
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
    },
};
use beekem::operation::CgkaOperation;
use dupe::Dupe;
use future_form::{future_form, FutureForm, Local, Sendable};
use futures::lock::Mutex;
use keyhive_crypto::{
    content::reference::ContentRef, signed::Signed, signer::async_signer::AsyncSigner,
};
use std::{collections::VecDeque, sync::Arc};

pub struct Deque<F: FutureForm, S: AsyncSigner<F>, T: ContentRef = [u8; 32]>(
    #[allow(clippy::type_complexity)] pub Arc<Mutex<VecDeque<Event<F, S, T, Deque<F, S, T>>>>>,
)
where
    Deque<F, S, T>: MembershipListener<F, S, T>;

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> Deque<F, S, T>
where
    Self: MembershipListener<F, S, T>,
{
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(VecDeque::new())))
    }

    pub async fn push(&self, event: Event<F, S, T, Self>) {
        let mut locked = self.0.lock().await;
        locked.push_back(event)
    }

    /// The event pushed last.
    pub async fn pop_latest(&self) -> Option<Event<F, S, T, Self>> {
        let mut locked = self.0.lock().await;
        locked.pop_back()
    }

    /// The event pushed first.
    pub async fn pop_earliest(&self) -> Option<Event<F, S, T, Self>> {
        let mut locked = self.0.lock().await;
        locked.pop_front()
    }

    pub async fn is_empty(&self) -> bool {
        let locked = self.0.lock().await;
        locked.is_empty()
    }

    pub async fn clear(&self) {
        let mut locked = self.0.lock().await;
        locked.clear()
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> Default for Deque<F, S, T>
where
    Self: MembershipListener<F, S, T>,
{
    fn default() -> Self {
        Self(Arc::new(Mutex::new(VecDeque::new())))
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> std::fmt::Debug for Deque<F, S, T>
where
    Self: MembershipListener<F, S, T>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Deque").field(&self.0).finish()
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> Clone for Deque<F, S, T>
where
    Self: MembershipListener<F, S, T>,
{
    fn clone(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> Dupe for Deque<F, S, T>
where
    Self: MembershipListener<F, S, T>,
{
    fn dupe(&self) -> Self {
        self.clone()
    }
}

#[future_form(Sendable, Local)]
impl<F: FutureForm, S: AsyncSigner<F> + Send + Sync, T: ContentRef + Send + Sync> PrekeyListener<F>
    for Deque<F, S, T>
where
    Self: MembershipListener<F, S, T> + Send + Sync,
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
impl<F: FutureForm, S: AsyncSigner<F> + Send + Sync, T: ContentRef + Send + Sync>
    MembershipListener<F, S, T> for Deque<F, S, T>
where
    Self: Send + Sync,
{
    fn on_delegation<'a>(
        &'a self,
        data: &'a Arc<Signed<Delegation<F, S, T, Self>>>,
    ) -> F::Future<'a, ()> {
        F::from_future(async move { self.push(Event::Delegated(data.dupe())).await })
    }

    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Signed<Revocation<F, S, T, Self>>>,
    ) -> F::Future<'a, ()> {
        F::from_future(async move { self.push(Event::Revoked(data.dupe())).await })
    }
}

#[future_form(Sendable, Local)]
impl<F: FutureForm, S: AsyncSigner<F> + Send + Sync, T: ContentRef + Send + Sync> CgkaListener<F>
    for Deque<F, S, T>
where
    Self: MembershipListener<F, S, T> + Send + Sync,
{
    fn on_cgka_op<'a>(&'a self, op: &'a Arc<Signed<CgkaOperation>>) -> F::Future<'a, ()> {
        F::from_future(async move { self.push(Event::CgkaOperation(op.dupe())).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyhive_crypto::{share_key::ShareSecretKey, signer::memory::MemorySigner};
    use rand::rngs::OsRng;

    type TestDeque = Deque<Sendable, MemorySigner>;

    fn prekey() -> Arc<Signed<AddKeyOp>> {
        let op = AddKeyOp {
            share_key: ShareSecretKey::generate(&mut OsRng).share_key(),
        };
        let signed = MemorySigner::generate(&mut OsRng)
            .try_sign_sync(op)
            .expect("signing succeeds");
        Arc::new(signed)
    }

    /// The prekey op a popped event carries. `Event`'s `PartialEq` needs the
    /// listener type to be `PartialEq`, which `Deque` is not.
    fn prekey_of(
        event: Option<Event<Sendable, MemorySigner, [u8; 32], TestDeque>>,
    ) -> Option<Arc<Signed<AddKeyOp>>> {
        match event? {
            Event::PrekeysExpanded(op) => Some(op),
            _ => None,
        }
    }

    #[tokio::test]
    async fn the_deque_pops_from_the_end_each_name_says() {
        let deque = TestDeque::new();
        assert!(deque.is_empty().await);
        let (first, second, third) = (prekey(), prekey(), prekey());
        for op in [&first, &second, &third] {
            deque.push(Event::PrekeysExpanded(op.dupe())).await;
        }
        assert!(!deque.is_empty().await);

        assert_eq!(prekey_of(deque.pop_latest().await), Some(third));
        assert_eq!(prekey_of(deque.pop_earliest().await), Some(first));
        assert_eq!(prekey_of(deque.pop_latest().await), Some(second));
        assert!(deque.is_empty().await);

        deque.push(Event::PrekeysExpanded(prekey())).await;
        deque.clear().await;
        assert!(deque.is_empty().await);
        assert!(deque.pop_latest().await.is_none());
    }
}
