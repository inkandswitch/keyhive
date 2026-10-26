use super::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener};
use crate::{
    content::heads::ContentHeads,
    event::Event,
    principal::individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
};
use beekem::operation::CgkaOperation;
use dupe::Dupe;
use future_form::{future_form, FutureForm, Local, Sendable};
use futures::lock::Mutex;
use keyhive_crypto::{
    content::reference::ContentRef,
    verified::{self, Verified},
};
use keyline::{delegation::Delegation, revocation::Revocation};
use std::{collections::VecDeque, sync::Arc};

/// A listener that queues every event.
#[derive(Debug)]
pub struct Deque<T: ContentRef>(pub Arc<Mutex<VecDeque<Event<T>>>>);

impl<T: ContentRef> Deque<T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(VecDeque::new())))
    }

    pub async fn push(&self, event: Event<T>) {
        self.0.lock().await.push_back(event)
    }

    /// The event pushed last.
    pub async fn pop_latest(&self) -> Option<Event<T>> {
        self.0.lock().await.pop_back()
    }

    /// The event pushed first.
    pub async fn pop_earliest(&self) -> Option<Event<T>> {
        self.0.lock().await.pop_front()
    }

    pub async fn is_empty(&self) -> bool {
        self.0.lock().await.is_empty()
    }

    pub async fn clear(&self) {
        self.0.lock().await.clear()
    }

    pub async fn len(&self) -> usize {
        self.0.lock().await.len()
    }
}

impl<T: ContentRef> Clone for Deque<T> {
    fn clone(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<T: ContentRef> Dupe for Deque<T> {}

impl<T: ContentRef> Default for Deque<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[future_form(Sendable, Local)]
impl<F: FutureForm, T: ContentRef + Send + Sync> PrekeyListener<F> for Deque<T> {
    fn on_prekeys_expanded<'a>(
        &'a self,
        new_prekey: &'a Arc<verified::Signed<AddKeyOp>>,
    ) -> F::Future<'a, ()> {
        F::from_future(async move { self.push(Event::PrekeysExpanded(new_prekey.dupe())).await })
    }

    fn on_prekey_rotated<'a>(
        &'a self,
        rotate_key: &'a Arc<verified::Signed<RotateKeyOp>>,
    ) -> F::Future<'a, ()> {
        F::from_future(async move { self.push(Event::PrekeyRotated(rotate_key.dupe())).await })
    }
}

#[future_form(Sendable, Local)]
impl<F: FutureForm, T: ContentRef + Send + Sync> MembershipListener<F, T> for Deque<T> {
    fn on_delegation<'a>(&'a self, data: &'a Arc<Verified<Delegation>>) -> F::Future<'a, ()> {
        F::from_future(async move { self.push(Event::Delegated(data.signed().dupe())).await })
    }

    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Verified<Revocation<ContentHeads<T>>>>,
    ) -> F::Future<'a, ()> {
        F::from_future(async move { self.push(Event::Revoked(data.signed().dupe())).await })
    }
}

#[future_form(Sendable, Local)]
impl<F: FutureForm, T: ContentRef + Send + Sync> CgkaListener<F> for Deque<T> {
    fn on_cgka_op<'a>(&'a self, data: &'a Arc<Verified<CgkaOperation>>) -> F::Future<'a, ()> {
        F::from_future(async move { self.push(Event::CgkaOperation(data.dupe())).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::individual::op::add_key::AddKeyOp;
    use keyhive_crypto::{share_key::ShareSecretKey, signer::memory::MemorySigner};
    use rand::rngs::OsRng;

    fn event() -> Event<[u8; 32]> {
        let op = AddKeyOp {
            share_key: ShareSecretKey::generate(&mut OsRng).share_key(),
        };
        let verified = Verified::sign_sync(&op, &MemorySigner::generate(&mut OsRng))
            .expect("signing succeeds");
        Event::PrekeysExpanded(verified.signed().dupe())
    }

    #[tokio::test]
    async fn the_deque_pops_from_the_end_each_name_says() {
        let deque = Deque::new();
        assert!(deque.is_empty().await);
        let (first, second, third) = (event(), event(), event());
        for e in [&first, &second, &third] {
            deque.push(e.clone()).await;
        }
        assert_eq!(deque.len().await, 3);
        assert!(!deque.is_empty().await);

        assert_eq!(deque.pop_latest().await, Some(third));
        assert_eq!(deque.pop_earliest().await, Some(first));
        assert_eq!(deque.len().await, 1);

        deque.clear().await;
        assert!(deque.is_empty().await);
        assert_eq!(deque.pop_latest().await, None);
    }
}
