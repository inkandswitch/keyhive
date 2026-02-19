use super::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener};
use crate::{
    cgka::operation::CgkaOperation,
    content::reference::ContentRef,
    crypto::{signed::Signed, signer::async_signer::{AsyncSignerLocal, AsyncSignerSend}},
    event::static_event::StaticEvent,
    principal::{
        group::{
            delegation::{Delegation, StaticDelegation},
            revocation::{Revocation, StaticRevocation},
        },
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
    },
};
use derive_more::{From, Into};
use dupe::Dupe;
use future_form::{FutureForm, Local, Sendable};
use futures::lock::Mutex;
use std::{collections::VecDeque, marker::PhantomData, sync::Arc};
use tracing::instrument;

/// A deque-based listener that stores events as [`StaticEvent`]s.
///
/// This listener stores events in a serializable form that can be used for
/// gossip, persistence, or replay. Events can be popped from either end.
/// Note that delegation and revocation events are stored as their static forms
/// (using hashes instead of full references).
#[derive(Debug, From, Into)]
pub struct Deque<S, T: ContentRef = [u8; 32]>(
    pub Arc<Mutex<VecDeque<StaticEvent<T>>>>,
    PhantomData<S>,
);

impl<S, T: ContentRef> Default for Deque<S, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, T: ContentRef> Deque<S, T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(VecDeque::new())), PhantomData)
    }

    pub async fn push(&self, event: StaticEvent<T>) {
        let mut locked = self.0.lock().await;
        locked.push_back(event)
    }

    pub async fn pop_latest(&self) -> Option<StaticEvent<T>> {
        let mut locked = self.0.lock().await;
        locked.pop_front()
    }

    pub async fn pop_earliest(&self) -> Option<StaticEvent<T>> {
        let mut locked = self.0.lock().await;
        locked.pop_back()
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

impl<S, T: ContentRef> Clone for Deque<S, T> {
    fn clone(&self) -> Self {
        Self(self.0.dupe(), PhantomData)
    }
}

impl<S, T: ContentRef> Dupe for Deque<S, T> {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

#[future_form::future_form(
    Sendable where S: Send + Sync, T: Send + Sync, Self: Send + Sync,
    Local
)]
impl<K: FutureForm + ?Sized, S, T: ContentRef> PrekeyListener<K> for Deque<S, T> {
    #[instrument(skip(self))]
    fn on_prekeys_expanded<'a>(
        &'a self,
        new_prekey: &'a Arc<Signed<AddKeyOp>>,
    ) -> K::Future<'a, ()> {
        K::from_future(async move {
            self.push(StaticEvent::PrekeysExpanded(Box::new(
                new_prekey.as_ref().clone(),
            )))
            .await
        })
    }

    #[instrument(skip(self))]
    fn on_prekey_rotated<'a>(
        &'a self,
        rotate_key: &'a Arc<Signed<RotateKeyOp>>,
    ) -> K::Future<'a, ()> {
        K::from_future(async move {
            self.push(StaticEvent::PrekeyRotated(Box::new(
                rotate_key.as_ref().clone(),
            )))
            .await
        })
    }
}

#[future_form::future_form(
    Sendable where S: Send + Sync, T: Send + Sync, Self: Send + Sync,
    Local
)]
impl<K: FutureForm + ?Sized, S, T: ContentRef> CgkaListener<K> for Deque<S, T> {
    #[instrument(skip(self))]
    fn on_cgka_op<'a>(&'a self, op: &'a Arc<Signed<CgkaOperation>>) -> K::Future<'a, ()> {
        K::from_future(async move {
            self.push(StaticEvent::CgkaOperation(Box::new(op.as_ref().clone())))
                .await
        })
    }
}

impl<S: AsyncSignerSend + Send + Sync, T: ContentRef + Send + Sync> MembershipListener<Sendable, S, T>
    for Deque<S, T>
where
    Self: Send + Sync,
{
    #[instrument(skip(self))]
    fn on_delegation<'a>(
        &'a self,
        data: &'a Arc<Signed<Delegation<Sendable, S, T, Self>>>,
    ) -> <Sendable as FutureForm>::Future<'a, ()> {
        // Convert to StaticDelegation eagerly to avoid capturing `data` in the async block
        let static_dlg: StaticDelegation<T> = data.payload().clone().into();
        let signed_static = data.as_ref().clone().map(|_| static_dlg);
        Sendable::from_future(async move {
            self.push(StaticEvent::Delegated(signed_static)).await
        })
    }

    #[instrument(skip(self))]
    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Signed<Revocation<Sendable, S, T, Self>>>,
    ) -> <Sendable as FutureForm>::Future<'a, ()> {
        // Convert to StaticRevocation eagerly to avoid capturing `data` in the async block
        let static_rev: StaticRevocation<T> = data.payload().clone().into();
        let signed_static = data.as_ref().clone().map(|_| static_rev);
        Sendable::from_future(async move {
            self.push(StaticEvent::Revoked(signed_static)).await
        })
    }
}

impl<S: AsyncSignerLocal, T: ContentRef> MembershipListener<Local, S, T> for Deque<S, T> {
    #[instrument(skip(self))]
    fn on_delegation<'a>(
        &'a self,
        data: &'a Arc<Signed<Delegation<Local, S, T, Self>>>,
    ) -> <Local as FutureForm>::Future<'a, ()> {
        // Convert to StaticDelegation eagerly to avoid capturing `data` in the async block
        let static_dlg: StaticDelegation<T> = data.payload().clone().into();
        let signed_static = data.as_ref().clone().map(|_| static_dlg);
        Local::from_future(async move {
            self.push(StaticEvent::Delegated(signed_static)).await
        })
    }

    #[instrument(skip(self))]
    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Signed<Revocation<Local, S, T, Self>>>,
    ) -> <Local as FutureForm>::Future<'a, ()> {
        // Convert to StaticRevocation eagerly to avoid capturing `data` in the async block
        let static_rev: StaticRevocation<T> = data.payload().clone().into();
        let signed_static = data.as_ref().clone().map(|_| static_rev);
        Local::from_future(async move {
            self.push(StaticEvent::Revoked(signed_static)).await
        })
    }
}
