use super::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener};
use crate::{
    cgka::operation::CgkaOperation,
    content::reference::ContentRef,
    crypto::{signed::Signed, signer::async_signer::AsyncSigner},
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
use derive_where::derive_where;
use dupe::Dupe;
use future_form::{FutureForm, Local, Sendable};
use futures::lock::Mutex;
use std::sync::Arc;
use tracing::instrument;

/// A logging listener that stores events as [`StaticEvent`]s.
///
/// This listener stores events in a serializable form that can be used for
/// gossip, persistence, or replay. Note that delegation and revocation events
/// are stored as their static forms (using hashes instead of full references).
#[derive(From, Into)]
#[derive_where(Debug; T)]
pub struct Log<S: AsyncSigner, T: ContentRef = [u8; 32]>(
    pub Arc<Mutex<Vec<StaticEvent<T>>>>,
    std::marker::PhantomData<S>,
);

impl<S: AsyncSigner, T: ContentRef> Log<S, T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())), std::marker::PhantomData)
    }

    pub async fn push(&self, event: StaticEvent<T>) {
        let mut locked = self.0.lock().await;
        locked.push(event)
    }

    pub async fn pop(&self) -> Option<StaticEvent<T>> {
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

impl<S: AsyncSigner, T: ContentRef> Clone for Log<S, T> {
    fn clone(&self) -> Self {
        Self(self.0.dupe(), std::marker::PhantomData)
    }
}

impl<S: AsyncSigner, T: ContentRef> Dupe for Log<S, T> {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<S: AsyncSigner, T: ContentRef> Default for Log<S, T> {
    fn default() -> Self {
        Self::new()
    }
}

#[future_form::future_form(
    Sendable where S: Send + Sync, T: Send + Sync, Self: Send + Sync,
    Local
)]
impl<K: FutureForm + ?Sized, S: AsyncSigner, T: ContentRef> PrekeyListener<K> for Log<S, T> {
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
impl<K: FutureForm + ?Sized, S: AsyncSigner, T: ContentRef> CgkaListener<K> for Log<S, T> {
    #[instrument(skip(self))]
    fn on_cgka_op<'a>(
        &'a self,
        data: &'a Arc<Signed<CgkaOperation>>,
    ) -> K::Future<'a, ()> {
        K::from_future(async move {
            self.push(StaticEvent::CgkaOperation(Box::new(data.as_ref().clone())))
                .await
        })
    }
}

impl<S: AsyncSigner + Send + Sync, T: ContentRef + Send + Sync> MembershipListener<Sendable, S, T>
    for Log<S, T>
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

impl<S: AsyncSigner, T: ContentRef> MembershipListener<Local, S, T> for Log<S, T> {
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
