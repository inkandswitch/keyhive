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
use derive_where::derive_where;
use dupe::Dupe;
use future_form::{FutureForm, Local, Sendable};
use futures::lock::Mutex;
use std::sync::Arc;
use tracing::instrument;

#[derive(From, Into)]
#[derive_where(Debug; T)]
pub struct Log<S: AsyncSigner, T: ContentRef = [u8; 32]>(
    #[allow(clippy::type_complexity)] pub Arc<Mutex<Vec<Event<S, T, Log<S, T>>>>>,
);

impl<S: AsyncSigner, T: ContentRef> Log<S, T> {
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

impl<S: AsyncSigner, T: ContentRef> Default for Log<S, T> {
    fn default() -> Self {
        Self::new()
    }
}

// Local implementations
impl<S: AsyncSigner, T: ContentRef> PrekeyListener<Local> for Log<S, T> {
    #[instrument(skip(self))]
    fn on_prekeys_expanded<'a>(
        &'a self,
        new_prekey: &'a Arc<Signed<AddKeyOp>>,
    ) -> <Local as future_form::FutureForm>::Future<'a, ()> {
        Local::from_future(async move {
            self.push(Event::PrekeysExpanded(new_prekey.dupe())).await
        })
    }

    #[instrument(skip(self))]
    fn on_prekey_rotated<'a>(
        &'a self,
        rotate_key: &'a Arc<Signed<RotateKeyOp>>,
    ) -> <Local as future_form::FutureForm>::Future<'a, ()> {
        Local::from_future(async move {
            self.push(Event::PrekeyRotated(rotate_key.dupe())).await
        })
    }
}

impl<S: AsyncSigner, T: ContentRef> CgkaListener<Local> for Log<S, T> {
    #[instrument(skip(self))]
    fn on_cgka_op<'a>(
        &'a self,
        data: &'a Arc<Signed<CgkaOperation>>,
    ) -> <Local as future_form::FutureForm>::Future<'a, ()> {
        Local::from_future(async move {
            self.push(Event::CgkaOperation(data.dupe())).await
        })
    }
}

impl<S: AsyncSigner, T: ContentRef> MembershipListener<Local, S, T> for Log<S, T> {
    #[instrument(skip(self))]
    fn on_delegation<'a>(
        &'a self,
        data: &'a Arc<Signed<Delegation<S, T, Self>>>,
    ) -> <Local as future_form::FutureForm>::Future<'a, ()> {
        Local::from_future(async move {
            self.push(Event::Delegated(data.dupe())).await
        })
    }

    #[instrument(skip(self))]
    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Signed<Revocation<S, T, Self>>>,
    ) -> <Local as future_form::FutureForm>::Future<'a, ()> {
        Local::from_future(async move {
            self.push(Event::Revoked(data.dupe())).await
        })
    }
}

// Sendable implementations
impl<S: AsyncSigner, T: ContentRef + Send + Sync> PrekeyListener<Sendable> for Log<S, T>
where
    Self: Send + Sync,
{
    #[instrument(skip(self))]
    fn on_prekeys_expanded<'a>(
        &'a self,
        new_prekey: &'a Arc<Signed<AddKeyOp>>,
    ) -> <Sendable as future_form::FutureForm>::Future<'a, ()> {
        Sendable::from_future(async move {
            self.push(Event::PrekeysExpanded(new_prekey.dupe())).await
        })
    }

    #[instrument(skip(self))]
    fn on_prekey_rotated<'a>(
        &'a self,
        rotate_key: &'a Arc<Signed<RotateKeyOp>>,
    ) -> <Sendable as future_form::FutureForm>::Future<'a, ()> {
        Sendable::from_future(async move {
            self.push(Event::PrekeyRotated(rotate_key.dupe())).await
        })
    }
}

impl<S: AsyncSigner, T: ContentRef + Send + Sync> CgkaListener<Sendable> for Log<S, T>
where
    Self: Send + Sync,
{
    #[instrument(skip(self))]
    fn on_cgka_op<'a>(
        &'a self,
        data: &'a Arc<Signed<CgkaOperation>>,
    ) -> <Sendable as future_form::FutureForm>::Future<'a, ()> {
        Sendable::from_future(async move {
            self.push(Event::CgkaOperation(data.dupe())).await
        })
    }
}

impl<S: AsyncSigner, T: ContentRef + Send + Sync> MembershipListener<Sendable, S, T> for Log<S, T>
where
    Self: Send + Sync,
{
    #[instrument(skip(self))]
    fn on_delegation<'a>(
        &'a self,
        data: &'a Arc<Signed<Delegation<S, T, Self>>>,
    ) -> <Sendable as future_form::FutureForm>::Future<'a, ()> {
        Sendable::from_future(async move {
            self.push(Event::Delegated(data.dupe())).await
        })
    }

    #[instrument(skip(self))]
    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Signed<Revocation<S, T, Self>>>,
    ) -> <Sendable as future_form::FutureForm>::Future<'a, ()> {
        Sendable::from_future(async move {
            self.push(Event::Revoked(data.dupe())).await
        })
    }
}
