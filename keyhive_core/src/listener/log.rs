use super::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener};
use crate::{
    event::Event,
    principal::{
        group::{delegation::Delegation, revocation::Revocation},
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
    },
};
use beekem::operation::CgkaOperation;
use derive_more::{From, Into};
use derive_where::derive_where;
use dupe::Dupe;
use future_form::FutureForm;
use futures::lock::Mutex;
use keyhive_crypto::{
    content::reference::ContentRef, signed::Signed, signer::async_signer::AsyncSigner,
};
use std::sync::Arc;
use tracing::instrument;

#[derive(From, Into)]
#[derive_where(Debug; T)]
pub struct Log<F: FutureForm, S: AsyncSigner<F>, T: ContentRef = [u8; 32]>(
    #[allow(clippy::type_complexity)] pub Arc<Mutex<Vec<Event<S, T, Log<F, S, T>>>>>,
);

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> Log<F, S, T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    pub async fn push(&self, event: Event<F, S, T, Self>) {
        let mut locked = self.0.lock().await;
        locked.push(event)
    }

    pub async fn pop(&self) -> Option<Event<F, S, T, Self>> {
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

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> Clone for Log<F, S, T> {
    fn clone(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> Dupe for Log<F, S, T> {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> Default for Log<F, S, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> PrekeyListener for Log<F, S, T> {
    #[instrument(skip(self))]
    async fn on_prekeys_expanded(&self, new_prekey: &Arc<Signed<AddKeyOp>>) {
        self.push(Event::PrekeysExpanded(new_prekey.dupe())).await
    }

    #[instrument(skip(self))]
    async fn on_prekey_rotated(&self, rotate_key: &Arc<Signed<RotateKeyOp>>) {
        self.push(Event::PrekeyRotated(rotate_key.dupe())).await
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> MembershipListener<S, T> for Log<F, S, T> {
    #[instrument(skip(self))]
    async fn on_delegation(&self, data: &Arc<Signed<Delegation<F, S, T, Self>>>) {
        self.push(Event::Delegated(data.dupe())).await
    }

    #[instrument(skip(self))]
    async fn on_revocation(&self, data: &Arc<Signed<Revocation<F, S, T, Self>>>) {
        self.push(Event::Revoked(data.dupe())).await
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> CgkaListener for Log<F, S, T> {
    #[instrument(skip(self))]
    async fn on_cgka_op(&self, data: &Arc<Signed<CgkaOperation>>) {
        self.push(Event::CgkaOperation(data.dupe())).await
    }
}
