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
use futures::lock::Mutex;
use std::{collections::VecDeque, sync::Arc};
use tracing::instrument;

#[derive(Debug, Default, From, Into)]
pub struct Deque<S: AsyncSigner, T: ContentRef = [u8; 32]>(
    #[allow(clippy::type_complexity)] pub Arc<Mutex<VecDeque<Event<S, T, Deque<S, T>>>>>,
);

impl<S: AsyncSigner, T: ContentRef> Deque<S, T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(VecDeque::new())))
    }

    pub async fn push(&self, event: Event<S, T, Self>) {
        let mut locked = self.0.lock().await;
        locked.push_back(event)
    }

    pub async fn pop_latest(&self) -> Option<Event<S, T, Self>> {
        let mut locked = self.0.lock().await;
        locked.pop_front()
    }

    pub async fn pop_earliest(&self) -> Option<Event<S, T, Self>> {
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

impl<S: AsyncSigner, T: ContentRef> Clone for Deque<S, T> {
    fn clone(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<S: AsyncSigner, T: ContentRef> Dupe for Deque<S, T> {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<S: AsyncSigner, T: ContentRef> PrekeyListener for Deque<S, T> {
    #[instrument(skip(self))]
    async fn on_prekeys_expanded(&self, new_prekey: &Arc<Signed<AddKeyOp>>) {
        self.push(Event::PrekeysExpanded(new_prekey.dupe())).await
    }

    #[instrument(skip(self))]
    async fn on_prekey_rotated(&self, rotate_key: &Arc<Signed<RotateKeyOp>>) {
        self.push(Event::PrekeyRotated(rotate_key.dupe())).await
    }
}

impl<S: AsyncSigner, T: ContentRef> MembershipListener<S, T> for Deque<S, T> {
    #[instrument(skip(self))]
    async fn on_delegation(&self, data: &Arc<Signed<Delegation<S, T, Self>>>) {
        self.push(Event::Delegated(data.dupe())).await
    }

    #[instrument(skip(self))]
    async fn on_revocation(&self, data: &Arc<Signed<Revocation<S, T, Self>>>) {
        self.push(Event::Revoked(data.dupe())).await
    }
}

impl<S: AsyncSigner, T: ContentRef> CgkaListener for Deque<S, T> {
    #[instrument(skip(self))]
    async fn on_cgka_op(&self, op: &Arc<Signed<CgkaOperation>>) {
        self.push(Event::CgkaOperation(op.dupe())).await
    }
}
