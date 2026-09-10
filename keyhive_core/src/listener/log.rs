use super::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener};
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
pub struct Log<F: FutureForm, S: AsyncSigner<F>, T: ContentRef = [u8; 32]>(
    #[allow(clippy::type_complexity)] pub Arc<Mutex<Vec<Event<F, S, T, Log<F, S, T>>>>>,
)
where
    Log<F, S, T>: MembershipListener<F, S, T>;

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> Log<F, S, T>
where
    Self: MembershipListener<F, S, T>,
{
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

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> Clone for Log<F, S, T>
where
    Self: MembershipListener<F, S, T>,
{
    fn clone(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> Dupe for Log<F, S, T>
where
    Self: MembershipListener<F, S, T>,
{
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> Default for Log<F, S, T>
where
    Self: MembershipListener<F, S, T>,
{
    fn default() -> Self {
        Self::new()
    }
}

#[future_form(Sendable, Local)]
impl<F: FutureForm, S: AsyncSigner<F> + Send + Sync, T: ContentRef + Send + Sync> PrekeyListener<F>
    for Log<F, S, T>
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
    MembershipListener<F, S, T> for Log<F, S, T>
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
    for Log<F, S, T>
where
    Self: MembershipListener<F, S, T> + Send + Sync,
{
    fn on_cgka_op<'a>(&'a self, data: &'a Arc<Signed<CgkaOperation>>) -> F::Future<'a, ()> {
        F::from_future(async move { self.push(Event::CgkaOperation(data.dupe())).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{keyhive::Keyhive, store::ciphertext::memory::MemoryCiphertextStore};
    use keyhive_crypto::signer::memory::MemorySigner;
    use nonempty::nonempty;

    #[tokio::test]
    async fn the_log_returns_what_was_emitted() {
        let log: Log<Sendable, MemorySigner> = Log::new();
        assert!(log.is_empty().await, "a fresh log is empty");

        let store: MemoryCiphertextStore<[u8; 32], Vec<u8>> = MemoryCiphertextStore::new();
        let hive: Keyhive<
            Sendable,
            MemorySigner,
            [u8; 32],
            Vec<u8>,
            Arc<Mutex<MemoryCiphertextStore<[u8; 32], Vec<u8>>>>,
            Log<Sendable, MemorySigner>,
        > = Keyhive::generate(
            MemorySigner::generate(&mut rand::rngs::OsRng),
            Arc::new(Mutex::new(store)),
            log.clone(),
            rand::rngs::OsRng,
        )
        .await
        .expect("keyhive generation should succeed");

        hive.generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .expect("doc generation should succeed");

        let emitted = log.len().await;
        assert!(emitted > 0, "creating a document emits events");

        let mut drained = 0;
        while log.pop().await.is_some() {
            drained += 1;
        }
        assert_eq!(drained, emitted, "every event the log held came back out");
        assert!(log.is_empty().await, "and draining it leaves it empty");
    }
}
