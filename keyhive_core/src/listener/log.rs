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
use keyhive_crypto::{content::reference::ContentRef, signed::Signed, verified::Verified};
use keyline::{delegation::Delegation, revocation::Revocation};
use std::sync::Arc;

/// A listener that records every event, in order.
#[derive(Debug)]
pub struct Log<T: ContentRef>(pub Arc<Mutex<Vec<Event<T>>>>);

impl<T: ContentRef> Log<T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    pub async fn push(&self, event: Event<T>) {
        self.0.lock().await.push(event)
    }

    pub async fn pop(&self) -> Option<Event<T>> {
        self.0.lock().await.pop()
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

impl<T: ContentRef> Clone for Log<T> {
    fn clone(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<T: ContentRef> Dupe for Log<T> {}

impl<T: ContentRef> Default for Log<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[future_form(Sendable, Local)]
impl<F: FutureForm, T: ContentRef + Send + Sync> PrekeyListener<F> for Log<T> {
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
impl<F: FutureForm, T: ContentRef + Send + Sync> MembershipListener<F, T> for Log<T> {
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
impl<F: FutureForm, T: ContentRef + Send + Sync> CgkaListener<F> for Log<T> {
    fn on_cgka_op<'a>(&'a self, data: &'a Arc<Signed<CgkaOperation>>) -> F::Future<'a, ()> {
        F::from_future(async move { self.push(Event::CgkaOperation(data.dupe())).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        keyhive::Keyhive, principal::public::Public,
        store::ciphertext::memory::MemoryCiphertextStore,
    };
    use keyhive_crypto::signer::memory::MemorySigner;
    use keyline::power::Power;
    use keyline_memory::MemoryKeyline;
    use nonempty::nonempty;
    use rand::rngs::OsRng;

    #[allow(clippy::type_complexity)]
    async fn logged(
        log: &Log<[u8; 32]>,
    ) -> Keyhive<
        Sendable,
        MemorySigner,
        [u8; 32],
        Vec<u8>,
        Arc<Mutex<MemoryCiphertextStore<[u8; 32], Vec<u8>>>>,
        Log<[u8; 32]>,
        OsRng,
        MemoryKeyline<ContentHeads<[u8; 32]>>,
    > {
        let store: MemoryCiphertextStore<[u8; 32], Vec<u8>> = MemoryCiphertextStore::new();
        Keyhive::generate(
            MemorySigner::generate(&mut OsRng),
            Arc::new(Mutex::new(store)),
            log.clone(),
            MemoryKeyline::new(),
            OsRng,
        )
        .await
        .expect("keyhive generation should succeed")
    }

    #[tokio::test]
    async fn the_log_returns_what_was_emitted() {
        let log: Log<[u8; 32]> = Log::new();
        assert!(log.is_empty().await, "a fresh log is empty");
        let hive = logged(&log).await;

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

    /// The listener hears of each certificate once, however often it is
    /// written: a second identical grant inserts nothing new.
    #[tokio::test]
    async fn a_repeated_grant_is_announced_once() {
        let log: Log<[u8; 32]> = Log::new();
        let hive = logged(&log).await;
        let doc = hive
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .expect("doc generation should succeed");
        hive.add_member(Public.id(), doc, Power::Read)
            .await
            .expect("the first grant succeeds");
        log.clear().await;

        hive.add_member(Public.id(), doc, Power::Read)
            .await
            .expect("the same grant again succeeds");
        assert!(log.is_empty().await, "nothing new to announce");
    }
}
