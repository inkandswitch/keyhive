//! Events that are emitted during operation of Keyhive.

pub mod static_event;

use self::static_event::StaticEvent;
use crate::{
    cgka::operation::CgkaOperation,
    content::reference::ContentRef,
    crypto::{
        digest::Digest, encrypted::EncryptedContent, signed::Signed,
        signer::async_signer::AsyncSigner,
    },
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::{
        document::id::DocumentId,
        group::{
            delegation::Delegation, membership_operation::MembershipOperation,
            revocation::Revocation,
        },
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp, KeyOp},
    },
    store::{ciphertext::CiphertextStore, secret_key::traits::ShareSecretStore},
};
use derive_more::{From, TryInto};
use derive_where::derive_where;
use dupe::Dupe;
use serde::Serialize;
use std::{collections::HashMap, rc::Rc};
use tracing::instrument;

/// Top-level event variants.
#[derive(PartialEq, Eq, From, TryInto)]
#[derive_where(Debug, Hash; T)]
pub enum Event<
    S: AsyncSigner,
    K: ShareSecretStore,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, K, T> = NoListener,
> {
    /// Prekeys were expanded.
    PrekeysExpanded(Rc<Signed<AddKeyOp>>),

    /// A prekey was rotated.
    PrekeyRotated(Rc<Signed<RotateKeyOp>>),

    /// A CGKA operation was performed.
    CgkaOperation(Rc<Signed<CgkaOperation>>),

    /// A delegation was created.
    Delegated(Rc<Signed<Delegation<S, K, T, L>>>),

    /// A delegation was revoked.
    Revoked(Rc<Signed<Revocation<S, K, T, L>>>),
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    Event<S, K, T, L>
{
    #[allow(clippy::type_complexity)]
    #[instrument(level = "debug", skip(ciphertext_store))]
    pub async fn now_decryptable<P, C: CiphertextStore<T, P>>(
        new_events: &[Event<S, K, T, L>],
        ciphertext_store: &C,
    ) -> Result<HashMap<DocumentId, Vec<Rc<EncryptedContent<P, T>>>>, C::GetCiphertextError> {
        let mut acc: HashMap<DocumentId, Vec<Rc<EncryptedContent<P, T>>>> = HashMap::new();

        for event in new_events {
            if let Event::CgkaOperation(op) = event {
                let op_digest = Digest::hash(op.as_ref());
                let doc_id = op.payload.doc_id();
                let more = ciphertext_store
                    .get_ciphertext_by_pcs_update(&op_digest)
                    .await?;

                acc.entry(*doc_id).or_default().extend(more.into_iter());
            }
        }

        Ok(acc)
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> From<KeyOp>
    for Event<S, K, T, L>
{
    fn from(key_op: KeyOp) -> Self {
        match key_op {
            KeyOp::Add(add) => Event::PrekeysExpanded(add),
            KeyOp::Rotate(rot) => Event::PrekeyRotated(rot),
        }
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    From<MembershipOperation<S, K, T, L>> for Event<S, K, T, L>
{
    fn from(op: MembershipOperation<S, K, T, L>) -> Self {
        match op {
            MembershipOperation::Delegation(d) => Event::Delegated(d),
            MembershipOperation::Revocation(r) => Event::Revoked(r),
        }
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    From<Event<S, K, T, L>> for StaticEvent<T>
{
    fn from(op: Event<S, K, T, L>) -> Self {
        match op {
            Event::Delegated(d) => StaticEvent::Delegated(Rc::unwrap_or_clone(d).map(Into::into)),
            Event::Revoked(r) => StaticEvent::Revoked(Rc::unwrap_or_clone(r).map(Into::into)),

            Event::CgkaOperation(cgka) => {
                StaticEvent::CgkaOperation(Box::new(Rc::unwrap_or_clone(cgka)))
            }

            Event::PrekeyRotated(pkr) => {
                StaticEvent::PrekeyRotated(Box::new(Rc::unwrap_or_clone(pkr).map(Into::into)))
            }
            Event::PrekeysExpanded(pke) => {
                StaticEvent::PrekeysExpanded(Box::new(Rc::unwrap_or_clone(pke).map(Into::into)))
            }
        }
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Serialize
    for Event<S, K, T, L>
{
    fn serialize<Z: serde::Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
        StaticEvent::from(self.clone()).serialize(serializer)
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Clone
    for Event<S, K, T, L>
{
    fn clone(&self) -> Self {
        match self {
            Event::Delegated(d) => Event::Delegated(Rc::clone(d)),
            Event::Revoked(r) => Event::Revoked(Rc::clone(r)),

            Event::CgkaOperation(cgka) => Event::CgkaOperation(Rc::clone(cgka)),

            Event::PrekeyRotated(pkr) => Event::PrekeyRotated(Rc::clone(pkr)),
            Event::PrekeysExpanded(pke) => Event::PrekeysExpanded(Rc::clone(pke)),
        }
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Dupe
    for Event<S, K, T, L>
{
    fn dupe(&self) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        access::Access,
        crypto::{
            share_key::ShareKey,
            signer::{memory::MemorySigner, sync_signer::SyncSigner},
            siv::Siv,
            symmetric_key::SymmetricKey,
        },
        principal::{
            agent::Agent,
            individual::{id::IndividualId, Individual},
        },
        store::{
            ciphertext::memory::MemoryCiphertextStore, secret_key::memory::MemorySecretKeyStore,
        },
    };
    use rand::rngs::ThreadRng;
    use std::{cell::RefCell, collections::BTreeMap};
    use test_utils::init_logging;
    use testresult::TestResult;

    #[tokio::test]
    async fn test_event_now_decryptable() -> TestResult {
        init_logging();

        let mut csprng = rand::thread_rng();
        let signer = MemorySigner::generate(&mut csprng);
        let doc_id1 = DocumentId::generate(&mut csprng);
        let doc_id2 = DocumentId::generate(&mut csprng);

        let cgka_op_1 = signer.try_sign_sync(CgkaOperation::Add {
            added_id: IndividualId::generate(&mut csprng),
            pk: ShareKey::generate(&mut csprng),
            leaf_index: 42,
            predecessors: vec![],
            add_predecessors: vec![],
            doc_id: doc_id1,
        })?;

        let cgka_op_2 = signer.try_sign_sync(CgkaOperation::Remove {
            id: IndividualId::generate(&mut csprng),
            leaf_idx: 4,
            predecessors: vec![],
            removed_keys: vec![],
            doc_id: doc_id2,
        })?;

        let cgka_op_3 = signer.try_sign_sync(CgkaOperation::Add {
            added_id: IndividualId::generate(&mut csprng),
            pk: ShareKey::generate(&mut csprng),
            leaf_index: 11,
            predecessors: vec![],
            add_predecessors: vec![],
            doc_id: doc_id1,
        })?;

        let hash1 = Digest::hash(&cgka_op_1);
        let hash2 = Digest::hash(&cgka_op_2);
        let hash3 = Digest::hash(&cgka_op_3);

        let events: Vec<
            Event<MemorySigner, MemorySecretKeyStore<ThreadRng>, [u8; 32], NoListener>,
        > = vec![
            Event::CgkaOperation(Rc::new(cgka_op_1)),
            Event::CgkaOperation(Rc::new(cgka_op_2)),
            Event::PrekeysExpanded(Rc::new(
                signer.try_sign_sync(AddKeyOp::generate(&mut csprng))?,
            )),
            Event::PrekeysExpanded(Rc::new(
                signer.try_sign_sync(AddKeyOp::generate(&mut csprng))?,
            )),
            Event::PrekeysExpanded(Rc::new(
                signer.try_sign_sync(AddKeyOp::generate(&mut csprng))?,
            )),
            Event::Delegated(Rc::new(signer.try_sign_sync(Delegation {
                delegate: Agent::Individual(Rc::new(RefCell::new(
                    Individual::generate(&signer, &mut csprng).await?,
                ))),
                can: Access::Read,
                proof: None,
                after_revocations: vec![],
                after_content: BTreeMap::new(),
            })?)),
        ];

        let ciphertext1 = Rc::new(EncryptedContent::new(
            Siv::new(&SymmetricKey::generate(&mut csprng), &[4, 5, 6], doc_id1)?,
            vec![4, 5, 6],
            ShareKey::from([1u8; 32]),
            hash1,
            [1u8; 32],
            [1u8; 32].into(),
        ));

        let ciphertext2 = Rc::new(EncryptedContent::new(
            Siv::new(&SymmetricKey::generate(&mut csprng), &[1, 2, 3], doc_id2)?,
            vec![1, 2, 3],
            [2u8; 32].into(),
            hash2,
            [2u8; 32],
            [2u8; 32].into(),
        ));

        let mut store: MemoryCiphertextStore<[u8; 32], Vec<u8>> = MemoryCiphertextStore::new();
        store.insert(ciphertext1.dupe());
        store.insert(ciphertext2.dupe());

        // Should not show up in updates
        store.insert(Rc::new(EncryptedContent::new(
            Siv::new(&SymmetricKey::generate(&mut csprng), &[0], doc_id1)?,
            vec![0],
            [3u8; 32].into(),
            hash3,
            [3u8; 32],
            [3u8; 32].into(),
        )));

        let decryptable = Event::now_decryptable(&events, &store).await?;
        tracing::info!("decryptable: {:?}", decryptable);
        assert_eq!(decryptable.len(), 2);
        assert!(decryptable.contains_key(&doc_id1));
        assert!(decryptable.contains_key(&doc_id2));

        tracing::debug!("store: {:?}", store);

        let doc1_results = decryptable.get(&doc_id1).unwrap();
        tracing::info!("doc1_results: {:?}", doc1_results);
        assert_eq!(doc1_results.len(), 1);
        assert!(doc1_results.contains(&ciphertext1));

        let doc2_results = decryptable.get(&doc_id2).unwrap();
        tracing::info!("doc2_results: {:?}", doc2_results);
        assert_eq!(doc2_results.len(), 1);
        assert!(doc2_results.contains(&ciphertext2));

        Ok(())
    }
}
