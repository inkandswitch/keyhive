//! Events that are emitted during operation of Keyhive.

pub mod static_event;

use self::static_event::StaticEvent;
use crate::{
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::{
        document::id::DocumentId,
        group::{
            delegation::Delegation, membership_operation::MembershipOperation,
            revocation::Revocation,
        },
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp, KeyOp},
    },
    store::ciphertext::CiphertextStore,
};
use beekem::{encrypted::EncryptedContent, operation::CgkaOperation};
use derive_more::{From, TryInto};
use derive_where::derive_where;
use dupe::Dupe;
use future_form::FutureForm;
use keyhive_crypto::{
    content::reference::ContentRef, digest::Digest, signed::Signed,
    signer::async_signer::AsyncSigner,
};
use serde::Serialize;
use std::{collections::HashMap, sync::Arc};
use tracing::instrument;

/// Top-level event variants.
#[derive(PartialEq, Eq, From, TryInto)]
#[derive_where(Debug, Hash; T)]
pub enum Event<
    F: FutureForm,
    S: AsyncSigner<F>,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    /// Prekeys were expanded.
    PrekeysExpanded(Arc<Signed<AddKeyOp>>),

    /// A prekey was rotated.
    PrekeyRotated(Arc<Signed<RotateKeyOp>>),

    /// A CGKA operation was performed.
    CgkaOperation(Arc<Signed<CgkaOperation>>),

    /// A delegation was created.
    Delegated(Arc<Signed<Delegation<F, S, T, L>>>),

    /// A delegation was revoked.
    Revoked(Arc<Signed<Revocation<F, S, T, L>>>),
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    Event<F, S, T, L>
{
    #[allow(clippy::type_complexity)]
    #[instrument(level = "debug", skip(ciphertext_store))]
    pub async fn now_decryptable<P, C: CiphertextStore<T, P>>(
        new_events: &[Event<F, S, T, L>],
        ciphertext_store: &C,
    ) -> Result<HashMap<DocumentId, Vec<Arc<EncryptedContent<P, T>>>>, C::GetCiphertextError> {
        let mut acc: HashMap<DocumentId, Vec<Arc<EncryptedContent<P, T>>>> = HashMap::new();

        for event in new_events {
            if let Event::CgkaOperation(op) = event {
                let op_digest = Digest::hash(op.as_ref());
                let doc_id: DocumentId = (*op.payload.doc_id()).into();
                let more = ciphertext_store
                    .get_ciphertext_by_pcs_update(&op_digest)
                    .await?;

                acc.entry(doc_id).or_default().extend(more.into_iter());
            }
        }

        Ok(acc)
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> From<KeyOp>
    for Event<F, S, T, L>
{
    fn from(key_op: KeyOp) -> Self {
        match key_op {
            KeyOp::Add(add) => Event::PrekeysExpanded(add),
            KeyOp::Rotate(rot) => Event::PrekeyRotated(rot),
        }
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    From<MembershipOperation<F, S, T, L>> for Event<F, S, T, L>
{
    fn from(op: MembershipOperation<F, S, T, L>) -> Self {
        match op {
            MembershipOperation::Delegation(d) => Event::Delegated(d),
            MembershipOperation::Revocation(r) => Event::Revoked(r),
        }
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    From<Event<F, S, T, L>> for StaticEvent<T>
{
    fn from(op: Event<F, S, T, L>) -> Self {
        match op {
            Event::Delegated(d) => StaticEvent::Delegated(Arc::unwrap_or_clone(d).map(Into::into)),
            Event::Revoked(r) => StaticEvent::Revoked(Arc::unwrap_or_clone(r).map(Into::into)),

            Event::CgkaOperation(cgka) => {
                StaticEvent::CgkaOperation(Box::new(Arc::unwrap_or_clone(cgka)))
            }

            Event::PrekeyRotated(pkr) => {
                StaticEvent::PrekeyRotated(Box::new(Arc::unwrap_or_clone(pkr).map(Into::into)))
            }
            Event::PrekeysExpanded(pke) => {
                StaticEvent::PrekeysExpanded(Box::new(Arc::unwrap_or_clone(pke).map(Into::into)))
            }
        }
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> Serialize
    for Event<F, S, T, L>
{
    fn serialize<Z: serde::Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
        StaticEvent::from(self.clone()).serialize(serializer)
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> Clone
    for Event<F, S, T, L>
{
    fn clone(&self) -> Self {
        match self {
            Event::Delegated(d) => Event::Delegated(Arc::clone(d)),
            Event::Revoked(r) => Event::Revoked(Arc::clone(r)),

            Event::CgkaOperation(cgka) => Event::CgkaOperation(Arc::clone(cgka)),

            Event::PrekeyRotated(pkr) => Event::PrekeyRotated(Arc::clone(pkr)),
            Event::PrekeysExpanded(pke) => Event::PrekeysExpanded(Arc::clone(pke)),
        }
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> Dupe
    for Event<F, S, T, L>
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
        principal::{
            agent::Agent,
            individual::{id::IndividualId, Individual},
        },
        store::ciphertext::memory::MemoryCiphertextStore,
    };
    use beekem::id::{MemberId, TreeId};
    use futures::lock::Mutex;
    use keyhive_crypto::{
        share_key::ShareKey,
        signer::{memory::MemorySigner},
        siv::Siv,
        symmetric_key::SymmetricKey,
        verifiable::Verifiable,
    };
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;
    use test_utils::init_logging;
    use testresult::TestResult;

    #[tokio::test]
    async fn test_event_now_decryptable() -> TestResult {
        init_logging();

        let mut csprng = OsRng;
        let signer = MemorySigner::generate(&mut csprng);
        let doc_id1 = DocumentId::generate(&mut csprng);
        let doc_id2 = DocumentId::generate(&mut csprng);

        let cgka_op_1 = signer.try_sign_sync(CgkaOperation::Add {
            added_id: MemberId(IndividualId::generate(&mut csprng).verifying_key()),
            pk: ShareKey::generate(&mut csprng),
            leaf_index: 42,
            predecessors: vec![],
            add_predecessors: vec![],
            doc_id: TreeId(doc_id1.verifying_key()),
        })?;

        let cgka_op_2 = signer.try_sign_sync(CgkaOperation::Remove {
            id: MemberId(IndividualId::generate(&mut csprng).verifying_key()),
            leaf_idx: 4,
            predecessors: vec![],
            removed_keys: vec![],
            doc_id: TreeId(doc_id2.verifying_key()),
        })?;

        let cgka_op_3 = signer.try_sign_sync(CgkaOperation::Add {
            added_id: MemberId(IndividualId::generate(&mut csprng).verifying_key()),
            pk: ShareKey::generate(&mut csprng),
            leaf_index: 11,
            predecessors: vec![],
            add_predecessors: vec![],
            doc_id: TreeId(doc_id1.verifying_key()),
        })?;

        let hash1 = Digest::hash(&cgka_op_1);
        let hash2 = Digest::hash(&cgka_op_2);
        let hash3 = Digest::hash(&cgka_op_3);

        let indie = Individual::generate(&signer, &mut csprng).await?;
        let events: Vec<Event<MemorySigner, [u8; 32], NoListener>> = vec![
            Event::CgkaOperation(Arc::new(cgka_op_1)),
            Event::CgkaOperation(Arc::new(cgka_op_2)),
            Event::PrekeysExpanded(Arc::new(
                signer.try_sign_sync(AddKeyOp::generate(&mut csprng))?,
            )),
            Event::PrekeysExpanded(Arc::new(
                signer.try_sign_sync(AddKeyOp::generate(&mut csprng))?,
            )),
            Event::PrekeysExpanded(Arc::new(
                signer.try_sign_sync(AddKeyOp::generate(&mut csprng))?,
            )),
            Event::Delegated(Arc::new(signer.try_sign_sync(Delegation {
                delegate: Agent::Individual(indie.id(), Arc::new(Mutex::new(indie))),
                can: Access::Read,
                proof: None,
                after_revocations: vec![],
                after_content: BTreeMap::new(),
            })?)),
        ];

        let ciphertext1 = Arc::new(EncryptedContent::new(
            Siv::new(
                &SymmetricKey::generate(&mut csprng),
                &[4, 5, 6],
                doc_id1.as_bytes(),
            ),
            vec![4, 5, 6],
            [1u8; 32].into(),
            hash1,
            [1u8; 32],
            [1u8; 32].into(),
        ));

        let ciphertext2 = Arc::new(EncryptedContent::new(
            Siv::new(
                &SymmetricKey::generate(&mut csprng),
                &[1, 2, 3],
                doc_id2.as_bytes(),
            ),
            vec![1, 2, 3],
            [2u8; 32].into(),
            hash2,
            [2u8; 32],
            [2u8; 32].into(),
        ));

        let store: MemoryCiphertextStore<[u8; 32], Vec<u8>> = MemoryCiphertextStore::new();
        store.insert(ciphertext1.dupe()).await;
        store.insert(ciphertext2.dupe()).await;

        // Should not show up in updates
        store
            .insert(Arc::new(EncryptedContent::new(
                Siv::new(
                    &SymmetricKey::generate(&mut csprng),
                    &[0],
                    doc_id1.as_bytes(),
                ),
                vec![0],
                [3u8; 32].into(),
                hash3,
                [3u8; 32],
                [3u8; 32].into(),
            )))
            .await;

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
