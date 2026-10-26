//! Events that are emitted during operation of Keyhive.

pub mod static_event;

use self::static_event::StaticEvent;
use crate::{
    content::heads::ContentHeads,
    principal::{
        document::id::DocumentId,
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp, KeyOp},
    },
    store::ciphertext::CiphertextStore,
};
use beekem::{encrypted::EncryptedContent, operation::CgkaOperation};
use derive_more::{From, TryInto};
use dupe::Dupe;
use future_form::FutureForm;
use keyhive_crypto::{
    content::reference::ContentRef,
    digest::Digest,
    signed::SerdeSigned,
    verified::{self},
};
use keyline::{certificate::Certificate, delegation::Delegation, revocation::Revocation};
use serde::{Serialize, Serializer};
use std::{collections::HashMap, sync::Arc};
use tracing::instrument;

/// Top-level event variants.
#[derive(Clone, Debug, Hash, PartialEq, Eq, From, TryInto)]
pub enum Event<T: ContentRef> {
    /// Prekeys were expanded, in wire form: verified before it became an
    /// event.
    PrekeysExpanded(Arc<verified::Signed<AddKeyOp>>),

    /// A prekey was rotated, in wire form.
    PrekeyRotated(Arc<verified::Signed<RotateKeyOp>>),

    /// A CGKA operation was performed.
    CgkaOperation(Arc<SerdeSigned<CgkaOperation>>),

    /// A Keyline delegation, in wire form: a store hands out what it holds
    /// without verifying it again.
    Delegated(Arc<verified::Signed<Delegation>>),

    /// A Keyline revocation, in wire form.
    Revoked(Arc<verified::Signed<Revocation<ContentHeads<T>>>>),
}

impl<T: ContentRef> Event<T> {
    #[allow(clippy::type_complexity)]
    #[instrument(level = "debug", skip(ciphertext_store))]
    pub async fn now_decryptable<F: FutureForm, P, C: CiphertextStore<F, T, P>>(
        new_events: &[Event<T>],
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

impl<T: ContentRef> From<KeyOp> for Event<T> {
    fn from(key_op: KeyOp) -> Self {
        match key_op {
            KeyOp::Add(add) => Event::PrekeysExpanded(add.signed().dupe()),
            KeyOp::Rotate(rot) => Event::PrekeyRotated(rot.signed().dupe()),
        }
    }
}

impl<T: ContentRef> From<Certificate<ContentHeads<T>>> for Event<T> {
    fn from(cert: Certificate<ContentHeads<T>>) -> Self {
        match cert {
            Certificate::Delegation(d) => Event::Delegated(d),
            Certificate::Revocation(r) => Event::Revoked(r),
        }
    }
}

impl<T: ContentRef> From<Event<T>> for StaticEvent<T> {
    fn from(op: Event<T>) -> Self {
        match op {
            Event::Delegated(d) => StaticEvent::Delegated(Arc::unwrap_or_clone(d)),
            Event::Revoked(r) => StaticEvent::Revoked(Arc::unwrap_or_clone(r)),

            Event::CgkaOperation(cgka) => {
                StaticEvent::CgkaOperation(Box::new(Arc::unwrap_or_clone(cgka)))
            }

            Event::PrekeyRotated(pkr) => StaticEvent::PrekeyRotated(Arc::unwrap_or_clone(pkr)),
            Event::PrekeysExpanded(pke) => StaticEvent::PrekeysExpanded(Arc::unwrap_or_clone(pke)),
        }
    }
}

impl<T: ContentRef> Serialize for Event<T> {
    fn serialize<Z: Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
        StaticEvent::from(self.clone()).serialize(serializer)
    }
}

impl<T: ContentRef> Dupe for Event<T> {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        principal::individual::id::IndividualId, store::ciphertext::memory::MemoryCiphertextStore,
    };
    use beekem::{
        id::{MemberId, TreeId},
        operation::CgkaChange,
    };
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use future_form::Sendable;
    use keyhive_crypto::{
        identifier::Identifier, share_key::ShareKey, signer::memory::MemorySigner,
        symmetric_key::SymmetricKey, verifiable::Verifiable, verified::Verified,
    };
    use keyline::power::Power;
    use rand::rngs::OsRng;
    use std::collections::BTreeSet;
    use test_utils::init_logging;
    use testresult::TestResult;

    #[tokio::test]
    async fn test_event_now_decryptable() -> TestResult {
        init_logging();

        let mut csprng = OsRng;
        let signer = MemorySigner::generate(&mut csprng);
        let doc_id1 = DocumentId::generate(&mut csprng);
        let doc_id2 = DocumentId::generate(&mut csprng);

        let cgka_op_1 = signer.try_sign_sync(CgkaOperation {
            doc_id: TreeId::from(doc_id1),
            predecessors: BTreeSet::new(),
            change: CgkaChange::Add {
                added_id: MemberId::from(&SigningKey::generate(&mut csprng)),
                pk: ShareKey::generate(&mut csprng),
                leaf_index: 42,
                invitation: None,
                key_proof: None,
                citations: BTreeSet::new(),
            },
        })?;

        let cgka_op_2 = signer.try_sign_sync(CgkaOperation {
            doc_id: TreeId::from(doc_id2),
            predecessors: BTreeSet::new(),
            change: CgkaChange::Remove {
                citations: BTreeSet::new(),
                removed: BTreeSet::new(),
            },
        })?;

        let cgka_op_3 = signer.try_sign_sync(CgkaOperation {
            doc_id: TreeId::from(doc_id1),
            predecessors: BTreeSet::new(),
            change: CgkaChange::Add {
                added_id: MemberId::from(&SigningKey::generate(&mut csprng)),
                pk: ShareKey::generate(&mut csprng),
                leaf_index: 11,
                invitation: None,
                key_proof: None,
                citations: BTreeSet::new(),
            },
        })?;

        let hash1 = Digest::hash(&cgka_op_1);
        let hash2 = Digest::hash(&cgka_op_2);
        let hash3 = Digest::hash(&cgka_op_3);

        let id = |key: VerifyingKey| {
            Identifier::try_from(key).expect("a generated key is a valid point")
        };
        let delegation = Verified::sign_sync(
            &Delegation::new(
                id(IndividualId::generate(&mut csprng).verifying_key()),
                id(doc_id1.verifying_key()),
                Power::Read,
            ),
            &signer,
        )?;
        let events: Vec<Event<[u8; 32]>> = vec![
            Event::CgkaOperation(Arc::new(cgka_op_1)),
            Event::CgkaOperation(Arc::new(cgka_op_2)),
            Event::PrekeysExpanded(
                Verified::sign_sync(&AddKeyOp::generate(&mut csprng), &signer)?
                    .signed()
                    .dupe(),
            ),
            Event::PrekeysExpanded(
                Verified::sign_sync(&AddKeyOp::generate(&mut csprng), &signer)?
                    .signed()
                    .dupe(),
            ),
            Event::PrekeysExpanded(
                Verified::sign_sync(&AddKeyOp::generate(&mut csprng), &signer)?
                    .signed()
                    .dupe(),
            ),
            Event::Delegated(delegation.signed().dupe()),
        ];

        let ciphertext1 = Arc::new(EncryptedContent::encrypt(
            &SymmetricKey::generate(&mut csprng),
            doc_id1.into(),
            [1u8; 32],
            [1u8; 32].into(),
            [1u8; 32].into(),
            hash1,
            &[4, 5, 6],
        )?);

        let ciphertext2 = Arc::new(EncryptedContent::encrypt(
            &SymmetricKey::generate(&mut csprng),
            doc_id2.into(),
            [2u8; 32],
            [2u8; 32].into(),
            [2u8; 32].into(),
            hash2,
            &[1, 2, 3],
        )?);

        let store: MemoryCiphertextStore<[u8; 32], Vec<u8>> = MemoryCiphertextStore::new();
        store.insert(ciphertext1.dupe()).await;
        store.insert(ciphertext2.dupe()).await;

        // Should not show up in updates
        store
            .insert(Arc::new(EncryptedContent::encrypt(
                &SymmetricKey::generate(&mut csprng),
                doc_id1.into(),
                [3u8; 32],
                [3u8; 32].into(),
                [3u8; 32].into(),
                hash3,
                &[0],
            )?))
            .await;

        let decryptable = Event::now_decryptable::<Sendable, _, _>(&events, &store).await?;
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
