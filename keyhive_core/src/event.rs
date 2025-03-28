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
    store::ciphertext::CiphertextStore,
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
pub enum Event<S: AsyncSigner, T: ContentRef = [u8; 32], L: MembershipListener<S, T> = NoListener> {
    /// Prekeys were expanded.
    PrekeysExpanded(Rc<Signed<AddKeyOp>>),

    /// A prekey was rotated.
    PrekeyRotated(Rc<Signed<RotateKeyOp>>),

    /// A CGKA operation was performed.
    CgkaOperation(Rc<Signed<CgkaOperation>>),

    /// A delegation was created.
    Delegated(Rc<Signed<Delegation<S, T, L>>>),

    /// A delegation was revoked.
    Revoked(Rc<Signed<Revocation<S, T, L>>>),
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Event<S, T, L> {
    #[instrument(level = "debug", skip(ciphertext_store))]
    pub async fn now_decryptable<P, C: CiphertextStore<T, P>>(
        new_events: &[Event<S, T, L>],
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

                acc.entry(*doc_id)
                    .or_default()
                    .extend_from_slice(more.as_slice());
            }
        }

        Ok(acc)
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<KeyOp> for Event<S, T, L> {
    fn from(key_op: KeyOp) -> Self {
        match key_op {
            KeyOp::Add(add) => Event::PrekeysExpanded(add),
            KeyOp::Rotate(rot) => Event::PrekeyRotated(rot),
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<MembershipOperation<S, T, L>>
    for Event<S, T, L>
{
    fn from(op: MembershipOperation<S, T, L>) -> Self {
        match op {
            MembershipOperation::Delegation(d) => Event::Delegated(d),
            MembershipOperation::Revocation(r) => Event::Revoked(r),
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<Event<S, T, L>>
    for StaticEvent<T>
{
    fn from(op: Event<S, T, L>) -> Self {
        match op {
            Event::Delegated(d) => StaticEvent::Delegated(Rc::unwrap_or_clone(d).map(Into::into)),
            Event::Revoked(r) => StaticEvent::Revoked(Rc::unwrap_or_clone(r).map(Into::into)),

            Event::CgkaOperation(cgka) => StaticEvent::CgkaOperation(Rc::unwrap_or_clone(cgka)),

            Event::PrekeyRotated(pkr) => {
                StaticEvent::PrekeyRotated(Rc::unwrap_or_clone(pkr).map(Into::into))
            }
            Event::PrekeysExpanded(pke) => {
                StaticEvent::PrekeysExpanded(Rc::unwrap_or_clone(pke).map(Into::into))
            }
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Serialize for Event<S, T, L> {
    fn serialize<Z: serde::Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
        StaticEvent::from(self.clone()).serialize(serializer)
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Clone for Event<S, T, L> {
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

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Dupe for Event<S, T, L> {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap};

    use crate::{
        access::Access,
        crypto::{
            share_key::ShareKey,
            signer::{memory::MemorySigner, sync_signer::SyncSigner},
        },
        principal::{
            group::Group,
            individual::{id::IndividualId, Individual},
        },
    };

    use super::*;

    #[tokio::test]
    async fn test_event_now_decryptable() {
        let mut csprng = rand::thread_rng();
        let signer = MemorySigner::generate(&mut csprng);
        let doc_id = DocumentId::generate(&mut csprng);
        let doc_id2 = DocumentId::generate(&mut csprng);

        let events = vec![
            Event::CgkaOperation(Rc::new(
                signer
                    .try_sign_sync(CgkaOperation::Add {
                        added_id: IndividualId::generate(&mut csprng),
                        pk: ShareKey::generate(&mut csprng),
                        leaf_index: 42,
                        predecessors: vec![],
                        add_predecessors: vec![],
                        doc_id,
                    })
                    .expect("signature to work"),
            )),
            Event::CgkaOperation(Rc::new(
                signer
                    .try_sign_sync(CgkaOperation::Remove {
                        id: IndividualId::generate(&mut csprng),
                        leaf_idx: 4,
                        predecessors: vec![],
                        removed_keys: vec![],
                        doc_id,
                    })
                    .expect("signature to work"),
            )),
            Event::PrekeysExpanded(Rc::new(
                signer
                    .try_sign_sync(AddKeyOp::generate(&mut csprng))
                    .expect("signature to work"),
            )),
            Event::PrekeysExpanded(Rc::new(
                signer
                    .try_sign_sync(AddKeyOp::generate(&mut csprng))
                    .expect("signature to work"),
            )),
            Event::PrekeysExpanded(Rc::new(
                signer
                    .try_sign_sync(AddKeyOp::generate(&mut csprng))
                    .expect("signature to work"),
            )),
            Event::CgkaOperation(Rc::new(
                signer
                    .try_sign_sync(CgkaOperation::Add {
                        added_id: IndividualId::generate(&mut csprng),
                        pk: ShareKey::generate(&mut csprng),
                        leaf_index: 11,
                        predecessors: vec![],
                        add_predecessors: vec![],
                        doc_id: doc_id2,
                    })
                    .expect("signature to work"),
            )),
            Event::Delegated(Rc::new(
                signer
                    .try_sign_sync(Delegation {
                        delegate: Rc::new(RefCell::new(Individual::generate(&signer, &mut csprng)))
                            .into(),
                        can: Access::Read,
                        proof: None,
                        after_revocations: vec![],
                        after_content: BTreeMap::new(),
                    })
                    .expect("signature to work"),
            )),
        ];

        let ciphertext_store = crate::store::ciphertext::NoCiphertextStore;
        let res = Event::now_decryptable(&[event], &ciphertext_store).await;
        assert!(res.is_ok());
    }
}
