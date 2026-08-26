use crate::{
    keyhive::{Keyhive, NotFound},
    listener::membership::MembershipListener,
    principal::{
        agent::Agent,
        document::{id::DocumentId, Document},
        group::id::GroupId,
        identifier::Identifier,
        membered::Membered,
    },
    store::ciphertext::{CiphertextStore, CiphertextStoreExt},
};
use future_form::FutureForm;
use futures::lock::Mutex;
use keyhive_crypto::{content::reference::ContentRef, signer::async_signer::AsyncSigner};
use serde::Deserialize;
use std::sync::Arc;

impl<
        F: FutureForm,
        S: AsyncSigner<F> + Clone,
        T: ContentRef,
        P: for<'de> Deserialize<'de>,
        C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
        L: MembershipListener<F, S, T>,
        R: rand::CryptoRng + rand::RngCore,
    > Keyhive<F, S, T, P, C, L, R>
{
    pub(crate) async fn agent_by_id(&self, id: Identifier) -> Result<Agent<F, S, T, L>, NotFound> {
        self.get_agent(id).await.ok_or(NotFound(Box::new(id)))
    }

    pub(crate) async fn document_by_id(
        &self,
        id: DocumentId,
    ) -> Result<Arc<Mutex<Document<F, S, T, L>>>, NotFound> {
        self.get_document(id)
            .await
            .ok_or(NotFound(Box::new(id.into())))
    }

    pub(crate) async fn membered_by_id(
        &self,
        id: Identifier,
    ) -> Result<Membered<F, S, T, L>, NotFound> {
        if let Some(doc) = self.get_document(DocumentId(id)).await {
            return Ok(Membered::Document(DocumentId(id), doc));
        }
        if let Some(group) = self.get_group(GroupId::new(id)).await {
            return Ok(Membered::Group(GroupId::new(id), group));
        }
        Err(NotFound(Box::new(id)))
    }
}
