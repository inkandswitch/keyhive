use crate::{
    access::Access,
    keyhive::{Keyhive, NotFound},
    listener::membership::MembershipListener,
    principal::{
        agent::Agent,
        document::{id::DocumentId, Document},
        group::id::GroupId,
        identifier::Identifier,
        membered::Membered,
        public::Public,
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
    /// What access `who` has for `doc`. Returns `None` for no access.
    ///
    /// Errors if we have never heard of `who` or `doc`.
    pub async fn access_for_doc(
        &self,
        who: impl Into<Identifier>,
        doc: DocumentId,
    ) -> Result<Option<Access>, NotFound> {
        let who = self.check_received(who.into()).await?;
        let members = self
            .document_by_id(doc)
            .await?
            .lock()
            .await
            .transitive_members()
            .await;
        Ok(members.get(&who).map(|(_, can)| *can))
    }

    /// The higher of `who`'s access to `doc` and public's access to `doc`.
    ///
    /// Errors if we have never heard of `who` or `doc`.
    pub async fn best_access_for_doc(
        &self,
        who: impl Into<Identifier>,
        doc: DocumentId,
    ) -> Result<Option<Access>, NotFound> {
        let who = self.check_received(who.into()).await?;
        let members = self.reachable_members(doc).await?;
        let direct = members.get(&who).map(|m| m.can);
        let public = members.get(&Public.id()).map(|m| m.can);
        // `None` sorts below `Some`, so this is "the better of the two, if either".
        Ok(direct.max(public))
    }

    /// Whether this instance has received the events that describe `who`.
    pub async fn has_received(&self, who: impl Into<Identifier>) -> bool {
        self.get_agent(who.into()).await.is_some()
    }

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
