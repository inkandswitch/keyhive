use crate::{
    access::Access,
    keyhive::{Keyhive, NotFound},
    listener::membership::MembershipListener,
    principal::{
        agent::Agent,
        document::{id::DocumentId, Document},
        identifier::Identifier,
        membered::{id::MemberedId, Membered},
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
        let direct = members.get(&who).copied();
        let public = members.get(&Public.id()).copied();
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
        id: MemberedId,
    ) -> Result<Membered<F, S, T, L>, NotFound> {
        match id {
            MemberedId::DocumentId(doc_id) => self
                .get_document(doc_id)
                .await
                .map(|doc| Membered::Document(doc_id, doc))
                .ok_or_else(|| NotFound(Box::new(doc_id.into()))),
            MemberedId::GroupId(group_id) => self
                .get_group(group_id)
                .await
                .map(|group| Membered::Group(group_id, group))
                .ok_or_else(|| NotFound(Box::new(group_id.into()))),
        }
    }
}
