pub mod id;

use super::{
    agent::{id::AgentId, Agent},
    document::{id::DocumentId, AddMemberError, AddMemberUpdate, Document, RevokeMemberUpdate},
    group::{
        delegation::Delegation, error::AddError, revocation::Revocation, Group, RevokeMemberError,
    },
    identifier::Identifier,
};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        digest::Digest, signed::Signed, signer::async_signer::AsyncSigner, verifiable::Verifiable,
    },
    listener::{membership::MembershipListener, no_listener::NoListener},
    util::content_addressed_map::CaMap,
};
use derive_where::derive_where;
use dupe::{Dupe, OptionDupedExt};
use futures::lock::Mutex;
use id::MemberedId;
use nonempty::NonEmpty;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

/// The union of Agents that have updatable membership
#[derive(Clone, Dupe)]
#[derive_where(Debug, PartialEq; T)]
pub enum Membered<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    Group(Arc<Mutex<Group<S, T, L>>>),
    Document(Arc<Mutex<Document<S, T, L>>>),
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Membered<S, T, L> {
    pub async fn get_capability(
        &self,
        agent_id: &Identifier,
    ) -> Option<Arc<Signed<Delegation<S, T, L>>>> {
        match self {
            Membered::Group(group) => {
                let locked = group.lock().await;
                locked.get_capability(agent_id).duped()
            }
            Membered::Document(doc) => {
                let locked = doc.lock().await;
                locked.get_capability(agent_id).duped()
            }
        }
    }

    pub async fn agent_id(&self) -> AgentId {
        match self {
            Membered::Group(group) => {
                let locked = group.lock().await;
                locked.agent_id()
            }
            Membered::Document(document) => {
                let locked = document.lock().await;
                locked.agent_id()
            }
        }
    }

    pub async fn membered_id(&self) -> MemberedId {
        match self {
            Membered::Group(group) => {
                let locked = group.lock().await;
                MemberedId::GroupId(locked.group_id())
            }
            Membered::Document(document) => {
                let locked = document.lock().await;
                MemberedId::DocumentId(locked.doc_id())
            }
        }
    }

    pub async fn delegation_heads(&self) -> CaMap<Signed<Delegation<S, T, L>>> {
        match self {
            Membered::Group(group) => group.lock().await.delegation_heads().clone(),
            Membered::Document(document) => document.lock().await.delegation_heads().clone(),
        }
    }

    pub async fn revocation_heads(&self) -> CaMap<Signed<Revocation<S, T, L>>> {
        match self {
            Membered::Group(group) => group.lock().await.revocation_heads().clone(),
            Membered::Document(document) => document.lock().await.revocation_heads().clone(),
        }
    }

    #[allow(clippy::type_complexity)]
    pub async fn members(&self) -> HashMap<Identifier, NonEmpty<Arc<Signed<Delegation<S, T, L>>>>> {
        match self {
            Membered::Group(group) => group.lock().await.members().clone(),
            Membered::Document(document) => document.lock().await.members().clone(),
        }
    }

    #[allow(clippy::type_complexity)]
    pub async fn add_member(
        &mut self,
        member_to_add: Agent<S, T, L>,
        can: Access,
        signer: &S,
        other_relevant_docs: &[Arc<Mutex<Document<S, T, L>>>],
    ) -> Result<AddMemberUpdate<S, T, L>, AddMemberError> {
        match self {
            Membered::Group(group) => Ok(group
                .lock()
                .await
                .add_member(member_to_add, can, signer, other_relevant_docs)
                .await?),
            Membered::Document(document) => {
                document
                    .lock()
                    .await
                    .add_member(member_to_add, can, signer, other_relevant_docs)
                    .await
            }
        }
    }

    #[allow(clippy::type_complexity)]
    pub async fn revoke_member(
        &mut self,
        member_id: Identifier,
        retain_all_other_members: bool,
        signer: &S,
        relevant_docs: &mut BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<RevokeMemberUpdate<S, T, L>, RevokeMemberError> {
        match self {
            Membered::Group(group) => {
                group
                    .lock()
                    .await
                    .revoke_member(member_id, retain_all_other_members, signer, relevant_docs)
                    .await
            }
            Membered::Document(document) => {
                document
                    .lock()
                    .await
                    .revoke_member(member_id, retain_all_other_members, signer, relevant_docs)
                    .await
            }
        }
    }

    pub async fn get_agent_revocations(
        &self,
        agent: &Agent<S, T, L>,
    ) -> Vec<Arc<Signed<Revocation<S, T, L>>>> {
        match self {
            Membered::Group(group) => group.lock().await.get_agent_revocations(agent).await,
            Membered::Document(document) => {
                document.lock().await.get_agent_revocations(agent).await
            }
        }
    }

    #[allow(clippy::type_complexity)]
    pub async fn receive_delegation(
        &self,
        delegation: Arc<Signed<Delegation<S, T, L>>>,
    ) -> Result<Digest<Signed<Delegation<S, T, L>>>, AddError> {
        match self {
            Membered::Group(group) => Ok(group.lock().await.receive_delegation(delegation).await?),
            Membered::Document(document) => {
                Ok(document.lock().await.receive_delegation(delegation).await?)
            }
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<Arc<Mutex<Group<S, T, L>>>>
    for Membered<S, T, L>
{
    fn from(group: Arc<Mutex<Group<S, T, L>>>) -> Self {
        Membered::Group(group)
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<Arc<Mutex<Document<S, T, L>>>>
    for Membered<S, T, L>
{
    fn from(document: Arc<Mutex<Document<S, T, L>>>) -> Self {
        Membered::Document(document)
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Verifiable for Membered<S, T, L> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        todo!("FIXME")
        // match self {
        //     Membered::Group(group) => group.lock().await.verifying_key(),
        //     Membered::Document(document) => document.lock().await.verifying_key(),
        // }
    }
}
