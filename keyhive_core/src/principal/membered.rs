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
        digest::Digest, share_key::ShareSecretStore, signed::Signed,
        signer::async_signer::AsyncSigner, verifiable::Verifiable,
    },
    listener::{membership::MembershipListener, no_listener::NoListener},
    util::content_addressed_map::CaMap,
};
use derive_where::derive_where;
use dupe::{Dupe, OptionDupedExt};
use id::MemberedId;
use nonempty::NonEmpty;
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    rc::Rc,
};

/// The union of Agents that have updatable membership
#[derive(Clone, Dupe)]
#[derive_where(Debug, PartialEq; T)]
pub enum Membered<
    S: AsyncSigner,
    K: ShareSecretStore,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, K, T> = NoListener,
> {
    Group(Rc<RefCell<Group<S, K, T, L>>>),
    Document(Rc<RefCell<Document<S, K, T, L>>>),
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    Membered<S, K, T, L>
{
    pub fn get_capability(
        &self,
        agent_id: &Identifier,
    ) -> Option<Rc<Signed<Delegation<S, K, T, L>>>> {
        match self {
            Membered::Group(group) => group.borrow().get_capability(agent_id).duped(),
            Membered::Document(doc) => doc.borrow().get_capability(agent_id).duped(),
        }
    }

    pub fn agent_id(&self) -> AgentId {
        match self {
            Membered::Group(group) => group.borrow().agent_id(),
            Membered::Document(document) => document.borrow().agent_id(),
        }
    }

    pub fn membered_id(&self) -> MemberedId {
        match self {
            Membered::Group(group) => MemberedId::GroupId(group.borrow().group_id()),
            Membered::Document(document) => MemberedId::DocumentId(document.borrow().doc_id()),
        }
    }

    pub fn delegation_heads(&self) -> CaMap<Signed<Delegation<S, K, T, L>>> {
        match self {
            Membered::Group(group) => group.borrow().delegation_heads().clone(),
            Membered::Document(document) => document.borrow().delegation_heads().clone(),
        }
    }

    pub fn revocation_heads(&self) -> CaMap<Signed<Revocation<S, K, T, L>>> {
        match self {
            Membered::Group(group) => group.borrow().revocation_heads().clone(),
            Membered::Document(document) => document.borrow().revocation_heads().clone(),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn members(&self) -> HashMap<Identifier, NonEmpty<Rc<Signed<Delegation<S, K, T, L>>>>> {
        match self {
            Membered::Group(group) => group.borrow().members().clone(),
            Membered::Document(document) => document.borrow().members().clone(),
        }
    }

    #[allow(clippy::await_holding_refcell_ref)] // FIXME
    #[allow(clippy::type_complexity)]
    pub async fn add_member<K: ShareSecretStore>(
        &mut self,
        member_to_add: Agent<S, K, T, L>,
        can: Access,
        signer: &S,
        other_relevant_docs: &[Rc<RefCell<Document<S, K, T, L>>>],
    ) -> Result<AddMemberUpdate<S, K, T, L>, AddMemberError> {
        match self {
            Membered::Group(group) => Ok(group
                .borrow_mut()
                .add_member(member_to_add, can, signer, other_relevant_docs)
                .await?),
            Membered::Document(document) => {
                document
                    .borrow_mut()
                    .add_member(member_to_add, can, signer, other_relevant_docs)
                    .await
            }
        }
    }

    #[allow(clippy::await_holding_refcell_ref)] // FIXME
    #[allow(clippy::type_complexity)]
    pub async fn revoke_member<K: ShareSecretStore>(
        &mut self,
        member_id: Identifier,
        retain_all_other_members: bool,
        signer: &S,
        relevant_docs: &mut BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<RevokeMemberUpdate<S, K, T, L>, RevokeMemberError> {
        match self {
            Membered::Group(group) => {
                group
                    .borrow_mut()
                    .revoke_member(member_id, retain_all_other_members, signer, relevant_docs)
                    .await
            }
            Membered::Document(document) => {
                document
                    .borrow_mut()
                    .revoke_member(member_id, retain_all_other_members, signer, relevant_docs)
                    .await
            }
        }
    }

    pub fn get_agent_revocations(
        &self,
        agent: &Agent<S, K, T, L>,
    ) -> Vec<Rc<Signed<Revocation<S, K, T, L>>>> {
        match self {
            Membered::Group(group) => group.borrow().get_agent_revocations(agent),
            Membered::Document(document) => document.borrow().get_agent_revocations(agent),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn receive_delegation(
        &self,
        delegation: Rc<Signed<Delegation<S, K, T, L>>>,
    ) -> Result<Digest<Signed<Delegation<S, K, T, L>>>, AddError> {
        match self {
            Membered::Group(group) => Ok(group.borrow_mut().receive_delegation(delegation)?),
            Membered::Document(document) => {
                Ok(document.borrow_mut().receive_delegation(delegation)?)
            }
        }
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    From<Rc<RefCell<Group<S, K, T, L>>>> for Membered<S, K, T, L>
{
    fn from(group: Rc<RefCell<Group<S, K, T, L>>>) -> Self {
        Membered::Group(group)
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    From<Rc<RefCell<Document<S, K, T, L>>>> for Membered<S, K, T, L>
{
    fn from(document: Rc<RefCell<Document<S, K, T, L>>>) -> Self {
        Membered::Document(document)
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Verifiable
    for Membered<S, K, T, L>
{
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            Membered::Group(group) => group.borrow().verifying_key(),
            Membered::Document(document) => document.borrow().verifying_key(),
        }
    }
}
