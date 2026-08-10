pub mod id;

use super::{
    agent::{id::AgentId, Agent},
    document::{id::DocumentId, AddMemberError, AddMemberUpdate, Document, RevokeMemberUpdate},
    group::{
        compute_add_proof, compute_revoke_proof, delegation::Delegation, error::AddError,
        id::GroupId, revocation::Revocation, transitive_members_walk, Group, RevokeMemberError,
    },
    identifier::Identifier,
};
use crate::{
    access::Access,
    crypto::digest::Digest,
    listener::{membership::MembershipListener, no_listener::NoListener},
    store::{delegation::DelegationStore, revocation::RevocationStore},
};
use dupe::{Dupe, OptionDupedExt};
use future_form::FutureForm;
use futures::lock::Mutex;
use id::MemberedId;
use keyhive_crypto::{
    content::reference::ContentRef, signed::Signed, signer::async_signer::AsyncSigner,
    verifiable::Verifiable,
};
use nonempty::NonEmpty;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

/// The union of Agents that have updatable membership
#[derive(Debug, Clone, Dupe)]
pub enum Membered<
    F: FutureForm,
    S: AsyncSigner<F>,
    T: ContentRef = [u8; 32],
    L: MembershipListener<F, S, T> = NoListener,
> {
    Group(GroupId, Arc<Mutex<Group<F, S, T, L>>>),
    Document(DocumentId, Arc<Mutex<Document<F, S, T, L>>>),
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    Membered<F, S, T, L>
{
    pub async fn get_capability(
        &self,
        agent_id: &Identifier,
    ) -> Option<Arc<Signed<Delegation<F, S, T, L>>>> {
        match self {
            Membered::Group(_, group) => {
                let locked = group.lock().await;
                locked.get_capability(agent_id).duped()
            }
            Membered::Document(_, doc) => {
                let locked = doc.lock().await;
                locked.get_capability(agent_id).duped()
            }
        }
    }

    pub fn agent_id(&self) -> AgentId {
        match self {
            Membered::Group(g_id, _) => (*g_id).into(),
            Membered::Document(doc_id, _) => (*doc_id).into(),
        }
    }

    pub fn membered_id(&self) -> MemberedId {
        match self {
            Membered::Group(id, _) => MemberedId::GroupId(*id),
            Membered::Document(id, _) => MemberedId::DocumentId(*id),
        }
    }

    pub async fn delegation_heads(&self) -> DelegationStore<F, S, T, L> {
        match self {
            Membered::Group(_, group) => group.lock().await.delegation_heads().clone(),
            Membered::Document(_, document) => document.lock().await.delegation_heads().clone(),
        }
    }

    pub async fn revocation_heads(&self) -> RevocationStore<F, S, T, L> {
        match self {
            Membered::Group(_, group) => group.lock().await.revocation_heads().clone(),
            Membered::Document(_, document) => document.lock().await.revocation_heads().clone(),
        }
    }

    #[allow(clippy::type_complexity)]
    pub async fn members(
        &self,
    ) -> HashMap<Identifier, NonEmpty<Arc<Signed<Delegation<F, S, T, L>>>>> {
        match self {
            Membered::Group(_, group) => group.lock().await.members().clone(),
            Membered::Document(_, document) => document.lock().await.members().clone(),
        }
    }

    pub async fn transitive_members(&self) -> HashMap<Identifier, (Agent<F, S, T, L>, Access)> {
        // Snapshot the direct membership under a short lock, then run the
        // transitive walk with NO lock held (it acquires only short per-node
        // locks). Holding the root across the walk would let concurrent walks
        // ABBA-deadlock.
        let (root_id, direct) = match self {
            Membered::Group(id, group) => {
                let locked = group.lock().await;
                (Identifier::from(*id), locked.direct_members_with_caps())
            }
            Membered::Document(id, doc) => {
                let locked = doc.lock().await;
                (Identifier::from(*id), locked.direct_members_with_caps())
            }
        };
        transitive_members_walk(root_id, direct).await
    }

    #[allow(clippy::type_complexity)]
    pub(crate) async fn add_member_with_manual_content(
        &self,
        member_to_add: Agent<F, S, T, L>,
        can: Access,
        signer: &S,
        after_content: BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<AddMemberUpdate<F, S, T, L>, AddMemberError> {
        let signer_vk = signer.verifying_key();
        // 1. Snapshot direct membership under a short lock.
        // 2. Compute the transitive proof with NO lock held (the walk only
        //    takes short per-node locks — it must never run while this
        //    resource's lock is held, as the membership graph is cyclic).
        // 3. Re-lock and mutate with the precomputed proof.
        let (root_vk, members) = match self {
            Membered::Group(_, group) => {
                let locked = group.lock().await;
                (locked.verifying_key(), locked.members().clone())
            }
            Membered::Document(_, document) => {
                let locked = document.lock().await;
                (locked.group.verifying_key(), locked.group.members().clone())
            }
        };
        let proof = compute_add_proof(root_vk, &members, signer_vk, can).await?;
        match self {
            Membered::Group(_, group) => Ok(group
                .lock()
                .await
                .add_member_with_manual_content(member_to_add, can, signer, after_content, proof)
                .await?),
            Membered::Document(_, document) => {
                document
                    .lock()
                    .await
                    .add_member_with_manual_content(
                        member_to_add,
                        can,
                        signer,
                        after_content,
                        proof,
                    )
                    .await
            }
        }
    }

    #[allow(clippy::type_complexity)]
    pub async fn add_member(
        &self,
        member_to_add: Agent<F, S, T, L>,
        can: Access,
        signer: &S,
        other_relevant_docs: &[Arc<Mutex<Document<F, S, T, L>>>],
    ) -> Result<AddMemberUpdate<F, S, T, L>, AddMemberError> {
        let signer_vk = signer.verifying_key();
        // Snapshot + lock-free proof, then mutate (see
        // [`add_member_with_manual_content`]).
        let (root_vk, members) = match self {
            Membered::Group(_, group) => {
                let locked = group.lock().await;
                (locked.verifying_key(), locked.members().clone())
            }
            Membered::Document(_, document) => {
                let locked = document.lock().await;
                (locked.group.verifying_key(), locked.group.members().clone())
            }
        };
        let proof = compute_add_proof(root_vk, &members, signer_vk, can).await?;
        match self {
            Membered::Group(_, group) => Ok(group
                .lock()
                .await
                .add_member(member_to_add, can, signer, other_relevant_docs, proof)
                .await?),
            Membered::Document(_, document) => {
                document
                    .lock()
                    .await
                    .add_member(member_to_add, can, signer, other_relevant_docs, proof)
                    .await
            }
        }
    }

    #[allow(clippy::type_complexity)]
    pub async fn revoke_member(
        &self,
        member_id: Identifier,
        retain_all_other_members: bool,
        signer: &S,
        relevant_docs: &mut BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<RevokeMemberUpdate<F, S, T, L>, RevokeMemberError> {
        let signer_vk = signer.verifying_key();
        // Snapshot direct membership, precompute the signer's authority proofs
        // per needed access level (transitive walks with NO lock held), then
        // mutate with the precomputed proofs. Two maps: `signer_authority`
        // authorizes the revocations themselves (transitive-only — the signer's
        // own individual delegation is not a valid revocation proof);
        // `re_add_authority` authorizes the `retain_all_other_members`
        // re-delegations (add semantics — the signer's own delegation is valid).
        let (root_vk, members) = match self {
            Membered::Group(_, group) => {
                let locked = group.lock().await;
                (locked.verifying_key(), locked.members().clone())
            }
            Membered::Document(_, document) => {
                let locked = document.lock().await;
                (locked.group.verifying_key(), locked.group.members().clone())
            }
        };
        let mut needed: HashSet<Access> = HashSet::new();
        if let Some(dlgs) = members.get(&member_id) {
            for d in dlgs.iter() {
                needed.insert(d.payload.can);
            }
        }
        for dlgs in members.values() {
            for d in dlgs.iter() {
                needed.insert(d.payload.can);
            }
        }
        let mut signer_authority = HashMap::new();
        let mut re_add_authority = HashMap::new();
        for can in needed {
            signer_authority.insert(
                can,
                compute_revoke_proof(root_vk, &members, signer_vk, can).await,
            );
            re_add_authority.insert(
                can,
                compute_add_proof(root_vk, &members, signer_vk, can).await,
            );
        }
        match self {
            Membered::Group(_, group) => {
                group
                    .lock()
                    .await
                    .revoke_member(
                        member_id,
                        retain_all_other_members,
                        signer,
                        relevant_docs,
                        &signer_authority,
                        &re_add_authority,
                    )
                    .await
            }
            Membered::Document(_, document) => {
                document
                    .lock()
                    .await
                    .revoke_member(
                        member_id,
                        retain_all_other_members,
                        signer,
                        relevant_docs,
                        &signer_authority,
                        &re_add_authority,
                    )
                    .await
            }
        }
    }

    pub async fn get_agent_revocations(
        &self,
        agent: &Agent<F, S, T, L>,
    ) -> Vec<Arc<Signed<Revocation<F, S, T, L>>>> {
        match self {
            Membered::Group(_, group) => group.lock().await.get_agent_revocations(agent).await,
            Membered::Document(_, document) => {
                document.lock().await.get_agent_revocations(agent).await
            }
        }
    }

    #[allow(clippy::type_complexity)]
    pub async fn receive_delegation(
        &self,
        delegation: Arc<Signed<Delegation<F, S, T, L>>>,
    ) -> Result<Digest<Signed<Delegation<F, S, T, L>>>, AddError> {
        match self {
            Membered::Group(_, group) => {
                Ok(group.lock().await.receive_delegation(delegation).await?)
            }
            Membered::Document(_, document) => {
                Ok(document.lock().await.receive_delegation(delegation).await?)
            }
        }
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    From<Group<F, S, T, L>> for Membered<F, S, T, L>
{
    fn from(group: Group<F, S, T, L>) -> Self {
        Membered::Group(group.group_id(), Arc::new(Mutex::new(group)))
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    From<Document<F, S, T, L>> for Membered<F, S, T, L>
{
    fn from(document: Document<F, S, T, L>) -> Self {
        Membered::Document(document.doc_id(), Arc::new(Mutex::new(document)))
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> Verifiable
    for Membered<F, S, T, L>
{
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.agent_id().verifying_key()
    }
}
