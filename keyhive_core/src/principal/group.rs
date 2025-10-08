//! Model a collection of agents with no associated content.

pub mod delegation;
pub mod dependencies;
pub mod error;
pub mod id;
pub mod membership_operation;
pub mod revocation;
pub mod state;

use self::{
    delegation::{Delegation, StaticDelegation},
    membership_operation::MembershipOperation,
    revocation::Revocation,
    state::GroupState,
};
use super::{
    agent::{id::AgentId, Agent},
    document::{id::DocumentId, AddMemberUpdate, Document, RevokeMemberUpdate},
    identifier::Identifier,
    individual::{id::IndividualId, Individual},
    membered::Membered,
};
use crate::{
    access::Access,
    cgka::{error::CgkaError, operation::CgkaOperation},
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        share_key::ShareKey,
        signed::{Signed, SigningError},
        signer::{
            async_signer::AsyncSigner,
            ephemeral::EphemeralSigner,
            sync_signer::{try_sign_basic, SyncSignerBasic},
        },
        verifiable::Verifiable,
    },
    listener::{membership::MembershipListener, no_listener::NoListener},
    store::{delegation::DelegationStore, revocation::RevocationStore},
    util::content_addressed_map::CaMap,
};
use derivative::Derivative;
use derive_more::Debug;
use derive_where::derive_where;
use dupe::{Dupe, IterDupedExt};
use futures::{lock::Mutex, stream::FuturesUnordered, StreamExt};
use id::GroupId;
use nonempty::{nonempty, NonEmpty};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::{Hash, Hasher},
    sync::Arc,
};
use thiserror::Error;

/// A collection of agents with no associated content.
///
/// Groups are stateful agents. It is possible the delegate control over them,
/// and they can be delegated to. This produces transitives lines of authority
/// through the network of [`Agent`]s.
#[derive(Clone, Derivative)]
#[derive_where(Debug; T)]
pub struct Group<S: AsyncSigner, T: ContentRef = [u8; 32], L: MembershipListener<S, T> = NoListener>
{
    pub(crate) id_or_indie: IdOrIndividual,

    /// The current view of members of a group.
    #[allow(clippy::type_complexity)]
    pub(crate) members: HashMap<Identifier, NonEmpty<Arc<Signed<Delegation<S, T, L>>>>>,

    /// Current view of revocations
    #[allow(clippy::type_complexity)]
    pub(crate) active_revocations: HashMap<[u8; 64], Arc<Signed<Revocation<S, T, L>>>>,

    /// The `Group`'s underlying (causal) delegation state.
    pub(crate) state: GroupState<S, T, L>,

    #[derive_where(skip)]
    pub(crate) listener: L,
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Group<S, T, L> {
    #[tracing::instrument(skip_all)]
    pub async fn new(
        group_id: GroupId,
        head: Arc<Signed<Delegation<S, T, L>>>,
        delegations: DelegationStore<S, T, L>,
        revocations: RevocationStore<S, T, L>,
        listener: L,
    ) -> Self {
        listener.on_delegation(&head).await;
        let mut group = Self {
            id_or_indie: IdOrIndividual::GroupId(group_id),
            members: HashMap::new(),
            state: state::GroupState::new(head, delegations, revocations).await,
            active_revocations: HashMap::new(),
            listener,
        };

        group.rebuild().await;
        group
    }

    #[tracing::instrument(skip_all)]
    pub async fn from_individual(
        individual: Individual,
        head: Arc<Signed<Delegation<S, T, L>>>,
        delegations: DelegationStore<S, T, L>,
        revocations: RevocationStore<S, T, L>,
        listener: L,
    ) -> Self {
        listener.on_delegation(&head).await;
        let mut group = Self {
            id_or_indie: IdOrIndividual::Individual(individual),
            members: HashMap::new(),
            state: GroupState::new(head, delegations, revocations).await,
            active_revocations: HashMap::new(),
            listener,
        };
        group.rebuild().await;
        group
    }

    /// Generate a new `Group` with a unique [`Identifier`] and the given `parents`.
    pub async fn generate<R: rand::CryptoRng + rand::RngCore>(
        parents: NonEmpty<Agent<S, T, L>>,
        delegations: DelegationStore<S, T, L>,
        revocations: RevocationStore<S, T, L>,
        listener: L,
        csprng: Arc<Mutex<R>>,
    ) -> Result<Group<S, T, L>, SigningError> {
        let mut locked_csprng = csprng.lock().await;
        let (group_result, _vk) =
            EphemeralSigner::with_signer(&mut *locked_csprng, |verifier, signer| {
                Self::generate_after_content(
                    signer,
                    verifier,
                    parents,
                    delegations,
                    revocations,
                    Default::default(),
                    listener,
                )
            });

        group_result.await
    }

    #[tracing::instrument(skip_all)]
    pub(crate) async fn generate_after_content(
        signer: Box<dyn SyncSignerBasic>,
        verifier: ed25519_dalek::VerifyingKey,
        parents: NonEmpty<Agent<S, T, L>>,
        delegations: DelegationStore<S, T, L>,
        revocations: RevocationStore<S, T, L>,
        after_content: BTreeMap<DocumentId, Vec<T>>,
        listener: L,
    ) -> Result<Self, SigningError> {
        let id = verifier.into();
        let group_id = GroupId(id);
        let mut delegation_heads = CaMap::new();

        {
            let async_listener = Arc::new(&listener);

            let mut futs = FuturesUnordered::new();
            for parent in parents.iter() {
                let dlg = try_sign_basic(
                    &*signer,
                    verifier,
                    Delegation {
                        delegate: parent.dupe(),
                        can: Access::Admin,
                        proof: None,
                        after_revocations: vec![],
                        after_content: after_content.clone(),
                    },
                )?;

                let rc = Arc::new(dlg);
                delegations.insert(rc.dupe()).await;
                delegation_heads.insert(rc.dupe());

                let listen = async_listener.dupe();
                futs.push(async move {
                    listen.on_delegation(&rc).await;
                    Ok::<(), SigningError>(())
                });
            }

            while let Some(res) = futs.next().await {
                res?;
            }
        }

        let mut group = Group {
            id_or_indie: IdOrIndividual::GroupId(group_id),
            members: HashMap::new(),
            active_revocations: HashMap::new(),
            state: GroupState {
                id: group_id,

                delegation_heads,
                delegations,

                revocation_heads: CaMap::new(),
                revocations,
            },
            listener,
        };

        group.rebuild().await;
        Ok(group)
    }

    pub fn id(&self) -> Identifier {
        self.group_id().into()
    }

    pub fn group_id(&self) -> GroupId {
        self.state.group_id()
    }

    pub fn agent_id(&self) -> AgentId {
        self.group_id().into()
    }

    pub async fn individual_ids(&self) -> HashSet<IndividualId> {
        let mut ids = HashSet::new();
        for delegations in self.members.values() {
            let more_ids = delegations[0].payload().delegate.individual_ids().await;
            ids.extend(more_ids.iter());
        }
        ids
    }

    pub async fn pick_individual_prekeys(
        &self,
        doc_id: DocumentId,
    ) -> HashMap<IndividualId, ShareKey> {
        let mut prekeys = HashMap::new();
        for (agent, _access) in self.transitive_members().await.values() {
            prekeys.extend(agent.pick_individual_prekeys(doc_id).await.iter());
        }
        prekeys
    }

    #[allow(clippy::type_complexity)]
    pub fn members(&self) -> &HashMap<Identifier, NonEmpty<Arc<Signed<Delegation<S, T, L>>>>> {
        &self.members
    }

    #[tracing::instrument(skip(self), fields(group_id = %self.group_id()))]
    pub async fn transitive_members(&self) -> HashMap<Identifier, (Agent<S, T, L>, Access)> {
        struct GroupAccess<Z: AsyncSigner, U: ContentRef, M: MembershipListener<Z, U>> {
            agent: Agent<Z, U, M>,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess<S, T, L>> = vec![];
        let mut seen: HashSet<([u8; 64], Access)> = HashSet::new();

        for member in self.members.keys() {
            let dlg = self
                .get_capability(member)
                .expect("members have capabilities by defintion");

            seen.insert((dlg.signature.to_bytes(), Access::Admin));

            explore.push(GroupAccess {
                agent: dlg.payload.delegate.clone(),
                agent_access: dlg.payload.can,
                parent_access: Access::Admin,
            });
        }

        let mut caps: HashMap<Identifier, (Agent<S, T, L>, Access)> = HashMap::new();

        while let Some(GroupAccess {
            agent: member,
            agent_access: access,
            parent_access,
        }) = explore.pop()
        {
            let id = member.id();
            if id == self.id() {
                continue;
            }

            let best_access = *caps
                .get(&id)
                .map(|(_, existing_access)| existing_access.max(&access))
                .unwrap_or(&access);

            let current_path_access = access.min(parent_access);
            caps.insert(member.id(), (member.dupe(), current_path_access));

            if let Some(membered) = match member {
                Agent::Group(id, inner_group) => Some(Membered::Group(id, inner_group.dupe())),
                Agent::Document(id, doc) => Some(Membered::Document(id, doc.dupe())),
                _ => None,
            } {
                for (mem_id, dlgs) in membered.members().await.iter() {
                    let dlg = membered
                        .get_capability(mem_id)
                        .await
                        .expect("members have capabilities by defintion");

                    caps.insert(*mem_id, (dlg.payload.delegate.dupe(), best_access));

                    'inner: for sub_dlg in dlgs.iter() {
                        if !seen.insert((sub_dlg.signature.to_bytes(), dlg.payload.can)) {
                            continue 'inner;
                        }

                        explore.push(GroupAccess {
                            agent: sub_dlg.payload.delegate.dupe(),
                            agent_access: sub_dlg.payload.can,
                            parent_access: best_access,
                        });
                    }
                }
            }
        }

        caps
    }

    pub fn delegation_heads(&self) -> &CaMap<Signed<Delegation<S, T, L>>> {
        &self.state.delegation_heads
    }

    pub fn revocation_heads(&self) -> &CaMap<Signed<Revocation<S, T, L>>> {
        &self.state.revocation_heads
    }

    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all)]
    pub fn get_capability(
        &self,
        member_id: &Identifier,
    ) -> Option<&Arc<Signed<Delegation<S, T, L>>>> {
        self.members.get(member_id).and_then(|delegations| {
            delegations
                .iter()
                .max_by(|d1, d2| d1.payload().can.cmp(&d2.payload().can))
        })
    }

    #[tracing::instrument(skip_all)]
    pub async fn get_agent_revocations(
        &self,
        agent: &Agent<S, T, L>,
    ) -> Vec<Arc<Signed<Revocation<S, T, L>>>> {
        self.state
            .revocations
            .0
            .lock()
            .await
            .iter()
            .filter_map(|(_digest, rvk)| {
                if rvk.payload().revoke.payload().delegate == *agent {
                    Some(rvk.dupe())
                } else {
                    None
                }
            })
            .collect()
    }

    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all)]
    pub async fn receive_delegation(
        &mut self,
        delegation: Arc<Signed<Delegation<S, T, L>>>,
    ) -> Result<Digest<Signed<Delegation<S, T, L>>>, error::AddError> {
        let digest = self.state.add_delegation(delegation).await?;
        tracing::info!("{:x?}", &digest);
        self.rebuild().await;
        Ok(digest)
    }

    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip(self), fields(group_id = %self.group_id()))]
    pub async fn receive_revocation(
        &mut self,
        revocation: Arc<Signed<Revocation<S, T, L>>>,
    ) -> Result<Digest<Signed<Revocation<S, T, L>>>, error::AddError> {
        self.listener.on_revocation(&revocation).await;
        let digest = self.state.add_revocation(revocation).await?;
        self.rebuild().await;
        Ok(digest)
    }

    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all)]
    pub async fn add_member(
        &mut self,
        member_to_add: Agent<S, T, L>,
        can: Access,
        signer: &S,
        relevant_docs: &[Arc<Mutex<Document<S, T, L>>>],
    ) -> Result<AddMemberUpdate<S, T, L>, AddGroupMemberError> {
        let mut after_content = BTreeMap::new();
        for d in relevant_docs {
            let locked = d.lock().await;
            after_content.insert(
                locked.doc_id(),
                locked.content_heads.iter().cloned().collect::<Vec<_>>(),
            );
        }

        self.add_member_with_manual_content(member_to_add, can, signer, after_content)
            .await
    }

    pub(crate) async fn add_member_with_manual_content(
        &mut self,
        member_to_add: Agent<S, T, L>,
        can: Access,
        signer: &S,
        after_content: BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<AddMemberUpdate<S, T, L>, AddGroupMemberError> {
        let proof = if self.verifying_key() == signer.verifying_key() {
            None
        } else {
            let p = self
                .get_capability(&signer.verifying_key().into())
                .ok_or(AddGroupMemberError::NoProof)?;

            if can > p.payload.can {
                return Err(AddGroupMemberError::AccessEscalation {
                    wanted: can,
                    have: p.payload().can,
                });
            }

            Some(p.dupe())
        };

        let delegation = signer
            .try_sign_async(Delegation {
                delegate: member_to_add,
                can,
                proof,
                after_revocations: self.state.revocation_heads.values().duped().collect(),
                after_content,
            })
            .await?;

        let rc = Arc::new(delegation);
        let _digest = self.receive_delegation(rc.dupe()).await?;
        self.listener.on_delegation(&rc).await;

        let cgka_ops = if rc.payload.can.is_reader() {
            self.add_cgka_member(rc.dupe(), signer).await?
        } else {
            Vec::new()
        };

        Ok(AddMemberUpdate {
            cgka_ops,
            delegation: rc,
        })
    }

    #[tracing::instrument(skip_all)]
    pub(crate) async fn add_cgka_member(
        &mut self,
        delegation: Arc<Signed<Delegation<S, T, L>>>,
        signer: &S,
    ) -> Result<Vec<Signed<CgkaOperation>>, CgkaError> {
        let mut cgka_ops = Vec::new();
        let docs: Vec<Arc<Mutex<Document<S, T, L>>>> = self
            .transitive_members()
            .await
            .values()
            .filter_map(|(agent, _)| {
                if let Agent::Document(_, doc) = agent {
                    Some(doc.dupe())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for doc in docs {
            for op in doc
                .lock()
                .await
                .add_cgka_member(&delegation, signer)
                .await?
            {
                cgka_ops.push(op);
            }
        }
        Ok(cgka_ops)
    }

    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all)]
    pub async fn revoke_member(
        &mut self,
        member_to_remove: Identifier,
        retain_all_other_members: bool,
        signer: &S,
        after_content: &BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<RevokeMemberUpdate<S, T, L>, RevokeMemberError> {
        let vk = signer.verifying_key();
        let mut revocations = vec![];
        let og_dlgs: Vec<_> = self.members.values().flatten().cloned().collect();

        let all_to_revoke: Vec<Arc<Signed<Delegation<S, T, L>>>> = self
            .members()
            .get(&member_to_remove)
            .map(|ne| Vec::<_>::from(ne.clone())) // Semi-inexpensive because `Vec<Arc<_>>`
            .unwrap_or_default();

        if all_to_revoke.is_empty() {
            self.members.remove(&member_to_remove);
            return Ok(RevokeMemberUpdate::default());
        }

        if vk == self.verifying_key() {
            // In the (unlikely) case that the group signing key still exists and is doing the revocation.
            // Arguably this could be made impossible, but it would likely be surprising behaviour.
            for to_revoke in all_to_revoke.iter() {
                let r = self
                    .build_revocation(signer, to_revoke.dupe(), None, after_content.clone())
                    .await?;
                self.receive_revocation(r.dupe()).await?;
                revocations.push(r);
            }
        } else {
            for to_revoke in all_to_revoke.iter() {
                let mut found = false;

                if let Some(member_dlgs) = self.members.get(&vk.into()) {
                    // "Double up" if you're an admin in case you get concurrently demoted.
                    // We include the admin proofs as well since those could also get revoked.
                    for mem_dlg in member_dlgs.clone().iter() {
                        if mem_dlg.payload.delegate.id() != member_to_remove {
                            continue;
                        }

                        if mem_dlg.payload().can == Access::Admin {
                            // Use your awesome & terrible admin powers!
                            //
                            // NOTE we don't do admin revocation cycle checking here for a few reasons:
                            // 1. Unknown to you, the cycle may be broken with some other revocation
                            // 2. It all gets resolved at materialization time
                            let r = self
                                .build_revocation(
                                    signer,
                                    to_revoke.dupe(),
                                    Some(mem_dlg.dupe()), // Admin proof
                                    after_content.clone(),
                                )
                                .await?;
                            self.receive_revocation(r.dupe()).await?;
                            revocations.push(r);
                            found = true;
                        }
                    }
                }

                if to_revoke.issuer == vk {
                    let r = self
                        .build_revocation(
                            signer,
                            to_revoke.dupe(),
                            Some(to_revoke.dupe()), // You issued it!
                            after_content.clone(),
                        )
                        .await?;
                    self.receive_revocation(r.dupe()).await?;
                    revocations.push(r);
                    found = true;
                } else {
                    // Look for proof of any ancestor
                    for ancestor in to_revoke.payload().proof_lineage() {
                        if ancestor.issuer == vk {
                            found = true;
                            let r = self
                                .build_revocation(
                                    signer,
                                    to_revoke.dupe(),
                                    Some(ancestor.dupe()),
                                    after_content.clone(),
                                )
                                .await?;
                            revocations.push(r.dupe());
                            self.receive_revocation(r).await?;
                            break;
                        }
                    }
                }

                if !found {
                    return Err(RevokeMemberError::NoProof);
                }
            }
        }

        for r in revocations.iter() {
            self.listener.on_revocation(r).await
        }

        let mut cgka_ops = Vec::new();
        let (individuals, docs): (
            Vec<Arc<Mutex<Individual>>>,
            Vec<Arc<Mutex<Document<S, T, L>>>>,
        ) = self.transitive_members().await.values().fold(
            (vec![], vec![]),
            |(mut indies, mut docs), (agent, _)| {
                match agent {
                    Agent::Individual(_, individual) => {
                        indies.push(individual.dupe());
                    }
                    Agent::Document(_, doc) => {
                        docs.push(doc.dupe());
                    }
                    _ => (),
                }

                (indies, docs)
            },
        );

        for indie in individuals {
            let id = {
                let locked_indie = indie.lock().await;
                locked_indie.id()
            };
            for doc in &docs {
                let mut locked_doc = doc.lock().await;
                if let Some(op) = locked_doc.remove_cgka_member(id, signer).await? {
                    cgka_ops.push(op);
                }
            }
        }

        let mut redelegations = vec![];
        if retain_all_other_members {
            for dlg in og_dlgs.iter() {
                if dlg.payload.delegate.id() == member_to_remove {
                    // Don't retain if they've delegated to themself
                    continue;
                }

                if let Some(proof) = &dlg.payload.proof {
                    if proof.payload.delegate.id() == member_to_remove {
                        let AddMemberUpdate { delegation, .. } = self
                            .add_member_with_manual_content(
                                dlg.payload.delegate.dupe(),
                                dlg.payload.can,
                                signer,
                                after_content.clone(),
                            )
                            .await?;

                        redelegations.push(delegation);
                    }
                }
            }
        }

        Ok(RevokeMemberUpdate {
            cgka_ops,
            revocations,
            redelegations,
        })
    }

    async fn build_revocation(
        &mut self,
        signer: &S,
        revoke: Arc<Signed<Delegation<S, T, L>>>,
        proof: Option<Arc<Signed<Delegation<S, T, L>>>>,
        after_content: BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<Arc<Signed<Revocation<S, T, L>>>, SigningError> {
        let revocation = signer
            .try_sign_async(Revocation {
                revoke,
                proof,
                after_content,
            })
            .await?;

        Ok(Arc::new(revocation))
    }

    #[tracing::instrument(skip_all)]
    pub async fn rebuild(&mut self) {
        self.members.clear();
        self.active_revocations.clear();

        #[allow(clippy::type_complexity)]
        let mut dlgs_in_play: HashMap<[u8; 64], Arc<Signed<Delegation<S, T, L>>>> = HashMap::new();
        let mut revoked_dlgs: HashSet<[u8; 64]> = HashSet::new();

        // {dlg_dep => Set<dlgs that depend on it>}
        let mut reverse_dlg_dep_map: HashMap<[u8; 64], HashSet<[u8; 64]>> = HashMap::new();

        let mut ops = MembershipOperation::topsort(
            &self.state.delegation_heads,
            &self.state.revocation_heads,
        );

        while let Some((_, op)) = ops.pop() {
            match op {
                MembershipOperation::Delegation(d) => {
                    // NOTE: friendly reminder that the topsort already includes all ancestors
                    if let Some(found_proof) = &d.payload.proof {
                        reverse_dlg_dep_map
                            .entry(found_proof.signature.to_bytes())
                            .and_modify(|set| {
                                set.insert(d.signature.to_bytes());
                            })
                            .or_insert_with(|| HashSet::from_iter([d.signature.to_bytes()]));

                        // If the proof was directly revoked, then check if they've been
                        // re-added some other way. Since `rebuild` recurses,
                        // we only need to check one level.
                        if revoked_dlgs.contains(&found_proof.signature.to_bytes())
                            || !dlgs_in_play.contains_key(&found_proof.signature.to_bytes())
                        {
                            if let Some(alt_proofs) = self.members.get(&found_proof.issuer.into()) {
                                if alt_proofs.iter().filter(|d| *d != found_proof).all(
                                    |alt_proof| alt_proof.payload.can < found_proof.payload.can,
                                ) {
                                    // No suitable proofs
                                    continue;
                                }
                            } else if found_proof.issuer != self.verifying_key() {
                                continue;
                            }
                        }
                    } else if d.issuer != self.verifying_key() {
                        debug_assert!(false, "Delegation without valid root proof");
                        continue;
                    }

                    if revoked_dlgs.contains(&d.signature.to_bytes()) {
                        continue;
                    }

                    dlgs_in_play.insert(d.signature.to_bytes(), d.dupe());

                    if let Some(mut_dlgs) = self.members.get_mut(&d.payload.delegate.id()) {
                        mut_dlgs.push(d.dupe());
                    } else {
                        self.members
                            .insert(d.payload.delegate.id(), nonempty![d.dupe()]);
                    }
                }
                MembershipOperation::Revocation(r) => {
                    if let Some(found_proof) = &r.payload.proof {
                        if revoked_dlgs.contains(&found_proof.signature.to_bytes())
                            || !dlgs_in_play.contains_key(&found_proof.signature.to_bytes())
                        {
                            if let Some(alt_proofs) = self.members.get(&found_proof.issuer.into()) {
                                if !alt_proofs
                                    .iter()
                                    .any(|p| p.payload.can >= found_proof.payload.can)
                                {
                                    continue;
                                }
                            }
                        }
                    } else if r.issuer != self.verifying_key() {
                        debug_assert!(false, "Revocation without valid root proof");
                        continue;
                    }

                    self.active_revocations
                        .insert(r.signature.to_bytes(), r.dupe());

                    // { Agent => delegation to drop }
                    let mut to_drop: Vec<(Identifier, [u8; 64])> = vec![];

                    let mut next_to_revoke = vec![r.payload.revoke.signature.to_bytes()];
                    while let Some(sig_to_revoke) = next_to_revoke.pop() {
                        revoked_dlgs.insert(sig_to_revoke);

                        if let Some(dlg) = dlgs_in_play.remove(&sig_to_revoke) {
                            to_drop.push((dlg.payload.delegate.id(), sig_to_revoke));
                        }

                        if let Some(dlg_sigs_to_revoke) = reverse_dlg_dep_map.get(&sig_to_revoke) {
                            for dlg_sig in dlg_sigs_to_revoke.iter() {
                                revoked_dlgs.insert(*dlg_sig);

                                if let Some(dep_dlg) = dlgs_in_play.remove(dlg_sig) {
                                    next_to_revoke.push(dep_dlg.signature.to_bytes());
                                }
                            }
                        }
                    }

                    for (id, sig) in to_drop {
                        let remaining = self
                            .members
                            .get(&id)
                            .map(|dlgs| {
                                dlgs.iter()
                                    .filter(|dlg| dlg.signature.to_bytes() != sig)
                                    .cloned()
                                    .collect()
                            })
                            .unwrap_or_default();

                        if let Some(dlgs) = NonEmpty::from_vec(remaining) {
                            self.members.insert(id, dlgs);
                        } else {
                            self.members.remove(&id);
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn dummy_from_archive(
        archive: GroupArchive<T>,
        delegations: DelegationStore<S, T, L>,
        revocations: RevocationStore<S, T, L>,
        listener: L,
    ) -> Self {
        Self {
            members: HashMap::new(),
            id_or_indie: archive.id_or_indie,
            state: GroupState::dummy_from_archive(archive.state, delegations, revocations),
            active_revocations: HashMap::new(),
            listener,
        }
    }

    #[tracing::instrument(skip_all)]
    pub fn into_archive(&self) -> GroupArchive<T> {
        GroupArchive {
            id_or_indie: self.id_or_indie.clone(),
            members: self
                .members
                .iter()
                .fold(HashMap::new(), |mut acc, (k, vs)| {
                    let hashes: Vec<_> =
                        vs.iter().map(|v| Digest::hash(v.as_ref()).into()).collect();
                    if let Some(ne) = NonEmpty::from_vec(hashes) {
                        acc.insert(*k, ne);
                    }
                    acc
                }),
            state: self.state.into_archive(),
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Hash for Group<S, T, L> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id_or_indie.hash(state);
        self.members.iter().collect::<BTreeMap<_, _>>().hash(state);
        self.state.hash(state);
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Verifiable for Group<S, T, L> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.state.verifying_key()
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdOrIndividual {
    GroupId(GroupId),
    Individual(Individual),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupArchive<T: ContentRef> {
    pub(crate) id_or_indie: IdOrIndividual,
    pub(crate) members: HashMap<Identifier, NonEmpty<Digest<Signed<StaticDelegation<T>>>>>,
    pub(crate) state: state::archive::GroupStateArchive<T>,
}

#[derive(Debug, Error)]
pub enum AddGroupMemberError {
    #[error(transparent)]
    SigningError(#[from] SigningError),

    #[error("No proof found")]
    NoProof,

    #[error("Access escalation. Wanted {wanted}, only have {have}.")]
    AccessEscalation { wanted: Access, have: Access },

    #[error(transparent)]
    AddError(#[from] error::AddError),

    #[error(transparent)]
    CgkaError(#[from] CgkaError),
}

#[derive(Debug, Error)]
pub enum RevokeMemberError {
    #[error(transparent)]
    AddError(#[from] error::AddError),

    #[error("Proof missing to authorize revocation")]
    NoProof,

    #[error(transparent)]
    SigningError(#[from] SigningError),

    #[error(transparent)]
    CgkaError(#[from] CgkaError),

    #[error("Redelagation error")]
    RedelegationError(#[from] AddGroupMemberError),
}

#[cfg(test)]
mod tests {
    use super::delegation::Delegation;
    use super::*;
    use crate::crypto::signer::memory::MemorySigner;
    use crate::principal::active::Active;
    use nonempty::nonempty;
    use pretty_assertions::assert_eq;
    use rand::rngs::OsRng;

    async fn setup_user<T: ContentRef, R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Active<MemorySigner, T> {
        let sk = MemorySigner::generate(csprng);
        Active::generate(sk, NoListener, csprng).await.unwrap()
    }

    async fn setup_groups<T: ContentRef, R: rand::CryptoRng + rand::RngCore>(
        alice: Arc<Mutex<Active<MemorySigner, T>>>,
        bob: Arc<Mutex<Active<MemorySigner, T>>>,
        csprng: Arc<Mutex<R>>,
    ) -> [Arc<Mutex<Group<MemorySigner, T>>>; 4] {
        /*              ┌───────────┐        ┌───────────┐
                        │           │        │           │
        ╔══════════════▶│   Alice   │        │    Bob    │
        ║               │           │        │           │
        ║               └─────▲─────┘        └───────────┘
        ║                     │                    ▲
        ║                     │                    ║
        ║               ┌───────────┐              ║
        ║               │           │              ║
        ║        ┌─────▶│  Group 0  │◀─────┐       ║
        ║        │      │           │      │       ║
        ║        │      └───────────┘      │       ║
        ║  ┌───────────┐             ┌───────────┐ ║
        ║  │           │             │           │ ║
        ╚══│  Group 1  │             │  Group 2  │═╝
           │           │             │           │
           └─────▲─────┘             └─────▲─────┘
                 │      ┌───────────┐      │
                 │      │           │      │
                 └──────│  Group 3  │──────┘
                        │           │
                        └───────────┘ */

        let alice_agent: Agent<MemorySigner, T, _> =
            Agent::Active(alice.lock().await.id(), alice.dupe());
        let bob_agent = Agent::Active(bob.lock().await.id(), bob.dupe());

        let dlg_store = DelegationStore::new();
        let rev_store = RevocationStore::new();

        let g0 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![alice_agent.dupe()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));
        let g0_gid = g0.lock().await.group_id();

        let g1 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![alice_agent, Agent::Group(g0_gid, g0.clone())],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));

        let g2 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![
                    bob_agent,
                    Agent::Group(g0.lock().await.group_id(), g0.clone())
                ],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));

        let g3 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![
                    Agent::Group(g1.lock().await.group_id(), g1.clone()),
                    Agent::Group(g2.lock().await.group_id(), g2.clone())
                ],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng,
            )
            .await
            .unwrap(),
        ));

        [g0, g1, g2, g3]
    }

    async fn setup_cyclic_groups<T: ContentRef, R: rand::CryptoRng + rand::RngCore>(
        alice: Arc<Mutex<Active<MemorySigner, T>>>,
        bob: Arc<Mutex<Active<MemorySigner, T>>>,
        csprng: Arc<Mutex<R>>,
    ) -> [Arc<Mutex<Group<MemorySigner, T>>>; 10] {
        let dlg_store = DelegationStore::new();
        let rev_store = RevocationStore::new();

        let group0 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Active(alice.lock().await.id(), alice.dupe())],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));

        let group1 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Active(bob.lock().await.id(), bob.dupe())],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));

        let group2 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Group(group1.lock().await.group_id(), group1.clone())],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));

        let group3 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Group(group2.lock().await.group_id(), group2.clone())],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));

        let group4 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Group(group3.lock().await.group_id(), group3.clone())],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));

        let group5 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Group(group4.lock().await.group_id(), group4.clone())],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));

        let group6 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Group(group5.lock().await.group_id(), group5.clone())],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));

        let group7 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Group(group6.lock().await.group_id(), group6.clone())],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));

        let group8 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Group(group7.lock().await.group_id(), group7.clone())],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));

        let group9 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Group(group8.lock().await.group_id(), group8.clone())],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));

        let (alice_id, alice_signer) = {
            let locked_alice = alice.lock().await;
            (locked_alice.id(), locked_alice.signer.clone())
        };

        {
            let mut locked_group0 = group0.lock().await;
            let proof = locked_group0
                .get_capability(&alice_id.into())
                .unwrap()
                .dupe();

            locked_group0
                .receive_delegation(Arc::new(
                    alice_signer
                        .try_sign_async(Delegation {
                            delegate: Agent::Group(group9.lock().await.group_id(), group9.dupe()),
                            can: Access::Admin,
                            proof: Some(proof),
                            after_revocations: vec![],
                            after_content: BTreeMap::new(),
                        })
                        .await
                        .unwrap(),
                ))
                .await
                .unwrap();
        }

        [
            group0, group1, group2, group3, group4, group5, group6, group7, group8, group9,
        ]
    }

    #[tokio::test]
    async fn test_transitive_self() {
        test_utils::init_logging();
        let mut csprng = OsRng;

        let alice = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let alice_agent: Agent<MemorySigner, String> =
            Agent::Active(alice.lock().await.id(), alice.dupe());
        let alice_id = alice_agent.id();

        let bob = Arc::new(Mutex::new(setup_user(&mut csprng).await));

        let [g0, ..]: [Arc<Mutex<Group<MemorySigner, String>>>; 4] =
            setup_groups(alice.dupe(), bob, Arc::new(Mutex::new(csprng))).await;
        let g0_mems = g0.lock().await.transitive_members().await;

        let expected = HashMap::from_iter([(
            alice_id,
            (Agent::Active(alice_id.into(), alice.dupe()), Access::Admin),
        )]);

        assert_eq!(g0_mems, expected);
    }

    #[tokio::test]
    async fn test_transitive_one() {
        test_utils::init_logging();
        let mut csprng = OsRng;

        let alice = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let alice_agent: Agent<MemorySigner, String> =
            Agent::Active(alice.lock().await.id(), alice.dupe());
        let alice_id = alice_agent.id();

        let bob = Arc::new(Mutex::new(setup_user(&mut csprng).await));

        let [g0, g1, ..] = setup_groups(alice.dupe(), bob, Arc::new(Mutex::new(csprng))).await;
        let g1_mems = g1.lock().await.transitive_members().await;

        let group0_id = { g0.lock().await.id() };
        let group0_gid = { g0.lock().await.group_id() };
        assert_eq!(
            g1_mems,
            HashMap::from_iter([
                (
                    alice_id,
                    (Agent::Active(alice_id.into(), alice.dupe()), Access::Admin)
                ),
                (
                    group0_id,
                    (Agent::Group(group0_gid, g0.dupe()), Access::Admin)
                )
            ])
        );
    }

    #[tokio::test]
    async fn test_transitive_two() {
        test_utils::init_logging();
        let mut csprng = OsRng;

        let alice = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let alice_agent: Agent<MemorySigner, String> =
            Agent::Active(alice.lock().await.id(), alice.dupe());
        let alice_id = alice_agent.id();

        let bob = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let bob_agent: Agent<MemorySigner, String> =
            Agent::Active(bob.lock().await.id(), bob.dupe());
        let bob_id = bob_agent.id();

        let [g0, _g1, g2, _g3]: [Arc<Mutex<Group<MemorySigner, String>>>; 4] =
            setup_groups(alice.dupe(), bob.dupe(), Arc::new(Mutex::new(csprng))).await;
        let g2_mems = g2.lock().await.transitive_members().await;

        let g0_id = { g0.lock().await.id() };

        assert_eq!(g2_mems.len(), 3);
        assert!(g2_mems.contains_key(&alice_id));
        assert!(g2_mems.contains_key(&bob_id));
        assert!(g2_mems.contains_key(&g0_id));
    }

    #[tokio::test]
    async fn test_transitive_three() {
        test_utils::init_logging();
        let mut csprng = OsRng;

        let alice = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let alice_id = { alice.lock().await.id() };
        let alice_agent: Agent<MemorySigner, String> = Agent::Active(alice_id, alice.dupe());
        let alice_id = alice_agent.id();

        let bob = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let bob_agent: Agent<MemorySigner, String> =
            Agent::Active(bob.lock().await.id(), bob.dupe());
        let bob_id = bob_agent.id();

        let [g0, g1, g2, g3]: [Arc<Mutex<Group<MemorySigner, String>>>; 4] =
            setup_groups(alice.dupe(), bob.dupe(), Arc::new(Mutex::new(csprng))).await;
        let g3_mems = g3.lock().await.transitive_members().await;

        assert_eq!(g3_mems.len(), 5);

        assert_eq!(
            g3_mems.keys().collect::<std::collections::HashSet<_>>(),
            HashSet::from_iter([
                &alice_id,
                &bob_id,
                &g0.lock().await.id(),
                &g1.lock().await.id(),
                &g2.lock().await.id(),
            ])
        );
    }

    #[tokio::test]
    async fn test_transitive_cycles() {
        test_utils::init_logging();
        let mut csprng = OsRng;

        let alice = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let alice_agent: Agent<MemorySigner, String> =
            Agent::Active(alice.lock().await.id(), alice.dupe());
        let alice_id = alice_agent.id();

        let bob = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let bob_agent: Agent<MemorySigner, String> =
            Agent::Active(bob.lock().await.id(), bob.dupe());
        let bob_id = bob_agent.id();

        let [g0, g1, g2, g3, g4, g5, g6, g7, g8, g9]: [Arc<Mutex<Group<MemorySigner, String>>>;
            10] = setup_cyclic_groups(alice.dupe(), bob.dupe(), Arc::new(Mutex::new(csprng))).await;
        let g0_mems = g0.lock().await.transitive_members().await;

        assert_eq!(g0_mems.len(), 11);
        assert!(g0_mems.contains_key(&alice_id));
        assert!(g0_mems.contains_key(&bob_id));
        assert!(g0_mems.contains_key(&g1.lock().await.id()));
        assert!(g0_mems.contains_key(&g2.lock().await.id()));
        assert!(g0_mems.contains_key(&g3.lock().await.id()));
        assert!(g0_mems.contains_key(&g4.lock().await.id()));
        assert!(g0_mems.contains_key(&g5.lock().await.id()));
        assert!(g0_mems.contains_key(&g6.lock().await.id()));
        assert!(g0_mems.contains_key(&g7.lock().await.id()));
        assert!(g0_mems.contains_key(&g8.lock().await.id()));
        assert!(g0_mems.contains_key(&g9.lock().await.id()));
    }

    #[tokio::test]
    async fn test_add_member() {
        test_utils::init_logging();
        let mut csprng = OsRng;

        let alice = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let alice_agent: Agent<MemorySigner> = Agent::Active(alice.lock().await.id(), alice.dupe());

        let bob = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let bob_agent: Agent<MemorySigner> = Agent::Active(bob.lock().await.id(), bob.dupe());

        let carol = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let carol_agent: Agent<MemorySigner> = Agent::Active(carol.lock().await.id(), carol.dupe());

        let signer = MemorySigner::generate(&mut csprng);
        let active = Arc::new(Mutex::new(
            Active::generate(signer, NoListener, &mut csprng)
                .await
                .unwrap(),
        ));

        let (active_id, active_signer) = {
            let locked_active = active.lock().await;
            (locked_active.id(), locked_active.signer.clone())
        };

        let dlg_store = DelegationStore::new();
        let rev_store = RevocationStore::new();

        let arc_csprng = Arc::new(Mutex::new(csprng));

        let g0 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Active(active_id, active.dupe())],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                arc_csprng.dupe(),
            )
            .await
            .unwrap(),
        ));

        let group0_agent = Agent::Group(g0.lock().await.group_id(), g0.dupe());

        let g1 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![alice_agent.dupe(), bob_agent.dupe(), group0_agent],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                arc_csprng.dupe(),
            )
            .await
            .unwrap(),
        ));

        let group1_agent = Agent::Group(g1.lock().await.group_id(), g1.dupe());

        let g2 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![group1_agent],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                arc_csprng.dupe(),
            )
            .await
            .unwrap(),
        ));

        g0.lock()
            .await
            .add_member(carol_agent.dupe(), Access::Write, &active_signer, &[])
            .await
            .unwrap();

        // FIXME trasnitive add
        // g2.borrow_mut()
        //     .add_member(
        //         carol_agent.dupe(),
        //         Access::Read,
        //         active.borrow().signer.clone(),
        //         &[],
        //     )
        //     .unwrap();

        let g0_mems = g0.lock().await.transitive_members().await;

        assert_eq!(g0_mems.len(), 2);

        assert_eq!(
            g0_mems.get(&active_id.into()),
            Some(&(active.lock().await.clone().into(), Access::Admin))
        );

        assert_eq!(
            g0_mems.get(&carol_agent.id()),
            Some(&(carol.lock().await.clone().into(), Access::Write)) // NOTE: non-admin!
        );

        let g2_mems = g2.lock().await.transitive_members().await;

        assert_eq!(
            g2_mems.get(&alice_agent.id()),
            Some(&(alice.lock().await.clone().into(), Access::Admin))
        );

        assert_eq!(
            g2_mems.get(&bob_agent.id()),
            Some(&(bob.lock().await.clone().into(), Access::Admin))
        );

        assert_eq!(
            g2_mems.get(&carol_agent.id()),
            Some(&(carol.lock().await.clone().into(), Access::Write)) // NOTE: non-admin!
        );

        let g0_id = { g0.lock().await.id() };
        assert_eq!(
            g2_mems.get(&g0_id),
            Some(&(g0.lock().await.clone().into(), Access::Admin))
        );

        let g1_id = { g1.lock().await.id() };
        assert_eq!(
            g2_mems.get(&g1_id),
            Some(&(g1.lock().await.clone().into(), Access::Admin))
        );

        assert_eq!(g2_mems.len(), 6);
    }

    #[tokio::test]
    async fn test_revoke_member() {
        // ┌─────────┐
        // │  Group  ├─┬────────────────────────────────────────────────────▶
        // └─────────┘ │
        //             └─┐                                          ╔══╗
        //               │                                          ║  ║
        // ┌─────────┐   ▼                                          ║  ║
        // │  Alice  │─ ─○──┬───────────╦─────┬─────────────╦──────═╩──╩═x──▶
        // └─────────┘      │           ║     │             ║
        //                  └─┐         ╚═╗   │             ║
        //                    │           ║   │             ║
        // ┌─────────┐        ▼           ║   └─┐           ╚═╗
        // │   Bob   ├ ─ ─ ─ ─○───┬───────x─ ─ ─│─ ─ ─○───────║─────────────▶
        // └─────────┘            │             │     ▲       ║
        //                        └─┐           │     │       ║
        //                          │           │   ┌─┘       ║
        // ┌─────────┐              ▼           ▼   │         ║
        // │  Carol  ├ ─ ─ ─ ─ ─ ─ ─○─┬─────────────┴─────────x─ ─ ─ ─ ─ ─ ▶
        // └─────────┘                │                       ║
        //                            └─┐                     ║
        //                              │                     ║
        // ┌─────────┐                  ▼                     ║
        // │   Dan   ├ ─ ─ ─ ─ ─ ─ ─ ─ ─○─────────────────────x─ ─ ─ ─ ─ ─ ▶
        // └─────────┘

        test_utils::init_logging();
        let mut csprng = OsRng;

        let alice = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let alice_agent: Agent<MemorySigner> = Agent::Active(alice.lock().await.id(), alice.dupe());

        let bob = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let bob_agent: Agent<MemorySigner> = Agent::Active(bob.lock().await.id(), bob.dupe());

        let carol = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let carol_agent: Agent<MemorySigner> = Agent::Active(carol.lock().await.id(), carol.dupe());

        let dan = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let dan_agent: Agent<MemorySigner> = Agent::Active(dan.lock().await.id(), dan.dupe());

        let (alice_id, alice_signer) = {
            let locked_alice = alice.lock().await;
            (locked_alice.id(), locked_alice.signer.clone())
        };

        let (bob_id, bob_signer) = {
            let locked_bob = bob.lock().await;
            (locked_bob.id(), locked_bob.signer.clone())
        };

        let (carol_id, carol_signer) = {
            let locked_carol = carol.lock().await;
            (locked_carol.id(), locked_carol.signer.clone())
        };

        let dan_id = dan.lock().await.id().into();

        let dlg_store = DelegationStore::new();
        let rev_store = RevocationStore::new();

        let mut g1 = Group::generate(
            nonempty![alice_agent.dupe()],
            dlg_store.dupe(),
            rev_store.dupe(),
            NoListener,
            Arc::new(Mutex::new(csprng)),
        )
        .await
        .unwrap();

        let _alice_adds_bob = g1
            .add_member(bob_agent.dupe(), Access::Write, &alice_signer, &[])
            .await
            .unwrap();

        let _bob_adds_carol = g1
            .add_member(carol_agent.dupe(), Access::Read, &bob_signer, &[])
            .await
            .unwrap();

        assert!(g1.members().contains_key(&alice_id.into()));
        assert!(g1.members().contains_key(&bob_id.into()));
        assert!(g1.members().contains_key(&carol_id.into()));
        assert!(!g1.members().contains_key(&dan_id));

        let _carol_adds_dan = g1
            .add_member(dan_agent.dupe(), Access::Read, &carol_signer, &[])
            .await
            .unwrap();

        assert!(g1.members.contains_key(&alice_id.into()));
        assert!(g1.members.contains_key(&bob_id.into()));
        assert!(g1.members.contains_key(&carol_id.into()));
        assert!(g1.members.contains_key(&dan_id));
        assert_eq!(g1.members.len(), 4);

        let _alice_revokes_bob = g1
            .revoke_member(bob_id.into(), true, &alice_signer, &BTreeMap::new())
            .await
            .unwrap();

        let bob_id = bob.lock().await.id();
        let carol_id = carol.lock().await.id();
        let dan_id = dan.lock().await.id();

        // Bob kicked out
        assert!(!g1.members.contains_key(&bob_id.into()));
        // Retained Carol & Dan
        assert!(g1.members.contains_key(&carol_id.into()));
        assert!(g1.members.contains_key(&dan_id.into()));

        let _bob_to_carol = g1
            .add_member(bob_agent.dupe(), Access::Read, &carol_signer, &[])
            .await
            .unwrap();

        assert!(g1.members.contains_key(&bob_id.into()));
        assert!(g1.members.contains_key(&carol_id.into()));
        assert!(g1.members.contains_key(&dan_id.into()));

        let _alice_revokes_carol = g1
            .revoke_member(carol_id.into(), false, &alice_signer, &BTreeMap::new())
            .await
            .unwrap();

        // Dropped Carol, which also kicks out can becuase `retain_all: false`
        assert!(!g1.members.contains_key(&carol_id.into()));
        // FIXME assert!(!g1.members.contains_key(&dan.borrow().id().into()));

        g1.revoke_member(alice_id.into(), false, &alice_signer, &BTreeMap::new())
            .await
            .unwrap();

        assert!(!g1.members.contains_key(&alice_id.into()));
        assert!(!g1.members.contains_key(&carol_id.into()));
        assert!(!g1.members.contains_key(&dan_id.into()));
    }
}
