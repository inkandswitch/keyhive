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
    listener::{membership::MembershipListener, no_listener::NoListener},
    store::{delegation::DelegationStore, revocation::RevocationStore},
};
use beekem::error::CgkaError;
use derivative::Derivative;
use derive_more::Debug;
use derive_where::derive_where;
use dupe::{Dupe, IterDupedExt};
use future_form::FutureForm;
use futures::{lock::Mutex, stream::FuturesUnordered, StreamExt};
use id::GroupId;
use keyhive_crypto::{
    content::reference::ContentRef,
    digest::Digest,
    share_key::ShareKey,
    signed::{Signed, SigningError},
    signer::{
        async_signer::AsyncSigner,
        ephemeral::EphemeralSigner,
        sync_signer::{try_sign_basic, SyncSignerBasic},
    },
    verifiable::Verifiable,
};
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
pub struct Group<
    F: FutureForm,
    S: AsyncSigner<F>,
    T: ContentRef = [u8; 32],
    L: MembershipListener<F, S, T> = NoListener,
> {
    pub(crate) id_or_indie: IdOrIndividual,

    /// The current view of members of a group.
    #[allow(clippy::type_complexity)]
    pub(crate) members: HashMap<Identifier, NonEmpty<Arc<Signed<Delegation<F, S, T, L>>>>>,

    /// Current view of revocations
    #[allow(clippy::type_complexity)]
    pub(crate) active_revocations: HashMap<[u8; 64], Arc<Signed<Revocation<F, S, T, L>>>>,

    /// The `Group`'s underlying (causal) delegation state.
    pub(crate) state: GroupState<F, S, T, L>,

    #[derive_where(skip)]
    pub(crate) listener: L,
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    Group<F, S, T, L>
{
    #[tracing::instrument(skip_all)]
    pub async fn new(
        group_id: GroupId,
        head: Arc<Signed<Delegation<F, S, T, L>>>,
        delegations: Arc<Mutex<DelegationStore<F, S, T, L>>>,
        revocations: Arc<Mutex<RevocationStore<F, S, T, L>>>,
        listener: L,
    ) -> Self {
        listener.on_delegation(group_id.into(), &head).await;
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
        head: Arc<Signed<Delegation<F, S, T, L>>>,
        delegations: Arc<Mutex<DelegationStore<F, S, T, L>>>,
        revocations: Arc<Mutex<RevocationStore<F, S, T, L>>>,
        listener: L,
    ) -> Self {
        listener.on_delegation(individual.id().into(), &head).await;
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
        parents: NonEmpty<Agent<F, S, T, L>>,
        delegations: Arc<Mutex<DelegationStore<F, S, T, L>>>,
        revocations: Arc<Mutex<RevocationStore<F, S, T, L>>>,
        listener: L,
        csprng: Arc<Mutex<R>>,
    ) -> Result<Group<F, S, T, L>, SigningError> {
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
        parents: NonEmpty<Agent<F, S, T, L>>,
        delegations: Arc<Mutex<DelegationStore<F, S, T, L>>>,
        revocations: Arc<Mutex<RevocationStore<F, S, T, L>>>,
        after_content: BTreeMap<DocumentId, Vec<T>>,
        listener: L,
    ) -> Result<Self, SigningError> {
        let id = verifier.into();
        let group_id = GroupId(id);
        let mut delegation_heads = DelegationStore::new();

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
                delegations.lock().await.insert(rc.dupe());
                delegation_heads.insert(rc.dupe());

                let listen = async_listener.dupe();
                let target = id;
                futs.push(async move {
                    listen.on_delegation(target, &rc).await;
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

                revocation_heads: RevocationStore::new(),
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
        let public_id = crate::principal::public::Public.id();
        for (id, (agent, _access)) in self.transitive_members().await.iter() {
            // Public must always be added with its single well-known key.
            if *id == public_id {
                prekeys.insert(
                    IndividualId(public_id),
                    crate::principal::public::Public.share_key(),
                );
            } else {
                prekeys.extend(agent.pick_individual_prekeys(doc_id).await.iter());
            }
        }
        prekeys
    }

    #[allow(clippy::type_complexity)]
    pub fn members(&self) -> &HashMap<Identifier, NonEmpty<Arc<Signed<Delegation<F, S, T, L>>>>> {
        &self.members
    }

    #[tracing::instrument(skip(self), fields(group_id = %self.group_id()))]
    pub async fn transitive_members(&self) -> HashMap<Identifier, (Agent<F, S, T, L>, Access)> {
        transitive_members_walk(self.id().into(), self.direct_members_with_caps()).await
    }

    /// The group's direct members and their capabilities.
    ///
    /// Must be called while the group's lock is held (it is a sync read of the
    /// direct membership state). The transitive walk itself is lock-free: see
    /// [`transitive_members_walk`].
    pub(crate) fn direct_members_with_caps(&self) -> Vec<(Agent<F, S, T, L>, Access)> {
        self.members
            .keys()
            .map(|member_id| {
                let dlg = self
                    .get_capability(member_id)
                    .expect("members have capabilities by definition");
                (dlg.payload.delegate.dupe(), dlg.payload.can)
            })
            .collect()
    }

    /// Returns agents whose delegations were revoked and who have no remaining
    /// active delegation in this group. Each entry includes the agent and the
    /// access level of the (now-revoked) delegation.
    pub fn revoked_members(&self) -> HashMap<Identifier, (Agent<F, S, T, L>, Access)> {
        let mut revoked: HashMap<Identifier, (Agent<F, S, T, L>, Access)> = HashMap::new();

        for r in self.active_revocations.values() {
            let delegate = &r.payload.revoke.payload.delegate;
            let id = delegate.id();
            let access = r.payload.revoke.payload.can;

            // Skip if agent still has an active delegation
            if self.members.contains_key(&id) {
                continue;
            }

            revoked
                .entry(id)
                .and_modify(|(_, existing)| {
                    if access > *existing {
                        *existing = access;
                    }
                })
                .or_insert_with(|| (delegate.clone(), access));
        }

        revoked
    }

    pub fn delegation_heads(&self) -> &DelegationStore<F, S, T, L> {
        &self.state.delegation_heads
    }

    pub fn revocation_heads(&self) -> &RevocationStore<F, S, T, L> {
        &self.state.revocation_heads
    }

    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all)]
    pub fn get_capability(
        &self,
        member_id: &Identifier,
    ) -> Option<&Arc<Signed<Delegation<F, S, T, L>>>> {
        self.members.get(member_id).and_then(|delegations| {
            delegations
                .iter()
                .max_by(|d1, d2| d1.payload().can.cmp(&d2.payload().can))
        })
    }

    #[tracing::instrument(skip_all)]
    pub async fn get_agent_revocations(
        &self,
        agent: &Agent<F, S, T, L>,
    ) -> Vec<Arc<Signed<Revocation<F, S, T, L>>>> {
        self.state
            .revocations
            .lock()
            .await
            .get_revocations_for_agent(&agent.agent_id())
            .map(|set| set.into_iter().collect())
            .unwrap_or_default()
    }

    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all)]
    pub async fn receive_delegation(
        &mut self,
        delegation: Arc<Signed<Delegation<F, S, T, L>>>,
    ) -> Result<Digest<Signed<Delegation<F, S, T, L>>>, error::AddError> {
        let digest = self.state.add_delegation(delegation.clone()).await?;
        tracing::info!("{:x?}", &digest);
        self.rebuild().await;
        self.listener.on_delegation(self.id(), &delegation).await;
        Ok(digest)
    }

    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip(self), fields(group_id = %self.group_id()))]
    pub async fn receive_revocation(
        &mut self,
        revocation: Arc<Signed<Revocation<F, S, T, L>>>,
    ) -> Result<Digest<Signed<Revocation<F, S, T, L>>>, error::AddError> {
        let digest = self.state.add_revocation(revocation.clone()).await?;
        self.rebuild().await;
        self.listener.on_revocation(self.id(), &revocation).await;
        Ok(digest)
    }

    /// NOTE: Callers must propagate CGKA adds to docs that contain this group.
    /// `Keyhive::add_member` handles this; calling this method directly will
    /// skip that propagation.
    ///
    /// `proof` must be precomputed by the caller via [`compute_add_proof`]
    /// without holding this group's lock (the transitive walk must not run
    /// while any document/group lock is held).
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all)]
    pub async fn add_member(
        &mut self,
        member_to_add: Agent<F, S, T, L>,
        can: Access,
        signer: &S,
        relevant_docs: &[Arc<Mutex<Document<F, S, T, L>>>],
        proof: Option<Arc<Signed<Delegation<F, S, T, L>>>>,
    ) -> Result<AddMemberUpdate<F, S, T, L>, AddGroupMemberError> {
        let mut after_content = BTreeMap::new();
        for d in relevant_docs {
            let locked = d.lock().await;
            after_content.insert(
                locked.doc_id(),
                locked.content_heads.iter().cloned().collect::<Vec<_>>(),
            );
        }

        self.add_member_with_manual_content(member_to_add, can, signer, after_content, proof)
            .await
    }

    /// Add a member to this group with manual content.
    ///
    /// NOTE: This does not add the added member's individuals to the
    /// CGKAs of documents that contain this group. Callers are responsible for
    /// propagating CGKA adds to affected docs (see `Keyhive::add_member`).
    ///
    /// `proof` must be precomputed by the caller via [`compute_add_proof`]
    /// without holding this group's lock (the transitive walk must not run
    /// while any document/group lock is held).
    pub(crate) async fn add_member_with_manual_content(
        &mut self,
        member_to_add: Agent<F, S, T, L>,
        can: Access,
        signer: &S,
        after_content: BTreeMap<DocumentId, Vec<T>>,
        proof: Option<Arc<Signed<Delegation<F, S, T, L>>>>,
    ) -> Result<AddMemberUpdate<F, S, T, L>, AddGroupMemberError> {
        let delegation = keyhive_crypto::signer::async_signer::try_sign_async::<F, _, _>(
            signer,
            Delegation {
                delegate: member_to_add,
                can,
                proof,
                after_revocations: self.state.revocation_heads.values().duped().collect(),
                after_content,
            },
        )
        .await?;

        let rc = Arc::new(delegation);
        let _digest = self.receive_delegation(rc.dupe()).await?;
        Ok(AddMemberUpdate {
            cgka_ops: Vec::new(),
            delegation: rc,
        })
    }

    /// Revoke a member from this group.
    ///
    /// NOTE: This does not remove the revoked member's individuals from the
    /// CGKAs of documents that contain this group. Callers are responsible for
    /// propagating CGKA removals to affected docs (see `Keyhive::revoke_member`).
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all)]
    pub async fn revoke_member(
        &mut self,
        member_to_remove: Identifier,
        retain_all_other_members: bool,
        signer: &S,
        after_content: &BTreeMap<DocumentId, Vec<T>>,
        // Signer's authority proofs per access level, precomputed by the
        // caller (via [`compute_revoke_proof`]/[`compute_add_proof`]) without
        // holding any lock. `signer_authority` authorizes the revocations
        // themselves (transitive-only proofs — see [`compute_revoke_proof`]);
        // `re_add_authority` authorizes the re-delegations issued for
        // `retain_all_other_members` (add semantics — the signer's own
        // delegation is valid there).
        signer_authority: &SignerAuthority<F, S, T, L>,
        re_add_authority: &SignerAuthority<F, S, T, L>,
    ) -> Result<RevokeMemberUpdate<F, S, T, L>, RevokeMemberError> {
        let vk = signer.verifying_key();
        let mut revocations = vec![];
        let og_dlgs: Vec<_> = self.members.values().flatten().cloned().collect();

        let all_to_revoke: Vec<Arc<Signed<Delegation<F, S, T, L>>>> = self
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
                    // The transitive walk must not run under this group's lock:
                    // the signer's authority proofs are precomputed lock-free by
                    // the caller (see [`compute_add_proof`]).
                    if let Some(Ok(Some(proof))) = signer_authority.get(&to_revoke.payload.can) {
                        let r = self
                            .build_revocation(
                                signer,
                                to_revoke.dupe(),
                                Some(proof.dupe()),
                                after_content.clone(),
                            )
                            .await?;
                        revocations.push(r.dupe());
                        self.receive_revocation(r).await?;
                        found = true;
                    }
                }

                if !found {
                    return Err(RevokeMemberError::NoProof);
                }
            }
        }

        let mut cgka_ops = Vec::new();

        let mut redelegations = vec![];
        if retain_all_other_members {
            for dlg in og_dlgs.iter() {
                if dlg.payload.delegate.id() == member_to_remove {
                    // Don't retain if they've delegated to themself
                    continue;
                }

                if let Some(proof) = &dlg.payload.proof {
                    if proof.payload.delegate.id() == member_to_remove {
                        // The re-delegation's proof is the signer's own authority
                        // at this access level, precomputed by the caller (lock-free).
                        let re_add_proof = match re_add_authority.get(&dlg.payload.can) {
                            Some(Ok(proof)) => proof.dupe(),
                            Some(Err(e)) => {
                                // `compute_add_proof` only produces these variants;
                                // `AddGroupMemberError` is not `Clone`.
                                let err = match e {
                                    AddGroupMemberError::AccessEscalation { wanted, have } => {
                                        AddGroupMemberError::AccessEscalation {
                                            wanted: *wanted,
                                            have: *have,
                                        }
                                    }
                                    AddGroupMemberError::NoProof => AddGroupMemberError::NoProof,
                                    _ => unreachable!(
                                        "compute_add_proof only returns AccessEscalation/NoProof"
                                    ),
                                };
                                return Err(err.into());
                            }
                            None => return Err(AddGroupMemberError::NoProof.into()),
                        };
                        let update = self
                            .add_member_with_manual_content(
                                dlg.payload.delegate.dupe(),
                                dlg.payload.can,
                                signer,
                                after_content.clone(),
                                re_add_proof,
                            )
                            .await?;

                        cgka_ops.extend(update.cgka_ops);
                        redelegations.push(update.delegation);
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
        revoke: Arc<Signed<Delegation<F, S, T, L>>>,
        proof: Option<Arc<Signed<Delegation<F, S, T, L>>>>,
        after_content: BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<Arc<Signed<Revocation<F, S, T, L>>>, SigningError> {
        let revocation = keyhive_crypto::signer::async_signer::try_sign_async::<F, _, _>(
            signer,
            Revocation {
                revoke,
                proof,
                after_content,
            },
        )
        .await?;

        Ok(Arc::new(revocation))
    }

    #[tracing::instrument(skip_all)]
    pub async fn rebuild(&mut self) {
        self.members.clear();
        self.active_revocations.clear();

        #[allow(clippy::type_complexity)]
        let mut dlgs_in_play: HashMap<[u8; 64], Arc<Signed<Delegation<F, S, T, L>>>> =
            HashMap::new();
        let mut revoked_dlgs: HashSet<[u8; 64]> = HashSet::new();

        // {dlg_dep => Set<dlgs that depend on it>}
        let mut reverse_dlg_dep_map: HashMap<[u8; 64], HashSet<[u8; 64]>> = HashMap::new();

        let mut ops = MembershipOperation::reverse_topsort(
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
                        // A delegation can arrive before its causal root proof
                        // during network sync. Keep it pending; a later
                        // rebuild will reconsider it once the dependency is
                        // present instead of panicking in debug builds.
                        tracing::debug!(
                            issuer = ?d.issuer,
                            group = ?self.group_id(),
                            "deferring delegation without a valid root proof"
                        );
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
                        // As with delegations, a revocation may be observed
                        // before its causal root proof. Leave it pending for
                        // the next rebuild rather than panicking.
                        tracing::debug!(
                            issuer = ?r.issuer,
                            group = ?self.group_id(),
                            "deferring revocation without a valid root proof"
                        );
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
        delegations: Arc<Mutex<DelegationStore<F, S, T, L>>>,
        revocations: Arc<Mutex<RevocationStore<F, S, T, L>>>,
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
                    let hashes: Vec<_> = vs
                        .iter()
                        .map(|v| Digest::hash(v.as_ref()).coerce())
                        .collect();
                    if let Some(ne) = NonEmpty::from_vec(hashes) {
                        acc.insert(*k, ne);
                    }
                    acc
                }),
            state: self.state.into_archive(),
        }
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> Hash
    for Group<F, S, T, L>
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id_or_indie.hash(state);
        self.members.iter().collect::<BTreeMap<_, _>>().hash(state);
        self.state.hash(state);
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> Verifiable
    for Group<F, S, T, L>
{
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
    use super::{delegation::Delegation, *};
    use crate::principal::active::Active;
    use future_form::Sendable;
    use keyhive_crypto::signer::memory::MemorySigner;
    use nonempty::nonempty;
    use pretty_assertions::assert_eq;
    use rand::rngs::OsRng;

    /// Compute the membership proof for a test signer, snapshotting first so
    /// the transitive walk never runs under a lock (mirrors the production
    /// `Membered` wrappers).
    async fn proof_for_arc<
        F: FutureForm,
        S: AsyncSigner<F>,
        T: ContentRef,
        L: MembershipListener<F, S, T>,
    >(
        g: &Arc<Mutex<Group<F, S, T, L>>>,
        signer: &S,
        can: Access,
    ) -> Option<Arc<Signed<Delegation<F, S, T, L>>>> {
        let (root_vk, members) = {
            let locked = g.lock().await;
            (locked.verifying_key(), locked.members().clone())
        };
        compute_add_proof(root_vk, &members, signer.verifying_key(), can)
            .await
            .expect("test signer should have authority")
    }

    /// Same as [`proof_for_arc`] but for a directly-held (non-`Mutex`) group.
    async fn proof_for<
        F: FutureForm,
        S: AsyncSigner<F>,
        T: ContentRef,
        L: MembershipListener<F, S, T>,
    >(
        g: &Group<F, S, T, L>,
        signer: &S,
        can: Access,
    ) -> Option<Arc<Signed<Delegation<F, S, T, L>>>> {
        compute_add_proof(g.verifying_key(), g.members(), signer.verifying_key(), can)
            .await
            .expect("test signer should have authority")
    }

    /// Signer authority proofs per access level, for the direct `revoke_member`
    /// calls in tests (the production wrappers compute this internally).
    /// Returns `(revocation_authority, re_add_authority)`.
    async fn authority_for<
        F: FutureForm,
        S: AsyncSigner<F>,
        T: ContentRef,
        L: MembershipListener<F, S, T>,
    >(
        g: &Group<F, S, T, L>,
        signer: &S,
    ) -> (SignerAuthority<F, S, T, L>, SignerAuthority<F, S, T, L>) {
        let mut revocation = HashMap::new();
        let mut re_add = HashMap::new();
        for can in [Access::Relay, Access::Read, Access::Edit, Access::Admin] {
            revocation.insert(
                can,
                compute_revoke_proof(g.verifying_key(), g.members(), signer.verifying_key(), can)
                    .await,
            );
            re_add.insert(
                can,
                compute_add_proof(g.verifying_key(), g.members(), signer.verifying_key(), can)
                    .await,
            );
        }
        (revocation, re_add)
    }
    async fn setup_user<T: ContentRef, R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Active<Sendable, MemorySigner, T> {
        let sk = MemorySigner::generate(csprng);
        Active::generate(sk, NoListener, csprng).await.unwrap()
    }

    async fn setup_groups<T: ContentRef, R: rand::CryptoRng + rand::RngCore>(
        alice: Arc<Mutex<Active<Sendable, MemorySigner, T>>>,
        bob: Arc<Mutex<Active<Sendable, MemorySigner, T>>>,
        csprng: Arc<Mutex<R>>,
    ) -> [Arc<Mutex<Group<Sendable, MemorySigner, T>>>; 4] {
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

        let alice_agent: Agent<Sendable, MemorySigner, T, _> =
            Agent::Active(alice.lock().await.id(), alice.dupe());
        let bob_agent = Agent::Active(bob.lock().await.id(), bob.dupe());

        let dlg_store = Arc::new(Mutex::new(DelegationStore::new()));
        let rev_store = Arc::new(Mutex::new(RevocationStore::new()));

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
        alice: Arc<Mutex<Active<Sendable, MemorySigner, T>>>,
        bob: Arc<Mutex<Active<Sendable, MemorySigner, T>>>,
        csprng: Arc<Mutex<R>>,
    ) -> [Arc<Mutex<Group<Sendable, MemorySigner, T>>>; 10] {
        let dlg_store = Arc::new(Mutex::new(DelegationStore::new()));
        let rev_store = Arc::new(Mutex::new(RevocationStore::new()));

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
                    keyhive_crypto::signer::async_signer::try_sign_async::<Sendable, _, _>(
                        &alice_signer,
                        Delegation {
                            delegate: Agent::Group(group9.lock().await.group_id(), group9.dupe()),
                            can: Access::Admin,
                            proof: Some(proof),
                            after_revocations: vec![],
                            after_content: BTreeMap::new(),
                        },
                    )
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
        let alice_agent: Agent<Sendable, MemorySigner, String> =
            Agent::Active(alice.lock().await.id(), alice.dupe());
        let alice_id = alice_agent.id();

        let bob = Arc::new(Mutex::new(setup_user(&mut csprng).await));

        let [g0, ..]: [Arc<Mutex<Group<Sendable, MemorySigner, String>>>; 4] =
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
        let alice_agent: Agent<Sendable, MemorySigner, String> =
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
        let alice_agent: Agent<Sendable, MemorySigner, String> =
            Agent::Active(alice.lock().await.id(), alice.dupe());
        let alice_id = alice_agent.id();

        let bob = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let bob_agent: Agent<Sendable, MemorySigner, String> =
            Agent::Active(bob.lock().await.id(), bob.dupe());
        let bob_id = bob_agent.id();

        let [g0, _g1, g2, _g3]: [Arc<Mutex<Group<Sendable, MemorySigner, String>>>; 4] =
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
        let alice_agent: Agent<Sendable, MemorySigner, String> =
            Agent::Active(alice_id, alice.dupe());
        let alice_id = alice_agent.id();

        let bob = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let bob_agent: Agent<Sendable, MemorySigner, String> =
            Agent::Active(bob.lock().await.id(), bob.dupe());
        let bob_id = bob_agent.id();

        let [g0, g1, g2, g3]: [Arc<Mutex<Group<Sendable, MemorySigner, String>>>; 4] =
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
        let alice_agent: Agent<Sendable, MemorySigner, String> =
            Agent::Active(alice.lock().await.id(), alice.dupe());
        let alice_id = alice_agent.id();

        let bob = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let bob_agent: Agent<Sendable, MemorySigner, String> =
            Agent::Active(bob.lock().await.id(), bob.dupe());
        let bob_id = bob_agent.id();

        let [g0, g1, g2, g3, g4, g5, g6, g7, g8, g9]: [Arc<
            Mutex<Group<Sendable, MemorySigner, String>>,
        >; 10] = setup_cyclic_groups(alice.dupe(), bob.dupe(), Arc::new(Mutex::new(csprng))).await;
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
    async fn test_transitive_access_cannot_exceed_parent() {
        test_utils::init_logging();
        let csprng = Arc::new(Mutex::new(OsRng));
        let delegations = Arc::new(Mutex::new(DelegationStore::new()));
        let revocations = Arc::new(Mutex::new(RevocationStore::new()));

        let root_owner = Arc::new(Mutex::new(setup_user::<String, _>(&mut OsRng).await));
        let leaf = Arc::new(Mutex::new(setup_user::<String, _>(&mut OsRng).await));
        let leaf_id = leaf.lock().await.id();
        let leaf_agent = Agent::Active(leaf_id, leaf.dupe());

        let leaf_group = Arc::new(Mutex::new(
            Group::generate(
                nonempty![leaf_agent],
                delegations.dupe(),
                revocations.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));
        let leaf_group_id = leaf_group.lock().await.group_id();

        let nested_group = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Group(leaf_group_id, leaf_group.dupe())],
                delegations.dupe(),
                revocations.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));
        let nested_group_id = nested_group.lock().await.group_id();

        let root_owner_id = root_owner.lock().await.id();
        let root = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Active(root_owner_id, root_owner.dupe())],
                delegations.dupe(),
                revocations.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));
        let root_owner_signer = root_owner.lock().await.signer.clone();

        let proof = proof_for_arc(&root, &root_owner_signer, Access::Read).await;
        root.lock()
            .await
            .add_member(
                Agent::Group(nested_group_id, nested_group.dupe()),
                Access::Read,
                &root_owner_signer,
                &[],
                proof,
            )
            .await
            .unwrap();

        let members = root.lock().await.transitive_members().await;
        assert_eq!(
            members
                .get(&nested_group_id.into())
                .map(|(_, access)| *access),
            Some(Access::Read)
        );
        assert_eq!(
            members
                .get(&leaf_group_id.into())
                .map(|(_, access)| *access),
            Some(Access::Read)
        );
        assert_eq!(
            members.get(&leaf_id.into()).map(|(_, access)| *access),
            Some(Access::Read)
        );
    }

    #[tokio::test]
    async fn test_transitive_access_uses_best_effective_path() {
        test_utils::init_logging();
        let csprng = Arc::new(Mutex::new(OsRng));
        let delegations = Arc::new(Mutex::new(DelegationStore::new()));
        let revocations = Arc::new(Mutex::new(RevocationStore::new()));

        let root_owner = Arc::new(Mutex::new(setup_user::<String, _>(&mut OsRng).await));
        let read_owner = Arc::new(Mutex::new(setup_user::<String, _>(&mut OsRng).await));
        let edit_owner = Arc::new(Mutex::new(setup_user::<String, _>(&mut OsRng).await));
        let target = Arc::new(Mutex::new(setup_user::<String, _>(&mut OsRng).await));

        let target_id = target.lock().await.id();
        let target_agent = Agent::Active(target_id, target.dupe());

        let read_owner_id = read_owner.lock().await.id();
        let read_group = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Active(read_owner_id, read_owner.dupe())],
                delegations.dupe(),
                revocations.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));
        let read_owner_signer = read_owner.lock().await.signer.clone();
        let proof = proof_for_arc(&read_group, &read_owner_signer, Access::Read).await;
        read_group
            .lock()
            .await
            .add_member(
                target_agent.dupe(),
                Access::Read,
                &read_owner_signer,
                &[],
                proof,
            )
            .await
            .unwrap();

        let edit_owner_id = edit_owner.lock().await.id();
        let edit_group = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Active(edit_owner_id, edit_owner.dupe())],
                delegations.dupe(),
                revocations.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));
        let edit_owner_signer = edit_owner.lock().await.signer.clone();
        let proof = proof_for_arc(&edit_group, &edit_owner_signer, Access::Edit).await;
        edit_group
            .lock()
            .await
            .add_member(target_agent, Access::Edit, &edit_owner_signer, &[], proof)
            .await
            .unwrap();

        let root_owner_id = root_owner.lock().await.id();
        let root = Arc::new(Mutex::new(
            Group::generate(
                nonempty![Agent::Active(root_owner_id, root_owner.dupe())],
                delegations.dupe(),
                revocations.dupe(),
                NoListener,
                csprng.dupe(),
            )
            .await
            .unwrap(),
        ));
        let root_owner_signer = root_owner.lock().await.signer.clone();

        let proof = proof_for_arc(&root, &root_owner_signer, Access::Admin).await;
        root.lock()
            .await
            .add_member(
                Agent::Group(read_group.lock().await.group_id(), read_group.dupe()),
                Access::Admin,
                &root_owner_signer,
                &[],
                proof,
            )
            .await
            .unwrap();
        let proof = proof_for_arc(&root, &root_owner_signer, Access::Admin).await;
        root.lock()
            .await
            .add_member(
                Agent::Group(edit_group.lock().await.group_id(), edit_group.dupe()),
                Access::Admin,
                &root_owner_signer,
                &[],
                proof,
            )
            .await
            .unwrap();

        let members = root.lock().await.transitive_members().await;
        assert_eq!(
            members.get(&target_id.into()).map(|(_, access)| *access),
            Some(Access::Edit)
        );
    }

    #[tokio::test]
    async fn test_add_member() {
        test_utils::init_logging();
        let mut csprng = OsRng;

        let alice = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let alice_agent: Agent<Sendable, MemorySigner> =
            Agent::Active(alice.lock().await.id(), alice.dupe());

        let bob = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let bob_agent: Agent<Sendable, MemorySigner> =
            Agent::Active(bob.lock().await.id(), bob.dupe());

        let carol = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let carol_agent: Agent<Sendable, MemorySigner> =
            Agent::Active(carol.lock().await.id(), carol.dupe());

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

        let dlg_store = Arc::new(Mutex::new(DelegationStore::new()));
        let rev_store = Arc::new(Mutex::new(RevocationStore::new()));

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

        let proof = proof_for_arc(&g0, &active_signer, Access::Edit).await;
        g0.lock()
            .await
            .add_member(carol_agent.dupe(), Access::Edit, &active_signer, &[], proof)
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
            Some(&(carol.lock().await.clone().into(), Access::Edit)) // NOTE: non-admin!
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
            Some(&(carol.lock().await.clone().into(), Access::Edit)) // NOTE: non-admin!
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
        let alice_agent: Agent<Sendable, MemorySigner> =
            Agent::Active(alice.lock().await.id(), alice.dupe());

        let bob = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let bob_agent: Agent<Sendable, MemorySigner> =
            Agent::Active(bob.lock().await.id(), bob.dupe());

        let carol = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let carol_agent: Agent<Sendable, MemorySigner> =
            Agent::Active(carol.lock().await.id(), carol.dupe());

        let dan = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let dan_agent: Agent<Sendable, MemorySigner> =
            Agent::Active(dan.lock().await.id(), dan.dupe());

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

        let dlg_store = Arc::new(Mutex::new(DelegationStore::new()));
        let rev_store = Arc::new(Mutex::new(RevocationStore::new()));

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
            .add_member(
                bob_agent.dupe(),
                Access::Edit,
                &alice_signer,
                &[],
                proof_for(&g1, &alice_signer, Access::Edit).await,
            )
            .await
            .unwrap();

        let _bob_adds_carol = g1
            .add_member(
                carol_agent.dupe(),
                Access::Read,
                &bob_signer,
                &[],
                proof_for(&g1, &bob_signer, Access::Read).await,
            )
            .await
            .unwrap();

        assert!(g1.members().contains_key(&alice_id.into()));
        assert!(g1.members().contains_key(&bob_id.into()));
        assert!(g1.members().contains_key(&carol_id.into()));
        assert!(!g1.members().contains_key(&dan_id));

        let _carol_adds_dan = g1
            .add_member(
                dan_agent.dupe(),
                Access::Read,
                &carol_signer,
                &[],
                proof_for(&g1, &carol_signer, Access::Read).await,
            )
            .await
            .unwrap();

        assert!(g1.members.contains_key(&alice_id.into()));
        assert!(g1.members.contains_key(&bob_id.into()));
        assert!(g1.members.contains_key(&carol_id.into()));
        assert!(g1.members.contains_key(&dan_id));
        assert_eq!(g1.members.len(), 4);

        let (rev_auth, re_add_auth) = authority_for(&g1, &alice_signer).await;
        let _alice_revokes_bob = g1
            .revoke_member(
                bob_id.into(),
                true,
                &alice_signer,
                &BTreeMap::new(),
                &rev_auth,
                &re_add_auth,
            )
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
            .add_member(
                bob_agent.dupe(),
                Access::Read,
                &carol_signer,
                &[],
                proof_for(&g1, &carol_signer, Access::Read).await,
            )
            .await
            .unwrap();

        assert!(g1.members.contains_key(&bob_id.into()));
        assert!(g1.members.contains_key(&carol_id.into()));
        assert!(g1.members.contains_key(&dan_id.into()));

        let (rev_auth, re_add_auth) = authority_for(&g1, &alice_signer).await;
        let _alice_revokes_carol = g1
            .revoke_member(
                carol_id.into(),
                false,
                &alice_signer,
                &BTreeMap::new(),
                &rev_auth,
                &re_add_auth,
            )
            .await
            .unwrap();

        // Dropped Carol, which also kicks out can becuase `retain_all: false`
        assert!(!g1.members.contains_key(&carol_id.into()));
        // FIXME assert!(!g1.members.contains_key(&dan.borrow().id().into()));

        let (rev_auth, re_add_auth) = authority_for(&g1, &alice_signer).await;
        g1.revoke_member(
            alice_id.into(),
            false,
            &alice_signer,
            &BTreeMap::new(),
            &rev_auth,
            &re_add_auth,
        )
        .await
        .unwrap();

        assert!(!g1.members.contains_key(&alice_id.into()));
        assert!(!g1.members.contains_key(&carol_id.into()));
        assert!(!g1.members.contains_key(&dan_id.into()));
    }

    /// Regression: a direct *individual* member revokes a *group* member whose
    /// delegation was issued by someone else (not in the signer's issuer/ancestor
    /// chain). The revocation must be authorized through the group intermediary
    /// (the revoked group itself contains the signer), NOT through the signer's
    /// own delegation — an Individual delegate is not a valid revocation proof
    /// and `add_revocation` rejects it ("Invalid proof chain").
    #[tokio::test]
    async fn test_revoke_group_member_by_direct_individual_member() {
        test_utils::init_logging();
        let mut csprng = OsRng;

        let alice = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let alice_agent: Agent<Sendable, MemorySigner> =
            Agent::Active(alice.lock().await.id(), alice.dupe());
        let (alice_id, alice_signer) = {
            let locked = alice.lock().await;
            (locked.id(), locked.signer.clone())
        };

        let bob = Arc::new(Mutex::new(setup_user(&mut csprng).await));
        let bob_agent: Agent<Sendable, MemorySigner> =
            Agent::Active(bob.lock().await.id(), bob.dupe());
        let (bob_id, bob_signer) = {
            let locked = bob.lock().await;
            (locked.id(), locked.signer.clone())
        };

        let dlg_store = Arc::new(Mutex::new(DelegationStore::new()));
        let rev_store = Arc::new(Mutex::new(RevocationStore::new()));
        let arc_csprng = Arc::new(Mutex::new(csprng));

        // g1: the resource group. Alice (root) plus the intermediary group g2.
        let g1 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![alice_agent.dupe()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                arc_csprng.dupe(),
            )
            .await
            .unwrap(),
        ));
        let g1_id = { g1.lock().await.group_id() };

        // g2: the intermediary group that contains bob (the eventual signer).
        let g2 = Arc::new(Mutex::new(
            Group::generate(
                nonempty![bob_agent.dupe()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                arc_csprng.dupe(),
            )
            .await
            .unwrap(),
        ));
        let g2_id = { g2.lock().await.group_id() };
        let g2_agent = Agent::Group(g2_id, g2.dupe());

        // Alice (root) grants g2 and bob direct Admin access to g1. The proofs
        // are computed BEFORE taking the lock (they snapshot + walk lock-free).
        let proof = proof_for_arc(&g1, &alice_signer, Access::Admin).await;
        g1.lock()
            .await
            .add_member(g2_agent.dupe(), Access::Admin, &alice_signer, &[], proof)
            .await
            .unwrap();
        let proof = proof_for_arc(&g1, &alice_signer, Access::Admin).await;
        g1.lock()
            .await
            .add_member(bob_agent.dupe(), Access::Admin, &alice_signer, &[], proof)
            .await
            .unwrap();

        assert!(g1.lock().await.members.contains_key(&g2_id.into()));
        assert!(g1.lock().await.members.contains_key(&bob_id.into()));

        // Bob (direct individual member, NOT the root) revokes g2 through the
        // production `Membered` wrapper. g2's delegation was issued by Alice,
        // so the issuer/ancestor paths do not apply — the revocation must be
        // proven through g2 itself (bob is a transitive member of g2).
        Membered::Group(g1_id, g1.dupe())
            .revoke_member(g2_id.into(), true, &bob_signer, &mut BTreeMap::new())
            .await
            .unwrap();

        assert!(
            !g1.lock().await.members.contains_key(&g2_id.into()),
            "g2 must be revoked from g1"
        );
        assert!(
            g1.lock().await.members.contains_key(&bob_id.into()),
            "bob must remain a member of g1"
        );
    }
}

/// Transitive-membership walk over the membered graph.
///
/// Never holds a doc/group lock across an await that acquires another lock.
/// The root's direct members are passed in (snapshotted by the caller under a
/// short lock); every visited node is then locked only long enough to clone
/// its direct members + capabilities before the lock is dropped, so at most
/// one lock is held at any instant. Concurrent walks rooted at different
/// docs/groups therefore cannot ABBA-deadlock with each other or with
/// materialization decrypts that briefly lock a single document.
pub(crate) async fn transitive_members_walk<
    F: FutureForm,
    S: AsyncSigner<F>,
    T: ContentRef,
    L: MembershipListener<F, S, T>,
>(
    root_id: Identifier,
    direct: Vec<(Agent<F, S, T, L>, Access)>,
) -> HashMap<Identifier, (Agent<F, S, T, L>, Access)> {
    let mut explore: Vec<(Membered<F, S, T, L>, Access)> = vec![];
    let mut expanded: HashMap<Identifier, Access> = HashMap::new();
    let mut caps: HashMap<Identifier, (Agent<F, S, T, L>, Access)> = HashMap::new();

    let enqueue = |agent: Agent<F, S, T, L>,
                   access: Access,
                   caps: &mut HashMap<Identifier, (Agent<F, S, T, L>, Access)>,
                   expanded: &mut HashMap<Identifier, Access>,
                   explore: &mut Vec<(Membered<F, S, T, L>, Access)>| {
        let id = agent.id();
        if id == root_id {
            return;
        }
        if caps
            .get(&id)
            .is_none_or(|(_, existing_access)| *existing_access < access)
        {
            caps.insert(id, (agent.dupe(), access));
        }
        if let Some(membered) = agent.as_membered() {
            if expanded
                .get(&id)
                .is_none_or(|existing_access| *existing_access < access)
            {
                expanded.insert(id, access);
                explore.push((membered, access));
            }
        }
    };

    for (delegate, can) in direct {
        enqueue(delegate, can, &mut caps, &mut expanded, &mut explore);
    }

    while let Some((membered, access)) = explore.pop() {
        let members = membered.members().await;
        for (mem_id, dlgs) in members.iter() {
            let dlg = membered
                .get_capability(mem_id)
                .await
                .expect("members have capabilities by definition");
            let member_access = access.min(dlg.payload.can);
            if caps
                .get(mem_id)
                .is_none_or(|(_, existing_access)| *existing_access < member_access)
            {
                caps.insert(*mem_id, (dlg.payload.delegate.dupe(), member_access));
            }
            for sub_dlg in dlgs.iter() {
                enqueue(
                    sub_dlg.payload.delegate.dupe(),
                    access.min(sub_dlg.payload.can),
                    &mut caps,
                    &mut expanded,
                    &mut explore,
                );
            }
        }
    }

    caps
}

/// Signer-authority proofs per access level, precomputed by the caller
/// (lock-free) and consumed by the group/document `revoke_member` paths.
pub(crate) type SignerAuthority<F, S, T, L> =
    HashMap<Access, Result<Option<Arc<Signed<Delegation<F, S, T, L>>>>, AddGroupMemberError>>;

/// Compute the membership proof for adding a member at access level `can`,
/// without holding any document/group lock.
///
/// `members` must be a snapshot of the resource's direct membership (cloned
/// under a short lock by the caller). The transitive walk acquires only short
/// per-node locks, so it must never run while another lock is held — callers
/// must take their snapshot, drop the lock, and only then call this.
///
/// Returns `Ok(None)` when the signer is the resource's own signing key.
pub(crate) async fn compute_add_proof<
    F: FutureForm,
    S: AsyncSigner<F>,
    T: ContentRef,
    L: MembershipListener<F, S, T>,
>(
    root_vk: ed25519_dalek::VerifyingKey,
    members: &HashMap<Identifier, NonEmpty<Arc<Signed<Delegation<F, S, T, L>>>>>,
    signer_vk: ed25519_dalek::VerifyingKey,
    can: Access,
) -> Result<Option<Arc<Signed<Delegation<F, S, T, L>>>>, AddGroupMemberError> {
    if root_vk == signer_vk {
        return Ok(None);
    }
    let signer_id = Identifier::from(signer_vk);
    if let Some(p) = members.get(&signer_id).and_then(|dlgs| {
        dlgs.iter()
            .max_by(|d1, d2| d1.payload().can.cmp(&d2.payload().can))
    }) {
        // Signer is a direct member of this group.
        if can > p.payload.can {
            return Err(AddGroupMemberError::AccessEscalation {
                wanted: can,
                have: p.payload().can,
            });
        }
        return Ok(Some(p.dupe()));
    }
    compute_transitive_proof(members, signer_id, can).await
}

/// Compute the proof authorizing a revocation at access level `can`.
///
/// Unlike [`compute_add_proof`], the signer's own direct delegation is NOT a
/// valid revocation proof: `add_revocation` validates the proof through
/// `is_transitive_member_of(proof.delegate, revoker, ..)`, which requires the
/// proof's delegate to be a membered group/doc intermediary — an Individual
/// delegate fails that check. So the direct-member shortcut is skipped and
/// only the transitive (membered-intermediary) search is performed, matching
/// the pre-lock-refactor behavior of `revoke_member`.
pub(crate) async fn compute_revoke_proof<
    F: FutureForm,
    S: AsyncSigner<F>,
    T: ContentRef,
    L: MembershipListener<F, S, T>,
>(
    root_vk: ed25519_dalek::VerifyingKey,
    members: &HashMap<Identifier, NonEmpty<Arc<Signed<Delegation<F, S, T, L>>>>>,
    signer_vk: ed25519_dalek::VerifyingKey,
    can: Access,
) -> Result<Option<Arc<Signed<Delegation<F, S, T, L>>>>, AddGroupMemberError> {
    if root_vk == signer_vk {
        return Ok(None);
    }
    compute_transitive_proof(members, Identifier::from(signer_vk), can).await
}

/// Single-pass transitive search: find a membered (group/doc) direct member
/// whose transitive members include `signer_id` at access >= `can`, and return
/// that member's delegation as the proof.
async fn compute_transitive_proof<
    F: FutureForm,
    S: AsyncSigner<F>,
    T: ContentRef,
    L: MembershipListener<F, S, T>,
>(
    members: &HashMap<Identifier, NonEmpty<Arc<Signed<Delegation<F, S, T, L>>>>>,
    signer_id: Identifier,
    can: Access,
) -> Result<Option<Arc<Signed<Delegation<F, S, T, L>>>>, AddGroupMemberError> {
    let mut best_access: Option<Access> = None;

    for (member_id, _) in members.iter() {
        let dlg = members
            .get(member_id)
            .and_then(|dlgs| {
                dlgs.iter()
                    .max_by(|d1, d2| d1.payload().can.cmp(&d2.payload().can))
            })
            .expect("members have capabilities by definition");

        if let Some(m) = dlg.payload.delegate.as_membered() {
            let sub_members = m.transitive_members().await;
            if let Some((_, sub_access)) = sub_members.get(&signer_id) {
                if *sub_access >= can {
                    return Ok(Some(dlg.dupe()));
                }
                if best_access.is_none_or(|a| *sub_access > a) {
                    best_access = Some(*sub_access);
                }
            }
        }
    }

    if let Some(access) = best_access {
        Err(AddGroupMemberError::AccessEscalation {
            wanted: can,
            have: access,
        })
    } else {
        Err(AddGroupMemberError::NoProof)
    }
}
