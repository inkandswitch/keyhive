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
    state::{GroupState, GroupStateArchive},
};
use super::{
    agent::{id::AgentId, Agent},
    document::{id::DocumentId, AddCgkaMemberError, AddMemberUpdate, Document, RevokeMemberUpdate},
    identifier::Identifier,
    individual::{id::IndividualId, Individual},
    membered::Membered,
    public::Public,
};
use crate::{
    access::Access,
    cgka::{error::CgkaError, operation::CgkaOperation},
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        share_key::ShareKey,
        signed::{Signed, SigningError},
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
use id::GroupId;
use nonempty::{nonempty, NonEmpty};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet},
    hash::{Hash, Hasher},
    rc::Rc,
};
use thiserror::Error;

/// A collection of agents with no associated content.
///
/// Groups are stateful agents. It is possible the delegate control over them,
/// and they can be delegated to. This produces transitives lines of authority
/// through the network of [`Agent`]s.
#[derive(Debug, Clone, Eq, Derivative)]
#[derive_where(PartialEq; T)]
pub struct Group<T: ContentRef = [u8; 32], L: MembershipListener<T> = NoListener> {
    pub(crate) individual: Individual,

    /// The current view of members of a group.
    #[allow(clippy::type_complexity)]
    pub(crate) members: HashMap<Identifier, NonEmpty<Rc<Signed<Delegation<T, L>>>>>,

    /// Current view of revocations
    pub(crate) active_revocations: HashMap<[u8; 64], Rc<Signed<Revocation<T, L>>>>,

    /// The `Group`'s underlying (causal) delegation state.
    pub(crate) state: GroupState<T, L>,

    #[debug(skip)]
    #[derive_where(skip)]
    pub(crate) listener: L,
}

impl<T: ContentRef, L: MembershipListener<T>> Group<T, L> {
    pub fn from_individual(
        individual: Individual,
        head: Rc<Signed<Delegation<T, L>>>,
        delegations: DelegationStore<T, L>,
        revocations: RevocationStore<T, L>,
        listener: L,
    ) -> Self {
        let mut group = Self {
            individual,
            members: HashMap::new(),
            state: GroupState::new(head, delegations, revocations),
            active_revocations: HashMap::new(),
            listener,
        };
        group.rebuild();
        group
    }

    /// Generate a new `Group` with a unique [`Identifier`] and the given `parents`.
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(
        parents: NonEmpty<Agent<T, L>>,
        delegations: DelegationStore<T, L>,
        revocations: RevocationStore<T, L>,
        listener: L,
        csprng: &mut R,
    ) -> Result<Group<T, L>, SigningError> {
        let sk = ed25519_dalek::SigningKey::generate(csprng);
        Self::generate_after_content(
            &sk,
            parents,
            delegations,
            revocations,
            Default::default(),
            listener,
        )
    }

    pub(crate) fn generate_after_content(
        signing_key: &ed25519_dalek::SigningKey,
        parents: NonEmpty<Agent<T, L>>,
        delegations: DelegationStore<T, L>,
        revocations: RevocationStore<T, L>,
        after_content: BTreeMap<DocumentId, Vec<T>>,
        listener: L,
    ) -> Result<Group<T, L>, SigningError> {
        let id = signing_key.verifying_key().into();
        let group_id = GroupId(id);

        let ds = delegations.dupe();
        let mut ds_mut = ds.borrow_mut();
        let mut delegation_heads = CaMap::new();

        parents.iter().try_fold((), |_, parent| {
            let dlg = Signed::try_sign(
                Delegation {
                    delegate: parent.dupe(),
                    can: Access::Admin,
                    proof: None,
                    after_revocations: vec![],
                    after_content: after_content.clone(),
                },
                signing_key,
            )?;

            let rc = Rc::new(dlg);
            ds_mut.insert(rc.dupe());
            delegation_heads.insert(rc.dupe());

            Ok::<(), SigningError>(())
        })?;

        let mut group = Group {
            individual: Individual::new(id.into()),
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

        group.rebuild();
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

    pub fn individual_ids(&self) -> HashSet<IndividualId> {
        HashSet::from_iter(
            self.members
                .values()
                .flat_map(|delegations| delegations[0].payload().delegate.individual_ids()),
        )
    }

    pub fn pick_individual_prekeys(&self, doc_id: DocumentId) -> HashMap<IndividualId, ShareKey> {
        HashMap::from_iter(
            self.transitive_members()
                .values()
                .flat_map(|(agent, _access)| agent.pick_individual_prekeys(doc_id)),
        )
    }

    #[allow(clippy::type_complexity)]
    pub fn members(&self) -> &HashMap<Identifier, NonEmpty<Rc<Signed<Delegation<T, L>>>>> {
        &self.members
    }

    pub fn transitive_members(&self) -> HashMap<Identifier, (Agent<T, L>, Access)> {
        struct GroupAccess<U: ContentRef, M: MembershipListener<U>> {
            agent: Agent<U, M>,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess<T, L>> = vec![];
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

        let mut caps: HashMap<Identifier, (Agent<T, L>, Access)> = HashMap::new();

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
                Agent::Group(inner_group) => Some(Membered::<T, L>::from(inner_group)),
                Agent::Document(doc) => Some(doc.into()),
                _ => None,
            } {
                for (mem_id, dlgs) in membered.members().iter() {
                    let dlg = membered
                        .get_capability(mem_id)
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

    pub fn is_publicly_replicable(&self) -> bool {
        self.members().contains_key(&Public.id())
    }

    pub fn is_publicly_readable(&self) -> bool {
        if let Some(dlg) = self.get_capability(&Public.id()) {
            dlg.payload.can >= Access::Read
        } else {
            false
        }
    }

    pub fn is_publicly_writable(&self) -> bool {
        if let Some(dlg) = self.get_capability(&Public.id()) {
            dlg.payload.can >= Access::Write
        } else {
            false
        }
    }

    pub fn is_publicly_administratable(&self) -> bool {
        if let Some(dlg) = self.get_capability(&Public.id()) {
            dlg.payload.can >= Access::Write
        } else {
            false
        }
    }

    pub fn make_public(
        &mut self,
        access: Access,
        signing_key: &ed25519_dalek::SigningKey,
        relevant_docs: &[Rc<RefCell<Document<T, L>>>],
    ) -> Result<AddMemberUpdate<T, L>, AddGroupMemberError> {
        self.add_member(Public.agent(), access, signing_key, relevant_docs)
    }

    pub fn make_private(
        &mut self,
        retain_all_other_members: bool,
        signing_key: &ed25519_dalek::SigningKey,
        after_content: &BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<RevokeMemberUpdate<T, L>, RevokeMemberError> {
        self.revoke_member(
            Public.id(),
            retain_all_other_members,
            signing_key,
            after_content,
        )
    }

    pub fn delegation_heads(&self) -> &CaMap<Signed<Delegation<T, L>>> {
        &self.state.delegation_heads
    }

    pub fn revocation_heads(&self) -> &CaMap<Signed<Revocation<T, L>>> {
        &self.state.revocation_heads
    }

    pub fn get_capability(&self, member_id: &Identifier) -> Option<&Rc<Signed<Delegation<T, L>>>> {
        self.members.get(member_id).and_then(|delegations| {
            delegations
                .iter()
                .max_by(|d1, d2| d1.payload().can.cmp(&d2.payload().can))
        })
    }

    pub fn get_agent_revocations(&self, agent: &Agent<T, L>) -> Vec<Rc<Signed<Revocation<T, L>>>> {
        self.state
            .revocations
            .borrow()
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

    pub fn receive_delegation(
        &mut self,
        delegation: Rc<Signed<Delegation<T, L>>>,
    ) -> Result<Digest<Signed<Delegation<T, L>>>, error::AddError> {
        let digest = self.state.add_delegation(delegation)?;
        self.rebuild();
        Ok(digest)
    }

    pub fn receive_revocation(
        &mut self,
        revocation: Rc<Signed<Revocation<T, L>>>,
    ) -> Result<Digest<Signed<Revocation<T, L>>>, error::AddError> {
        let digest = self.state.add_revocation(revocation)?;
        self.rebuild();
        Ok(digest)
    }

    pub fn add_member(
        &mut self,
        member_to_add: Agent<T, L>,
        can: Access,
        signing_key: &ed25519_dalek::SigningKey,
        relevant_docs: &[Rc<RefCell<Document<T, L>>>],
    ) -> Result<AddMemberUpdate<T, L>, AddGroupMemberError> {
        let after_content = relevant_docs
            .iter()
            .map(|d| {
                (
                    d.borrow().doc_id(),
                    d.borrow().content_heads.iter().cloned().collect::<Vec<_>>(),
                )
            })
            .collect();

        self.add_member_with_manual_content(member_to_add, can, signing_key, after_content)
    }

    pub(crate) fn add_member_with_manual_content(
        &mut self,
        member_to_add: Agent<T, L>,
        can: Access,
        signing_key: &ed25519_dalek::SigningKey,
        after_content: BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<AddMemberUpdate<T, L>, AddGroupMemberError> {
        let proof = if self.verifying_key() == signing_key.verifying_key() {
            None
        } else {
            let p = self
                .get_capability(&signing_key.verifying_key().into())
                .ok_or(AddGroupMemberError::NoProof)?;

            if can > p.payload.can {
                return Err(AddGroupMemberError::AccessEscalation {
                    wanted: can,
                    have: p.payload().can,
                });
            }

            Some(p.dupe())
        };

        let delegation = Signed::try_sign(
            Delegation {
                delegate: member_to_add,
                can,
                proof,
                after_revocations: self.state.revocation_heads.values().duped().collect(),
                after_content,
            },
            signing_key,
        )?;

        let rc = Rc::new(delegation);
        self.listener.on_delegation(&rc);
        let _digest = self.receive_delegation(rc.dupe())?;

        Ok(AddMemberUpdate {
            cgka_ops: self.add_cgka_member(rc.dupe(), signing_key)?,
            delegation: rc,
        })
    }

    pub fn add_cgka_member(
        &mut self,
        delegation: Rc<Signed<Delegation<T, L>>>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Vec<Signed<CgkaOperation>>, AddCgkaMemberError> {
        let mut cgka_ops = Vec::new();
        let docs: Vec<Rc<RefCell<Document<T, L>>>> = self
            .transitive_members()
            .values()
            .filter_map(|(agent, _)| {
                if let Agent::Document(doc) = agent {
                    Some(doc.dupe())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for doc in docs {
            for op in doc.borrow_mut().add_cgka_member(&delegation, signing_key)? {
                cgka_ops.push(op);
            }
        }
        Ok(cgka_ops)
    }

    #[allow(clippy::type_complexity)]
    pub fn revoke_member(
        &mut self,
        member_to_remove: Identifier,
        retain_all_other_members: bool,
        signing_key: &ed25519_dalek::SigningKey,
        after_content: &BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<RevokeMemberUpdate<T, L>, RevokeMemberError> {
        let vk = signing_key.verifying_key();
        let mut revocations = vec![];
        let og_dlgs: Vec<_> = self.members.values().flatten().cloned().collect();

        let all_to_revoke: Vec<Rc<Signed<Delegation<T, L>>>> = self
            .members()
            .get(&member_to_remove)
            .map(|ne| Vec::<_>::from(ne.clone())) // Semi-inexpensive because `Vec<Rc<_>>`
            .unwrap_or_default();

        if all_to_revoke.is_empty() {
            self.members.remove(&member_to_remove);
            return Ok(RevokeMemberUpdate::default());
        }

        if vk == self.verifying_key() {
            // In the (unlikely) case that the group signing key still exists and is doing the revocation.
            // Arguably this could be made impossible, but it would likely be surprising behaviour.
            for to_revoke in all_to_revoke.iter() {
                let r = self.build_revocation(
                    signing_key,
                    to_revoke.dupe(),
                    None,
                    after_content.clone(),
                )?;
                self.receive_revocation(r.dupe())?;
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
                            let r = self.build_revocation(
                                signing_key,
                                to_revoke.dupe(),
                                Some(mem_dlg.dupe()), // Admin proof
                                after_content.clone(),
                            )?;

                            self.receive_revocation(r.dupe())?;
                            revocations.push(r);
                            found = true;
                        }
                    }
                }

                if to_revoke.issuer == vk {
                    let r = self.build_revocation(
                        signing_key,
                        to_revoke.dupe(),
                        Some(to_revoke.dupe()), // You issued it!
                        after_content.clone(),
                    )?;
                    self.receive_revocation(r.dupe())?;
                    revocations.push(r);
                    found = true;
                } else {
                    // Look for proof of any ancestor
                    for ancestor in to_revoke.payload().proof_lineage() {
                        if ancestor.issuer == vk {
                            found = true;
                            let r = self.build_revocation(
                                signing_key,
                                to_revoke.dupe(),
                                Some(ancestor.dupe()),
                                after_content.clone(),
                            )?;
                            revocations.push(r.dupe());
                            self.receive_revocation(r)?;
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
            self.listener.on_revocation(r);
        }

        let mut cgka_ops = Vec::new();
        let (individuals, docs): (
            Vec<Rc<RefCell<Individual>>>,
            Vec<Rc<RefCell<Document<T, L>>>>,
        ) = self.transitive_members().values().fold(
            (vec![], vec![]),
            |(mut indies, mut docs), (agent, _)| {
                match agent {
                    Agent::Individual(individual) => {
                        indies.push(individual.dupe());
                    }
                    Agent::Document(doc) => {
                        docs.push(doc.dupe());
                    }
                    _ => (),
                }

                (indies, docs)
            },
        );

        for indie in individuals {
            let id = indie.borrow().id();
            for doc in &docs {
                if let Some(op) = doc.borrow_mut().remove_cgka_member(id, signing_key)? {
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
                // FIXME go through entire history
                if let Some(proof) = &dlg.payload.proof {
                    if proof.payload.delegate.id() == member_to_remove {
                        let AddMemberUpdate { delegation, .. } = self
                            .add_member_with_manual_content(
                                dlg.payload.delegate.dupe(),
                                dlg.payload.can,
                                signing_key,
                                after_content.clone(),
                            )?;

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

    fn build_revocation(
        &mut self,
        signing_key: &ed25519_dalek::SigningKey,
        revoke: Rc<Signed<Delegation<T, L>>>,
        proof: Option<Rc<Signed<Delegation<T, L>>>>,
        after_content: BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<Rc<Signed<Revocation<T, L>>>, SigningError> {
        let revocation = Signed::try_sign(
            Revocation {
                revoke,
                proof,
                after_content,
            },
            signing_key,
        )?;

        Ok(Rc::new(revocation))
    }

    pub fn rebuild(&mut self) {
        self.members.clear();
        self.active_revocations.clear();

        let mut dlgs_in_play: HashMap<[u8; 64], Rc<Signed<Delegation<T, L>>>> = HashMap::new();
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
                    if revoked_dlgs.contains(&d.signature.to_bytes()) {
                        continue;
                    }

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
        delegations: DelegationStore<T, L>,
        revocations: RevocationStore<T, L>,
        listener: L,
    ) -> Self {
        Self {
            members: HashMap::new(),
            individual: archive.individual,
            state: GroupState::dummy_from_archive(archive.state, delegations, revocations),
            active_revocations: HashMap::new(),
            listener,
        }
    }
}

impl<T: ContentRef, L: MembershipListener<T>> Hash for Group<T, L> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.individual.hash(state);
        self.members.iter().collect::<BTreeMap<_, _>>().hash(state);
        self.state.hash(state);
    }
}

impl<T: ContentRef, L: MembershipListener<T>> Verifiable for Group<T, L> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.state.verifying_key()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupArchive<T: ContentRef> {
    pub(crate) individual: Individual,
    pub(crate) members: HashMap<Identifier, NonEmpty<Digest<Signed<StaticDelegation<T>>>>>,
    pub(crate) state: GroupStateArchive<T>,
}

impl<T: ContentRef, L: MembershipListener<T>> From<Group<T, L>> for GroupArchive<T> {
    fn from(group: Group<T, L>) -> Self {
        GroupArchive {
            individual: group.individual.clone(),
            members: group
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
            state: GroupStateArchive::<T>::from(&group.state),
        }
    }
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
    AddCgkaMemberError(#[from] AddCgkaMemberError),
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
    use super::*;

    use super::delegation::Delegation;
    use crate::principal::active::Active;
    use nonempty::nonempty;
    use pretty_assertions::assert_eq;
    use std::cell::RefCell;

    fn setup_user(csprng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Active {
        let sk = ed25519_dalek::SigningKey::generate(csprng);
        Active::generate(sk, NoListener, csprng).unwrap()
    }

    fn setup_groups<T: ContentRef>(
        alice: Rc<RefCell<Active>>,
        bob: Rc<RefCell<Active>>,
        csprng: &mut (impl rand::CryptoRng + rand::RngCore),
    ) -> [Rc<RefCell<Group<T>>>; 4] {
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

        let alice_agent: Agent<T> = alice.into();
        let bob_agent = bob.into();

        let dlg_store = DelegationStore::new();
        let rev_store = RevocationStore::new();

        let g0 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![alice_agent.dupe()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng,
            )
            .unwrap(),
        ));

        let g1 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![alice_agent, g0.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng,
            )
            .unwrap(),
        ));

        let g2 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![bob_agent, g1.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng,
            )
            .unwrap(),
        ));

        let g3 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![g1.clone().into(), g2.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng,
            )
            .unwrap(),
        ));

        [g0, g1, g2, g3]
    }

    fn setup_cyclic_groups<T: ContentRef, R: rand::CryptoRng + rand::RngCore>(
        alice: Rc<RefCell<Active>>,
        bob: Rc<RefCell<Active>>,
        csprng: &mut R,
    ) -> [Rc<RefCell<Group<T>>>; 10] {
        let dlg_store = DelegationStore::new();
        let rev_store = RevocationStore::new();

        let group0 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![alice.dupe().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng,
            )
            .unwrap(),
        ));

        let group1 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![bob.into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng,
            )
            .unwrap(),
        ));

        let group2 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![group1.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng,
            )
            .unwrap(),
        ));

        let group3 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![group2.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng,
            )
            .unwrap(),
        ));

        let group4 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![group3.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng,
            )
            .unwrap(),
        ));

        let group5 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![group4.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng,
            )
            .unwrap(),
        ));

        let group6 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![group5.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng,
            )
            .unwrap(),
        ));

        let group7 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![group6.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng,
            )
            .unwrap(),
        ));

        let group8 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![group7.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng,
            )
            .unwrap(),
        ));

        let group9 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![group8.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                csprng,
            )
            .unwrap(),
        ));

        let proof = group0
            .borrow()
            .get_capability(&alice.borrow().id().into())
            .unwrap()
            .dupe();

        group0
            .borrow_mut()
            .receive_delegation(Rc::new(
                Signed::try_sign(
                    Delegation {
                        delegate: group9.clone().into(),
                        can: Access::Admin,
                        proof: Some(proof),
                        after_revocations: vec![],
                        after_content: BTreeMap::new(),
                    },
                    &alice.borrow().signing_key,
                )
                .unwrap(),
            ))
            .unwrap();

        [
            group0, group1, group2, group3, group4, group5, group6, group7, group8, group9,
        ]
    }

    #[test]
    fn test_transitive_self() {
        let csprng = &mut rand::thread_rng();

        let alice = Rc::new(RefCell::new(setup_user(csprng)));
        let alice_agent: Agent<String> = alice.dupe().into();
        let alice_id = alice_agent.id();

        let bob = Rc::new(RefCell::new(setup_user(csprng)));

        let [g0, ..]: [Rc<RefCell<Group<String>>>; 4] = setup_groups(alice.dupe(), bob, csprng);
        let g0_mems = g0.borrow().transitive_members();

        let expected = HashMap::from_iter([(alice_id, (alice.dupe().into(), Access::Admin))]);

        assert_eq!(g0_mems, expected);
    }

    #[test]
    fn test_transitive_one() {
        let csprng = &mut rand::thread_rng();

        let alice = Rc::new(RefCell::new(setup_user(csprng)));
        let alice_agent: Agent<String> = alice.dupe().into();
        let alice_id = alice_agent.id();

        let bob = Rc::new(RefCell::new(setup_user(csprng)));

        let [g0, g1, ..] = setup_groups(alice.dupe(), bob, csprng);
        let g1_mems = g1.borrow().transitive_members();

        assert_eq!(
            g1_mems,
            HashMap::from_iter([
                (
                    alice_id,
                    (Agent::<String>::from(alice.dupe()), Access::Admin)
                ),
                (
                    g0.borrow().id(),
                    (Agent::<String>::from(g0.dupe()), Access::Admin)
                )
            ])
        );
    }

    #[test]
    fn test_transitive_two() {
        let csprng = &mut rand::thread_rng();

        let alice = Rc::new(RefCell::new(setup_user(csprng)));
        let alice_agent: Agent<String> = alice.dupe().into();
        let alice_id = alice_agent.id();

        let bob = Rc::new(RefCell::new(setup_user(csprng)));
        let bob_agent: Agent<String> = bob.dupe().into();
        let bob_id = bob_agent.id();

        let [g0, g1, g2, _g3]: [Rc<RefCell<Group<String>>>; 4] =
            setup_groups(alice.dupe(), bob.dupe(), csprng);
        let g1_mems = g2.borrow().transitive_members();

        assert_eq!(
            g1_mems,
            HashMap::from_iter([
                (alice_id, (alice.into(), Access::Admin)),
                (bob_id, (bob.into(), Access::Admin)),
                (g0.borrow().id(), (g0.dupe().into(), Access::Admin)),
                (g1.borrow().id(), (g1.dupe().into(), Access::Admin)),
            ])
        );
    }

    #[test]
    fn test_transitive_three() {
        let csprng = &mut rand::thread_rng();

        let alice = Rc::new(RefCell::new(setup_user(csprng)));
        let alice_agent: Agent<String> = alice.dupe().into();
        let alice_id = alice_agent.id();

        let bob = Rc::new(RefCell::new(setup_user(csprng)));
        let bob_agent: Agent<String> = bob.dupe().into();
        let bob_id = bob_agent.id();

        let [g0, g1, g2, g3]: [Rc<RefCell<Group<String>>>; 4] =
            setup_groups(alice.dupe(), bob.dupe(), csprng);
        let g3_mems = g3.borrow().transitive_members();

        assert_eq!(g3_mems.len(), 5);

        assert_eq!(
            g3_mems.keys().collect::<std::collections::HashSet<_>>(),
            HashSet::from_iter([
                &alice_id,
                &bob_id,
                &g0.borrow().id(),
                &g1.borrow().id(),
                &g2.borrow().id(),
            ])
        );
    }

    #[test]
    fn test_transitive_cycles() {
        let csprng = &mut rand::thread_rng();

        let alice = Rc::new(RefCell::new(setup_user(csprng)));
        let alice_agent: Agent<String> = alice.dupe().into();
        let alice_id = alice_agent.id();

        let bob = Rc::new(RefCell::new(setup_user(csprng)));
        let bob_agent: Agent<String> = bob.dupe().into();
        let bob_id = bob_agent.id();

        let [g0, g1, g2, g3, g4, g5, g6, g7, g8, g9]: [Rc<RefCell<Group<String>>>; 10] =
            setup_cyclic_groups(alice.dupe(), bob.dupe(), csprng);
        let g0_mems = g0.borrow().transitive_members();

        assert_eq!(g0_mems.len(), 11);

        assert_eq!(
            g0_mems,
            HashMap::from_iter([
                (alice_id, (alice.into(), Access::Admin)),
                (bob_id, (bob.into(), Access::Admin)),
                (g1.borrow().id(), (g1.dupe().into(), Access::Admin)),
                (g2.borrow().id(), (g2.dupe().into(), Access::Admin)),
                (g3.borrow().id(), (g3.dupe().into(), Access::Admin)),
                (g4.borrow().id(), (g4.dupe().into(), Access::Admin)),
                (g5.borrow().id(), (g5.dupe().into(), Access::Admin)),
                (g6.borrow().id(), (g6.dupe().into(), Access::Admin)),
                (g7.borrow().id(), (g7.dupe().into(), Access::Admin)),
                (g8.borrow().id(), (g8.dupe().into(), Access::Admin)),
                (g9.borrow().id(), (g9.dupe().into(), Access::Admin)),
            ])
        );
    }

    #[test]
    fn test_add_member() {
        let mut csprng = rand::thread_rng();

        let alice = Rc::new(RefCell::new(setup_user(&mut csprng)));
        let alice_agent: Agent = alice.dupe().into();

        let bob = Rc::new(RefCell::new(setup_user(&mut csprng)));
        let bob_agent: Agent = bob.dupe().into();

        let carol = Rc::new(RefCell::new(setup_user(&mut csprng)));
        let carol_agent: Agent = carol.dupe().into();

        let signer = ed25519_dalek::SigningKey::generate(&mut csprng);
        let active = Rc::new(RefCell::new(
            Active::generate(signer, NoListener, &mut csprng).unwrap(),
        ));

        let dlg_store = DelegationStore::new();
        let rev_store = RevocationStore::new();

        let g0 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![active.dupe().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                &mut csprng,
            )
            .unwrap(),
        ));

        let g1 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![alice_agent.dupe(), bob_agent.dupe(), g0.dupe().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                &mut csprng,
            )
            .unwrap(),
        ));

        let g2 = Rc::new(RefCell::new(
            Group::generate(
                nonempty![g1.dupe().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                NoListener,
                &mut csprng,
            )
            .unwrap(),
        ));

        g0.borrow_mut()
            .add_member(
                carol_agent.dupe(),
                Access::Write,
                &active.borrow().signing_key,
                &[],
            )
            .unwrap();

        // FIXME trasnitive add
        // g2.borrow_mut()
        //     .add_member(
        //         carol_agent.dupe(),
        //         Access::Read,
        //         active.borrow().signing_key.clone(),
        //         &[],
        //     )
        //     .unwrap();

        let g0_mems = g0.borrow().transitive_members();

        assert_eq!(g0_mems.len(), 2);

        assert_eq!(
            g0_mems.get(&active.dupe().borrow().id().into()),
            Some(&(active.dupe().into(), Access::Admin))
        );

        assert_eq!(
            g0_mems.get(&carol_agent.id()),
            Some(&(carol.clone().into(), Access::Write)) // NOTE: non-admin!
        );

        let g2_mems = g2.borrow().transitive_members();

        assert_eq!(
            g2_mems.get(&alice_agent.id()),
            Some(&(alice.into(), Access::Admin))
        );

        assert_eq!(
            g2_mems.get(&bob_agent.id()),
            Some(&(bob.into(), Access::Admin))
        );

        assert_eq!(
            g2_mems.get(&carol_agent.id()),
            Some(&(carol.into(), Access::Write)) // NOTE: non-admin!
        );

        assert_eq!(
            g2_mems.get(&g0.borrow().id()),
            Some(&(g0.dupe().into(), Access::Admin))
        );

        assert_eq!(
            g2_mems.get(&g1.borrow().id()),
            Some(&(g1.dupe().into(), Access::Admin))
        );

        assert_eq!(g2_mems.len(), 6);
    }

    #[test]
    fn test_revoke_member() {
        let mut csprng = rand::thread_rng();

        let alice = Rc::new(RefCell::new(setup_user(&mut csprng)));
        let alice_agent: Agent = alice.dupe().into();

        let bob = Rc::new(RefCell::new(setup_user(&mut csprng)));
        let bob_agent: Agent = bob.dupe().into();

        let carol = Rc::new(RefCell::new(setup_user(&mut csprng)));
        let carol_agent: Agent = carol.dupe().into();

        let dan = Rc::new(RefCell::new(setup_user(&mut csprng)));
        let dan_agent: Agent = dan.dupe().into();

        let dlg_store = DelegationStore::new();
        let rev_store = RevocationStore::new();

        let mut g1 = Group::generate(
            nonempty![alice_agent.dupe()],
            dlg_store.dupe(),
            rev_store.dupe(),
            NoListener,
            &mut csprng,
        )
        .unwrap();

        g1.add_member(
            bob_agent.dupe(),
            Access::Write,
            &alice.borrow().signing_key,
            &[],
        )
        .unwrap();

        g1.add_member(
            carol_agent.dupe(),
            Access::Read,
            &bob.borrow().signing_key,
            &[],
        )
        .unwrap();

        dbg!(alice.borrow().id());
        dbg!(bob.borrow().id());
        dbg!(carol.borrow().id());
        dbg!(dan.borrow().id());

        assert!(g1.members().contains_key(&alice.borrow().id().into()));
        assert!(g1.members().contains_key(&bob.borrow().id().into()));
        assert!(g1.members().contains_key(&carol.borrow().id().into()));
        assert!(!g1.members().contains_key(&dan.borrow().id().into()));

        g1.add_member(
            dan_agent.dupe(),
            Access::Read,
            &carol.borrow().signing_key,
            &[],
        )
        .unwrap();

        assert!(g1.members.contains_key(&alice.borrow().id().into()));
        assert!(g1.members.contains_key(&bob.borrow().id().into()));
        assert!(g1.members.contains_key(&carol.borrow().id().into()));
        assert!(g1.members.contains_key(&dan.borrow().id().into()));
        assert_eq!(g1.members.len(), 4);

        g1.revoke_member(
            bob.borrow().id().into(),
            true,
            &alice.borrow().signing_key,
            &BTreeMap::new(),
        )
        .unwrap();

        // Bob kicked out
        assert!(!g1.members.contains_key(&bob.borrow().id().into()));
        // Retained Carol & Dan
        assert!(g1.members.contains_key(&carol.borrow().id().into()));
        assert!(g1.members.contains_key(&dan.borrow().id().into()));

        // g1.add_member(
        //     bob_agent.dupe(),
        //     Access::Read,
        //     &carol.borrow().signing_key,
        //     &[],
        // )
        // .unwrap();

        // assert!(g1.members.contains_key(&bob.borrow().id().into()));
        // assert!(g1.members.contains_key(&carol.borrow().id().into()));
        // assert!(g1.members.contains_key(&dan.borrow().id().into()));

        // g1.revoke_member(
        //     carol.borrow().id().into(),
        //     false,
        //     &alice.borrow().signing_key,
        //     &BTreeMap::new(),
        // )
        // .unwrap();

        // // Dropped Carol, but not Dan because Dan is no longer connected to Carol
        // assert!(!g1.members.contains_key(&carol.borrow().id().into()));
        // assert!(g1.members.contains_key(&dan.borrow().id().into()));

        // dbg!("********************");
        // dbg!("********************");
        // dbg!("********************");
        // dbg!("********************");
        // dbg!("********************");
        // dbg!("********************");
        // dbg!("********************");

        // g1.revoke_member(
        //     alice.borrow().id().into(),
        //     false,
        //     &alice.borrow().signing_key,
        //     &BTreeMap::new(),
        // )
        // .unwrap();

        // assert!(!g1.members.contains_key(&alice.borrow().id().into()));

        // dbg!(Identifier::from(g1.id()));
        // dbg!(Identifier::from(alice.borrow().verifying_key()));
        // dbg!(Identifier::from(bob.borrow().verifying_key()));
        // dbg!(Identifier::from(carol.borrow().verifying_key()));
        // dbg!(Identifier::from(dan.borrow().verifying_key()));

        // dbg!("");

        // if let Some(dlgs) = g1.members.get(&carol.borrow().id().into()) {
        //     for d in dlgs.iter() {
        //         if d.issuer == alice.borrow().verifying_key() {
        //             dbg!("1: BOOM BOOM BOOM");
        //         }
        //         dbg!(Identifier::from(d.issuer));
        //     }
        // }

        // assert!(!g1.members.contains_key(&carol.borrow().id().into()));

        // if let Some(dlgs) = g1.members.get(&dan.borrow().id().into()) {
        //     for d in dlgs.iter() {
        //         dbg!("2: BOOM BOOM BOOM");
        //         dbg!("asdfgh");
        //         dbg!(Identifier::from(d.issuer));
        //     }
        // }

        // assert!(!g1.members.contains_key(&dan.borrow().id().into()));
    }
}
