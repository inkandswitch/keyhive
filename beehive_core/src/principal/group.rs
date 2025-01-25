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
};
use super::{
    agent::{id::AgentId, Agent},
    document::{id::DocumentId, Document},
    identifier::Identifier,
    individual::{id::IndividualId, Individual},
    membered::Membered,
};
use crate::{
    access::Access,
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

    /// The `Group`'s underlying (causal) delegation state.
    pub(crate) state: state::GroupState<T, L>,

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
            state: state::GroupState::new(head, delegations, revocations),
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

        let mut delegation_heads = CaMap::new();
        let mut members = HashMap::new();

        let ds = delegations.dupe();
        let mut ds_mut = ds.borrow_mut();

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
            members.insert(parent.id(), nonempty![rc]);

            Ok::<(), SigningError>(())
        })?;

        let state = state::GroupState {
            id: group_id,

            delegation_heads,
            delegations,

            revocation_heads: CaMap::new(),
            revocations,
        };

        Ok(Group {
            individual: Individual::new(id.into()),
            members,
            state,
            listener,
        })
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

    // FIXME make note that the best way to do this is to add_deegation after get_capability
    pub fn add_member(
        &mut self,
        member_to_add: Agent<T, L>,
        can: Access,
        signing_key: &ed25519_dalek::SigningKey,
        relevant_docs: &[&Document<T, L>],
    ) -> Result<Rc<Signed<Delegation<T, L>>>, AddGroupMemberError> {
        let after_content = relevant_docs
            .iter()
            .map(|d| {
                (
                    d.doc_id(),
                    d.content_heads.iter().cloned().collect::<Vec<_>>(),
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
    ) -> Result<Rc<Signed<Delegation<T, L>>>, AddGroupMemberError> {
        let indie: Individual = signing_key.verifying_key().into();
        let agent: Agent<T, L> = indie.into();

        let proof = if self.verifying_key() == signing_key.verifying_key() {
            None
        } else {
            let p = self
                .get_capability(&agent.id())
                .ok_or(AddGroupMemberError::NoProof)?;

            if can > p.payload().can {
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
        Ok(rc)
    }

    #[allow(clippy::type_complexity)]
    pub fn revoke_member(
        &mut self,
        member_to_remove: Identifier,
        signing_key: &ed25519_dalek::SigningKey,
        after_content: &BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<Vec<Rc<Signed<Revocation<T, L>>>>, RevokeMemberError> {
        let vk = signing_key.verifying_key();
        let mut revocations = vec![];

        let all_to_revoke: Vec<Rc<Signed<Delegation<T, L>>>> = self
            .members()
            .get(&member_to_remove)
            .map(|ne| Vec::<_>::from(ne.clone())) // Semi-inexpensive because `Vec<Rc<_>>`
            .unwrap_or_default();

        if all_to_revoke.is_empty() {
            self.members.remove(&member_to_remove);
            return Ok(vec![]);
        }

        if vk == self.verifying_key() {
            // In the unlikely case that the group signing key still exists and is doing the revocation.
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

        Ok(revocations)
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
        let mut stateful_revocations = HashSet::new();

        for (_, op) in
            MembershipOperation::topsort(&self.state.delegation_heads, &self.state.revocation_heads)
                .iter()
        {
            match op {
                MembershipOperation::Delegation(d) => {
                    if stateful_revocations.contains(&d.signature.to_bytes()) {
                        continue;
                    }

                    if let Some(found_proof) = &d.payload.proof {
                        if let Some(issuer_proofs) = self.members.get(&found_proof.issuer.into()) {
                            if issuer_proofs.contains(found_proof) {
                                // Seems okay, so proceed as normal
                            } else {
                                // Proof not in the current state, so skip this one
                                continue;
                            }
                        } else if found_proof.issuer != self.verifying_key() {
                            continue;
                        };
                    } else if d.issuer != self.verifying_key() {
                        continue;
                    }

                    if let Some(mut_dlgs) = self.members.get_mut(&d.payload.delegate.id()) {
                        mut_dlgs.push(d.dupe());
                    } else {
                        self.members
                            .insert(d.payload().delegate.id(), nonempty![d.dupe()]);
                    }
                }
                MembershipOperation::Revocation(r) => {
                    if let Some(mut_dlgs) = self
                        .members
                        .get(&r.payload().revoke.payload().delegate.id())
                    {
                        if let Some(found_proof) = &r.payload().proof {
                            if let Some(issuer_proofs) =
                                self.members.get(&found_proof.issuer.into())
                            {
                                if !issuer_proofs.contains(found_proof) {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        }

                        stateful_revocations.insert(r.payload.revoked().signature.to_bytes());

                        // TODO maintain this as a CaMap for easier removals
                        let remaining =
                            mut_dlgs.clone().into_iter().fold(vec![], |mut acc, dlg| {
                                if dlg.signature == r.payload().revoke.signature {
                                    acc
                                } else {
                                    acc.push(dlg);
                                    acc
                                }
                            });

                        let id = r.payload().revoke.payload().delegate.id();
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
            state: state::GroupState::dummy_from_archive(archive.state, delegations, revocations),
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
    pub(crate) state: state::GroupStateArchive<T>,
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
            state: state::GroupStateArchive::<T>::from(&group.state),
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
}

#[derive(Debug, Error)]
pub enum RevokeMemberError {
    #[error(transparent)]
    AddError(#[from] error::AddError),

    #[error("Proof missing to authorize revocation")]
    NoProof,

    #[error(transparent)]
    SigningError(#[from] SigningError),
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
}
