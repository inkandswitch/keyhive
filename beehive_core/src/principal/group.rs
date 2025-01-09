//! Model a collection of agents with no associated content.

pub mod error;
pub mod id;
pub mod operation;
pub mod state;
pub mod store;

use super::{
    agent::{id::AgentId, signer::AgentSigner, Agent},
    document::{id::DocumentId, Document},
    identifier::Identifier,
    individual::{id::IndividualId, Individual},
    verifiable::Verifiable,
};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        share_key::ShareKey,
        signed::{Signed, SigningError},
    },
    util::content_addressed_map::CaMap,
};
use dupe::{Dupe, IterDupedExt};
use id::GroupId;
use nonempty::NonEmpty;
use operation::{delegation::Delegation, revocation::Revocation, Operation};
use serde::{ser::SerializeStruct, Serialize, Serializer};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet},
    rc::Rc,
};
use thiserror::Error;

/// A collection of agents with no associated content.
///
/// Groups are stateful agents. It is possible the delegate control over them,
/// and they can be delegated to. This produces transitives lines of authority
/// through the network of [`Agent`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group<T: ContentRef> {
    /// The current view of members of a group.
    pub(crate) members: HashMap<AgentId, Vec<Rc<Signed<Delegation<T>>>>>,

    /// The `Group`'s underlying (causal) delegation state.
    pub(crate) state: state::GroupState<T>,
}

impl<T: ContentRef> Group<T> {
    pub fn new(
        head: Signed<Delegation<T>>,
        delegations: Rc<RefCell<CaMap<Signed<Delegation<T>>>>>,
        revocations: Rc<RefCell<CaMap<Signed<Revocation<T>>>>>,
    ) -> Self {
        let mut group = Self {
            members: HashMap::new(),
            state: state::GroupState::new(head, delegations, revocations),
        };
        group.rebuild();
        group
    }

    /// Generate a new `Group` with a unique [`Identifier`] and the given `parents`.
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(
        parents: NonEmpty<Agent<T>>,
        delegations: Rc<RefCell<CaMap<Signed<Delegation<T>>>>>,
        revocations: Rc<RefCell<CaMap<Signed<Revocation<T>>>>>,
        csprng: &mut R,
    ) -> Result<Group<T>, SigningError> {
        let sk = ed25519_dalek::SigningKey::generate(csprng);
        let group_signer = AgentSigner::group_signer_from_key(sk);
        let group_id = GroupId(group_signer.verifying_key().into());

        let mut delegation_heads = CaMap::new();
        let mut members = HashMap::new();

        parents.iter().try_fold((), |_, parent| {
            let dlg = Signed::try_sign(
                Delegation {
                    delegate: parent.dupe(),
                    can: Access::Admin,
                    proof: None,
                    after_revocations: vec![],
                    after_content: BTreeMap::new(),
                },
                &group_signer,
            )?;

            let rc = Rc::new(dlg);
            delegations.borrow_mut().insert(rc.dupe());
            delegation_heads.insert(rc.dupe());
            members.insert((*parent).agent_id(), vec![rc]);

            Ok::<(), SigningError>(())
        })?;

        Ok(Group {
            members,
            state: state::GroupState {
                id: group_id,

                delegation_heads,
                delegations,

                revocation_heads: CaMap::new(),
                revocations,
            },
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
        let mut ids = HashSet::new();
        for delegations in self.members.values() {
            ids.extend(&delegations[0].payload().delegate.individual_ids())
        }
        ids
    }

    pub fn pick_individual_prekeys(&self, doc_id: DocumentId) -> HashMap<IndividualId, ShareKey> {
        let mut m = HashMap::new();
        for delegations in self.members.values() {
            m.extend(
                &delegations[0]
                    .payload()
                    .delegate
                    .pick_individual_prekeys(doc_id),
            );
        }
        m
    }

    pub fn members(&self) -> &HashMap<AgentId, Vec<Rc<Signed<Delegation<T>>>>> {
        &self.members
    }

    pub fn delegation_heads(&self) -> &CaMap<Signed<Delegation<T>>> {
        &self.state.delegation_heads
    }

    pub fn get_capability(&self, member_id: &AgentId) -> Option<&Rc<Signed<Delegation<T>>>> {
        self.members.get(member_id).and_then(|delegations| {
            delegations
                .iter()
                .max_by(|d1, d2| d1.payload().can.cmp(&d2.payload().can))
        })
    }

    pub fn get_agent_revocations(&self, agent: &Agent<T>) -> Vec<Rc<Signed<Revocation<T>>>> {
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
        delegation: Rc<Signed<Delegation<T>>>,
    ) -> Result<Digest<Signed<Delegation<T>>>, error::AddError> {
        let digest = self.state.add_delegation(delegation)?;
        self.rebuild();
        Ok(digest)
    }

    pub fn receive_revocation(
        &mut self,
        revocation: Rc<Signed<Revocation<T>>>,
    ) -> Result<Digest<Signed<Revocation<T>>>, error::AddError> {
        let digest = self.state.add_revocation(revocation)?;
        self.rebuild();
        Ok(digest)
    }

    pub fn add_member(
        &mut self,
        member_to_add: Agent<T>,
        can: Access,
        signing_key: ed25519_dalek::SigningKey,
        relevant_docs: &[&Rc<RefCell<Document<T>>>],
    ) -> Result<Rc<Signed<Delegation<T>>>, AddMemberError> {
        let indie: Individual = signing_key.verifying_key().into();
        let agent: Agent<T> = indie.into();

        let proof = if self.verifying_key() == signing_key.verifying_key() {
            None
        } else {
            let p = self
                .get_capability(&agent.agent_id())
                .ok_or(AddMemberError::NoProof)?;

            if can > p.payload().can {
                return Err(AddMemberError::AccessEscalation {
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
                after_content: relevant_docs
                    .iter()
                    .map(|d| {
                        (
                            d.borrow().doc_id(),
                            d.borrow().content_heads.iter().cloned().collect::<Vec<_>>(),
                        )
                    })
                    .collect(),
            },
            &AgentSigner::group_signer_from_key(signing_key),
        )?;

        let rc = Rc::new(delegation);
        let _digest = self.receive_delegation(rc.dupe())?;
        Ok(rc)
    }

    pub fn revoke_member(
        &mut self,
        member_to_remove: AgentId,
        signer: AgentSigner,
        after_content: &BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<Vec<Rc<Signed<Revocation<T>>>>, RevokeMemberError> {
        let agent_id = AgentId::from(signer.clone());
        let signer_id = signer.id();
        let mut revocations = vec![];

        let all_to_revoke: Vec<Rc<Signed<Delegation<T>>>> = self
            .members()
            .get(&member_to_remove)
            .cloned() // Relatively cheap since it's &Vec<Rc<_>>
            .unwrap_or_default();

        if all_to_revoke.is_empty() {
            self.members.remove(&member_to_remove);
            return Ok(vec![]);
        }

        if agent_id == self.agent_id() {
            // In the unlikely case that the group signing key still exists and is doing the revocation.
            // Arguably this could be made impossible, but it would likely be surprising behaviour.
            for to_revoke in all_to_revoke.iter() {
                let r = self.build_revocation(
                    signer.dupe(),
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

                if let Some(member_dlgs) = self.members().get(&agent_id) {
                    for mem_dlg in member_dlgs.clone().iter() {
                        if mem_dlg.payload().can == Access::Admin {
                            // Use your awesome & terrible admin powers!
                            //
                            // NOTE we don't do admin revocation cycle checking here for a few reasons:
                            // 1. Unknown to you, the cycle may be broken with some other revocation
                            // 2. It all gets resolved at materialization time
                            let r = self.build_revocation(
                                signer.dupe(),
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

                // "Double up" even if you're an admin in case you get concurrently demoted.
                // We include the admin proofs as well since those could also get revoked.

                if to_revoke.signed_by == signer_id {
                    found = true;
                    revocations.push(self.build_revocation(
                        signer.dupe(),
                        to_revoke.dupe(),
                        Some(to_revoke.dupe()),
                        after_content.clone(),
                    )?);
                } else {
                    for ancestor in to_revoke.payload().proof_lineage() {
                        if ancestor.signed_by == signer_id {
                            found = true;
                            let r = self.build_revocation(
                                signer.dupe(),
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

        Ok(revocations)
    }

    fn build_revocation(
        &mut self,
        signer: AgentSigner,
        revoke: Rc<Signed<Delegation<T>>>,
        proof: Option<Rc<Signed<Delegation<T>>>>,
        after_content: BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<Rc<Signed<Revocation<T>>>, SigningError> {
        let revocation = Signed::try_sign(
            Revocation {
                revoke,
                proof,
                after_content,
            },
            &signer.dupe(),
        )?;

        Ok(Rc::new(revocation))
    }

    pub fn rebuild(&mut self) {
        for (_, op) in
            Operation::topsort(&self.state.delegation_heads, &self.state.revocation_heads).iter()
        {
            match op {
                Operation::Delegation(d) => {
                    // FIXME check for escelation
                    if let Some(mut_dlgs) = self.members.get_mut(&d.payload().delegate.agent_id()) {
                        mut_dlgs.push(d.dupe());
                    } else {
                        self.members
                            .insert(d.payload().delegate.agent_id(), vec![d.dupe()]);
                    }
                }
                Operation::Revocation(r) => {
                    if let Some(mut_dlgs) = self
                        .members
                        .get_mut(&r.payload().revoke.payload().delegate.agent_id())
                    {
                        // FIXME OOOOOR is an admin
                        // FIXME maintain this as a CaMap for easier removals, too
                        mut_dlgs.retain(|d| *d != r.payload().revoke);
                    }
                }
            }
        }
    }
}

impl<T: ContentRef> Verifiable for Group<T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.state.verifying_key()
    }
}

// FIXME test and consistent order
impl<T: ContentRef> std::hash::Hash for Group<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for m in self.members.iter() {
            m.hash(state);
        }
        self.state.hash(state);
    }
}

impl<T: ContentRef> Serialize for Group<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let members = self
            .members
            .iter()
            .map(|(k, v)| (k, v.len()))
            .collect::<HashMap<_, _>>();

        let mut state = serializer.serialize_struct("Group", 2)?;
        state.serialize_field("members", &members)?;
        state.serialize_field("state", &self.state)?;
        state.end()
    }
}

#[derive(Debug, Error)]
pub enum AddMemberError {
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

    use super::{operation::delegation::Delegation, store::GroupStore};
    use crate::principal::active::Active;
    use nonempty::nonempty;
    use std::cell::RefCell;

    fn setup_user(csprng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Active {
        let sk = ed25519_dalek::SigningKey::generate(csprng);
        Active::generate(sk, csprng).unwrap()
    }

    fn setup_groups<T: ContentRef>(
        store: &mut GroupStore<T>,
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

        let dlg_store = Rc::new(RefCell::new(CaMap::new()));
        let rev_store = Rc::new(RefCell::new(CaMap::new()));

        let g0 = store
            .generate_group(
                nonempty![alice_agent.dupe()],
                dlg_store.dupe(),
                rev_store.dupe(),
                csprng,
            )
            .unwrap();

        let g1 = store
            .generate_group(
                nonempty![alice_agent, g0.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                csprng,
            )
            .unwrap();

        let g2 = store
            .generate_group(
                nonempty![bob_agent, g1.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                csprng,
            )
            .unwrap();

        let g3 = store
            .generate_group(
                nonempty![g1.clone().into(), g2.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                csprng,
            )
            .unwrap();

        [g0, g1, g2, g3]
    }

    fn setup_cyclic_groups<T: ContentRef, R: rand::CryptoRng + rand::RngCore>(
        gs: &mut GroupStore<T>,
        alice: Rc<RefCell<Active>>,
        bob: Rc<RefCell<Active>>,
        csprng: &mut R,
    ) -> [Rc<RefCell<Group<T>>>; 10] {
        let dlg_store = Rc::new(RefCell::new(CaMap::new()));
        let rev_store = Rc::new(RefCell::new(CaMap::new()));

        let group0 = gs
            .generate_group(
                nonempty![alice.dupe().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                csprng,
            )
            .unwrap();

        let group1 = gs
            .generate_group(
                nonempty![bob.into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                csprng,
            )
            .unwrap();

        let group2 = gs
            .generate_group(
                nonempty![group1.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                csprng,
            )
            .unwrap();

        let group3 = gs
            .generate_group(
                nonempty![group2.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                csprng,
            )
            .unwrap();

        let group4 = gs
            .generate_group(
                nonempty![group3.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                csprng,
            )
            .unwrap();

        let group5 = gs
            .generate_group(
                nonempty![group4.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                csprng,
            )
            .unwrap();

        let group6 = gs
            .generate_group(
                nonempty![group5.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                csprng,
            )
            .unwrap();

        let group7 = gs
            .generate_group(
                nonempty![group6.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                csprng,
            )
            .unwrap();

        let group8 = gs
            .generate_group(
                nonempty![group7.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                csprng,
            )
            .unwrap();

        let group9 = gs
            .generate_group(
                nonempty![group8.clone().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                csprng,
            )
            .unwrap();

        let proof = group0
            .borrow()
            .get_capability(&alice.borrow().agent_id())
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
                    &alice.borrow().signer(),
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
        let alice_id = alice_agent.agent_id();

        let bob = Rc::new(RefCell::new(setup_user(csprng)));

        let mut gs: GroupStore<String> = GroupStore::new();
        let [g0, ..] = setup_groups(&mut gs, alice.clone(), bob, csprng);

        let g0_mems = gs.transitive_members(&g0.dupe().as_ref().clone().into_inner());

        assert_eq!(
            g0_mems,
            BTreeMap::from_iter([(alice_id, (alice.into(), Access::Admin))])
        );
    }

    #[test]
    fn test_transitive_one() {
        let csprng = &mut rand::thread_rng();

        let alice = Rc::new(RefCell::new(setup_user(csprng)));
        let alice_agent: Agent<String> = alice.dupe().into();
        let alice_id = alice_agent.agent_id();

        let bob = Rc::new(RefCell::new(setup_user(csprng)));

        let mut gs: GroupStore<String> = GroupStore::new();

        let [_g0, g1, _g2, _g3] = setup_groups(&mut gs, alice.dupe(), bob, csprng);
        let g1_mems = gs.transitive_members(&g1.borrow());

        assert_eq!(
            g1_mems,
            BTreeMap::from_iter([(alice_id, (alice.clone().into(), Access::Admin))])
        );
    }

    #[test]
    fn test_transitive_two() {
        let csprng = &mut rand::thread_rng();

        let alice = Rc::new(RefCell::new(setup_user(csprng)));
        let alice_agent: Agent<String> = alice.dupe().into();
        let alice_id = alice_agent.agent_id();

        let bob = Rc::new(RefCell::new(setup_user(csprng)));
        let bob_agent: Agent<String> = bob.dupe().into();
        let bob_id = bob_agent.agent_id();

        let mut gs: GroupStore<String> = GroupStore::new();

        let [_g0, _g1, g2, _g3] = setup_groups(&mut gs, alice.dupe(), bob.dupe(), csprng);
        let g1_mems = gs.transitive_members(&g2.borrow());

        assert_eq!(
            g1_mems,
            BTreeMap::from_iter([
                (alice_id, (alice.into(), Access::Admin)),
                (bob_id, (bob.into(), Access::Admin))
            ])
        );
    }

    #[test]
    fn test_transitive_three() {
        let csprng = &mut rand::thread_rng();

        let alice = Rc::new(RefCell::new(setup_user(csprng)));
        let alice_agent: Agent<String> = alice.dupe().into();
        let alice_id = alice_agent.agent_id();

        let bob = Rc::new(RefCell::new(setup_user(csprng)));
        let bob_agent: Agent<String> = bob.dupe().into();
        let bob_id = bob_agent.agent_id();

        let mut gs: GroupStore<String> = GroupStore::new();

        let [_g0, _g1, _g2, g3] = setup_groups(&mut gs, alice.dupe(), bob.dupe(), csprng);
        let g1_mems = gs.transitive_members(&g3.borrow());

        assert_eq!(
            g1_mems,
            BTreeMap::from_iter([
                (alice_id, (alice.into(), Access::Admin)),
                (bob_id, (bob.into(), Access::Admin))
            ])
        );
    }

    #[test]
    fn test_transitive_cycles() {
        let csprng = &mut rand::thread_rng();

        let alice = Rc::new(RefCell::new(setup_user(csprng)));
        let alice_agent: Agent<String> = alice.dupe().into();
        let alice_id = alice_agent.agent_id();

        let bob = Rc::new(RefCell::new(setup_user(csprng)));
        let bob_agent: Agent<String> = bob.dupe().into();
        let bob_id = bob_agent.agent_id();

        let mut gs: GroupStore<String> = GroupStore::new();

        let [g0, ..] = setup_cyclic_groups(&mut gs, alice.dupe(), bob.dupe(), csprng);
        let g1_mems = gs.transitive_members(&g0.borrow());

        assert_eq!(
            g1_mems,
            BTreeMap::from_iter([
                (alice_id, (alice.into(), Access::Admin)),
                (bob_id, (bob.into(), Access::Admin))
            ])
        );
    }

    #[test]
    fn test_add_member() {
        let csprng = &mut rand::thread_rng();

        let alice = Rc::new(RefCell::new(setup_user(csprng)));
        let alice_agent: Agent<String> = alice.dupe().into();

        let bob = Rc::new(RefCell::new(setup_user(csprng)));
        let bob_agent: Agent<String> = bob.dupe().into();

        let carol = Rc::new(RefCell::new(setup_user(csprng)));
        let carol_agent: Agent<String> = carol.dupe().into();

        let signer = ed25519_dalek::SigningKey::generate(csprng);
        let active = Rc::new(RefCell::new(Active::generate(signer, csprng).unwrap()));
        let active_agent: Agent<String> = active.dupe().into();

        let dlg_store = Rc::new(RefCell::new(CaMap::new()));
        let rev_store = Rc::new(RefCell::new(CaMap::new()));
        let mut csprng = rand::thread_rng();

        let mut gs: GroupStore<String> = GroupStore::new();

        let g0 = gs
            .generate_group(
                nonempty![active.dupe().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                &mut csprng,
            )
            .unwrap();

        let g1 = gs
            .generate_group(
                nonempty![alice_agent.dupe(), bob_agent.dupe(), g0.dupe().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                &mut csprng,
            )
            .unwrap();

        let g2 = gs
            .generate_group(
                nonempty![carol_agent.dupe(), g1.dupe().into()],
                dlg_store.dupe(),
                rev_store.dupe(),
                &mut csprng,
            )
            .unwrap();

        g0.borrow_mut()
            .add_member(
                carol_agent.dupe(),
                Access::Write,
                active.borrow().signing_key.clone(),
                &[],
            )
            .unwrap();

        gs.insert(g0.clone().into());
        let g0_mems = gs.transitive_members(&g0.borrow());

        assert_eq!(g0_mems.len(), 2);

        assert_eq!(
            g0_mems.get(&active.dupe().borrow().agent_id()),
            Some(&(active.dupe().into(), Access::Admin))
        );

        assert_eq!(
            g0_mems.get(&carol_agent.agent_id()),
            Some(&(carol.clone().into(), Access::Write))
        );

        let g2_mems = gs.transitive_members(&g2.borrow());

        assert_eq!(g2_mems.len(), 4);

        assert_eq!(
            g2_mems.get(&active_agent.agent_id()),
            Some(&(active.into(), Access::Admin))
        );

        assert_eq!(
            g2_mems.get(&alice_agent.agent_id()),
            Some(&(alice.into(), Access::Admin))
        );

        assert_eq!(
            g2_mems.get(&bob_agent.agent_id()),
            Some(&(bob.into(), Access::Admin))
        );

        assert_eq!(
            g2_mems.get(&carol_agent.agent_id()),
            Some(&(carol.into(), Access::Admin))
        );
    }
}
