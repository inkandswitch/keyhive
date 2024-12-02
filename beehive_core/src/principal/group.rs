//! Model a collection of agents with no associated content.

pub mod id;
pub mod operation;
pub mod state;
pub mod store;

use super::{
    agent::{Agent, AgentId},
    document::Document,
    identifier::Identifier,
    individual::{id::IndividualId, Individual},
    verifiable::Verifiable,
};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        share_key::ShareKey,
        signed::{Signed, SigningError, VerificationError},
    },
    util::content_addressed_map::CaMap,
};
use dupe::{Dupe, IterDupedExt};
use id::GroupId;
use nonempty::NonEmpty;
use operation::{delegation::Delegation, revocation::Revocation, AncestorError, Operation};
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
    /// Generate a new `Group` with a unique [`Identifier`] and the given `parents`.
    pub fn generate(parents: NonEmpty<Agent<T>>) -> Result<Group<T>, SigningError> {
        let group_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let group_id = GroupId(group_signer.verifying_key().into());

        let mut delegations = CaMap::new();
        let mut delegation_heads = HashSet::new();
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
            delegations.insert(rc.dupe());
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

                revocation_heads: HashSet::new(),
                revocations: CaMap::new(),
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

    pub fn pick_individual_prekeys<R: rand::CryptoRng + rand::RngCore>(
        &self,
        csprng: &mut R,
    ) -> HashMap<IndividualId, ShareKey> {
        let mut m = HashMap::new();
        for delegations in self.members.values() {
            m.extend(
                &delegations[0]
                    .payload()
                    .delegate
                    .pick_individual_prekeys(csprng),
            );
        }
        m
    }

    pub fn members(&self) -> &HashMap<AgentId, Vec<Rc<Signed<Delegation<T>>>>> {
        &self.members
    }

    pub fn delegations(&self) -> &CaMap<Signed<Delegation<T>>> {
        &self.state.delegations
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

    pub fn add_delegation(
        &mut self,
        signed_delegation: Signed<Delegation<T>>,
    ) -> Result<(), AddDelegationError> {
        signed_delegation.try_verify()?;
        if signed_delegation.subject() != self.group_id().into() {
            return Err(AddDelegationError::InvalidSubject);
        }

        let id = signed_delegation.payload().delegate.agent_id();
        let rc = Rc::new(signed_delegation);
        self.state.delegations.insert(rc.dupe());

        match self.members.get_mut(&id) {
            Some(caps) => {
                caps.push(rc);
            }
            None => {
                self.members.insert(id, vec![rc]);
            }
        }

        Ok(())
    }

    pub fn add_member(
        &mut self,
        member_to_add: Agent<T>,
        can: Access,
        signing_key: &ed25519_dalek::SigningKey,
        after_revocations: &[Rc<Signed<Revocation<T>>>],
        relevant_docs: &[Rc<RefCell<Document<T>>>],
    ) -> Result<(), AddMemberError> {
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
                after_revocations: after_revocations.iter().duped().collect(),
                after_content: relevant_docs
                    .iter()
                    .map(|d| {
                        (
                            d.borrow().doc_id(),
                            (
                                (*d).dupe(),
                                d.borrow()
                                    .content_heads
                                    .iter()
                                    .map(|c| (*c).clone())
                                    .collect(),
                            ),
                        )
                    })
                    .collect(),
            },
            &signing_key,
        )?;

        Ok(self.add_delegation(delegation)?)
    }

    pub fn revoke_member(
        &mut self,
        member_to_remove: AgentId,
        signing_key: &ed25519_dalek::SigningKey,
        relevant_docs: &[&Rc<RefCell<Document<T>>>], // TODO just lookup reachable docs directly
    ) -> Result<(), SigningError> {
        let revocations = &mut self.state.revocations;

        if let Some(revoke_dlgs) = self.members.remove(&member_to_remove) {
            revoke_dlgs.iter().try_fold((), |_, dlg| {
                let revocation = Signed::try_sign(
                    Revocation {
                        revoke: dlg.dupe(),
                        proof: None, // FIXME lookup a valid proof
                        after_content: relevant_docs
                            .iter()
                            .map(|d| {
                                (
                                    d.borrow().doc_id(),
                                    (
                                        (*d).dupe(),
                                        (*d).borrow()
                                            .content_heads
                                            .iter()
                                            .map(|c| (*c).clone())
                                            .collect(),
                                    ),
                                )
                            })
                            .collect(),
                    },
                    &signing_key,
                )?;

                revocations.insert(Rc::new(revocation));

                Ok(())
            })
        } else {
            Ok(())
        }

        // FIXME check that you can actually do this with tiebreaking, seniroity etc etc
    }

    pub fn materialize(&mut self) -> Result<(), AncestorError> {
        Ok(
            for (_, op) in
                Operation::topsort(&self.state.delegation_heads, &self.state.revocation_heads)?
                    .iter()
            {
                match op {
                    Operation::Delegation(d) => {
                        if let Some(mut_dlgs) =
                            self.members.get_mut(&d.payload().delegate.agent_id())
                        {
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
                            // FIXME maintain this as a CaMap for easier removals, too
                            mut_dlgs.retain(|d| *d != r.payload().revoke);
                        }
                    }
                }
            },
        )
    }

    pub fn add_revocation(
        &mut self,
        signed_revocation: Signed<Revocation<T>>,
    ) -> Result<(), state::AddError> {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        self.members.remove(
            &signed_revocation
                .payload()
                .revoke
                .payload()
                .delegate
                .agent_id(),
        );

        self.state.add_revocation(signed_revocation)
    }

    // pub fn add_member(&mut self, delegation: Signed<Delegation>) {
    //     FIXME check subject, signature, find dependencies or quarantine
    //     ...look at the quarantine and see if any of them depend on this one
    //     ...etc etc
    //     self.state.delegations.insert(delegation.into());
    //     todo!() // rebuild, later do IVM
    // }

    // pub fn revoke(&mut self, revocation: Signed<Revocation>) {
    //     self.state.revocations.insert(revocation.into());
    //     todo!() // rebuild, later do IVM
    // }
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
    AddDelegationError(#[from] AddDelegationError),
}

#[derive(Debug, Error)]
pub enum AddDelegationError {
    #[error(transparent)]
    VerificationError(#[from] VerificationError),

    #[error("Invalid subject")]
    InvalidSubject,
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::{operation::delegation::Delegation, store::GroupStore};
    use crate::principal::{active::Active, individual::Individual};
    use nonempty::nonempty;
    use std::cell::RefCell;

    fn setup_user() -> Individual {
        ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
            .verifying_key()
            .into()
    }

    fn setup_groups<T: ContentRef>(
        store: &mut GroupStore<T>,
        alice: Rc<RefCell<Individual>>,
        bob: Rc<RefCell<Individual>>,
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

        let g0 = store.generate_group(nonempty![alice_agent.dupe()]).unwrap();
        let g1 = store
            .generate_group(nonempty![alice_agent, g0.clone().into()])
            .unwrap();
        let g2 = store
            .generate_group(nonempty![bob_agent, g1.clone().into()])
            .unwrap();
        let g3 = store
            .generate_group(nonempty![g1.clone().into(), g2.clone().into()])
            .unwrap();

        [g0, g1, g2, g3]
    }

    fn setup_cyclic_groups<T: ContentRef, R: rand::CryptoRng + rand::RngCore>(
        gs: &mut GroupStore<T>,
        alice: Rc<RefCell<Individual>>,
        bob: Rc<RefCell<Individual>>,
        csprng: &mut R,
    ) -> [Rc<RefCell<Group<T>>>; 10] {
        let signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let active = Active::generate(signer, csprng).unwrap();

        let group0 = gs.generate_group(nonempty![alice.into()]).unwrap();
        let group1 = gs.generate_group(nonempty![bob.into()]).unwrap();
        let group2 = gs.generate_group(nonempty![group1.clone().into()]).unwrap();
        let group3 = gs.generate_group(nonempty![group2.clone().into()]).unwrap();
        let group4 = gs.generate_group(nonempty![group3.clone().into()]).unwrap();
        let group5 = gs.generate_group(nonempty![group4.clone().into()]).unwrap();
        let group6 = gs.generate_group(nonempty![group5.clone().into()]).unwrap();
        let group7 = gs.generate_group(nonempty![group6.clone().into()]).unwrap();
        let group8 = gs.generate_group(nonempty![group7.clone().into()]).unwrap();
        let group9 = gs.generate_group(nonempty![group8.clone().into()]).unwrap();

        group0.borrow_mut().add_delegation(
            Signed::try_sign(
                Delegation {
                    delegate: group9.clone().into(),
                    can: Access::Admin,
                    proof: None,
                    after_revocations: vec![],
                    after_content: BTreeMap::new(),
                },
                &active.signer,
            )
            .unwrap(),
        );

        [
            group0, group1, group2, group3, group4, group5, group6, group7, group8, group9,
        ]
    }

    #[test]
    fn test_transitive_self() {
        let alice = Rc::new(RefCell::new(setup_user()));
        let alice_agent: Agent<String> = alice.dupe().into();
        let alice_id = alice_agent.agent_id();

        let bob = Rc::new(RefCell::new(setup_user()));

        let mut gs: GroupStore<String> = GroupStore::new();
        let [g0, ..] = setup_groups(&mut gs, alice.clone(), bob);

        let g0_mems = gs.transitive_members(&g0.dupe().as_ref().clone().into_inner());

        assert_eq!(
            g0_mems,
            BTreeMap::from_iter([(alice_id, (alice.into(), Access::Admin))])
        );
    }

    #[test]
    fn test_transitive_one() {
        let alice = Rc::new(RefCell::new(setup_user()));
        let alice_agent: Agent<String> = alice.dupe().into();
        let alice_id = alice_agent.agent_id();

        let bob = Rc::new(RefCell::new(setup_user()));

        let mut gs: GroupStore<String> = GroupStore::new();

        let [_g0, g1, _g2, _g3] = setup_groups(&mut gs, alice.dupe(), bob);
        let g1_mems = gs.transitive_members(&g1.borrow());

        assert_eq!(
            g1_mems,
            BTreeMap::from_iter([(alice_id, (alice.clone().into(), Access::Admin))])
        );
    }

    #[test]
    fn test_transitive_two() {
        let alice = Rc::new(RefCell::new(setup_user()));
        let alice_agent: Agent<String> = alice.dupe().into();
        let alice_id = alice_agent.agent_id();

        let bob = Rc::new(RefCell::new(setup_user()));
        let bob_agent: Agent<String> = bob.dupe().into();
        let bob_id = bob_agent.agent_id();

        let mut gs: GroupStore<String> = GroupStore::new();

        let [_g0, _g1, g2, _g3] = setup_groups(&mut gs, alice.dupe(), bob.dupe());
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
        let alice = Rc::new(RefCell::new(setup_user()));
        let alice_agent: Agent<String> = alice.dupe().into();
        let alice_id = alice_agent.agent_id();

        let bob = Rc::new(RefCell::new(setup_user()));
        let bob_agent: Agent<String> = bob.dupe().into();
        let bob_id = bob_agent.agent_id();

        let mut gs: GroupStore<String> = GroupStore::new();

        let [_g0, _g1, _g2, g3] = setup_groups(&mut gs, alice.dupe(), bob.dupe());
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

        let alice = Rc::new(RefCell::new(setup_user()));
        let alice_agent: Agent<String> = alice.dupe().into();
        let alice_id = alice_agent.agent_id();

        let bob = Rc::new(RefCell::new(setup_user()));
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

        let alice = Rc::new(RefCell::new(setup_user()));
        let alice_agent: Agent<String> = alice.dupe().into();

        let bob = Rc::new(RefCell::new(setup_user()));
        let bob_agent: Agent<String> = bob.dupe().into();

        let carol = Rc::new(RefCell::new(setup_user()));
        let carol_agent: Agent<String> = carol.dupe().into();

        let signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let active = Rc::new(RefCell::new(Active::generate(signer, csprng).unwrap()));
        let active_agent: Agent<String> = active.dupe().into();

        let mut gs: GroupStore<String> = GroupStore::new();

        let g0 = gs.generate_group(nonempty![active.dupe().into()]).unwrap();
        let g1 = gs
            .generate_group(nonempty![
                alice_agent.dupe(),
                bob_agent.dupe(),
                g0.dupe().into()
            ])
            .unwrap();
        let g2 = gs
            .generate_group(nonempty![carol_agent.dupe(), g1.dupe().into()])
            .unwrap();

        g0.borrow_mut()
            .add_member(
                carol_agent.dupe(),
                Access::Write,
                &active.borrow().signer,
                &[],
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
