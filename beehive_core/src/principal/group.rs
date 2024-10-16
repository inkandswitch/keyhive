//! Model a collect.clone(),ion of agents with no associated content.

pub mod id;
pub mod operation;
pub mod state;
pub mod store;

use super::{
    agent::{Agent, AgentId},
    verifiable::Verifiable,
};
use crate::{
    access::Access, content::reference::ContentRef, crypto::signed::Signed,
    util::content_addressed_map::CaMap,
};
use id::GroupId;
use nonempty::NonEmpty;
use operation::{delegation::Delegation, revocation::Revocation, Operation};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A collection of agents with no associated content.
///
/// Groups are stateful agents. It is possible the delegate control over them,
/// and they can be delegated to. This produces transitives lines of authority
/// through the network of [`Agent`]s.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Group<'a, T: ContentRef> {
    /// The current view of members of a group.
    pub members: BTreeMap<AgentId, &'a Box<Signed<Delegation<'a, T>>>>, // FIXME make not publicly editable

    /// The `Group`'s underlying (causal) delegation state.
    pub state: state::GroupState<'a, T>,
}

impl<'a, T: ContentRef> Group<'a, T> {
    /// Generate a new `Group` with a unique [`Identifier`] and the given `parents`.
    pub fn generate(parents: NonEmpty<&'a Agent<T>>) -> Group<'a, T> {
        let group_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let group_id = GroupId(group_signer.verifying_key().into());

        let (delegations, members) = parents.iter().fold(
            (CaMap::new(), BTreeMap::new()),
            |(mut op_acc, mut mem_acc), parent| {
                let del = Delegation {
                    delegate: parent,
                    can: Access::Admin,
                    proof: None,
                    after_revocations: vec![],
                    after_content: BTreeMap::new(),
                };

                let signed_op = Box::new(Signed::sign(del.clone().into(), &group_signer));
                let signed_del = Box::new(Signed::sign(del, &group_signer));

                mem_acc.insert((*parent).id(), &signed_del);

                op_acc.insert(signed_op);
                (op_acc, mem_acc)
            },
        );

        Group {
            members,
            state: state::GroupState {
                id: group_id,
                delegation_heads: BTreeSet::from_iter(delegations.keys().iter()),
                delegations,

                revocation_heads: BTreeSet::new(),
                revocations: CaMap::new(),
            },
        }
    }

    pub fn id(&self) -> GroupId {
        self.state.id
    }

    pub fn agent_id(&self) -> AgentId {
        self.id().into()
    }

    // FIXME get_capability?
    pub fn get(&self, agent: &AgentId) -> Option<&Box<Signed<Delegation<T>>>> {
        self.members.get(agent).copied()
    }

    // FIXME rename
    pub fn add_member(&mut self, signed_delegation: Signed<Delegation<'a, T>>) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        // FIXME even better: use dgp (e.g. Valid<Signed<Delegation<'a, T>>)

        let boxed = Box::new(signed_delegation);
        let id = boxed.payload.delegate.id();
        self.state.delegations.insert(boxed);
        self.members.insert(id, &boxed);
        // let new_ref = self.state.delegations.get(&hash).expect("value that was just added to be there");
    }

    pub fn materialize(state: state::GroupState<T>) -> Self {
        // FIXME oof that's a lot of cloning

        let ops: Vec<Signed<Operation<T>>> = state
            .delegations
            .iter()
            .map(|(_k, v)| v.map(|d| d.into()))
            .chain(state.revocations.iter().map(|(_k, v)| v.map(|r| r.into())))
            .collect();

        let heads: Vec<&Signed<Operation<T>>> = todo!();

        let members = Operation::topsort(&heads, &ops)
            .expect("FIXME")
            .iter()
            .fold(BTreeMap::new(), |mut acc, signed| match signed {
                Signed {
                    payload: Operation::Delegation(delegation),
                    signature,
                    verifying_key,
                } => {
                    acc.insert(
                        delegation.delegate,
                        Signed {
                            payload: delegation.clone(),
                            signature,
                            verifying_key,
                        },
                    );

                    acc
                }
                Signed {
                    payload: Operation::Revocation(revocation),
                    ..
                } => {
                    acc.remove(&revocation.revoke.payload.delegate);
                    acc
                }
            });

        Group { state, members }
    }

    pub fn revoke(&mut self, signed_revocation: Signed<Revocation<T>>) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        self.members
            .remove(&signed_revocation.payload.revoke.payload.delegate.id());

        let boxed = Box::new(signed_revocation);
        self.state.revocations.insert(boxed);
        self.state.revocation_heads.insert(&signed_revocation);
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

impl<'a, T: ContentRef> Verifiable for Group<'a, T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.state.verifying_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::{operation::delegation::Delegation, store::GroupStore};
    use crate::principal::{active::Active, individual::Individual};
    use nonempty::nonempty;

    fn setup_user() -> Individual {
        ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
            .verifying_key()
            .into()
    }

    fn setup_store<'a, T: ContentRef>(
        alice: &Individual,
        bob: &Individual,
    ) -> (GroupStore<'a, T>, [Group<'a, T>; 4]) {
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

        let alice_agent = alice.clone().into();
        let bob_agent = bob.clone().into();

        let group0 = Group::generate(nonempty![&alice_agent]);
        let group0_agent: Agent<'a, T> = group0.clone().into();

        let group1 = Group::generate(nonempty![&alice_agent, &group0_agent]);
        let group1_agent = group1.clone().into();

        let group2 = Group::generate(nonempty![&group0_agent, &bob_agent]);
        let group2_agent = group2.clone().into();

        let group3 = Group::generate(nonempty![&group1_agent, &group2_agent]);

        let mut gs = GroupStore::new();

        gs.insert(group0.clone());
        gs.insert(group1.clone());
        gs.insert(group2.clone());
        gs.insert(group3.clone());

        (gs, [group0, group1, group2, group3])
    }

    fn setup_cyclic_store<'a, T: Clone + Ord + Serialize>(
        alice: &Individual,
        bob: &Individual,
    ) -> (GroupStore<'a, T>, [Group<'a, T>; 10]) {
        let alice_agent = alice.clone().into();
        let bob_agent = bob.clone().into();

        let group0 = Group::generate(nonempty![&alice_agent]);

        let group1 = Group::generate(nonempty![&bob_agent]);
        let group1_agent = group1.clone().into();

        let group2 = Group::generate(nonempty![&group1_agent]);
        let group2_agent = group2.clone().into();

        let group3 = Group::generate(nonempty![&group2_agent, &group2_agent]);
        let group3_agent = group3.clone().into();

        let group4 = Group::generate(nonempty![&group3_agent, &group2_agent]);
        let group4_agent = group4.clone().into();

        let group5 = Group::generate(nonempty![&group4_agent, &group2_agent]);
        let group5_agent = group5.clone().into();

        let group6 = Group::generate(nonempty![&group5_agent, &group2_agent]);
        let group6_agent = group6.clone().into();

        let group7 = Group::generate(nonempty![&group6_agent, &group2_agent]);
        let group7_agent = group7.clone().into();

        let group8 = Group::generate(nonempty![&group7_agent, &group2_agent]);
        let group8_agent = group8.clone().into();

        let mut group9 = Group::generate(nonempty![&group8_agent, &alice_agent]);

        let active = Active::generate();

        group9.add_member(Signed::sign(
            Delegation {
                delegate: &alice.clone().into(),
                can: Access::Admin,
                proof: None,
                after_revocations: vec![],
                after_content: vec![],
            },
            &active.signer,
        ));

        let mut gs = GroupStore::new();

        gs.insert(group0.clone());
        gs.insert(group1.clone());
        gs.insert(group2.clone());
        gs.insert(group3.clone());
        gs.insert(group4.clone());
        gs.insert(group5.clone());
        gs.insert(group6.clone());
        gs.insert(group7.clone());
        gs.insert(group8.clone());
        gs.insert(group9.clone());

        (
            gs,
            [
                group0, group1, group2, group3, group4, group5, group6, group7, group8, group9,
            ],
        )
    }

    #[test]
    fn test_transitive_self() {
        let alice = setup_user();
        let alice_agent: Agent<'_, String> = alice.clone().into();

        let bob = setup_user();

        let (gs, [g0, _g1, _g2, _g3]) = setup_store(&alice, &bob);
        let g0_mems: BTreeMap<&Agent<'_, _>, Access> = gs.transative_members(&g0);

        assert_eq!(
            g0_mems,
            BTreeMap::from_iter([(&alice_agent, Access::Admin)])
        );
    }

    #[test]
    fn test_transitive_one() {
        let alice = setup_user();
        let alice_agent: Agent<'_, String> = alice.clone().into();

        let bob = setup_user();

        let (gs, [_g0, g1, _g2, _g3]) = setup_store(&alice, &bob);
        let g1_mems: BTreeMap<&Agent<'_, _>, Access> = gs.transative_members(&g1);

        assert_eq!(
            g1_mems,
            BTreeMap::from_iter([(&alice_agent, Access::Admin)])
        );
    }

    #[test]
    fn test_transitive_two() {
        let alice = setup_user();
        let bob = setup_user();

        let (gs, [_g0, _g1, g2, _g3]) = setup_store(&alice, &bob);
        let g2_mems: BTreeMap<&Agent<'_, String>, Access> = gs.transative_members(&g2);

        assert_eq!(
            g2_mems,
            BTreeMap::from_iter([
                (&alice.clone().into(), Access::Admin),
                (&bob.clone().into(), Access::Admin)
            ])
        );
    }

    #[test]
    fn test_transitive_tree() {
        let alice = setup_user();
        let bob = setup_user();

        let (gs, [_g0, _g1, _g2, g3]) = setup_store(&alice, &bob);
        let g3_mems: BTreeMap<Agent, Access> = gs.transative_members(&g3);

        assert_eq!(
            g3_mems,
            BTreeMap::from_iter([(alice.into(), Access::Admin), (bob.into(), Access::Admin)])
        );
    }

    #[test]
    fn test_transitive_cycles() {
        let alice = setup_user();
        let bob = setup_user();

        let (gs, [_, _, _, _, _, _, _, _, _, g9]) = setup_cyclic_store(&alice, &bob);
        let g9_mems: BTreeMap<Agent, Access> = gs.transative_members(&g9);

        assert_eq!(
            g9_mems,
            BTreeMap::from_iter([(alice.into(), Access::Admin), (bob.into(), Access::Admin)])
        );
    }

    #[test]
    fn test_add_member() {
        let alice = setup_user();
        let bob = setup_user();
        let carol = setup_user();

        let alice_agent: Agent<'_, _> = alice.into();
        let carol_agent: Agent<'_, _> = carol.into();

        let (mut gs, [mut g0, _, _, _]) = setup_store(&alice, &bob);

        let active = Active::generate();

        g0.add_member(Signed::sign(
            Delegation {
                delegate: &carol_agent,
                can: Access::Admin,
                proof: None,
                after_revocations: vec![],
                after_content: vec![],
            },
            &active.signer,
        ));

        gs.insert(g0.clone().into());

        let g0_mems: BTreeMap<&Agent<'_, _>, Access> = gs.transative_members(&g0);

        assert_eq!(
            g0_mems,
            BTreeMap::from_iter([(&alice_agent, Access::Admin), (&carol_agent, Access::Admin)])
        );
    }
}
