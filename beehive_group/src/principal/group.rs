use super::{
    agent::Agent, identifier::Identifier, individual::Individual, membered::MemberedId,
    traits::Verifiable,
};
use crate::crypto::hash::{CAStore, Hash};
use crate::operation::Operation;
use crate::{
    access::Access,
    crypto::signed::Signed,
    operation::{delegation::Delegation, revocation::Revocation},
};
use std::collections::{BTreeMap, BTreeSet};

pub mod state;
pub mod store;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Group {
    pub delegates: BTreeMap<Agent, (Access, Signed<Delegation>)>,
    pub state: state::GroupState,
}

impl Group {
    pub fn id(&self) -> Identifier {
        self.state.id
    }

    pub fn add_member(&mut self, signed_delegation: Signed<Delegation>) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        self.delegates.insert(
            signed_delegation.payload.to.clone(),
            (signed_delegation.payload.can, signed_delegation.clone()),
        );

        self.state
            .ops
            .insert(signed_delegation.map(|delegation| delegation.into()).into());
    }

    pub fn create(parents: Vec<Agent>) -> Group {
        let group_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let group_id = group_signer.verifying_key().into();

        let (ops, delegates) = parents.iter().fold(
            (CAStore::new(), BTreeMap::new()),
            |(mut op_acc, mut mem_acc), parent| {
                let del = Delegation {
                    subject: MemberedId::GroupId(group_id),
                    from: group_id,
                    to: parent.clone(),
                    can: Access::Admin,
                    proof: vec![],
                    after_auth: vec![],
                };

                let signed_op = Signed::sign(del.clone().into(), &group_signer);
                let signed_del = Signed::sign(del, &group_signer);

                mem_acc.insert(parent.clone(), (Access::Admin, signed_del.clone()));

                op_acc.insert(signed_op);
                (op_acc, mem_acc)
            },
        );

        Group {
            delegates,
            state: crate::principal::group::state::GroupState {
                id: group_id,
                heads: BTreeSet::from_iter(ops.clone().into_keys()),
                ops,
            },
        }
    }

    pub fn materialize(state: state::GroupState) -> Self {
        // FIXME oof that's a lot of cloning to get the heads
        let delegates = Operation::topsort(state.heads.clone().into_iter().collect(), &state.ops)
            .expect("FIXME")
            .iter()
            .fold(BTreeMap::new(), |mut acc, signed| match signed {
                Signed {
                    payload: Operation::Delegation(delegation),
                    signature,
                    verifying_key,
                } => {
                    acc.insert(
                        delegation.to.clone(),
                        (
                            delegation.can,
                            Signed {
                                payload: delegation.clone(),
                                signature: *signature,
                                verifying_key: *verifying_key,
                            },
                        ),
                    );

                    acc
                }
                Signed {
                    payload: Operation::Revocation(revocation),
                    ..
                } =>
                // FIXME allow downgrading instead of straight removal?
                {
                    acc.remove(&revocation.revoke.payload.to);
                    acc
                }
            });

        Group { state, delegates }
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

impl Verifiable for Group {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id().verifying_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::store::GroupStore;
    use crate::operation::delegation::Delegation;
    use crate::principal::{active::Active, individual::Individual, membered::MemberedId};
    use std::collections::BTreeSet;

    fn setup_user() -> Individual {
        ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
            .verifying_key()
            .into()
    }

    fn setup_store(alice: &Individual, bob: &Individual) -> (GroupStore, [Group; 4]) {
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

        let group0 = Group::create(vec![alice.clone().into()]);
        let group1 = Group::create(vec![alice.clone().into(), group0.clone().into()]);
        let group2 = Group::create(vec![group0.clone().into(), bob.clone().into()]);
        let group3 = Group::create(vec![group1.clone().into(), group2.clone().into()]);

        let mut gs = GroupStore::new();
        // FIXME horrifying
        gs.insert(group0.clone().into());
        gs.insert(group1.clone().into());
        gs.insert(group2.clone().into());
        gs.insert(group3.clone().into());

        (gs, [group0, group1, group2, group3])
    }

    fn setup_cyclic_store(alice: &Individual, bob: &Individual) -> (GroupStore, [Group; 10]) {
        let group0 = Group::create(vec![alice.clone().into()]);
        let group1 = Group::create(vec![bob.clone().into()]);

        let group2 = Group::create(vec![group1.clone().into()]);
        let group3 = Group::create(vec![group2.clone().into(), group2.clone().into()]);
        let group4 = Group::create(vec![group3.clone().into(), group2.clone().into()]);
        let group5 = Group::create(vec![group4.clone().into(), group2.clone().into()]);
        let group6 = Group::create(vec![group5.clone().into(), group2.clone().into()]);
        let group7 = Group::create(vec![group6.clone().into(), group2.clone().into()]);
        let group8 = Group::create(vec![group7.clone().into(), group2.clone().into()]);
        let mut group9 = Group::create(vec![group8.clone().into(), alice.clone().into()]);

        let active = Active::generate();

        group9.add_member(Signed::sign(
            Delegation {
                subject: MemberedId::GroupId(group9.id()),
                from: group9.id(),
                to: alice.clone().into(),
                can: Access::Admin,
                proof: vec![],
                after_auth: vec![],
            },
            &active.signer,
        ));

        let mut gs = GroupStore::new();
        // FIXME horrifying
        gs.insert(group0.clone().into());
        gs.insert(group1.clone().into());
        gs.insert(group2.clone().into());
        gs.insert(group3.clone().into());
        gs.insert(group4.clone().into());
        gs.insert(group5.clone().into());
        gs.insert(group6.clone().into());
        gs.insert(group7.clone().into());
        gs.insert(group8.clone().into());
        gs.insert(group9.clone().into());

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
        let bob = setup_user();

        let (gs, [g0, _g1, _g2, _g3]) = setup_store(&alice, &bob);
        let g0_mems: BTreeMap<Agent, Access> = gs.transative_members(&g0);

        assert_eq!(
            g0_mems,
            BTreeMap::from_iter([(alice.into(), Access::Admin)])
        );
    }

    #[test]
    fn test_transitive_one() {
        let alice = setup_user();
        let bob = setup_user();

        let (gs, [_g0, g1, _g2, _g3]) = setup_store(&alice, &bob);
        let g1_mems: BTreeMap<Agent, Access> = gs.transative_members(&g1);

        assert_eq!(
            g1_mems,
            BTreeMap::from_iter([(alice.into(), Access::Admin)])
        );
    }

    #[test]
    fn test_transitive_two() {
        let alice = setup_user();
        let bob = setup_user();

        let (gs, [_g0, _g1, g2, _g3]) = setup_store(&alice, &bob);
        let g2_mems: BTreeMap<Agent, Access> = gs.transative_members(&g2);

        assert_eq!(
            g2_mems,
            BTreeMap::from_iter([(alice.into(), Access::Admin), (bob.into(), Access::Admin)])
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

        let (mut gs, [mut g0, _, _, _]) = setup_store(&alice, &bob);

        let active = Active::generate();

        g0.add_member(Signed::sign(
            Delegation {
                subject: MemberedId::GroupId(g0.id()),
                from: active.id(),
                to: carol.clone().into(),
                can: Access::Admin,
                proof: vec![],
                after_auth: vec![],
            },
            &active.signer,
        ));

        gs.insert(g0.clone().into());

        let g0_mems: BTreeMap<Agent, Access> = gs.transative_members(&g0);

        assert_eq!(
            g0_mems,
            BTreeMap::from_iter([(alice.into(), Access::Admin), (carol.into(), Access::Admin)])
        );
    }
}
