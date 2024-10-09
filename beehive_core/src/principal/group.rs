pub mod operation;
pub mod state;
pub mod store;

use super::auth_state::AuthState;
use super::{agent::Agent, identifier::Identifier, membered::MemberedId, traits::Verifiable};
use crate::crypto::hash::Hash;
use crate::util::content_addressed_map::CaMap;
use crate::{access::Access, crypto::signed::Signed};
use base64::prelude::*;
use operation::Operation;
use operation::{delegation::Delegation, revocation::Revocation};
use state::{AddError, GroupState};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Group {
    pub delegates: BTreeMap<Agent, (Access, Signed<Delegation>)>,
    // FIXME: This exists to trace delegators via an Operation, which only
    // knows about the Identifier, but ideally we wouldn't keep the extra set.
    pub delegate_ids: BTreeMap<Identifier, Agent>,
    pub quarantine: BTreeMap<Hash<Signed<Operation>>, BTreeSet<Signed<Delegation>>>,
    pub state: state::GroupState,
}

impl std::fmt::Display for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.state.id.as_bytes()))
    }
}

impl Group {
    pub fn id(&self) -> Identifier {
        self.state.id
    }

    pub fn add_member(&mut self, signed_delegation: Signed<Delegation>) {
        signed_delegation
            // FIXME should be able to use just ? once this fn returns Result
            .verify()
            .map_err(AddError::InvalidSignature)
            .expect("FIXME");
        if signed_delegation.payload.subject != MemberedId::GroupId(self.id()) {
            panic!("FIXME");
            // return AddError::InvalidSubject;
        }

        //FIXME look for id in materialized view
        if let Some(proof) = &signed_delegation.payload.delegator_proof {
            if !self.id_in_delegates(signed_delegation.payload.delegator) || !self.state.ops.contains_key(proof) {
                self.quarantine
                    .entry(*proof)
                    .or_default()
                    .insert(signed_delegation);
                return;
            }
        } else {
            if signed_delegation.payload.delegator != self.id() {
                panic!("FIXME");
                // return AddError::InvalidDelegation
            }
        }

        self.delegates.insert(
            signed_delegation.payload.delegate.clone(),
            (signed_delegation.payload.can, signed_delegation.clone()),
        );
        self.delegate_ids.insert(signed_delegation.payload.delegate.id(), signed_delegation.payload.delegate.clone());

        self.state
            .ops
            .insert(signed_delegation.clone().map(|delegation| delegation.into()));

        let delegation_hash = Hash::hash(signed_delegation.clone().map(|delegation| delegation.into()));
        if self
            .quarantine
            .contains_key(&delegation_hash)
        {
            for delegate in self
                .quarantine
                .remove(&delegation_hash)
                .unwrap_or_default()
            {
                self.add_member(delegate);
            }
        }
    }

    pub fn new(parents: Vec<&Agent>) -> Group {
        let group_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let group_id = group_signer.verifying_key().into();

        let (ops, delegates) = parents.iter().fold(
            (CaMap::new(), BTreeMap::new()),
            |(mut op_acc, mut mem_acc), parent| {
                let del = Delegation {
                    subject: MemberedId::GroupId(group_id),
                    delegator: group_id,
                    delegate: (*parent).clone(),
                    can: Access::Admin,
                    delegator_proof: None,
                    after_revocations: vec![],
                };

                let signed_op: Signed<Operation> = Signed::sign(del.clone().into(), &group_signer);
                let signed_del = Signed::sign(del, &group_signer);

                mem_acc.insert((*parent).clone(), (Access::Admin, signed_del.clone()));

                op_acc.insert(signed_op);
                (op_acc, mem_acc)
            },
        );

        let mut delegate_ids = BTreeMap::new();
        for agent in delegates.keys() {
            delegate_ids.insert(agent.id(), agent.clone());
        }

        Group {
            delegates,
            delegate_ids,
            quarantine: BTreeMap::new(),
            state: GroupState {
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
                        delegation.delegate.clone(),
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
                    acc.remove(&revocation.revoked_agent());
                    acc
                }
            });

        let mut delegate_ids = BTreeMap::new();
        for agent in delegates.keys() {
            delegate_ids.insert(agent.id(), agent.clone());
        }

        // FIXME: How should we handle quarantine here?
        let quarantine = BTreeMap::new();
        Group {
            delegates,
            delegate_ids,
            quarantine,
            state,
        }
    }

    pub fn revoke(&mut self, signed_revocation: Signed<Revocation>) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        self.delegates
            .remove(&signed_revocation.payload.revoke.payload.delegate);
        self.delegate_ids
            .remove(&signed_revocation.payload.revoke.payload.delegate.id());

        self.state
            .ops
            .insert(signed_revocation.map(|revocation| revocation.into()));
    }

    pub fn find_delegation(&self, delegate: Identifier) -> Option<&Signed<Delegation>> {
        let agent = self.delegate_ids.get(&delegate)?;
        Some(&self.delegates.get(agent)?.1)
    }

    pub fn id_in_delegates(&self, delegate: Identifier) -> bool {
        self.find_delegation(delegate).is_some()
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

impl AuthState for Group {
    fn id(&self) -> Identifier {
        self.state.id()
    }

    fn auth_heads(&self) -> &BTreeSet<Hash<Signed<Operation>>> {
        self.state.auth_heads()
    }

    fn auth_heads_mut(&mut self) -> &mut BTreeSet<Hash<Signed<Operation>>> {
        self.state.auth_heads_mut()
    }

    fn auth_ops(&self) -> &CaMap<Signed<Operation>> {
        self.state.auth_ops()
    }

    fn auth_ops_mut(&mut self) -> &mut CaMap<Signed<Operation>> {
        self.state.auth_ops_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::operation::delegation::Delegation;
    use super::store::GroupStore;
    use crate::principal::{active::Active, individual::Individual, membered::MemberedId};

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

        let group0 = Group::new(vec![&alice.clone().into()]);
        let group1 = Group::new(vec![&alice.clone().into(), &group0.clone().into()]);
        let group2 = Group::new(vec![&group0.clone().into(), &bob.clone().into()]);
        let group3 = Group::new(vec![&group1.clone().into(), &group2.clone().into()]);

        let mut gs = GroupStore::new();
        // FIXME horrifying clones 😱
        gs.insert(group0.clone().into());
        gs.insert(group1.clone().into());
        gs.insert(group2.clone().into());
        gs.insert(group3.clone().into());

        (gs, [group0, group1, group2, group3])
    }

    fn setup_cyclic_store(alice: &Individual, bob: &Individual) -> (GroupStore, [Group; 10]) {
        let group0 = Group::new(vec![&alice.clone().into()]);
        let group1 = Group::new(vec![&bob.clone().into()]);

        let group2 = Group::new(vec![&group1.clone().into()]);
        let group3 = Group::new(vec![&group2.clone().into(), &group2.clone().into()]);
        let group4 = Group::new(vec![&group3.clone().into(), &group2.clone().into()]);
        let group5 = Group::new(vec![&group4.clone().into(), &group2.clone().into()]);
        let group6 = Group::new(vec![&group5.clone().into(), &group2.clone().into()]);
        let group7 = Group::new(vec![&group6.clone().into(), &group2.clone().into()]);
        let group8 = Group::new(vec![&group7.clone().into(), &group2.clone().into()]);
        let mut group9 = Group::new(vec![&group8.clone().into(), &alice.clone().into()]);

        let active = Active::generate();

        group9.add_member(Signed::sign(
            Delegation {
                subject: MemberedId::GroupId(group9.id()),
                delegator: group9.id(),
                delegate: alice.clone().into(),
                can: Access::Admin,
                delegator_proof: None,
                after_revocations: vec![],
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
        let g0_mems: BTreeMap<Agent, Access> = gs.transitive_members(&g0);

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
        let g1_mems: BTreeMap<Agent, Access> = gs.transitive_members(&g1);

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
        let g2_mems: BTreeMap<Agent, Access> = gs.transitive_members(&g2);

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
        let g3_mems: BTreeMap<Agent, Access> = gs.transitive_members(&g3);

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
        let g9_mems: BTreeMap<Agent, Access> = gs.transitive_members(&g9);

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

        let delegator_proof = g0.find_delegation(alice.id).expect("Should find proof.");
        g0.add_member(Signed::sign(
            Delegation {
                subject: MemberedId::GroupId(g0.id()),
                delegator: alice.id,
                delegate: carol.clone().into(),
                can: Access::Admin,
                delegator_proof: Some(Hash::hash(delegator_proof.clone().map(|delegation| delegation.into()))),
                after_revocations: vec![],
            },
            &active.signer,
        ));

        gs.insert(g0.clone().into());

        let g0_mems: BTreeMap<Agent, Access> = gs.transitive_members(&g0);

        assert_eq!(
            g0_mems,
            BTreeMap::from_iter([(alice.into(), Access::Admin), (carol.into(), Access::Admin)])
        );
    }

    #[test]
    // FIXME: When add_member returns Error, use that instead
    #[should_panic]
    fn test_add_member_with_invalid_subject() {
        let alice = setup_user();
        let bob = setup_user();
        let carol = setup_user();
        let dan = setup_user();
        let erin = setup_user();

        let (_, [mut g0, _, _, _]) = setup_store(&alice, &bob);
        let (_, [mut g1, _, _, _]) = setup_store(&carol, &dan);

        let active = Active::generate();


        g0.add_member(Signed::sign(
            Delegation {
                subject: MemberedId::GroupId(g1.id()),
                delegator: active.id(),
                delegate: erin.clone().into(),
                can: Access::Admin,
                delegator_proof: None,
                after_revocations: vec![],
            },
            &active.signer,
        ));
    }

    #[test]
    fn test_add_member_with_invalid_delegation() {
        let alice = setup_user();
        let bob = setup_user();
        let carol = setup_user();
        let dan = setup_user();

        let (_, [mut g0, _, _, _]) = setup_store(&alice, &bob);

        let active = Active::generate();

        let alice_delegator_proof = g0.find_delegation(alice.id).expect("Should find proof.");
        let carol_delegation = Signed::sign(
            Delegation {
                subject: MemberedId::GroupId(g0.id()),
                delegator: alice.id,
                delegate: carol.clone().into(),
                can: Access::Admin,
                delegator_proof: Some(Hash::hash(alice_delegator_proof.clone().map(|delegation| delegation.into()))),
                after_revocations: vec![],
            },
            &active.signer,
        );

        g0.add_member(Signed::sign(
            Delegation {
                subject: MemberedId::GroupId(g0.id()),
                delegator: carol.id,
                delegate: dan.clone().into(),
                can: Access::Admin,
                delegator_proof: Some(Hash::hash(carol_delegation.clone().map(|delegation| delegation.into()))),
                after_revocations: vec![],
            },
            &active.signer,
        ));
        assert!(!g0.delegate_ids.contains_key(&dan.id));
        g0.add_member(carol_delegation);
        assert!(g0.delegate_ids.contains_key(&dan.id));
    }
}
