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
                    can: Access::Read,
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

    use crate::operation::delegation::Delegation;
    use crate::principal::{active::Active, individual::Individual, membered::MemberedId};
    use std::collections::BTreeSet;

    #[test]
    fn test_materialization() {
        let user: Individual = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
            .verifying_key()
            .into();

        /*
                        ┌───────────┐
                        │           │
        ┌──────────────▶│   User    │
        │               │           │
        │               └─────▲─────┘
        │                     │
        │                     │
        │               ┌───────────┐
        │               │           │
        │        ┌─────▶│  Group 0  │◀─────┐
        │        │      │           │      │
        │        │      └───────────┘      │
        │  ┌───────────┐             ┌───────────┐
        │  │           │             │           │
        └──│  Group 1  │             │  Group 2  │
           │           │             │           │
           └───────────┘             └───────────┘
                 ▲                         ▲
                 │      ┌───────────┐      │
                 │      │           │      │
                 └──────│  Group 3  │──────┘
                        │           │
                        └───────────┘
         */

        let group0 = Group::create(vec![user.clone().into()]);
        let group1 = Group::create(vec![user.clone().into(), group0.clone().into()]);
        let group2 = Group::create(vec![group0.clone().into()]);
        let group3 = Group::create(vec![group1.clone().into(), group2.clone().into()]);

        assert_eq!(1, 1);
    }
}
