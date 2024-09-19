use super::{agent::Agent, identifier::Identifier, traits::Verifiable};
use crate::operation::Operation;
use crate::{
    access::Access,
    crypto::signed::Signed,
    operation::{delegation::Delegation, revocation::Revocation},
};
use std::collections::BTreeMap;

pub mod state;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Group {
    pub id: Identifier,
    pub delegates: BTreeMap<Agent, (Access, Signed<Delegation>)>,
    pub state: state::GroupState,
}

impl Group {
    pub fn materialize(state: state::GroupState) -> Self {
        let delegates = Operation::topsort(todo!(), state.ops())
            .expect("FIXME")
            .iter()
            .fold(BTreeMap::new(), |acc, signed| match signed {
                Signed {
                    payload: Operation::Delegation(delegation),
                    signature,
                    verifying_key,
                } => {
                    acc.insert(
                        delegation.to,
                        (
                            delegation.can,
                            Signed {
                                payload: *delegation,
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

        Group {
            id: state.id.into(),
            state,
            delegates,
        }
    }

    pub fn add_member(&mut self, delegation: Signed<Delegation>) {
        self.state.delegations.insert(delegation.into());
        todo!() // rebuild, later do IVM
    }

    pub fn revoke(&mut self, revocation: Signed<Revocation>) {
        self.state.revocations.insert(revocation.into());
        todo!() // rebuild, later do IVM
    }
}

impl Verifiable for Group {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id.verifying_key
    }
}
