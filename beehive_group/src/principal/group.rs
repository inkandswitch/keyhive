use super::{agent::Agent, identifier::Identifier, traits::Verifiable};
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
        // PSEUDOCODE
        // walk graph adding all parents to nodes
        //   ^^ this can probably be put directly on Operation
        // build a partial order
        //

        // Note to self: verify upon adding, not here

        let delegates = todo!();

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
