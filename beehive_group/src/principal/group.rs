use super::{
    agent::Agent, identifier::Identifier, individual::Individual, membered::MemberedId,
    traits::Verifiable,
};
use crate::{
    access::Access,
    crypto::{hash::CAStore, signed::Signed},
    operation::{delegation::Delegation, revocation::Revocation, Operation},
};
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Group {
    pub id: Identifier,
    pub delegates: BTreeMap<Agent, (Access, Signed<Delegation>)>, // FIXME ref that &'a signed<del>
    pub state: GroupState,
}

impl Group {
    pub fn add_member(&mut self, delegation: Signed<Delegation>) {
        self.state.delegations.insert(delegation.into());
        todo!() // rebuild, later do IVM
    }
}

impl Verifiable for Group {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id.verifying_key
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupState {
    pub id: Identifier,
    pub delegations: CAStore<Signed<Delegation>>,
    pub revocations: CAStore<Signed<Revocation>>,
}

impl From<VerifyingKey> for GroupState {
    fn from(verifier: VerifyingKey) -> Self {
        GroupState {
            id: verifier.into(),
            delegations: CAStore::new(),
            revocations: CAStore::new(),
        }
    }
}

impl PartialOrd for GroupState {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // FIXME use all fields
        self.id.to_bytes().partial_cmp(&other.id.to_bytes())
    }
}

impl Ord for GroupState {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.to_bytes().cmp(&other.id.to_bytes())
    }
}

impl GroupState {
    pub fn new(parent: Individual) -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifier: VerifyingKey = signing_key.verifying_key();

        let init = Delegation {
            subject: MemberedId::GroupId(verifier.into()),

            from: verifier.into(),
            to: parent.into(),
            can: Access::Admin,

            proof: vec![],
            after_auth: vec![],
        };

        let signed_init: Signed<Delegation> = Signed::sign(&init, &signing_key);

        // FIXME zeroize signing key

        Self {
            id: verifier.into(),
            delegations: CAStore::from_iter([signed_init.into()]),
            revocations: CAStore::new(),
        }
    }

    // pub fn get_capability(&self, agent: Agent) -> Option<Capability> {
    //     self.authority_ops.iter().find_map(|op| match op {
    //         Operation::Delegation(delegation) => {
    //             if delegation.to == agent {
    //                 Some(delegation.can)
    //             } else {
    //                 None
    //             }
    //         }
    //         _ => None,
    //     })
    // }
}

impl Verifiable for GroupState {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id.verifying_key
    }
}
