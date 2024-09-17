use super::agent::Agent;
use super::identifier::Identifier;
use super::membered::MemberedId;
use super::{individual::Individual, traits::Verifiable};
use crate::{
    access::Access,
    crypto::{hash::CAStore, signed::Signed},
    operation::{delegation::Delegation, Operation},
};
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeMap;

// FIXME rnemae statelss to ID?

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Group {
    pub id: Identifier,
    pub delegates: BTreeMap<Agent, Access>,
}

impl Verifiable for Group {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id.verifying_key
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupState {
    pub id: Identifier,
    pub authority_ops: CAStore<Signed<Operation>>,
}

impl From<VerifyingKey> for GroupState {
    fn from(verifier: VerifyingKey) -> Self {
        GroupState {
            id: verifier.into(),
            authority_ops: CAStore::new(),
        }
    }
}

// impl PartialOrd for GroupState {
//     fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
//         // FIXME use all fields
//         self.verifier
//             .to_bytes()
//             .partial_cmp(&other.verifier.to_bytes())
//     }
// }
//
// impl Ord for GroupState {
//     fn cmp(&self, other: &Self) -> std::cmp::Ordering {
//         self.verifier.to_bytes().cmp(&other.verifier.to_bytes())
//     }
// }

impl GroupState {
    pub fn new(parent: Individual) -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifier: VerifyingKey = signing_key.verifying_key();

        let init = Operation::Delegation(Delegation {
            subject: MemberedId::GroupId(verifier.into()),

            from: verifier.into(),
            to: parent.into(),
            can: Access::Admin,

            proof: vec![],
            after_auth: vec![],
        });

        let signed_init: Signed<Operation> = Signed::sign(&init, &signing_key);

        // FIXME zeroize signing key

        Self {
            id: verifier.into(),
            authority_ops: CAStore::from_iter([signed_init]),
        }
    }
}

impl Verifiable for GroupState {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id.verifying_key
    }
}
