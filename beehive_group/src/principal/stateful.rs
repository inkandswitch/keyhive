use super::{stateless::Stateless, traits::Verifiable};
use crate::{
    access::Access,
    crypto::Signed,
    hash::CAStore,
    operation::{delegation::Delegation, Operation},
};
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Stateful {
    pub verifier: VerifyingKey,
    pub authority_ops: CAStore<Signed<Operation>>,
}

impl From<VerifyingKey> for Stateful {
    fn from(verifier: VerifyingKey) -> Self {
        Stateful {
            verifier,
            authority_ops: CAStore::new(),
        }
    }
}

impl PartialOrd for Stateful {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // FIXME use all fields
        self.verifier
            .to_bytes()
            .partial_cmp(&other.verifier.to_bytes())
    }
}

impl Ord for Stateful {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.verifier.to_bytes().cmp(&other.verifier.to_bytes())
    }
}

pub struct Materialized {
    pub id: VerifyingKey,
    pub delegates: BTreeMap<VerifyingKey, Access>,
}

impl Stateful {
    pub fn new(parent: Stateless) -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifier: VerifyingKey = signing_key.verifying_key();

        let init = Operation::Delegation(Delegation {
            subject: verifier.into(),

            from: verifier.into(),
            to: parent.into(),
            can: Access::Admin,

            proof: vec![],
            after_auth: vec![],
        });

        let signed_init: Signed<Operation> = Signed::sign(&init, &signing_key);

        // FIXME zeroize signing key

        Self {
            verifier,
            authority_ops: CAStore::from_iter([signed_init]),
        }
    }

    pub fn materialize(&self) -> Result<Materialized, ()> {
        todo!();

        // Ok(Materialized {
        //     id: VerifyingKey::from_bytes(&[0; 32]).unwrap(),
        //     delegates: BTreeMap::new(),
        // })
    }
}

impl Verifiable for Stateful {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.verifier
    }
}
