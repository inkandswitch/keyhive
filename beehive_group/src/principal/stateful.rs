use super::traits::Verifiable;
use crate::access::Access;
use crate::hash::CAStore;
use crate::operation::Operation;
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Op();

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Stateful {
    pub verifier: VerifyingKey,
    pub auth_ops: CAStore<Operation>,
}

impl From<VerifyingKey> for Stateful {
    fn from(verifier: VerifyingKey) -> Self {
        Stateful {
            verifier,
            auth_ops: CAStore::new(),
        }
    }
}

impl PartialOrd for Stateful {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
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
