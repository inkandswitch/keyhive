use crate::access::Access;
use crate::hash::CAStore;
use crate::operation::Operation;
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeMap;

use super::traits::Identifiable;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Op();

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Stateful {
    verifier: VerifyingKey,
    auth_ops: CAStore<Operation>,
}

impl PartialOrd for Stateful {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.verifier
            .to_bytes()
            .partial_cmp(&other.verifier.to_bytes())
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

impl Identifiable for Stateful {
    fn id(&self) -> [u8; 32] {
        self.verifier.to_bytes()
    }
}
