use super::{causal_key::CausalKey, hash::Hash, symmetric_key::SymmetricKey};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Envelope<T> {
    pub payload: T,
    pub ancestors: BTreeMap<Hash<Envelope<T>>, SymmetricKey>,
}

impl<T> Envelope<T> {
    pub fn causal_keys(&self) -> Vec<CausalKey<Envelope<T>>> {
        self.ancestors
            .iter()
            .map(|(hash, key)| CausalKey {
                hash: *hash,
                key: *key,
            })
            .collect()
    }
}
