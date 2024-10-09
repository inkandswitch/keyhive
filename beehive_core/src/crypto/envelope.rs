use super::{hash::Hash, symmetric_key::SymmetricKey};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Envelope<T> {
    pub payload: T,
    pub ancestors: BTreeMap<SymmetricKey>,
}

impl<T> Envelope<T> {
    pub fn causal_keys(&self) -> Vec<CausalKey<T>> {
        self.ancestors
            .iter()
            .map(|(key, _)| CausalKey {
                hash: Hash::hash(self),
                key: key.clone(),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CausalKey<T> {
    pub hash: Hash<Envelope<T>>,
    pub key: SymmetricKey,
}
